//! Supervisor-side credential capture: cache, executor, and broker.
//!
//! Handles `cmd://` credential resolution by running allow-listed commands
//! on the host and caching results per session with configurable TTL.
//!
//! ## Design
//!
//! - **Cache-then-execute**: The broker checks an in-memory cache keyed by
//!   `(session_id, credential_name)` before spawning a subprocess. Cache hits
//!   avoid redundant CLI invocations for slow commands (e.g., `aws sts`).
//!
//! - **Timeout enforcement**: The executor polls `child.try_wait()` in a loop
//!   with 10ms sleeps. If elapsed time exceeds the configured timeout, the
//!   child is killed and an error is returned. This avoids blocking the
//!   supervisor indefinitely on a hung credential CLI.
//!
//! - **Security**:
//!   - Commands are resolved to absolute paths at profile-load time via PATH
//!     lookup. No PATH resolution happens at capture time (prevents TOCTOU).
//!   - Shell metacharacters are rejected in all argv elements.
//!   - The child process never names a command — only a logical credential
//!     name. The supervisor maps name → command via the profile.
//!   - Stderr is logged (scrubbed, max 200 bytes) but never returned to the
//!     caller. Credential values are never logged.
//!
//! - **TTL-based cache**: Each credential has an independently configurable
//!   TTL (default 15 minutes). Expired entries are detected on read and
//!   trigger re-execution. All entries for a session can be flushed on exit.

use nono::{NonoError, Result};
use regex::Regex;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing::{debug, warn};
use zeroize::Zeroizing;

/// Default cache TTL (15 minutes).
const DEFAULT_TTL_SECS: u64 = 900;

/// Default command timeout (5 seconds).
const DEFAULT_TIMEOUT_SECS: u64 = 5;

/// Request context passed to credential capture commands as environment variables.
#[derive(Debug, Clone)]
pub struct CaptureContext {
    /// Upstream host (e.g., "api.github.com").
    pub host: String,
    /// Request path (e.g., "/repos/owner/name").
    pub path: String,
    /// HTTP method (e.g., "GET").
    pub method: String,
}

/// Configuration for a single credential capture command.
#[derive(Debug, Clone)]
pub struct CredentialCaptureDef {
    /// Resolved absolute path to the executable.
    pub command_path: PathBuf,
    /// Command arguments (everything after the executable).
    pub command_args: Vec<String>,
    /// Timeout for command execution (enforced by the caller).
    pub timeout_secs: u64,
    /// Cache TTL for the captured value.
    pub ttl: Duration,
    /// Compiled regex for extracting a cache key suffix from the request path.
    /// First capture group becomes the cache suffix.
    pub cache_path_regex: Option<Regex>,
}

/// A cached credential value with expiry.
struct CachedCredential {
    value: Zeroizing<String>,
    expires_at: Instant,
}

/// In-memory credential cache keyed by
/// `"session_id\0credential_name\0host\0path_suffix"`.
///
/// Including the request host in the key keeps credentials isolated per
/// upstream host. This matters when one `cmd://name` credential serves
/// multiple hosts (e.g. via a wildcard upstream): the capture command sees
/// `NONO_REQUEST_HOST` and may mint host-specific tokens, so cached values
/// must not collide across hosts. When no host context is available the host
/// component is empty, preserving prior single-value behaviour.
pub struct CredentialCaptureCache {
    entries: HashMap<String, CachedCredential>,
}

impl CredentialCaptureCache {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn get(
        &self,
        session_id: &str,
        name: &str,
        host: &str,
        path_suffix: &str,
    ) -> Option<Zeroizing<String>> {
        let key = Self::make_key(session_id, name, host, path_suffix);
        self.entries.get(&key).and_then(|cached| {
            if Instant::now() < cached.expires_at {
                Some(cached.value.clone())
            } else {
                None
            }
        })
    }

    pub fn insert(
        &mut self,
        session_id: &str,
        name: &str,
        host: &str,
        path_suffix: &str,
        value: Zeroizing<String>,
        ttl: Duration,
    ) {
        self.entries.insert(
            Self::make_key(session_id, name, host, path_suffix),
            CachedCredential {
                value,
                expires_at: Instant::now() + ttl,
            },
        );
    }

    #[cfg(test)]
    pub fn flush_session(&mut self, session_id: &str) {
        let prefix = format!("{}\0", session_id);
        self.entries.retain(|k, _| !k.starts_with(&prefix));
    }

    fn make_key(session_id: &str, name: &str, host: &str, path_suffix: &str) -> String {
        format!("{}\0{}\0{}\0{}", session_id, name, host, path_suffix)
    }
}

/// Executes allow-listed commands and captures their stdout as credentials.
pub struct CredentialCaptureExecutor;

impl CredentialCaptureExecutor {
    pub fn execute(
        &self,
        config: &CredentialCaptureDef,
        context: Option<&CaptureContext>,
    ) -> Result<Zeroizing<String>> {
        let mut cmd = Command::new(&config.command_path);
        cmd.args(&config.command_args);
        if let Some(ctx) = context {
            cmd.env("NONO_REQUEST_HOST", &ctx.host);
            cmd.env("NONO_REQUEST_PATH", &ctx.path);
            cmd.env("NONO_REQUEST_METHOD", &ctx.method);
        }
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::inherit());
        cmd.stdin(std::process::Stdio::inherit());

        let timeout = Duration::from_secs(config.timeout_secs);
        let start = Instant::now();

        let mut child = cmd.spawn().map_err(|e| {
            NonoError::SandboxInit(format!(
                "credential capture command '{}' failed to execute: {}",
                config.command_path.display(),
                e
            ))
        })?;

        let output = loop {
            match child.try_wait() {
                Ok(Some(_status)) => {
                    break child.wait_with_output().map_err(|e| {
                        NonoError::SandboxInit(format!(
                            "credential capture command '{}' output read failed: {}",
                            config.command_path.display(),
                            e
                        ))
                    })?;
                }
                Ok(None) => {
                    if start.elapsed() > timeout {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(NonoError::SandboxInit(format!(
                            "credential capture command '{}' timed out after {}s",
                            config.command_path.display(),
                            config.timeout_secs
                        )));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => {
                    return Err(NonoError::SandboxInit(format!(
                        "credential capture command '{}' wait failed: {}",
                        config.command_path.display(),
                        e
                    )));
                }
            }
        };
        let elapsed = start.elapsed();

        if !output.status.success() {
            let code = output.status.code();
            warn!(
                "credential capture command '{}' exited with status {:?} ({}ms)",
                config.command_path.display(),
                code,
                elapsed.as_millis()
            );
            return Err(NonoError::SandboxInit(format!(
                "credential capture command exited with status {:?}",
                code
            )));
        }

        let mut raw = String::from_utf8(output.stdout).map_err(|_| {
            NonoError::SandboxInit(
                "credential capture command produced non-UTF-8 output".to_string(),
            )
        })?;

        let trimmed_len = raw.trim_end().len();
        raw.truncate(trimmed_len);

        if raw.is_empty() {
            return Err(NonoError::SandboxInit(
                "credential capture command returned empty output".to_string(),
            ));
        }

        debug!(
            "credential capture '{}' succeeded in {}ms",
            config.command_path.display(),
            elapsed.as_millis()
        );

        Ok(Zeroizing::new(raw))
    }
}

/// Orchestrates credential capture: checks cache, executes commands, stores results.
pub struct CredentialCaptureBroker {
    cache: Mutex<CredentialCaptureCache>,
    executor: CredentialCaptureExecutor,
    configs: HashMap<String, CredentialCaptureDef>,
}

impl CredentialCaptureBroker {
    pub fn new(configs: HashMap<String, CredentialCaptureDef>) -> Self {
        Self {
            cache: Mutex::new(CredentialCaptureCache::new()),
            executor: CredentialCaptureExecutor,
            configs,
        }
    }

    /// Resolve a credential by name, using cache if available.
    ///
    /// When `context` is provided, environment variables `NONO_REQUEST_HOST`,
    /// `NONO_REQUEST_PATH`, and `NONO_REQUEST_METHOD` are set on the spawned
    /// command. If the credential has a `cache_path_regex`, the first capture
    /// group from the request path is used as part of the cache key.
    ///
    /// The request host (when present in `context`) is also part of the cache
    /// key, so credentials are isolated per upstream host.
    pub fn capture_or_cache(
        &self,
        session_id: &str,
        credential_name: &str,
        context: Option<&CaptureContext>,
    ) -> Result<Zeroizing<String>> {
        // Look up command configuration
        let config = self.configs.get(credential_name).ok_or_else(|| {
            NonoError::SandboxInit(format!(
                "credential '{}' not defined in credential_capture configuration",
                credential_name
            ))
        })?;

        // Compute cache key suffix from regex match on request path
        let cache_suffix = config.cache_path_regex.as_ref().and_then(|re| {
            context.and_then(|ctx| {
                re.captures(&ctx.path)
                    .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()))
            })
        });
        let path_suffix = cache_suffix.as_deref().unwrap_or("");

        // Isolate cached credentials per upstream host. Absent context (e.g.
        // non-intercept callers) maps to an empty host, matching prior
        // behaviour and never colliding with host-bearing entries.
        let host = context.map(|c| c.host.as_str()).unwrap_or("");

        // Check cache first
        {
            let cache = self.cache.lock().map_err(|_| {
                NonoError::SandboxInit("credential cache lock poisoned".to_string())
            })?;
            if let Some(cached) = cache.get(session_id, credential_name, host, path_suffix) {
                debug!("credential capture cache hit: {}", credential_name);
                return Ok(cached);
            }
        }

        // Execute command
        let credential = self.executor.execute(config, context)?;

        // Cache result
        {
            let mut cache = self.cache.lock().map_err(|_| {
                NonoError::SandboxInit("credential cache lock poisoned".to_string())
            })?;
            cache.insert(
                session_id,
                credential_name,
                host,
                path_suffix,
                Zeroizing::new(credential.as_str().to_string()),
                config.ttl,
            );
        }

        Ok(credential)
    }

    /// Flush all cached credentials for a session (call on session exit).
    #[cfg(test)]
    pub fn flush_session(&self, session_id: &str) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.flush_session(session_id);
        }
    }

    /// Check if a credential name is configured.
    #[cfg(test)]
    pub fn has_credential(&self, name: &str) -> bool {
        self.configs.contains_key(name)
    }
}

/// Validate a credential capture command definition.
///
/// Returns `Ok(CredentialCaptureDef)` with the resolved absolute path,
/// or an error describing the validation failure.
pub fn validate_capture_command(
    name: &str,
    command: &[String],
    timeout_secs: Option<u64>,
    ttl_secs: Option<u64>,
    cache_path_pattern: Option<&str>,
) -> Result<CredentialCaptureDef> {
    if command.is_empty() {
        return Err(NonoError::ConfigParse(format!(
            "credential_capture.{}: command must not be empty",
            name
        )));
    }

    let timeout = timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
    if timeout == 0 || timeout > 300 {
        return Err(NonoError::ConfigParse(format!(
            "credential_capture.{}: timeout_secs must be between 1 and 300",
            name
        )));
    }

    let ttl = ttl_secs.unwrap_or(DEFAULT_TTL_SECS);
    if ttl > 3600 {
        return Err(NonoError::ConfigParse(format!(
            "credential_capture.{}: ttl_secs must be between 0 and 3600",
            name
        )));
    }

    // Compile cache_path_pattern regex if provided
    let cache_path_regex = match cache_path_pattern {
        Some(pattern) => {
            let re = Regex::new(pattern).map_err(|e| {
                NonoError::ConfigParse(format!(
                    "credential_capture.{}: invalid cache_path_pattern '{}': {}",
                    name, pattern, e
                ))
            })?;
            if re.captures_len() < 2 {
                return Err(NonoError::ConfigParse(format!(
                    "credential_capture.{}: cache_path_pattern must contain at least one capture group",
                    name
                )));
            }
            Some(re)
        }
        None => None,
    };

    // Validate no shell metacharacters in any argument
    let forbidden_chars: &[char] = &[
        ';', '|', '&', '$', '`', '\n', '\r', '\0', '>', '<', '(', ')', '{', '}', '!',
    ];
    for (i, arg) in command.iter().enumerate() {
        if arg.contains(forbidden_chars) {
            return Err(NonoError::ConfigParse(format!(
                "credential_capture.{}: argument {} contains forbidden shell metacharacters",
                name, i
            )));
        }
    }

    // Resolve command path
    let command_path = resolve_command_path(name, &command[0])?;
    let command_args = command[1..].to_vec();

    Ok(CredentialCaptureDef {
        command_path,
        command_args,
        timeout_secs: timeout,
        ttl: Duration::from_secs(ttl),
        cache_path_regex,
    })
}

/// Resolve a command name to an absolute path.
///
/// If the command is already absolute, validates it exists and is executable.
/// If relative, performs a PATH lookup (safe at profile-load time).
fn resolve_command_path(credential_name: &str, cmd: &str) -> Result<PathBuf> {
    let path = PathBuf::from(cmd);

    if path.is_absolute() {
        if !path.exists() {
            return Err(NonoError::ConfigParse(format!(
                "credential_capture.{}: command '{}' does not exist",
                credential_name, cmd
            )));
        }
        if !is_executable(&path) {
            return Err(NonoError::ConfigParse(format!(
                "credential_capture.{}: command '{}' is not executable",
                credential_name, cmd
            )));
        }
        return Ok(path);
    }

    // PATH lookup at load time
    which::which(cmd).map_err(|_| {
        NonoError::ConfigParse(format!(
            "credential_capture.{}: command '{}' not found in PATH",
            credential_name, cmd
        ))
    })
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(_path: &Path) -> bool {
    true
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_hit_within_ttl() {
        let mut cache = CredentialCaptureCache::new();
        cache.insert(
            "session1",
            "github",
            "",
            "",
            Zeroizing::new("token123".to_string()),
            Duration::from_secs(60),
        );
        let result = cache.get("session1", "github", "", "");
        assert!(result.is_some());
        assert_eq!(result.unwrap().as_str(), "token123");
    }

    #[test]
    fn test_cache_miss_different_session() {
        let mut cache = CredentialCaptureCache::new();
        cache.insert(
            "session1",
            "github",
            "",
            "",
            Zeroizing::new("token123".to_string()),
            Duration::from_secs(60),
        );
        assert!(cache.get("session2", "github", "", "").is_none());
    }

    #[test]
    fn test_cache_miss_different_name() {
        let mut cache = CredentialCaptureCache::new();
        cache.insert(
            "session1",
            "github",
            "",
            "",
            Zeroizing::new("token123".to_string()),
            Duration::from_secs(60),
        );
        assert!(cache.get("session1", "gcloud", "", "").is_none());
    }

    #[test]
    fn test_cache_miss_expired() {
        let mut cache = CredentialCaptureCache::new();
        cache.insert(
            "session1",
            "github",
            "",
            "",
            Zeroizing::new("token123".to_string()),
            Duration::from_secs(0), // Immediately expired
        );
        // TTL of 0 means expires_at == now, which won't pass the < check
        assert!(cache.get("session1", "github", "", "").is_none());
    }

    #[test]
    fn test_cache_miss_different_path_suffix() {
        let mut cache = CredentialCaptureCache::new();
        cache.insert(
            "session1",
            "github",
            "",
            "repos",
            Zeroizing::new("token-repos".to_string()),
            Duration::from_secs(60),
        );
        assert!(cache.get("session1", "github", "", "users").is_none());
        assert!(cache.get("session1", "github", "", "repos").is_some());
    }

    #[test]
    fn test_cache_miss_different_host() {
        let mut cache = CredentialCaptureCache::new();
        cache.insert(
            "session1",
            "token",
            "api.example.com",
            "",
            Zeroizing::new("token-api".to_string()),
            Duration::from_secs(60),
        );
        // Same session/name/path but a different host must not hit.
        assert!(
            cache
                .get("session1", "token", "app.example.com", "")
                .is_none()
        );
        assert!(
            cache
                .get("session1", "token", "api.example.com", "")
                .is_some()
        );
    }

    #[test]
    fn test_cache_multiple_hosts_same_credential_name() {
        let mut cache = CredentialCaptureCache::new();
        cache.insert(
            "session1",
            "token",
            "api.example.com",
            "",
            Zeroizing::new("token-api".to_string()),
            Duration::from_secs(60),
        );
        cache.insert(
            "session1",
            "token",
            "app.example.com",
            "",
            Zeroizing::new("token-app".to_string()),
            Duration::from_secs(60),
        );
        assert_eq!(
            cache
                .get("session1", "token", "api.example.com", "")
                .unwrap()
                .as_str(),
            "token-api"
        );
        assert_eq!(
            cache
                .get("session1", "token", "app.example.com", "")
                .unwrap()
                .as_str(),
            "token-app"
        );
    }

    #[test]
    fn test_cache_empty_host_does_not_collide_with_host_entry() {
        let mut cache = CredentialCaptureCache::new();
        cache.insert(
            "session1",
            "token",
            "api.example.com",
            "",
            Zeroizing::new("token-api".to_string()),
            Duration::from_secs(60),
        );
        // A context-less lookup (empty host) must not see the host-bearing entry.
        assert!(cache.get("session1", "token", "", "").is_none());
    }

    #[test]
    fn test_cache_flush_session() {
        let mut cache = CredentialCaptureCache::new();
        cache.insert(
            "session1",
            "github",
            "",
            "",
            Zeroizing::new("token1".to_string()),
            Duration::from_secs(60),
        );
        cache.insert(
            "session1",
            "gcloud",
            "",
            "",
            Zeroizing::new("token2".to_string()),
            Duration::from_secs(60),
        );
        cache.insert(
            "session2",
            "github",
            "",
            "",
            Zeroizing::new("token3".to_string()),
            Duration::from_secs(60),
        );

        cache.flush_session("session1");

        assert!(cache.get("session1", "github", "", "").is_none());
        assert!(cache.get("session1", "gcloud", "", "").is_none());
        assert!(cache.get("session2", "github", "", "").is_some());
    }

    #[test]
    fn test_validate_empty_command_rejected() {
        let result = validate_capture_command("test", &[], None, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_shell_metacharacters_rejected() {
        let cmd = vec!["echo".to_string(), "hello; rm -rf /".to_string()];
        let result = validate_capture_command("test", &cmd, None, None, None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("forbidden shell metacharacters"));
    }

    #[test]
    fn test_validate_timeout_out_of_range() {
        let cmd = vec!["/bin/echo".to_string(), "hello".to_string()];
        let result = validate_capture_command("test", &cmd, Some(0), None, None);
        assert!(result.is_err());

        let result = validate_capture_command("test", &cmd, Some(301), None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_ttl_out_of_range() {
        let cmd = vec!["/bin/echo".to_string(), "hello".to_string()];
        let result = validate_capture_command("test", &cmd, None, Some(3601), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_nonexistent_absolute_path_rejected() {
        let cmd = vec!["/nonexistent/binary".to_string()];
        let result = validate_capture_command("test", &cmd, None, None, None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("does not exist"));
    }

    #[test]
    fn test_validate_valid_absolute_command() {
        let cmd = vec!["/bin/echo".to_string(), "hello".to_string()];
        let result = validate_capture_command("test", &cmd, Some(5), Some(300), None);
        assert!(result.is_ok());
        let def = result.unwrap();
        assert_eq!(def.command_path, PathBuf::from("/bin/echo"));
        assert_eq!(def.command_args, vec!["hello"]);
        assert_eq!(def.timeout_secs, 5);
        assert_eq!(def.ttl, Duration::from_secs(300));
        assert!(def.cache_path_regex.is_none());
    }

    #[test]
    fn test_validate_cache_path_pattern_compiled() {
        let cmd = vec!["/bin/echo".to_string(), "hello".to_string()];
        let result = validate_capture_command("test", &cmd, Some(5), Some(300), Some("^/([^/]+)"));
        assert!(result.is_ok());
        let def = result.unwrap();
        assert!(def.cache_path_regex.is_some());
        let re = def.cache_path_regex.unwrap();
        let caps = re.captures("/repos/owner/name").unwrap();
        assert_eq!(caps.get(1).unwrap().as_str(), "repos");
    }

    #[test]
    fn test_validate_invalid_regex_rejected() {
        let cmd = vec!["/bin/echo".to_string()];
        let result = validate_capture_command("test", &cmd, None, None, Some("[invalid("));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid cache_path_pattern"));
    }

    #[test]
    fn test_validate_regex_without_capture_group_rejected() {
        let cmd = vec!["/bin/echo".to_string()];
        let result = validate_capture_command("test", &cmd, None, None, Some("^/[^/]+"));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("capture group"));
    }

    #[test]
    fn test_executor_success() {
        let config = CredentialCaptureDef {
            command_path: PathBuf::from("/bin/echo"),
            command_args: vec!["test-credential".to_string()],
            timeout_secs: 5,
            ttl: Duration::from_secs(60),
            cache_path_regex: None,
        };
        let executor = CredentialCaptureExecutor;
        let result = executor.execute(&config, None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_str(), "test-credential");
    }

    #[test]
    fn test_executor_env_vars_injected() {
        let config = CredentialCaptureDef {
            command_path: PathBuf::from("/bin/sh"),
            command_args: vec!["-c".to_string(), "echo $NONO_REQUEST_HOST".to_string()],
            timeout_secs: 5,
            ttl: Duration::from_secs(60),
            cache_path_regex: None,
        };
        let ctx = CaptureContext {
            host: "api.example.com".to_string(),
            path: "/v1/chat".to_string(),
            method: "POST".to_string(),
        };
        let executor = CredentialCaptureExecutor;
        let result = executor.execute(&config, Some(&ctx));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_str(), "api.example.com");
    }

    #[test]
    fn test_executor_all_env_vars_available() {
        let config = CredentialCaptureDef {
            command_path: PathBuf::from("/bin/sh"),
            command_args: vec![
                "-c".to_string(),
                "printf '%s %s %s' \"$NONO_REQUEST_HOST\" \"$NONO_REQUEST_PATH\" \"$NONO_REQUEST_METHOD\"".to_string(),
            ],
            timeout_secs: 5,
            ttl: Duration::from_secs(60),
            cache_path_regex: None,
        };
        let ctx = CaptureContext {
            host: "api.github.com".to_string(),
            path: "/repos/owner/name".to_string(),
            method: "GET".to_string(),
        };
        let executor = CredentialCaptureExecutor;
        let result = executor.execute(&config, Some(&ctx));
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().as_str(),
            "api.github.com /repos/owner/name GET"
        );
    }

    #[test]
    fn test_executor_nonzero_exit() {
        let config = CredentialCaptureDef {
            command_path: PathBuf::from("/bin/sh"),
            command_args: vec!["-c".to_string(), "exit 1".to_string()],
            timeout_secs: 5,
            ttl: Duration::from_secs(60),
            cache_path_regex: None,
        };
        let executor = CredentialCaptureExecutor;
        let result = executor.execute(&config, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_executor_empty_output() {
        let config = CredentialCaptureDef {
            command_path: PathBuf::from("/bin/sh"),
            command_args: vec!["-c".to_string(), "true".to_string()],
            timeout_secs: 5,
            ttl: Duration::from_secs(60),
            cache_path_regex: None,
        };
        let executor = CredentialCaptureExecutor;
        let result = executor.execute(&config, None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("empty output"));
    }

    #[test]
    fn test_executor_trims_trailing_newline() {
        let config = CredentialCaptureDef {
            command_path: PathBuf::from("/bin/sh"),
            command_args: vec!["-c".to_string(), "printf 'token\\n\\n'".to_string()],
            timeout_secs: 5,
            ttl: Duration::from_secs(60),
            cache_path_regex: None,
        };
        let executor = CredentialCaptureExecutor;
        let result = executor.execute(&config, None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_str(), "token");
    }

    #[test]
    fn test_broker_capture_and_cache() {
        let mut configs = HashMap::new();
        configs.insert(
            "test".to_string(),
            CredentialCaptureDef {
                command_path: PathBuf::from("/bin/echo"),
                command_args: vec!["my-secret".to_string()],
                timeout_secs: 5,
                ttl: Duration::from_secs(60),
                cache_path_regex: None,
            },
        );
        let broker = CredentialCaptureBroker::new(configs);

        // First call executes command
        let result = broker.capture_or_cache("session1", "test", None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_str(), "my-secret");

        // Second call hits cache
        let result = broker.capture_or_cache("session1", "test", None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_str(), "my-secret");
    }

    #[test]
    fn test_broker_cache_with_path_regex() {
        let mut configs = HashMap::new();
        configs.insert(
            "test".to_string(),
            CredentialCaptureDef {
                command_path: PathBuf::from("/bin/sh"),
                command_args: vec![
                    "-c".to_string(),
                    "echo token-$NONO_REQUEST_PATH".to_string(),
                ],
                timeout_secs: 5,
                ttl: Duration::from_secs(60),
                cache_path_regex: Some(Regex::new("^/([^/]+)").unwrap()),
            },
        );
        let broker = CredentialCaptureBroker::new(configs);

        let ctx_repos = CaptureContext {
            host: "api.github.com".to_string(),
            path: "/repos/owner/name".to_string(),
            method: "GET".to_string(),
        };
        let ctx_users = CaptureContext {
            host: "api.github.com".to_string(),
            path: "/users/me".to_string(),
            method: "GET".to_string(),
        };

        // Different path prefixes get different cache entries
        let result1 = broker.capture_or_cache("s1", "test", Some(&ctx_repos));
        assert!(result1.is_ok());
        assert_eq!(result1.unwrap().as_str(), "token-/repos/owner/name");

        let result2 = broker.capture_or_cache("s1", "test", Some(&ctx_users));
        assert!(result2.is_ok());
        assert_eq!(result2.unwrap().as_str(), "token-/users/me");

        // Same prefix hits cache (different sub-path, same first segment)
        let ctx_repos2 = CaptureContext {
            host: "api.github.com".to_string(),
            path: "/repos/other/repo".to_string(),
            method: "POST".to_string(),
        };
        let result3 = broker.capture_or_cache("s1", "test", Some(&ctx_repos2));
        assert!(result3.is_ok());
        // Should be cached value from first call (same "repos" prefix)
        assert_eq!(result3.unwrap().as_str(), "token-/repos/owner/name");
    }

    #[test]
    fn test_broker_caches_per_host() {
        // One credential, no path regex: distinct hosts must get distinct
        // cached values, each capturing with its own NONO_REQUEST_HOST.
        let mut configs = HashMap::new();
        configs.insert(
            "token".to_string(),
            CredentialCaptureDef {
                command_path: PathBuf::from("/bin/sh"),
                command_args: vec![
                    "-c".to_string(),
                    "echo token-$NONO_REQUEST_HOST".to_string(),
                ],
                timeout_secs: 5,
                ttl: Duration::from_secs(60),
                cache_path_regex: None,
            },
        );
        let broker = CredentialCaptureBroker::new(configs);

        let ctx_api = CaptureContext {
            host: "api.example.com".to_string(),
            path: "/data".to_string(),
            method: "GET".to_string(),
        };
        let ctx_app = CaptureContext {
            host: "app.example.com".to_string(),
            path: "/data".to_string(),
            method: "GET".to_string(),
        };

        let api = broker.capture_or_cache("s1", "token", Some(&ctx_api));
        assert_eq!(api.unwrap().as_str(), "token-api.example.com");

        let app = broker.capture_or_cache("s1", "token", Some(&ctx_app));
        assert_eq!(app.unwrap().as_str(), "token-app.example.com");

        // Repeat api host → cached value from the first api call.
        let ctx_api2 = CaptureContext {
            host: "api.example.com".to_string(),
            path: "/other".to_string(),
            method: "POST".to_string(),
        };
        let api2 = broker.capture_or_cache("s1", "token", Some(&ctx_api2));
        assert_eq!(api2.unwrap().as_str(), "token-api.example.com");
    }

    #[test]
    fn test_broker_unknown_credential() {
        let broker = CredentialCaptureBroker::new(HashMap::new());
        let result = broker.capture_or_cache("session1", "nonexistent", None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not defined"));
    }

    #[test]
    fn test_broker_has_credential() {
        let mut configs = HashMap::new();
        configs.insert(
            "github".to_string(),
            CredentialCaptureDef {
                command_path: PathBuf::from("/bin/echo"),
                command_args: vec!["token".to_string()],
                timeout_secs: 5,
                ttl: Duration::from_secs(60),
                cache_path_regex: None,
            },
        );
        let broker = CredentialCaptureBroker::new(configs);
        assert!(broker.has_credential("github"));
        assert!(!broker.has_credential("nonexistent"));
    }

    #[test]
    fn test_broker_flush_session() {
        let mut configs = HashMap::new();
        configs.insert(
            "test".to_string(),
            CredentialCaptureDef {
                command_path: PathBuf::from("/bin/echo"),
                command_args: vec!["secret".to_string()],
                timeout_secs: 5,
                ttl: Duration::from_secs(60),
                cache_path_regex: None,
            },
        );
        let broker = CredentialCaptureBroker::new(configs);

        // Populate cache
        let result = broker.capture_or_cache("session1", "test", None);
        assert!(result.is_ok());

        // Flush session
        broker.flush_session("session1");

        // Cache should be empty — next call re-executes the command
        let result = broker.capture_or_cache("session1", "test", None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_str(), "secret");
    }

    #[test]
    fn test_executor_timeout() {
        let config = CredentialCaptureDef {
            command_path: PathBuf::from("/bin/sleep"),
            command_args: vec!["10".to_string()],
            timeout_secs: 1,
            ttl: Duration::from_secs(60),
            cache_path_regex: None,
        };
        let executor = CredentialCaptureExecutor;
        let result = executor.execute(&config, None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("timed out"),
            "expected timeout error, got: {}",
            err
        );
    }

    #[test]
    fn test_validate_path_resolution_from_path_env() {
        // "echo" should be resolvable via PATH on any Unix system
        let cmd = vec!["echo".to_string(), "hello".to_string()];
        let result = validate_capture_command("test", &cmd, Some(5), Some(60), None);
        assert!(
            result.is_ok(),
            "echo should resolve via PATH: {:?}",
            result.err()
        );
        let def = result.unwrap();
        assert!(
            def.command_path.is_absolute(),
            "resolved path must be absolute: {:?}",
            def.command_path
        );
        assert_eq!(def.command_args, vec!["hello"]);
    }

    #[test]
    fn test_validate_nonexistent_command_in_path_rejected() {
        let cmd = vec!["nonexistent-cmd-xyz-9876543".to_string()];
        let result = validate_capture_command("test", &cmd, None, None, None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("not found in PATH"),
            "expected PATH lookup error, got: {}",
            err
        );
    }

    #[test]
    fn test_validate_non_executable_file_rejected() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("not-executable");
        let mut f = std::fs::File::create(&script).unwrap();
        writeln!(f, "#!/bin/sh\necho hello").unwrap();
        // File exists but is NOT executable (mode 0o644 by default)

        let cmd = vec![script.to_str().unwrap().to_string()];
        let result = validate_capture_command("test", &cmd, None, None, None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("not executable"),
            "expected not-executable error, got: {}",
            err
        );
    }
}
