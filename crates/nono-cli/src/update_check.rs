//! Background update checker for nono CLI
//!
//! Checks for new versions by contacting `update.nono.sh`. The check runs in a
//! background thread with a 3-second timeout and is throttled to once per 24 hours.
//!
//! Each request sends a randomly generated UUID (created on first run and stored
//! locally), the current nono version, the OS name, the CPU architecture, and a
//! coarse CI environment classification. The CI classification is derived only
//! from well-known environment variable names and never includes raw environment
//! values. None of these values are derived from hardware identifiers or user
//! accounts. No personally identifiable information is collected or transmitted.
//! No IP addresses are logged by the update service.
//!
//! To disable the update check, set `NONO_NO_UPDATE_CHECK=1` or add
//! `[updates] check = false` to `$XDG_CONFIG_HOME/nono/config.toml` (default `~/.config/nono/config.toml`).

use chrono::{DateTime, Utc};
use nono::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

/// State file name in user_state_dir()
const UPDATE_STATE_FILE: &str = "update-check.json";

/// How often to check for updates (24 hours)
const CHECK_INTERVAL_SECS: i64 = 86400;

/// HTTP timeout for the update check request
const CHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Update service URL
const UPDATE_SERVICE_URL: &str = "https://update.nono.sh/v1/check";

/// Persisted update check state
#[derive(Debug, Serialize, Deserialize)]
struct UpdateCheckState {
    /// Installation UUID (generated once, persisted)
    uuid: String,
    /// Timestamp of last successful check
    last_check: DateTime<Utc>,
    /// Cached result from last check
    cached_result: Option<UpdateInfo>,
}

/// Update information returned from the service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateInfo {
    /// Latest available version
    pub latest_version: String,
    /// Whether the current version is outdated
    pub update_available: bool,
    /// Optional message (for announcements)
    pub message: Option<String>,
    /// URL for release notes
    pub release_url: Option<String>,
}

/// Request payload sent to the update service
#[derive(Debug, Serialize)]
struct UpdateCheckRequest {
    uuid: String,
    version: String,
    platform: String,
    arch: String,
    ci: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    ci_provider: Option<&'static str>,
}

const CI_PROVIDER_ENV_VARS: &[(&str, &str)] = &[
    ("GITHUB_ACTIONS", "github_actions"),
    ("GITLAB_CI", "gitlab_ci"),
    ("CIRCLECI", "circleci"),
    ("BUILDKITE", "buildkite"),
    ("TF_BUILD", "azure_pipelines"),
    ("TRAVIS", "travis_ci"),
    ("JENKINS_URL", "jenkins"),
    ("JENKINS_HOME", "jenkins"),
    ("BITBUCKET_BUILD_NUMBER", "bitbucket_pipelines"),
    ("APPVEYOR", "appveyor"),
    ("TEAMCITY_VERSION", "teamcity"),
    ("DRONE", "drone"),
    ("SEMAPHORE", "semaphore"),
    ("CODESHIP", "codeship"),
    ("WOODPECKER", "woodpecker"),
    ("NETLIFY", "netlify"),
    ("VERCEL", "vercel"),
    ("RENDER", "render"),
];

/// Handle for a background update check.
pub struct UpdateCheckHandle {
    result: Arc<Mutex<Option<UpdateInfo>>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl UpdateCheckHandle {
    /// Consume the handle and return any update info.
    ///
    /// Waits briefly for the background thread to complete (bounded by the 3s
    /// HTTP timeout on the thread itself).
    pub fn take_result(mut self) -> Option<UpdateInfo> {
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        let guard = self.result.lock().ok()?;
        guard.clone()
    }
}

/// Start a background update check.
///
/// Returns `None` immediately if:
/// - The `NONO_NO_UPDATE_CHECK` env var is set
/// - The user opted out via config
/// - A check was performed within the last 24 hours (returns cached result if
///   an update was found)
/// - The state directory is unavailable
pub fn start_background_check() -> Option<UpdateCheckHandle> {
    // Check env var opt-out
    if std::env::var("NONO_NO_UPDATE_CHECK").is_ok() {
        return None;
    }

    // Check config file opt-out
    if is_opted_out_via_config() {
        return None;
    }

    let state = load_or_create_state()?;
    let now = Utc::now();
    let elapsed = now.signed_duration_since(state.last_check).num_seconds();

    if elapsed < CHECK_INTERVAL_SECS {
        // Return cached result without spawning a thread, but only if the
        // cached version is actually newer than what we're running
        let current = env!("CARGO_PKG_VERSION");
        if state
            .cached_result
            .as_ref()
            .is_some_and(|r| r.update_available && is_newer_version(current, &r.latest_version))
        {
            let result = Arc::new(Mutex::new(state.cached_result));
            return Some(UpdateCheckHandle {
                result,
                handle: None,
            });
        }
        return None;
    }

    // Needs a fresh check — spawn background thread
    let uuid = state.uuid.clone();
    let result: Arc<Mutex<Option<UpdateInfo>>> = Arc::new(Mutex::new(None));
    let result_clone = Arc::clone(&result);

    let handle = thread::spawn(move || {
        let current = env!("CARGO_PKG_VERSION");
        if let Some(info) = perform_check(&uuid) {
            let updated_state = UpdateCheckState {
                uuid,
                last_check: Utc::now(),
                cached_result: Some(info.clone()),
            };
            let _ = save_state(&updated_state);

            if info.update_available
                && is_newer_version(current, &info.latest_version)
                && let Ok(mut guard) = result_clone.lock()
            {
                *guard = Some(info);
            }
        }
    });

    Some(UpdateCheckHandle {
        result,
        handle: Some(handle),
    })
}

/// Check user config for update opt-out
fn is_opted_out_via_config() -> bool {
    match crate::config::user::load_user_config() {
        Ok(Some(config)) => !config.updates.check,
        _ => false,
    }
}

/// Get the state file path
fn state_file_path() -> Option<PathBuf> {
    crate::config::user_state_dir().map(|d| d.join(UPDATE_STATE_FILE))
}

/// Load existing state or create a new one with a fresh UUID
fn load_or_create_state() -> Option<UpdateCheckState> {
    let path = state_file_path()?;

    if path.exists() {
        let content = std::fs::read_to_string(&path).ok()?;
        let state: UpdateCheckState = serde_json::from_str(&content).ok()?;
        return Some(state);
    }

    let state = UpdateCheckState {
        uuid: generate_uuid(),
        last_check: DateTime::UNIX_EPOCH,
        cached_result: None,
    };
    save_state(&state).ok()?;
    Some(state)
}

/// Persist state to the state file
fn save_state(state: &UpdateCheckState) -> Result<()> {
    let path = state_file_path().ok_or_else(|| {
        nono::NonoError::ConfigParse("Could not determine state directory".to_string())
    })?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| nono::NonoError::ConfigWrite {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }

    let content = serde_json::to_string_pretty(state)
        .map_err(|e| nono::NonoError::ConfigParse(format!("Failed to serialize state: {}", e)))?;

    std::fs::write(&path, content).map_err(|e| nono::NonoError::ConfigWrite { path, source: e })?;

    Ok(())
}

/// Generate a v4-style UUID using the rand crate (already a dependency)
fn generate_uuid() -> String {
    use rand::RngExt;
    let mut rng = rand::rng();
    let bytes: [u8; 16] = rng.random();

    // Set version 4 and variant bits
    let time_hi = (u16::from_be_bytes([bytes[6], bytes[7]]) & 0x0fff) | 0x4000;
    let clock_seq = (u16::from_be_bytes([bytes[8], bytes[9]]) & 0x3fff) | 0x8000;

    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_be_bytes([bytes[4], bytes[5]]),
        time_hi,
        clock_seq,
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

/// Resolve the update service URL.
///
/// Uses `NONO_UPDATE_URL` env var to set your own URL for testing or private instances. Defaults to the public service.
fn update_url() -> String {
    std::env::var("NONO_UPDATE_URL").unwrap_or_else(|_| UPDATE_SERVICE_URL.to_string())
}

/// Compare two semver version strings, returning true if `latest` is strictly newer than `current`.
fn is_newer_version(current: &str, latest: &str) -> bool {
    let parse = |s: &str| -> Option<(u64, u64, u64)> {
        let s = s.strip_prefix('v').unwrap_or(s);
        let mut parts = s.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next()?.parse().ok()?;
        Some((major, minor, patch))
    };
    match (parse(current), parse(latest)) {
        (Some(c), Some(l)) => l > c,
        _ => false,
    }
}

fn detect_ci_provider() -> Option<&'static str> {
    for (env_var, provider) in CI_PROVIDER_ENV_VARS {
        if env_marker_present(env_var) {
            return Some(provider);
        }
    }

    if env_marker_present("CI") {
        return Some("generic");
    }

    None
}

fn env_marker_present(key: &str) -> bool {
    std::env::var_os(key).is_some_and(|value| {
        let value = value.to_string_lossy();
        let value = value.trim();
        !value.is_empty() && !value.eq_ignore_ascii_case("false") && value != "0"
    })
}

/// Perform the HTTP check against the update service
fn perform_check(uuid: &str) -> Option<UpdateInfo> {
    let ci_provider = detect_ci_provider();
    let request = UpdateCheckRequest {
        uuid: uuid.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        platform: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        ci: ci_provider.is_some(),
        ci_provider,
    };

    let body = serde_json::to_string(&request).ok()?;

    let url = update_url();

    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(CHECK_TIMEOUT))
        .build()
        .new_agent();

    let response = agent
        .post(&url)
        .header("Content-Type", "application/json")
        .header(
            "User-Agent",
            &format!("nono-cli/{}", env!("CARGO_PKG_VERSION")),
        )
        .send(body.as_bytes())
        .ok()?;

    if response.status() != 200 {
        return None;
    }

    let response_body = response.into_body().read_to_string().ok()?;
    serde_json::from_str(&response_body).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_uuid_format() {
        let uuid = generate_uuid();
        // 8-4-4-4-12 hex format
        let parts: Vec<&str> = uuid.split('-').collect();
        assert_eq!(parts.len(), 5, "UUID should have 5 groups: {}", uuid);
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);

        // Version 4: third group starts with '4'
        assert!(
            parts[2].starts_with('4'),
            "Version nibble should be 4: {}",
            parts[2]
        );

        // Variant: fourth group starts with 8, 9, a, or b
        let variant_char = parts[3].chars().next().unwrap_or('0');
        assert!(
            ['8', '9', 'a', 'b'].contains(&variant_char),
            "Variant nibble should be 8-b: {}",
            parts[3]
        );
    }

    #[test]
    fn test_generate_uuid_uniqueness() {
        let a = generate_uuid();
        let b = generate_uuid();
        assert_ne!(a, b, "Two UUIDs should not be equal");
    }

    #[test]
    fn test_state_roundtrip() {
        let state = UpdateCheckState {
            uuid: "test-uuid-1234".to_string(),
            last_check: Utc::now(),
            cached_result: Some(UpdateInfo {
                latest_version: "1.0.0".to_string(),
                update_available: true,
                message: Some("New release!".to_string()),
                release_url: Some("https://example.com".to_string()),
            }),
        };

        let json = serde_json::to_string(&state).expect("serialize");
        let restored: UpdateCheckState = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(restored.uuid, "test-uuid-1234");
        let cached = restored.cached_result.expect("should have cached result");
        assert_eq!(cached.latest_version, "1.0.0");
        assert!(cached.update_available);
        assert_eq!(cached.message.as_deref(), Some("New release!"));
    }

    #[test]
    fn test_state_roundtrip_no_cached() {
        let state = UpdateCheckState {
            uuid: "test-uuid".to_string(),
            last_check: DateTime::UNIX_EPOCH,
            cached_result: None,
        };

        let json = serde_json::to_string(&state).expect("serialize");
        let restored: UpdateCheckState = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(restored.uuid, "test-uuid");
        assert!(restored.cached_result.is_none());
    }

    #[test]
    fn test_env_var_opt_out() {
        let _lock = match crate::test_env::ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        // When NONO_NO_UPDATE_CHECK is set, start_background_check returns None
        let _env = crate::test_env::EnvVarGuard::set_all(&[("NONO_NO_UPDATE_CHECK", "1")]);
        let handle = start_background_check();
        assert!(handle.is_none());
    }

    #[test]
    fn test_detect_ci_environment_github_actions() {
        let _lock = match crate::test_env::ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let _env = crate::test_env::EnvVarGuard::set_all(&[
            ("GITHUB_ACTIONS", "true"),
            ("GITLAB_CI", ""),
            ("CIRCLECI", ""),
            ("BUILDKITE", ""),
            ("TF_BUILD", ""),
            ("TRAVIS", ""),
            ("JENKINS_URL", ""),
            ("JENKINS_HOME", ""),
            ("BITBUCKET_BUILD_NUMBER", ""),
            ("APPVEYOR", ""),
            ("TEAMCITY_VERSION", ""),
            ("DRONE", ""),
            ("SEMAPHORE", ""),
            ("CODESHIP", ""),
            ("WOODPECKER", ""),
            ("NETLIFY", ""),
            ("VERCEL", ""),
            ("RENDER", ""),
            ("CI", ""),
        ]);

        assert_eq!(detect_ci_provider(), Some("github_actions"));
    }

    #[test]
    fn test_detect_ci_environment_generic_ci() {
        let _lock = match crate::test_env::ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let _env = crate::test_env::EnvVarGuard::set_all(&[
            ("GITHUB_ACTIONS", ""),
            ("GITLAB_CI", ""),
            ("CIRCLECI", ""),
            ("BUILDKITE", ""),
            ("TF_BUILD", ""),
            ("TRAVIS", ""),
            ("JENKINS_URL", ""),
            ("JENKINS_HOME", ""),
            ("BITBUCKET_BUILD_NUMBER", ""),
            ("APPVEYOR", ""),
            ("TEAMCITY_VERSION", ""),
            ("DRONE", ""),
            ("SEMAPHORE", ""),
            ("CODESHIP", ""),
            ("WOODPECKER", ""),
            ("NETLIFY", ""),
            ("VERCEL", ""),
            ("RENDER", ""),
            ("CI", "true"),
        ]);

        assert_eq!(detect_ci_provider(), Some("generic"));
    }

    #[test]
    fn test_detect_ci_environment_falsey_markers_are_ignored() {
        let _lock = match crate::test_env::ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let _env = crate::test_env::EnvVarGuard::set_all(&[
            ("GITHUB_ACTIONS", "false"),
            ("GITLAB_CI", "0"),
            ("CIRCLECI", ""),
            ("BUILDKITE", ""),
            ("TF_BUILD", ""),
            ("TRAVIS", ""),
            ("JENKINS_URL", ""),
            ("JENKINS_HOME", ""),
            ("BITBUCKET_BUILD_NUMBER", ""),
            ("APPVEYOR", ""),
            ("TEAMCITY_VERSION", ""),
            ("DRONE", ""),
            ("SEMAPHORE", ""),
            ("CODESHIP", ""),
            ("WOODPECKER", ""),
            ("NETLIFY", ""),
            ("VERCEL", ""),
            ("RENDER", ""),
            ("CI", "0"),
        ]);

        assert_eq!(detect_ci_provider(), None);
    }

    #[test]
    fn test_detect_ci_environment_no_ci() {
        let _lock = match crate::test_env::ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let _env = crate::test_env::EnvVarGuard::set_all(&[
            ("GITHUB_ACTIONS", ""),
            ("GITLAB_CI", ""),
            ("CIRCLECI", ""),
            ("BUILDKITE", ""),
            ("TF_BUILD", ""),
            ("TRAVIS", ""),
            ("JENKINS_URL", ""),
            ("JENKINS_HOME", ""),
            ("BITBUCKET_BUILD_NUMBER", ""),
            ("APPVEYOR", ""),
            ("TEAMCITY_VERSION", ""),
            ("DRONE", ""),
            ("SEMAPHORE", ""),
            ("CODESHIP", ""),
            ("WOODPECKER", ""),
            ("NETLIFY", ""),
            ("VERCEL", ""),
            ("RENDER", ""),
            ("CI", ""),
        ]);

        assert_eq!(detect_ci_provider(), None);
    }

    #[test]
    fn test_update_request_serializes_ci_context() {
        let request = UpdateCheckRequest {
            uuid: "test-uuid".to_string(),
            version: "1.2.3".to_string(),
            platform: "linux".to_string(),
            arch: "x86_64".to_string(),
            ci: true,
            ci_provider: Some("github_actions"),
        };

        let json = serde_json::to_value(&request).expect("serialize");
        assert_eq!(json["ci"], true);
        assert_eq!(json["ci_provider"], "github_actions");
    }

    #[test]
    fn test_is_newer_version() {
        // Strictly newer
        assert!(is_newer_version("0.6.0", "0.6.1"));
        assert!(is_newer_version("0.6.1", "0.7.0"));
        assert!(is_newer_version("0.6.1", "1.0.0"));

        // Same version
        assert!(!is_newer_version("0.6.1", "0.6.1"));

        // Older (downgrade)
        assert!(!is_newer_version("0.6.1", "0.6.0"));
        assert!(!is_newer_version("1.0.0", "0.9.9"));

        // With v prefix
        assert!(is_newer_version("v0.6.0", "v0.6.1"));
        assert!(is_newer_version("0.6.0", "v0.6.1"));
        assert!(!is_newer_version("v0.6.1", "0.6.0"));

        // Malformed input
        assert!(!is_newer_version("bad", "0.6.1"));
        assert!(!is_newer_version("0.6.1", "bad"));
        assert!(!is_newer_version("", ""));
    }

    #[test]
    fn test_update_info_deserialize() {
        let json = r#"{
            "latest_version": "0.7.0",
            "update_available": true,
            "message": null,
            "release_url": "https://github.com/always-further/nono/releases/tag/v0.7.0"
        }"#;

        let info: UpdateInfo = serde_json::from_str(json).expect("deserialize");
        assert_eq!(info.latest_version, "0.7.0");
        assert!(info.update_available);
        assert!(info.message.is_none());
        assert!(info.release_url.is_some());
    }
}
