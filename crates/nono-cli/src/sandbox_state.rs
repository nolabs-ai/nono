//! Sandbox state persistence for `nono why --self`
//!
//! When nono runs a command, it writes the capability state to a temp file
//! and passes the path via NONO_CAP_FILE. This allows sandboxed processes
//! to query their own capabilities using `nono why --self`.

use nono::{AccessMode, CapabilitySet, FsCapability, NonoError, Result};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use tracing::debug;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

/// Sandbox state stored for `nono why --self`
#[derive(Debug, Serialize, Deserialize)]
pub struct SandboxState {
    /// Filesystem capabilities
    pub fs: Vec<FsCapState>,
    /// Whether network is blocked
    pub net_blocked: bool,
    /// Commands explicitly allowed
    pub allowed_commands: Vec<String>,
    /// Commands explicitly blocked
    pub blocked_commands: Vec<String>,
    /// Paths exempted from deny groups via bypass_protection (canonicalized).
    /// Plan 36-01c: renamed from `override_deny_paths`; serde alias ensures
    /// backward compat with existing NONO_CAP_FILE JSON from running sessions.
    #[serde(default, alias = "override_deny_paths")]
    pub bypass_protection_paths: Vec<String>,
    /// Proxy domain allowlist at sandbox creation time
    #[serde(default)]
    pub allowed_domains: Vec<String>,
}

/// Serializable filesystem capability state
#[derive(Debug, Serialize, Deserialize)]
pub struct FsCapState {
    /// Original path as specified
    pub original: String,
    /// Resolved absolute path
    pub path: String,
    /// Access level: "read", "write", or "readwrite"
    pub access: String,
    /// Whether this is a single file (vs directory)
    pub is_file: bool,
}

impl SandboxState {
    /// Create sandbox state from a CapabilitySet, bypass_protection paths, and domain allowlist
    pub fn from_caps(
        caps: &CapabilitySet,
        bypass_protection_paths: &[PathBuf],
        allowed_domains: &[String],
    ) -> Self {
        Self {
            fs: caps
                .fs_capabilities()
                .iter()
                .map(|c| FsCapState {
                    original: c.original.display().to_string(),
                    path: c.resolved.display().to_string(),
                    access: match c.access {
                        AccessMode::Read => "read".to_string(),
                        AccessMode::Write => "write".to_string(),
                        AccessMode::ReadWrite => "readwrite".to_string(),
                    },
                    is_file: c.is_file,
                })
                .collect(),
            net_blocked: caps.is_network_blocked(),
            allowed_commands: caps.allowed_commands().to_vec(),
            blocked_commands: caps.blocked_commands().to_vec(),
            bypass_protection_paths: bypass_protection_paths
                .iter()
                .map(|p| p.display().to_string())
                .collect(),
            allowed_domains: allowed_domains.to_vec(),
        }
    }

    /// Get bypass_protection paths as PathBufs for query use
    pub fn bypass_protection_as_paths(&self) -> Vec<PathBuf> {
        self.bypass_protection_paths
            .iter()
            .map(PathBuf::from)
            .collect()
    }

    /// Convert back to a CapabilitySet
    ///
    /// Paths are re-validated through the standard constructors which
    /// canonicalize paths and verify existence. This prevents crafted
    /// state files from injecting arbitrary paths that bypass validation.
    ///
    /// Returns an error if any path no longer exists or fails validation.
    pub fn to_caps(&self) -> Result<CapabilitySet> {
        let mut caps = CapabilitySet::new();

        for fs_cap in &self.fs {
            let access = match fs_cap.access.as_str() {
                "read" => AccessMode::Read,
                "write" => AccessMode::Write,
                "readwrite" => AccessMode::ReadWrite,
                other => {
                    return Err(NonoError::ConfigParse(format!(
                        "invalid access mode in sandbox state: {other}"
                    )));
                }
            };

            let cap = if fs_cap.is_file {
                FsCapability::new_file(&fs_cap.original, access)?
            } else {
                FsCapability::new_dir(&fs_cap.original, access)?
            };
            caps.add_fs(cap);
        }

        if !self.allowed_domains.is_empty() {
            caps.set_network_mode_mut(nono::NetworkMode::ProxyOnly {
                port: 0,
                bind_ports: vec![],
            });
        } else {
            caps.set_network_blocked(self.net_blocked);
        }
        for cmd in &self.allowed_commands {
            caps.add_allowed_command(cmd.clone());
        }
        for cmd in &self.blocked_commands {
            caps.add_blocked_command(cmd.clone());
        }

        Ok(caps)
    }

    /// Write sandbox state to a file with secure permissions
    ///
    /// # Security
    /// This function implements multiple defenses against temp file attacks:
    /// - Uses `create_new(true)` to fail if file exists (prevents symlink attacks)
    /// - Sets `mode(0o600)` for owner-only read/write permissions (Unix)
    /// - Atomic write operation (no TOCTOU window)
    pub fn write_to_file(&self, path: &std::path::Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self).map_err(|e| {
            NonoError::ConfigParse(format!("Failed to serialize sandbox state: {}", e))
        })?;

        // SECURITY: Use OpenOptions with create_new(true) to prevent symlink attacks
        #[cfg(unix)]
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| NonoError::ConfigWrite {
                path: path.to_path_buf(),
                source: e,
            })?;

        #[cfg(not(unix))]
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .map_err(|e| NonoError::ConfigWrite {
                path: path.to_path_buf(),
                source: e,
            })?;

        file.write_all(json.as_bytes())
            .map_err(|e| NonoError::ConfigWrite {
                path: path.to_path_buf(),
                source: e,
            })?;

        Ok(())
    }
}

/// Maximum size for capability state files (1 MB is more than enough)
const MAX_CAP_FILE_SIZE: u64 = 1_048_576;

/// Validate the NONO_CAP_FILE path for security
fn validate_cap_file_path(path_str: &str) -> Result<PathBuf> {
    let path = PathBuf::from(path_str);
    if !path.is_absolute() {
        return Err(NonoError::EnvVarValidation {
            var: "NONO_CAP_FILE".to_string(),
            reason: "path must be absolute".to_string(),
        });
    }

    let canonical = path
        .canonicalize()
        .map_err(|e| NonoError::CapFileValidation {
            reason: format!("failed to canonicalize path: {}", e),
        })?;

    // Must be in system temp directory
    let temp_dir =
        std::env::temp_dir()
            .canonicalize()
            .map_err(|e| NonoError::CapFileValidation {
                reason: format!("failed to canonicalize temp directory: {}", e),
            })?;

    if !canonical.starts_with(&temp_dir) {
        return Err(NonoError::CapFileValidation {
            reason: format!(
                "path must be in temp directory ({}), got: {}",
                temp_dir.display(),
                canonical.display()
            ),
        });
    }

    // Must match expected naming pattern
    let file_name = canonical
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| NonoError::CapFileValidation {
            reason: "invalid file name".to_string(),
        })?;

    if !file_name.starts_with(".nono-") || !file_name.ends_with(".json") {
        return Err(NonoError::CapFileValidation {
            reason: format!(
                "file name must match pattern .nono-*.json, got: {}",
                file_name
            ),
        });
    }

    // File size must be reasonable
    let metadata = std::fs::metadata(&canonical).map_err(|e| NonoError::CapFileValidation {
        reason: format!("failed to read file metadata: {}", e),
    })?;

    if metadata.len() > MAX_CAP_FILE_SIZE {
        return Err(NonoError::CapFileTooLarge {
            size: metadata.len(),
            max: MAX_CAP_FILE_SIZE,
        });
    }

    if !metadata.is_file() {
        return Err(NonoError::CapFileValidation {
            reason: "path must be a regular file".to_string(),
        });
    }

    Ok(canonical)
}

/// Load sandbox state from NONO_CAP_FILE environment variable
///
/// Returns None if not running inside a nono sandbox (env var not set).
pub fn load_sandbox_state() -> Option<SandboxState> {
    let cap_file_str = std::env::var("NONO_CAP_FILE").ok()?;

    let validated_path = validate_cap_file_path(&cap_file_str).unwrap_or_else(|e| {
        eprintln!("SECURITY: NONO_CAP_FILE validation failed: {}", e);
        eprintln!("SECURITY: This may indicate an attack attempt or a bug in nono");
        std::process::exit(1);
    });

    let content = std::fs::read_to_string(&validated_path).unwrap_or_else(|e| {
        eprintln!("Error reading capability state file: {}", e);
        std::process::exit(1);
    });

    let state: SandboxState = serde_json::from_str(&content).unwrap_or_else(|e| {
        eprintln!("Error parsing capability state file: {}", e);
        std::process::exit(1);
    });

    Some(state)
}

// WR-02 fix (REVIEW.md): the previous `is_process_running` PID-liveness
// helper was removed alongside the PID-based cleanup logic. The current
// state-file naming scheme uses random hex (see
// `execution_runtime::next_capability_state_file_path`), so liveness
// cannot be inferred from the filename. `cleanup_stale_state_files`
// below uses mtime instead.

/// WR-02 fix (REVIEW.md): cleanup window for stale sandbox state files.
///
/// State files older than this are eligible for cleanup. Set to 7 days so a
/// developer who leaves a `nono run` shell open over a weekend still finds
/// its session file intact on Monday. Tuned conservatively because the
/// alternative (parsing a PID out of the filename to detect liveness) does
/// not work with the random-hex naming scheme introduced by
/// `execution_runtime::next_capability_state_file_path` (8 random bytes →
/// 16 hex chars per file, no PID embedded).
const STALE_STATE_FILE_MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;

/// Clean up stale sandbox state files from previous nono runs.
///
/// State files are written to `std::env::temp_dir()` with the naming pattern
/// `.nono-<16-hex-chars>.json` (see
/// `execution_runtime::next_capability_state_file_path`). Because the suffix
/// is random hex (not a PID), liveness cannot be inferred from the filename.
/// This function instead removes any matching file whose modification time
/// is older than `STALE_STATE_FILE_MAX_AGE_SECS`. The mtime-based heuristic
/// is robust to the naming scheme — a single fresh state file is touched on
/// every supervised run, so the window stays bounded.
///
/// Errors during stat/remove are downgraded to `debug!` lines: cleanup is
/// best-effort and must never block a real `nono run` invocation.
pub fn cleanup_stale_state_files() {
    let temp_dir = std::env::temp_dir();

    let entries = match std::fs::read_dir(&temp_dir) {
        Ok(entries) => entries,
        Err(e) => {
            debug!("Failed to read temp directory for cleanup: {}", e);
            return;
        }
    };

    let max_age = std::time::Duration::from_secs(STALE_STATE_FILE_MAX_AGE_SECS);
    let now = std::time::SystemTime::now();
    let mut cleaned_count = 0;
    let mut kept_count = 0;

    for entry in entries.flatten() {
        let file_name = match entry.file_name().to_str() {
            Some(name) => name.to_string(),
            None => continue,
        };

        if !file_name.starts_with(".nono-") || !file_name.ends_with(".json") {
            continue;
        }

        // Use mtime (not name parsing) so the random-hex suffix shape from
        // execution_runtime::next_capability_state_file_path is supported.
        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(e) => {
                debug!("Failed to stat candidate state file {}: {}", file_name, e);
                continue;
            }
        };
        let mtime = match metadata.modified() {
            Ok(t) => t,
            Err(e) => {
                debug!("Failed to read mtime for state file {}: {}", file_name, e);
                continue;
            }
        };
        let age = match now.duration_since(mtime) {
            Ok(d) => d,
            Err(_) => {
                // Clock skew (mtime in the future). Treat as fresh — never
                // delete a file we cannot reason about.
                kept_count += 1;
                continue;
            }
        };
        if age < max_age {
            kept_count += 1;
            continue;
        }

        let file_path = temp_dir.join(&file_name);
        match std::fs::remove_file(&file_path) {
            Ok(()) => {
                debug!(
                    "Cleaned up stale state file {} (age {}s)",
                    file_name,
                    age.as_secs()
                );
                cleaned_count += 1;
            }
            Err(e) => {
                debug!("Failed to remove stale state file {}: {}", file_name, e);
            }
        }
    }

    if cleaned_count > 0 {
        debug!(
            "Cleanup complete: removed {} stale state file(s), {} kept",
            cleaned_count, kept_count
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::{lock_env, EnvVarGuard};
    use tempfile::tempdir;

    #[test]
    fn test_sandbox_state_roundtrip() {
        let mut caps = CapabilitySet::new().block_network();
        caps.add_allowed_command("pip".to_string());

        let state = SandboxState::from_caps(&caps, &[], &[]);
        assert!(state.net_blocked);
        assert_eq!(state.allowed_commands, vec!["pip"]);

        let restored = state
            .to_caps()
            .expect("to_caps failed on network-only state");
        assert!(restored.is_network_blocked());
        assert_eq!(restored.allowed_commands(), vec!["pip"]);
    }

    #[test]
    fn test_sandbox_state_write_and_read() {
        let dir = tempdir().expect("Failed to create temp dir");
        let file_path = dir.path().join("test_state.json");

        let caps = CapabilitySet::new().block_network();

        let state = SandboxState::from_caps(&caps, &[], &[]);
        state
            .write_to_file(&file_path)
            .expect("Failed to write state");

        let content = std::fs::read_to_string(&file_path).expect("Failed to read file");
        let loaded: SandboxState = serde_json::from_str(&content).expect("Failed to parse state");

        assert!(loaded.net_blocked);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_validate_cap_file_path_accepts_windows_runtime_temp_dir() {
        let dir = tempdir().expect("Failed to create temp dir");
        let cap_file = dir.path().join(".nono-123.json");
        std::fs::write(&cap_file, "{}").expect("write cap file");

        let _guard = lock_env();
        let _env = EnvVarGuard::set_all(&[
            ("TMP", dir.path().to_str().expect("utf8 path")),
            ("TEMP", dir.path().to_str().expect("utf8 path")),
        ]);

        let validated = validate_cap_file_path(cap_file.to_str().expect("utf8 path"))
            .expect("runtime temp cap file should validate");
        assert_eq!(
            validated,
            cap_file.canonicalize().expect("canonical cap file path")
        );
    }
}
