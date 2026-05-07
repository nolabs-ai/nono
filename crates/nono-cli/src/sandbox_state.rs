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
    /// Paths exempted from deny groups via bypass_protection (canonicalized)
    /// ALIAS(canonical="bypass_protection_paths", introduced="v0.41.0", remove_by="v1.0.0", issue="#594")
    #[serde(default, alias = "override_deny_paths")]
    pub bypass_protection_paths: Vec<String>,
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
    /// Create sandbox state from a CapabilitySet and bypass_protection paths
    pub fn from_caps(caps: &CapabilitySet, bypass_protection_paths: &[PathBuf]) -> Self {
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

        caps.set_network_blocked(self.net_blocked);
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

/// Check if a process with the given PID is currently running
#[cfg(unix)]
fn is_process_running(pid: u32) -> bool {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;

    let nix_pid = Pid::from_raw(pid as i32);
    match kill(nix_pid, None) {
        Ok(()) => true,
        Err(nix::errno::Errno::ESRCH) => false,
        Err(nix::errno::Errno::EPERM) => true,
        _ => true,
    }
}

#[cfg(not(unix))]
fn is_process_running(_pid: u32) -> bool {
    true
}

/// Clean up stale sandbox state files from previous nono runs
pub fn cleanup_stale_state_files() {
    let temp_dir = std::env::temp_dir();

    let entries = match std::fs::read_dir(&temp_dir) {
        Ok(entries) => entries,
        Err(e) => {
            debug!("Failed to read temp directory for cleanup: {}", e);
            return;
        }
    };

    let current_pid = std::process::id();
    let mut cleaned_count = 0;
    let mut skipped_count = 0;

    for entry in entries.flatten() {
        let file_name = match entry.file_name().to_str() {
            Some(name) => name.to_string(),
            None => continue,
        };

        if !file_name.starts_with(".nono-") || !file_name.ends_with(".json") {
            continue;
        }

        let pid_str = file_name
            .trim_start_matches(".nono-")
            .trim_end_matches(".json");

        let pid = match pid_str.parse::<u32>() {
            Ok(p) => p,
            Err(_) => {
                debug!("Skipping state file with invalid PID: {}", file_name);
                continue;
            }
        };

        if pid == current_pid {
            continue;
        }

        if is_process_running(pid) {
            skipped_count += 1;
            continue;
        }

        let file_path = temp_dir.join(&file_name);
        match std::fs::remove_file(&file_path) {
            Ok(()) => {
                debug!("Cleaned up stale state file for PID {}: {}", pid, file_name);
                cleaned_count += 1;
            }
            Err(e) => {
                debug!("Failed to remove stale state file {}: {}", file_name, e);
            }
        }
    }

    if cleaned_count > 0 {
        debug!(
            "Cleanup complete: removed {} stale state file(s), {} active",
            cleaned_count, skipped_count
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_sandbox_state_roundtrip() {
        let mut caps = CapabilitySet::new().block_network();
        caps.add_allowed_command("pip".to_string());

        let state = SandboxState::from_caps(&caps, &[]);
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

        let state = SandboxState::from_caps(&caps, &[]);
        state
            .write_to_file(&file_path)
            .expect("Failed to write state");

        let content = std::fs::read_to_string(&file_path).expect("Failed to read file");
        let loaded: SandboxState = serde_json::from_str(&content).expect("Failed to parse state");

        assert!(loaded.net_blocked);
    }
}
