//! Session discovery and management for the rollback system
//!
//! Provides functions to discover, load, and manage rollback sessions stored
//! under `$XDG_STATE_HOME/nono/rollbacks/` (default `~/.local/state/nono/rollbacks/`).
//! Reads also check `~/.nono/rollbacks/` until v1.0.0.

use crate::state_paths;
use nono::undo::{SessionMetadata, SnapshotManager};
use nono::{NonoError, Result};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Information about a discovered rollback session
#[derive(Debug)]
pub struct SessionInfo {
    /// Session metadata loaded from session.json
    pub metadata: SessionMetadata,
    /// Path to the session directory
    pub dir: PathBuf,
    /// Total disk usage in bytes
    pub disk_size: u64,
    /// Whether the session's process is still running
    pub is_alive: bool,
    /// Whether the session appears stale (ended is None and PID is dead)
    pub is_stale: bool,
}

/// Get the canonical rollback root directory (`$XDG_STATE_HOME/nono/rollbacks/`).
pub fn rollback_root() -> Result<PathBuf> {
    state_paths::rollback_root()
}

/// Discover all rollback sessions across canonical and legacy roots.
///
/// Scans rollback root directories, loads session metadata from each
/// subdirectory, and enriches with derived data (disk size, alive status).
/// Sessions with missing or corrupt metadata are skipped. When the same
/// session ID exists in multiple roots, the canonical root wins.
pub fn discover_sessions() -> Result<Vec<SessionInfo>> {
    let mut sessions = Vec::new();
    let mut seen_ids = BTreeSet::new();

    for root in state_paths::rollback_discovery_roots()? {
        if !root.exists() {
            continue;
        }

        let entries = fs::read_dir(&root).map_err(|e| {
            NonoError::Snapshot(format!(
                "Failed to read rollback directory {}: {e}",
                root.display()
            ))
        })?;

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            let dir = entry.path();
            if !dir.is_dir() {
                continue;
            }

            let metadata = match SnapshotManager::load_session_metadata(&dir) {
                Ok(m) => m,
                Err(_) => continue,
            };

            if !seen_ids.insert(metadata.session_id.clone()) {
                continue;
            }

            state_paths::warn_if_legacy_rollback_data_read(&dir);
            sessions.push(build_session_info(dir, metadata));
        }
    }

    sessions.sort_by(|a, b| b.metadata.started.cmp(&a.metadata.started));
    Ok(sessions)
}

/// Load a specific session by ID.
///
/// The session_id is validated to prevent path traversal — it must not
/// contain path separators or `..` components. The resolved path is
/// verified to be within a rollback root directory.
pub fn load_session(session_id: &str) -> Result<SessionInfo> {
    validate_session_id(session_id)?;

    for root in state_paths::rollback_discovery_roots()? {
        let dir = root.join(session_id);
        if !dir.exists() {
            continue;
        }

        let canonical_root = root.canonicalize().map_err(|e| {
            NonoError::SessionNotFound(format!(
                "Cannot canonicalize rollback root {}: {}",
                root.display(),
                e
            ))
        })?;
        let canonical_dir = dir
            .canonicalize()
            .map_err(|_| NonoError::SessionNotFound(session_id.to_string()))?;
        if !canonical_dir.starts_with(&canonical_root) {
            continue;
        }

        let metadata = SnapshotManager::load_session_metadata(&dir)?;
        state_paths::warn_if_legacy_rollback_data_read(&dir);
        return Ok(build_session_info(dir, metadata));
    }

    Err(NonoError::SessionNotFound(session_id.to_string()))
}

/// Calculate the total disk usage of all sessions across rollback roots.
pub fn total_storage_bytes() -> Result<u64> {
    let mut total: u64 = 0;
    let mut seen_roots = BTreeSet::new();
    for root in state_paths::rollback_discovery_roots()? {
        if !seen_roots.insert(root.clone()) || !root.exists() {
            continue;
        }
        total = total.saturating_add(calculate_dir_size(&root));
    }
    Ok(total)
}

/// Remove a session directory.
pub fn remove_session(dir: &Path) -> Result<()> {
    fs::remove_dir_all(dir).map_err(|e| {
        NonoError::Snapshot(format!(
            "Failed to remove session directory {}: {e}",
            dir.display()
        ))
    })
}

fn build_session_info(dir: PathBuf, metadata: SessionMetadata) -> SessionInfo {
    let pid = parse_pid_from_session_id(&metadata.session_id);
    let is_alive = pid.map(is_process_alive).unwrap_or(false);
    let is_stale = metadata.ended.is_none() && !is_alive;
    let disk_size = calculate_dir_size(&dir);

    SessionInfo {
        metadata,
        dir,
        disk_size,
        is_alive,
        is_stale,
    }
}

/// Validate a session ID to prevent path traversal.
///
/// Session IDs must match the format `YYYYMMDD-HHMMSS-<pid>` and must not
/// contain path separators, `..`, or other dangerous characters.
fn validate_session_id(session_id: &str) -> Result<()> {
    if session_id.is_empty() {
        return Err(NonoError::SessionNotFound("empty session ID".to_string()));
    }
    if session_id.contains(std::path::MAIN_SEPARATOR)
        || session_id.contains('/')
        || session_id.contains("..")
        || session_id.contains('\0')
    {
        return Err(NonoError::SessionNotFound(format!(
            "invalid session ID: {session_id}"
        )));
    }
    Ok(())
}

/// Parse the PID from a session ID formatted as `YYYYMMDD-HHMMSS-<pid>`.
fn parse_pid_from_session_id(session_id: &str) -> Option<u32> {
    session_id.rsplit('-').next()?.parse().ok()
}

/// Check if a process with the given PID is still alive.
fn is_process_alive(pid: u32) -> bool {
    // kill(pid, 0) checks if the process exists without sending a signal
    // SAFETY: This is a standard POSIX way to check process existence.
    // Signal 0 does not actually send anything.
    unsafe { nix::libc::kill(pid as nix::libc::pid_t, 0) == 0 }
}

/// Calculate the total size of all files in a directory tree.
fn calculate_dir_size(dir: &Path) -> u64 {
    WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter_map(|e| e.metadata().ok())
        .filter(|m| m.is_file())
        .map(|m| m.len())
        .sum()
}

/// Format a byte count as a human-readable string.
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::{ENV_LOCK, EnvVarGuard};

    #[test]
    fn validate_session_id_rejects_traversal() {
        assert!(validate_session_id("../../../etc").is_err());
        assert!(validate_session_id("foo/bar").is_err());
        assert!(validate_session_id("foo\0bar").is_err());
        assert!(validate_session_id("..").is_err());
        assert!(validate_session_id("").is_err());
    }

    #[test]
    fn validate_session_id_accepts_valid() {
        assert!(validate_session_id("20260214-143022-12345").is_ok());
        assert!(validate_session_id("test-session").is_ok());
    }

    #[test]
    fn parse_pid_from_session_id_valid() {
        assert_eq!(
            parse_pid_from_session_id("20260214-143022-12345"),
            Some(12345)
        );
    }

    #[test]
    fn parse_pid_from_session_id_invalid() {
        assert_eq!(parse_pid_from_session_id("no-pid-here"), None);
        assert_eq!(parse_pid_from_session_id(""), None);
    }

    #[test]
    fn format_bytes_display() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GB");
    }

    #[test]
    fn discover_sessions_empty_dir() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let size = calculate_dir_size(dir.path());
        assert_eq!(size, 0);
    }

    #[test]
    fn calculate_dir_size_works() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        fs::write(dir.path().join("a.txt"), b"hello").expect("write");
        fs::write(dir.path().join("b.txt"), b"world!").expect("write");
        let size = calculate_dir_size(dir.path());
        assert_eq!(size, 11); // 5 + 6
    }

    #[test]
    fn is_current_process_alive() {
        assert!(is_process_alive(std::process::id()));
    }

    #[test]
    fn dead_process_not_alive() {
        assert!(!is_process_alive(99_999_999));
    }

    #[test]
    fn discover_sessions_reads_legacy_rollback_root() {
        let _env_lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().expect("tempdir");
        let state = tmp.path().join("state");
        fs::create_dir_all(&state).expect("mkdir state");
        let home = tmp.path().to_string_lossy().to_string();
        let state_str = state.to_string_lossy().to_string();
        let _env = EnvVarGuard::set_all(&[("HOME", &home), ("XDG_STATE_HOME", &state_str)]);

        let legacy_dir = state_paths::legacy_rollback_root()
            .expect("legacy rollback root")
            .join("20260421-111111-30001");
        fs::create_dir_all(&legacy_dir).expect("mkdir legacy rollback session");
        SnapshotManager::write_session_metadata(
            &legacy_dir,
            &SessionMetadata {
                session_id: "20260421-111111-30001".to_string(),
                started: "2026-04-21T11:11:11+01:00".to_string(),
                ended: Some("2026-04-21T11:11:12+01:00".to_string()),
                command: vec!["/bin/true".to_string()],
                executable_identity: None,
                tracked_paths: vec![PathBuf::from("/tmp/work")],
                snapshot_count: 2,
                exit_code: Some(0),
                merkle_roots: Vec::new(),
                network_events: Vec::new(),
                audit_event_count: 0,
                audit_integrity: None,
                audit_attestation: None,
            },
        )
        .expect("write metadata");

        let sessions = discover_sessions().expect("discover");
        let ids: Vec<_> = sessions
            .iter()
            .map(|s| s.metadata.session_id.as_str())
            .collect();
        assert!(ids.contains(&"20260421-111111-30001"));
    }
}
