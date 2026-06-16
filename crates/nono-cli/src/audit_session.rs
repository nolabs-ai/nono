//! Session discovery and management for the audit system.
//!
//! Audit sessions are stored under `$XDG_STATE_HOME/nono/audit/` (default
//! `~/.local/state/nono/audit/`). For backwards compatibility, reads also
//! check `~/.nono/audit/` until v1.0.0, and legacy audit metadata under
//! `~/.nono/rollbacks/` (or the canonical rollback root) when no migrated
//! audit entry exists yet.

use crate::state_paths;
use nono::undo::{SessionMetadata, SnapshotManager};
use nono::{NonoError, Result};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Information about a discovered audit session
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

/// Get the canonical audit root directory (`$XDG_STATE_HOME/nono/audit/`).
pub fn audit_root() -> Result<PathBuf> {
    state_paths::audit_root()
}

/// Discover all audit sessions.
///
/// Reads the primary audit root and also the legacy rollback root for older
/// sessions that have not been migrated. Session IDs found in the primary root
/// take precedence over legacy entries with the same ID.
pub fn discover_sessions() -> Result<Vec<SessionInfo>> {
    let mut sessions = Vec::new();
    let mut seen_ids = BTreeSet::new();
    let primary_root = audit_root()?;
    let legacy_roots = state_paths::LegacyRootSet::resolve()?;

    let mut roots: Vec<PathBuf> = state_paths::audit_discovery_roots()?;
    roots.extend(state_paths::rollback_discovery_roots()?);

    for root in roots {
        if !root.exists() {
            continue;
        }

        let entries = fs::read_dir(&root).map_err(|e| {
            NonoError::Snapshot(format!(
                "Failed to read audit directory {}: {e}",
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

            let is_primary = dir.starts_with(&primary_root);
            if !is_primary && metadata.snapshot_count > 0 {
                continue;
            }

            if !seen_ids.insert(metadata.session_id.clone()) {
                continue;
            }

            legacy_roots.warn_if_legacy_audit_data_read(&dir);
            sessions.push(build_session_info(dir, metadata));
        }
    }

    sessions.sort_by(|a, b| b.metadata.started.cmp(&a.metadata.started));
    Ok(sessions)
}

/// Load a specific audit session by ID.
pub fn load_session(session_id: &str) -> Result<SessionInfo> {
    validate_session_id(session_id)?;
    let primary_root = audit_root()?;
    let legacy_roots = state_paths::LegacyRootSet::resolve()?;
    let mut roots: Vec<PathBuf> = state_paths::audit_discovery_roots()?;
    roots.extend(state_paths::rollback_discovery_roots()?);

    for root in roots {
        let dir = root.join(session_id);
        if !dir.exists() {
            continue;
        }

        let canonical_root = root.canonicalize().map_err(|e| {
            NonoError::SessionNotFound(format!(
                "Cannot canonicalize audit root {}: {}",
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
        let is_primary = dir.starts_with(&primary_root);
        if !is_primary && metadata.snapshot_count > 0 {
            continue;
        }

        legacy_roots.warn_if_legacy_audit_data_read(&dir);
        return Ok(build_session_info(dir, metadata));
    }

    Err(NonoError::SessionNotFound(session_id.to_string()))
}

/// Remove an audit session directory.
pub fn remove_session(dir: &Path) -> Result<()> {
    fs::remove_dir_all(dir).map_err(|e| {
        NonoError::Snapshot(format!(
            "Failed to remove audit session directory {}: {e}",
            dir.display()
        ))
    })
}

/// Whether the directory is under the primary audit root.
pub fn is_primary_audit_session(dir: &Path) -> bool {
    let Ok(root) = audit_root() else {
        return false;
    };
    let Ok(canonical_root) = root.canonicalize() else {
        return false;
    };
    let Ok(canonical_dir) = dir.canonicalize() else {
        return false;
    };
    canonical_dir.starts_with(&canonical_root)
}

/// Whether a legacy rollback-root entry only contains audit metadata.
pub fn is_legacy_audit_only_session(info: &SessionInfo) -> bool {
    !is_primary_audit_session(&info.dir) && info.metadata.snapshot_count == 0
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

fn parse_pid_from_session_id(session_id: &str) -> Option<u32> {
    session_id.rsplit('-').next()?.parse().ok()
}

fn is_process_alive(pid: u32) -> bool {
    // SAFETY: POSIX kill(pid, 0) checks process existence without sending a signal.
    unsafe { nix::libc::kill(pid as nix::libc::pid_t, 0) == 0 }
}

fn calculate_dir_size(dir: &Path) -> u64 {
    WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter_map(|e| e.metadata().ok())
        .filter(|m| m.is_file())
        .map(|m| m.len())
        .sum()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::test_env::{ENV_LOCK, EnvVarGuard};
    use nono::undo::SessionMetadata;

    #[test]
    fn discover_sessions_excludes_rollback_backed_entries() {
        let _env_lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("state");
        fs::create_dir_all(&state).unwrap();
        let home = tmp.path().to_string_lossy().to_string();
        let state_str = state.to_string_lossy().to_string();
        let _env = EnvVarGuard::set_all(&[("HOME", &home), ("XDG_STATE_HOME", &state_str)]);

        let audit_dir = audit_root().unwrap().join("20260421-111111-10001");
        fs::create_dir_all(&audit_dir).unwrap();
        SnapshotManager::write_session_metadata(
            &audit_dir,
            &SessionMetadata {
                session_id: "20260421-111111-10001".to_string(),
                started: "2026-04-21T11:11:11+01:00".to_string(),
                ended: Some("2026-04-21T11:11:12+01:00".to_string()),
                command: vec!["/bin/pwd".to_string()],
                executable_identity: None,
                tracked_paths: vec![PathBuf::from("/tmp/work")],
                snapshot_count: 0,
                exit_code: Some(0),
                merkle_roots: Vec::new(),
                network_events: Vec::new(),
                audit_event_count: 2,
                audit_integrity: None,
                audit_attestation: None,
            },
        )
        .unwrap();

        let legacy_audit_dir = state_paths::legacy_rollback_root()
            .unwrap()
            .join("20260421-111111-10002");
        fs::create_dir_all(&legacy_audit_dir).unwrap();
        SnapshotManager::write_session_metadata(
            &legacy_audit_dir,
            &SessionMetadata {
                session_id: "20260421-111111-10002".to_string(),
                started: "2026-04-21T11:11:11+01:00".to_string(),
                ended: Some("2026-04-21T11:11:12+01:00".to_string()),
                command: vec!["/bin/echo".to_string()],
                executable_identity: None,
                tracked_paths: vec![PathBuf::from("/tmp/work")],
                snapshot_count: 0,
                exit_code: Some(0),
                merkle_roots: Vec::new(),
                network_events: Vec::new(),
                audit_event_count: 2,
                audit_integrity: None,
                audit_attestation: None,
            },
        )
        .unwrap();

        let rollback_dir = state_paths::legacy_rollback_root()
            .unwrap()
            .join("20260421-111111-10003");
        fs::create_dir_all(&rollback_dir).unwrap();
        SnapshotManager::write_session_metadata(
            &rollback_dir,
            &SessionMetadata {
                session_id: "20260421-111111-10003".to_string(),
                started: "2026-04-21T11:11:11+01:00".to_string(),
                ended: Some("2026-04-21T11:11:12+01:00".to_string()),
                command: vec!["/bin/true".to_string()],
                executable_identity: None,
                tracked_paths: vec![PathBuf::from("/tmp/work")],
                snapshot_count: 2,
                exit_code: Some(0),
                merkle_roots: Vec::new(),
                network_events: Vec::new(),
                audit_event_count: 2,
                audit_integrity: None,
                audit_attestation: None,
            },
        )
        .unwrap();

        let sessions = discover_sessions().unwrap();
        let ids: Vec<_> = sessions
            .iter()
            .map(|s| s.metadata.session_id.as_str())
            .collect();

        assert!(ids.contains(&"20260421-111111-10001"));
        assert!(ids.contains(&"20260421-111111-10002"));
        assert!(!ids.contains(&"20260421-111111-10003"));
    }

    #[test]
    fn discover_sessions_reads_legacy_audit_root() {
        let _env_lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("state");
        fs::create_dir_all(&state).unwrap();
        let home = tmp.path().to_string_lossy().to_string();
        let state_str = state.to_string_lossy().to_string();
        let _env = EnvVarGuard::set_all(&[("HOME", &home), ("XDG_STATE_HOME", &state_str)]);

        let legacy_audit_dir = state_paths::legacy_audit_root()
            .unwrap()
            .join("20260421-111111-20001");
        fs::create_dir_all(&legacy_audit_dir).unwrap();
        SnapshotManager::write_session_metadata(
            &legacy_audit_dir,
            &SessionMetadata {
                session_id: "20260421-111111-20001".to_string(),
                started: "2026-04-21T11:11:11+01:00".to_string(),
                ended: Some("2026-04-21T11:11:12+01:00".to_string()),
                command: vec!["/bin/echo".to_string()],
                executable_identity: None,
                tracked_paths: vec![PathBuf::from("/tmp/work")],
                snapshot_count: 0,
                exit_code: Some(0),
                merkle_roots: Vec::new(),
                network_events: Vec::new(),
                audit_event_count: 1,
                audit_integrity: None,
                audit_attestation: None,
            },
        )
        .unwrap();

        let sessions = discover_sessions().unwrap();
        let ids: Vec<_> = sessions
            .iter()
            .map(|s| s.metadata.session_id.as_str())
            .collect();
        assert!(ids.contains(&"20260421-111111-20001"));
        assert!(is_legacy_audit_only_session(
            sessions
                .iter()
                .find(|s| s.metadata.session_id == "20260421-111111-20001")
                .expect("legacy session")
        ));
    }

    #[test]
    fn discover_sessions_does_not_warn_when_legacy_audit_root_is_empty() {
        let _env_lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("state");
        fs::create_dir_all(&state).unwrap();
        let home = tmp.path().to_string_lossy().to_string();
        let state_str = state.to_string_lossy().to_string();
        let _env = EnvVarGuard::set_all(&[("HOME", &home), ("XDG_STATE_HOME", &state_str)]);

        let legacy_root = state_paths::legacy_audit_root().unwrap();
        fs::create_dir_all(&legacy_root).unwrap();
        fs::write(legacy_root.join("ledger.ndjson"), b"{}\n").unwrap();

        let canonical_dir = state_paths::audit_root()
            .unwrap()
            .join("20260421-111111-30001");
        fs::create_dir_all(&canonical_dir).unwrap();
        SnapshotManager::write_session_metadata(
            &canonical_dir,
            &SessionMetadata {
                session_id: "20260421-111111-30001".to_string(),
                started: "2026-04-21T11:11:11+01:00".to_string(),
                ended: Some("2026-04-21T11:11:12+01:00".to_string()),
                command: vec!["/bin/echo".to_string()],
                executable_identity: None,
                tracked_paths: vec![PathBuf::from("/tmp/work")],
                snapshot_count: 0,
                exit_code: Some(0),
                merkle_roots: Vec::new(),
                network_events: Vec::new(),
                audit_event_count: 1,
                audit_integrity: None,
                audit_attestation: None,
            },
        )
        .unwrap();

        let sessions = discover_sessions().unwrap();
        assert_eq!(sessions.len(), 1);
        assert!(is_primary_audit_session(&sessions[0].dir));
    }
}
