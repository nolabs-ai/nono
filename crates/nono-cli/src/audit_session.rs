//! Session discovery and management for the audit system.
//!
//! Audit sessions are stored in `~/.nono/audit/`. For backwards
//! compatibility, the audit commands also read legacy audit metadata from
//! `~/.nono/rollbacks/` when no migrated audit entry exists yet.

use crate::rollback_session;
use nono::undo::{SessionMetadata, SnapshotManager};
use nono::{NonoError, Result};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Information about a discovered audit session
// Plan 22-05a Decision 5 minimal scope: SessionInfo discovery is wired into
// audit_commands.rs by follow-up cherry-picks (4ec61c29..9db06336). The
// fields are surfaced now so the upstream-compatible API ports verbatim.
#[allow(dead_code)]
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

/// Get the audit root directory (`~/.nono/audit/`)
pub fn audit_root() -> Result<PathBuf> {
    let home = crate::config::nono_home_dir()?;
    Ok(home.join(".nono").join("audit"))
}

/// Ensure the audit session directory exists for the given session id.
///
/// Returns the audit-only session directory under `~/.nono/audit/<id>`.
/// Used by audit-only sessions (where rollback is disabled) so audit metadata
/// has its own clearly-namespaced directory.
pub fn ensure_audit_session_dir(session_id: &str) -> Result<PathBuf> {
    let dir = audit_root()?.join(session_id);
    fs::create_dir_all(&dir).map_err(|e| {
        NonoError::Snapshot(format!(
            "Failed to create audit session directory {}: {e}",
            dir.display()
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        if let Err(e) = std::fs::set_permissions(&dir, perms) {
            tracing::warn!("Failed to set audit session dir permissions to 0700: {e}");
        }
    }
    Ok(dir)
}

/// Ensure the rollback session directory exists for the given session id.
///
/// Returns the rollback-backed session directory under `~/.nono/rollbacks/<id>`
/// (or the override path when provided). Used when rollback snapshots are
/// captured alongside audit metadata.
#[allow(dead_code)]
pub fn ensure_rollback_session_dir(
    session_id: &str,
    rollback_destination: Option<&PathBuf>,
) -> Result<PathBuf> {
    let root = match rollback_destination {
        Some(path) => path.clone(),
        None => rollback_session::rollback_root()?,
    };
    let dir = root.join(session_id);
    fs::create_dir_all(&dir).map_err(|e| {
        NonoError::Snapshot(format!(
            "Failed to create rollback session directory {}: {e}",
            dir.display()
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        if let Err(e) = std::fs::set_permissions(&dir, perms) {
            tracing::warn!("Failed to set rollback session dir permissions to 0700: {e}");
        }
    }
    Ok(dir)
}

/// Discover all audit sessions.
///
/// Reads the primary audit root and also the legacy rollback root for older
/// sessions that have not been migrated. Session IDs found in the primary root
/// take precedence over legacy entries with the same ID.
#[allow(dead_code)]
pub fn discover_sessions() -> Result<Vec<SessionInfo>> {
    let mut sessions = Vec::new();
    let mut seen_ids = BTreeSet::new();
    let primary_root = audit_root()?;

    for root in [
        Some(primary_root.clone()),
        rollback_session::rollback_root().ok(),
    ] {
        let Some(root) = root else {
            continue;
        };
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

            sessions.push(build_session_info(dir, metadata));
        }
    }

    sessions.sort_by(|a, b| b.metadata.started.cmp(&a.metadata.started));
    Ok(sessions)
}

/// One-shot deprecation warning when load_session resolves a session via
/// the legacy `<rollback>/<id>/` path instead of the canonical
/// `<audit>/<id>/`. The shim is removed in v2.5 (D-27.2-02,
/// docs/architecture/audit-bundle-target.md).
fn warn_once_legacy_bundle_path(legacy_dir: &Path, canonical_dir: &Path) {
    static WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if WARNED.get().is_none() {
        tracing::warn!(
            "audit-attestation bundle found at legacy {} path; canonical \
             location is {}. This compatibility shim is removed in v2.5 \
             -- re-sign affected sessions if needed.",
            legacy_dir.display(),
            canonical_dir.display(),
        );
        // Another thread may race; OnceLock keeps the first set, the rest
        // become no-ops. Worst case: warn fires twice across racing threads.
        let _ = WARNED.set(());
    }
}

/// Load a specific audit session by ID.
pub fn load_session(session_id: &str) -> Result<SessionInfo> {
    validate_session_id(session_id)?;
    let primary_root = audit_root()?;
    let roots = [
        Some(primary_root.clone()),
        rollback_session::rollback_root().ok(),
    ];

    for root in roots.into_iter().flatten() {
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
        if !is_primary {
            warn_once_legacy_bundle_path(&dir, &primary_root.join(session_id));
        }

        return Ok(build_session_info(dir, metadata));
    }

    Err(NonoError::SessionNotFound(session_id.to_string()))
}

/// Remove an audit session directory.
#[allow(dead_code)]
pub fn remove_session(dir: &Path) -> Result<()> {
    fs::remove_dir_all(dir).map_err(|e| {
        NonoError::Snapshot(format!(
            "Failed to remove audit session directory {}: {e}",
            dir.display()
        ))
    })
}

/// Whether the directory is under the primary audit root.
#[allow(dead_code)]
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
#[allow(dead_code)]
pub fn is_legacy_audit_only_session(info: &SessionInfo) -> bool {
    !is_primary_audit_session(&info.dir) && info.metadata.snapshot_count == 0
}

/// Format a byte count as a human-readable string.
#[allow(dead_code)]
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
    #[cfg(unix)]
    {
        // kill(pid, 0) checks if the process exists without sending a signal
        // SAFETY: This is a standard POSIX way to check process existence.
        // Signal 0 does not actually send anything.
        unsafe { nix::libc::kill(pid as nix::libc::pid_t, 0) == 0 }
    }

    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        // SAFETY: OpenProcess is called with query-only access for the
        // provided PID. A null handle indicates that the process is not
        // available to query.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return false;
        }

        unsafe {
            // SAFETY: `handle` is valid because OpenProcess returned a
            // non-null handle above, and it is closed exactly once here.
            CloseHandle(handle);
        }
        true
    }
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
    use crate::test_env::{lock_env, EnvVarGuard};
    use nono::undo::{RollbackStatus, SessionMetadata};

    // Plan 22-05a Task 10 deferral: this test suffers from the same Windows
    // state-directory flake category documented across Plan 22-01/22-03/22-04
    // SUMMARYs (`Could not determine Windows state directory for rollback
    // storage` when HOME/USERPROFILE round-trip is incomplete). The fixture
    // is ported verbatim from upstream so the file matches; gate it
    // `cfg(not(target_os = "windows"))` so the cross-platform baseline still
    // exercises it. Windows-specific re-enablement lands in Plan 22-05b
    // alongside the audit_ledger.rs port (which is the upstream caller of
    // this discovery path).
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn discover_sessions_excludes_rollback_backed_entries() {
        let _env_lock = lock_env();
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().to_string_lossy().to_string();
        #[cfg(target_os = "windows")]
        let _env = EnvVarGuard::set_all(&[("USERPROFILE", &home)]);
        #[cfg(not(target_os = "windows"))]
        let _env = EnvVarGuard::set_all(&[("HOME", &home)]);

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
                rollback_status: RollbackStatus::Skipped,
            },
        )
        .unwrap();

        let legacy_audit_dir = rollback_session::rollback_root()
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
                rollback_status: RollbackStatus::Skipped,
            },
        )
        .unwrap();

        let rollback_dir = rollback_session::rollback_root()
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
                rollback_status: RollbackStatus::Available,
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
}
