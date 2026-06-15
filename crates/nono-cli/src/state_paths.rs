//! XDG-based paths for nono runtime state (audit trails, session registry, rollbacks).
//!
//! Canonical storage lives under `$XDG_STATE_HOME/nono/` (default
//! `~/.local/state/nono/`). Until v1.0.0, reads also fall back to legacy
//! `~/.nono/{audit,sessions,rollbacks}/` trees with a one-time deprecation warning.

use nono::{NonoError, Result, try_canonicalize};
use std::cell::Cell;
use std::path::{Path, PathBuf};

const LEGACY_HOME_SUBDIR: &str = ".nono";
const LEGACY_REMOVE_BY: &str = "v1.0.0";
const AUDIT_LEDGER_FILENAME: &str = "ledger.ndjson";

thread_local! {
    static LEGACY_AUDIT_WARNED: Cell<bool> = const { Cell::new(false) };
    static LEGACY_SESSIONS_WARNED: Cell<bool> = const { Cell::new(false) };
    static LEGACY_ROLLBACK_WARNED: Cell<bool> = const { Cell::new(false) };
}

/// Resolve the XDG state base directory (`$XDG_STATE_HOME`, default `~/.local/state`).
///
/// When `$XDG_STATE_HOME` is unset, nono uses `$HOME/.local/state` on every platform
/// (same convention as `gh`, Claude Code, and profile `$XDG_STATE_HOME` expansion),
/// not macOS `~/Library/Application Support`.
fn resolve_xdg_state_base() -> Result<PathBuf> {
    if let Ok(raw) = std::env::var("XDG_STATE_HOME") {
        let path = PathBuf::from(&raw);
        if path.is_absolute() {
            return Ok(path);
        }
        tracing::warn!(
            "Ignoring invalid XDG_STATE_HOME='{}' (must be absolute), falling back to default state dir",
            raw
        );
    }

    let home = dirs::home_dir().ok_or(NonoError::HomeNotFound)?;
    Ok(home.join(".local").join("state"))
}

/// Resolve `$XDG_STATE_HOME/nono` (default `~/.local/state/nono`).
pub fn user_state_dir() -> Result<PathBuf> {
    Ok(resolve_xdg_state_base()?.join("nono"))
}

/// Legacy `~/.nono` root (pre-XDG audit, session, and rollback data).
pub fn legacy_home_state_root() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or(NonoError::HomeNotFound)?;
    Ok(home.join(LEGACY_HOME_SUBDIR))
}

/// Primary audit root: `$XDG_STATE_HOME/nono/audit/`.
pub fn audit_root() -> Result<PathBuf> {
    Ok(user_state_dir()?.join("audit"))
}

/// Legacy audit root: `~/.nono/audit/` (read fallback until v1.0.0).
pub fn legacy_audit_root() -> Result<PathBuf> {
    Ok(legacy_home_state_root()?.join("audit"))
}

/// Primary session registry: `$XDG_STATE_HOME/nono/sessions/`.
pub fn sessions_dir() -> Result<PathBuf> {
    Ok(user_state_dir()?.join("sessions"))
}

/// Legacy session registry: `~/.nono/sessions/` (read fallback until v1.0.0).
pub fn legacy_sessions_dir() -> Result<PathBuf> {
    Ok(legacy_home_state_root()?.join("sessions"))
}

/// Primary rollback root: `$XDG_STATE_HOME/nono/rollbacks/`.
pub fn rollback_root() -> Result<PathBuf> {
    Ok(user_state_dir()?.join("rollbacks"))
}

/// Legacy rollback root: `~/.nono/rollbacks/` (read fallback until v1.0.0).
pub fn legacy_rollback_root() -> Result<PathBuf> {
    Ok(legacy_home_state_root()?.join("rollbacks"))
}

/// Audit roots to scan when discovering or loading sessions (primary first).
pub fn audit_discovery_roots() -> Result<Vec<PathBuf>> {
    let primary = audit_root()?;
    let mut roots = vec![primary.clone()];
    if let Ok(legacy) = legacy_audit_root()
        && legacy != primary
    {
        roots.push(legacy);
    }
    Ok(roots)
}

/// Session registry directories to scan when listing or loading (primary first).
pub fn session_registry_dirs_for_read() -> Result<Vec<PathBuf>> {
    let primary = sessions_dir()?;
    let mut dirs = vec![primary.clone()];
    if let Ok(legacy) = legacy_sessions_dir()
        && legacy != primary
    {
        dirs.push(legacy);
    }
    Ok(dirs)
}

/// Rollback roots to scan when discovering or loading sessions (primary first).
pub fn rollback_discovery_roots() -> Result<Vec<PathBuf>> {
    let primary = rollback_root()?;
    let mut roots = vec![primary.clone()];
    if let Ok(legacy) = legacy_rollback_root()
        && legacy != primary
    {
        roots.push(legacy);
    }
    Ok(roots)
}

/// Returns true when any rollback root directory exists.
pub fn any_rollback_root_exists() -> Result<bool> {
    Ok(rollback_discovery_roots()?.iter().any(|root| root.exists()))
}

/// Protected state roots that must not be grantable to sandboxed children.
pub fn protected_state_roots() -> Result<Vec<PathBuf>> {
    let mut roots = vec![
        try_canonicalize(&legacy_home_state_root()?),
        try_canonicalize(&user_state_dir()?),
    ];
    roots.sort();
    roots.dedup();
    Ok(roots)
}

/// Emit a one-time warning when legacy audit data is read.
pub(crate) fn warn_legacy_audit_path(path: &Path) {
    LEGACY_AUDIT_WARNED.with(|warned| {
        if warned.get() {
            return;
        }
        warned.set(true);
        eprintln!(
            "warning: reading audit data from deprecated path {} (will be removed in {LEGACY_REMOVE_BY}); \
             new audit data is stored under $XDG_STATE_HOME/nono/audit/ (default ~/.local/state/nono/audit/)",
            path.display(),
        );
    });
}

fn warn_legacy_sessions_path(path: &Path) {
    LEGACY_SESSIONS_WARNED.with(|warned| {
        if warned.get() {
            return;
        }
        warned.set(true);
        eprintln!(
            "warning: reading session registry from deprecated path {} (will be removed in {LEGACY_REMOVE_BY}); \
             new session files are stored under $XDG_STATE_HOME/nono/sessions/ (default ~/.local/state/nono/sessions/)",
            path.display(),
        );
    });
}

fn warn_legacy_rollback_path(path: &Path) {
    LEGACY_ROLLBACK_WARNED.with(|warned| {
        if warned.get() {
            return;
        }
        warned.set(true);
        eprintln!(
            "warning: reading rollback data from deprecated path {} (will be removed in {LEGACY_REMOVE_BY}); \
             new rollback data is stored under $XDG_STATE_HOME/nono/rollbacks/ (default ~/.local/state/nono/rollbacks/)",
            path.display(),
        );
    });
}

/// Returns true when `path` is under the legacy rollback root (not the canonical one).
pub fn is_legacy_rollback_path(path: &Path) -> bool {
    let Ok(legacy) = legacy_rollback_root() else {
        return false;
    };
    let Ok(primary) = rollback_root() else {
        return false;
    };
    if legacy == primary {
        return false;
    }
    path.starts_with(&legacy) && !path.starts_with(&primary)
}

/// Warn once after successfully reading audit metadata from a legacy tree.
pub(crate) fn warn_if_legacy_audit_data_read(session_dir: &Path) {
    if is_legacy_audit_path(session_dir) {
        let _ = legacy_audit_root().map(|root| warn_legacy_audit_path(&root));
        return;
    }
    if is_legacy_rollback_path(session_dir) {
        let _ = legacy_rollback_root().map(|root| warn_legacy_rollback_path(&root));
    }
}

/// Warn once after successfully reading rollback metadata from a legacy tree.
pub(crate) fn warn_if_legacy_rollback_data_read(session_dir: &Path) {
    if is_legacy_rollback_path(session_dir) {
        let _ = legacy_rollback_root().map(|root| warn_legacy_rollback_path(&root));
    }
}

/// Warn once after successfully reading a session registry file from a legacy tree.
pub(crate) fn warn_if_legacy_session_file_read(session_file: &Path) {
    let Ok(legacy) = legacy_sessions_dir() else {
        return;
    };
    let Ok(primary) = sessions_dir() else {
        return;
    };
    if legacy == primary {
        return;
    }
    if session_file.starts_with(&legacy) {
        warn_legacy_sessions_path(&legacy);
    }
}

/// Returns true when `path` is under the legacy audit root (not the canonical one).
pub fn is_legacy_audit_path(path: &Path) -> bool {
    let Ok(legacy) = legacy_audit_root() else {
        return false;
    };
    let Ok(primary) = audit_root() else {
        return false;
    };
    if legacy == primary {
        return false;
    }
    path.starts_with(&legacy) && !path.starts_with(&primary)
}

/// Copy a legacy audit ledger into the canonical root on first write, if needed.
pub fn maybe_migrate_legacy_audit_ledger() -> Result<()> {
    let primary = audit_root()?;
    let legacy = legacy_audit_root()?;
    if primary == legacy {
        return Ok(());
    }

    let new_ledger = primary.join(AUDIT_LEDGER_FILENAME);
    if new_ledger.exists() {
        return Ok(());
    }

    let legacy_ledger = legacy.join(AUDIT_LEDGER_FILENAME);
    if !legacy_ledger.exists() {
        return Ok(());
    }

    std::fs::create_dir_all(&primary).map_err(|e| {
        NonoError::Snapshot(format!(
            "Failed to create audit root {}: {e}",
            primary.display()
        ))
    })?;

    std::fs::copy(&legacy_ledger, &new_ledger).map_err(|e| {
        NonoError::Snapshot(format!(
            "Failed to migrate audit ledger from {} to {}: {e}",
            legacy_ledger.display(),
            new_ledger.display()
        ))
    })?;

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::test_env::{ENV_LOCK, EnvVarGuard};
    use std::fs;

    fn isolated_env(base: &Path) -> (EnvVarGuard, PathBuf) {
        let home = base.join("home");
        let state = base.join("state");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&state).unwrap();
        let home_str = home.to_string_lossy().to_string();
        let state_str = state.to_string_lossy().to_string();
        let guard = EnvVarGuard::set_all(&[("HOME", &home_str), ("XDG_STATE_HOME", &state_str)]);
        (guard, home)
    }

    #[test]
    fn default_state_base_uses_local_state_without_xdg_env() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let home_str = home.to_string_lossy().to_string();
        let _env = EnvVarGuard::set_all(&[("HOME", &home_str)]);
        assert_eq!(
            user_state_dir().unwrap(),
            home.join(".local").join("state").join("nono")
        );
    }

    #[test]
    fn canonical_paths_use_xdg_state_home() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let (_env, home) = isolated_env(tmp.path());

        assert_eq!(
            audit_root().unwrap(),
            tmp.path().join("state").join("nono").join("audit")
        );
        assert_eq!(
            sessions_dir().unwrap(),
            tmp.path().join("state").join("nono").join("sessions")
        );
        assert_eq!(
            legacy_audit_root().unwrap(),
            home.join(".nono").join("audit")
        );
        assert_eq!(
            legacy_sessions_dir().unwrap(),
            home.join(".nono").join("sessions")
        );
        assert_eq!(
            rollback_root().unwrap(),
            tmp.path().join("state").join("nono").join("rollbacks")
        );
        assert_eq!(
            legacy_rollback_root().unwrap(),
            home.join(".nono").join("rollbacks")
        );
    }

    #[test]
    fn protected_roots_include_both_legacy_and_xdg() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let (_env, home) = isolated_env(tmp.path());

        let roots = protected_state_roots().unwrap();
        assert_eq!(roots.len(), 2);
        assert!(roots.iter().any(|p| p.ends_with(".nono")));
        assert!(
            roots
                .iter()
                .any(|p| p.ends_with("nono") && !p.ends_with(".nono"))
        );
        let _ = home;
    }

    #[test]
    fn audit_discovery_roots_lists_primary_before_legacy() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let (_env, _home) = isolated_env(tmp.path());

        let roots = audit_discovery_roots().unwrap();
        assert_eq!(roots.len(), 2);
        assert!(roots[0].ends_with("nono/audit"));
        assert!(roots[1].ends_with(".nono/audit"));
    }

    #[test]
    fn rollback_discovery_roots_lists_primary_before_legacy() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let (_env, _home) = isolated_env(tmp.path());

        let roots = rollback_discovery_roots().unwrap();
        assert_eq!(roots.len(), 2);
        assert!(roots[0].ends_with("nono/rollbacks"));
        assert!(roots[1].ends_with(".nono/rollbacks"));
    }
}
