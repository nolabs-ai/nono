use crate::audit_attestation::{AuditSigner, write_audit_attestation};
use crate::audit_integrity::AuditRecorder;
use crate::audit_ledger;
use crate::launch_runtime::{RollbackLaunchOptions, rollback_base_exclusions};
use crate::{config, output, rollback_preflight, rollback_session, rollback_ui};
use nono::undo::ExecutableIdentity;
use nono::{AccessMode, CapabilitySet, Result};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tracing::warn;

pub(crate) struct AuditState {
    pub(crate) session_id: String,
    pub(crate) session_dir: PathBuf,
}

pub(crate) struct RollbackRuntimeState {
    pub(crate) session_dir: PathBuf,
    pub(crate) manager: nono::undo::SnapshotManager,
    pub(crate) baseline: nono::undo::SnapshotManifest,
    pub(crate) tracked_paths: Vec<PathBuf>,
    pub(crate) atomic_temp_before: HashSet<PathBuf>,
    pub(crate) session_id: String,
}

pub(crate) struct AuditSnapshotState {
    pub(crate) manager: nono::undo::SnapshotManager,
    pub(crate) baseline_root: nono::undo::ContentHash,
    pub(crate) tracked_paths: Vec<PathBuf>,
}

pub(crate) struct RollbackExitContext<'a> {
    pub(crate) audit_state: Option<&'a AuditState>,
    pub(crate) rollback_state: Option<RollbackRuntimeState>,
    pub(crate) audit_snapshot_state: Option<AuditSnapshotState>,
    pub(crate) audit_tracked_paths: Vec<PathBuf>,
    pub(crate) audit_recorder: Option<&'a Mutex<AuditRecorder>>,
    pub(crate) audit_integrity_enabled: bool,
    pub(crate) proxy_handle: Option<&'a nono_proxy::server::ProxyHandle>,
    pub(crate) executable_identity: Option<&'a ExecutableIdentity>,
    pub(crate) audit_signer: Option<&'a AuditSigner>,
    pub(crate) redaction_policy: &'a nono::ScrubPolicy,
    pub(crate) started: &'a str,
    pub(crate) ended: &'a str,
    pub(crate) command: &'a [String],
    pub(crate) exit_code: i32,
    pub(crate) silent: bool,
    pub(crate) rollback_prompt_disabled: bool,
}

fn rollback_vcs_exclusions() -> Vec<String> {
    [".git", ".hg", ".svn"]
        .iter()
        .map(|entry| String::from(*entry))
        .collect()
}

fn rollback_exclusion_patterns(rollback: &RollbackLaunchOptions) -> Vec<String> {
    let mut patterns = if rollback.track_all {
        rollback_vcs_exclusions()
    } else {
        rollback_base_exclusions()
    };
    patterns.extend(rollback.exclude_patterns.iter().cloned());
    patterns.sort_unstable();
    patterns.dedup();
    patterns
}

fn rollback_exclusion_config(
    rollback: &RollbackLaunchOptions,
    exclude_patterns: &[String],
) -> nono::undo::ExclusionConfig {
    nono::undo::ExclusionConfig {
        use_gitignore: true,
        exclude_patterns: exclude_patterns.to_vec(),
        exclude_globs: rollback.exclude_globs.clone(),
        force_include: rollback.include.clone(),
    }
}

fn build_snapshot_manager(
    session_dir: PathBuf,
    tracked_paths: &[PathBuf],
    exclusion_config: nono::undo::ExclusionConfig,
) -> Result<nono::undo::SnapshotManager> {
    let roots = tracked_paths
        .iter()
        .map(|tracked_path| {
            let exclusion =
                nono::undo::ExclusionFilter::new(exclusion_config.clone(), tracked_path)?;
            Ok((tracked_path.clone(), exclusion))
        })
        .collect::<Result<Vec<_>>>()?;

    nono::undo::SnapshotManager::new_per_root(session_dir, roots, nono::undo::WalkBudget::default())
}

fn enforce_rollback_limits(silent: bool) {
    let config = match config::user::load_user_config() {
        Ok(Some(config)) => config,
        Ok(None) => config::user::UserConfig::default(),
        Err(e) => {
            tracing::warn!("Failed to load user config for rollback limits: {e}");
            return;
        }
    };

    let sessions = match rollback_session::discover_sessions() {
        Ok(sessions) => sessions,
        Err(e) => {
            tracing::warn!("Failed to discover sessions for limit enforcement: {e}");
            return;
        }
    };

    if sessions.is_empty() {
        return;
    }

    let max_sessions = config.rollback.max_sessions;
    let storage_bytes_f64 =
        (config.rollback.max_storage_gb.max(0.0) * 1024.0 * 1024.0 * 1024.0).min(u64::MAX as f64);
    let max_storage_bytes = storage_bytes_f64 as u64;

    let completed: Vec<&rollback_session::SessionInfo> = sessions
        .iter()
        .filter(|session| !session.is_alive)
        .collect();

    let mut pruned = 0usize;
    let mut pruned_bytes = 0u64;

    if completed.len() > max_sessions {
        for session in &completed[max_sessions..] {
            if let Err(e) = rollback_session::remove_session(&session.dir) {
                tracing::warn!(
                    "Failed to prune session {}: {e}",
                    session.metadata.session_id
                );
            } else {
                pruned = pruned.saturating_add(1);
                pruned_bytes = pruned_bytes.saturating_add(session.disk_size);
            }
        }
    }

    let total = match rollback_session::total_storage_bytes() {
        Ok(total) => total,
        Err(_) => return,
    };

    if total > max_storage_bytes {
        let remaining = match rollback_session::discover_sessions() {
            Ok(sessions) => sessions,
            Err(_) => return,
        };

        let mut current_total = total;
        for session in remaining.iter().rev().filter(|session| !session.is_alive) {
            if current_total <= max_storage_bytes {
                break;
            }
            if let Err(e) = rollback_session::remove_session(&session.dir) {
                tracing::warn!(
                    "Failed to prune session {}: {e}",
                    session.metadata.session_id
                );
            } else {
                current_total = current_total.saturating_sub(session.disk_size);
                pruned = pruned.saturating_add(1);
                pruned_bytes = pruned_bytes.saturating_add(session.disk_size);
            }
        }
    }

    if pruned > 0 && !silent {
        eprintln!(
            "  Auto-pruned {} old session(s) (freed {})",
            pruned,
            rollback_session::format_bytes(pruned_bytes),
        );
    }
}

fn create_session_dir(root: &Path, session_id: &str) -> Result<PathBuf> {
    let session_dir = root.join(session_id);
    std::fs::create_dir_all(&session_dir).map_err(|e| {
        nono::NonoError::Snapshot(format!(
            "Failed to create session directory {}: {}",
            session_dir.display(),
            e
        ))
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        if let Err(e) = std::fs::set_permissions(&session_dir, perms) {
            warn!("Failed to set session directory permissions to 0700: {e}");
        }
    }

    Ok(session_dir)
}

/// Create a new audit session directory with a unique ID.
fn ensure_audit_session_dir() -> Result<(String, PathBuf)> {
    let session_id = format!(
        "{}-{}",
        chrono::Local::now().format("%Y%m%d-%H%M%S"),
        std::process::id()
    );

    let audit_root = crate::audit_session::audit_root()?;
    let session_dir = create_session_dir(&audit_root, &session_id)?;

    Ok((session_id, session_dir))
}

fn ensure_rollback_session_dir(
    session_id: &str,
    rollback_destination: Option<&PathBuf>,
) -> Result<PathBuf> {
    let rollback_root = match rollback_destination {
        Some(path) => path.clone(),
        None => crate::rollback_session::rollback_root()?,
    };
    create_session_dir(&rollback_root, session_id)
}

pub(crate) fn create_audit_state(
    audit_disabled: bool,
    _rollback_destination: Option<&PathBuf>,
) -> Result<Option<AuditState>> {
    if audit_disabled {
        return Ok(None);
    }

    let (session_id, session_dir) = ensure_audit_session_dir()?;

    Ok(Some(AuditState {
        session_id,
        session_dir,
    }))
}

pub(crate) fn warn_if_rollback_flags_ignored(rollback: &RollbackLaunchOptions, silent: bool) {
    if !rollback.disabled {
        return;
    }

    let has_rollback_flags = rollback.track_all
        || !rollback.include.is_empty()
        || !rollback.exclude_patterns.is_empty()
        || !rollback.exclude_globs.is_empty();
    if has_rollback_flags {
        warn!(
            "--no-rollback is active; rollback flags \
             (--rollback-all, --rollback-include, --rollback-exclude) \
             have no effect"
        );
        if !silent {
            eprintln!(
                "  [nono] Warning: --no-rollback is active; \
                 rollback customization flags have no effect."
            );
        }
    }
}

/// Derive audit tracked paths from capabilities: user-granted directories.
///
/// These paths identify the session scope for audit UX such as `audit list`.
/// They are intentionally broader than snapshot roots and include read-only
/// user-granted directories like `--allow-cwd`.
pub(crate) fn derive_audit_tracked_paths(caps: &CapabilitySet) -> Vec<PathBuf> {
    let mut tracked_paths: Vec<PathBuf> = caps
        .fs_capabilities()
        .iter()
        .filter(|cap| !cap.is_file && cap.source.is_user_intent())
        .map(|cap| cap.resolved.clone())
        .collect();
    prefer_workdir_path(&mut tracked_paths, std::env::current_dir().ok().as_deref());
    tracked_paths
}

/// Derive snapshot tracked paths from capabilities: user-granted writable directories.
///
/// These paths define where filesystem hashing and rollback snapshots are
/// allowed to walk.
pub(crate) fn derive_snapshot_tracked_paths(caps: &CapabilitySet) -> Vec<PathBuf> {
    let mut tracked_paths: Vec<PathBuf> = caps
        .fs_capabilities()
        .iter()
        .filter(|cap| {
            !cap.is_file
                && matches!(cap.access, AccessMode::Write | AccessMode::ReadWrite)
                && cap.source.is_user_intent()
        })
        .map(|cap| cap.resolved.clone())
        .collect();
    prefer_workdir_path(&mut tracked_paths, std::env::current_dir().ok().as_deref());
    tracked_paths
}

fn prefer_workdir_path(tracked_paths: &mut [PathBuf], workdir: Option<&std::path::Path>) {
    let Some(workdir) = workdir else {
        return;
    };

    if let Some(index) = tracked_paths
        .iter()
        .position(|path| path == workdir || workdir.starts_with(path) || path.starts_with(workdir))
    {
        tracked_paths.swap(0, index);
    }
}

fn attestation_session_dir<'a>(
    rollback_session_dir: &'a Path,
    audit_state: Option<&'a AuditState>,
) -> &'a Path {
    audit_state
        .map(|state| state.session_dir.as_path())
        .unwrap_or(rollback_session_dir)
}

pub(crate) fn initialize_audit_snapshots(
    caps: &CapabilitySet,
    audit_state: &AuditState,
    rollback: &RollbackLaunchOptions,
) -> Result<Option<AuditSnapshotState>> {
    let tracked_paths = derive_snapshot_tracked_paths(caps);
    if tracked_paths.is_empty() {
        return Ok(None);
    }

    let patterns = rollback_exclusion_patterns(rollback);
    let exclusion_config = rollback_exclusion_config(rollback, &patterns);
    let manager = build_snapshot_manager(
        audit_state.session_dir.clone(),
        &tracked_paths,
        exclusion_config,
    )?;
    let baseline_root = manager.compute_merkle_root()?;

    Ok(Some(AuditSnapshotState {
        manager,
        baseline_root,
        tracked_paths,
    }))
}

pub(crate) fn initialize_rollback_state(
    rollback: &RollbackLaunchOptions,
    caps: &CapabilitySet,
    audit_state: Option<&AuditState>,
    silent: bool,
) -> Result<Option<RollbackRuntimeState>> {
    if !rollback.requested || rollback.disabled {
        return Ok(None);
    }

    enforce_rollback_limits(silent);

    // When audit is active, share its session directory. Otherwise create
    // a standalone rollback directory so snapshots still have somewhere to
    // live (handles the --rollback --no-audit case).
    let (session_id, session_dir) = match audit_state {
        Some(state) => (
            state.session_id.clone(),
            ensure_rollback_session_dir(&state.session_id, rollback.destination.as_ref())?,
        ),
        None => {
            let session_id = format!(
                "{}-{}",
                chrono::Local::now().format("%Y%m%d-%H%M%S"),
                std::process::id()
            );
            let session_dir =
                ensure_rollback_session_dir(&session_id, rollback.destination.as_ref())?;
            (session_id, session_dir)
        }
    };

    let tracked_paths = derive_snapshot_tracked_paths(caps);

    if tracked_paths.is_empty() {
        return Ok(None);
    }

    let mut patterns = rollback_exclusion_patterns(rollback);
    let base_patterns = patterns.clone();
    let preflight_exclusion = nono::undo::ExclusionFilter::new(
        rollback_exclusion_config(rollback, &patterns),
        &tracked_paths[0],
    )?;

    if !rollback.track_all {
        let preflight_result = rollback_preflight::run_preflight(
            &tracked_paths,
            &preflight_exclusion,
            &rollback.skip_dirs,
        );

        if preflight_result.needs_warning() {
            let auto_excluded: Vec<&rollback_preflight::HeavyDir> = preflight_result
                .heavy_dirs
                .iter()
                .filter(|dir| !rollback.include.contains(&dir.name))
                .collect();

            if !auto_excluded.is_empty() {
                let excluded_names: Vec<String> =
                    auto_excluded.iter().map(|dir| dir.name.clone()).collect();
                let mut all_patterns = base_patterns.clone();
                all_patterns.extend(excluded_names);
                all_patterns.sort_unstable();
                all_patterns.dedup();
                patterns = all_patterns;

                if !silent {
                    rollback_preflight::print_auto_exclude_notice(
                        &auto_excluded,
                        &preflight_result,
                    );
                }
            }
        }
    }

    let mut manager = build_snapshot_manager(
        session_dir.clone(),
        &tracked_paths,
        rollback_exclusion_config(rollback, &patterns),
    )?;

    let baseline = manager.create_baseline()?;
    let atomic_temp_before = manager.collect_atomic_temp_files();

    output::print_rollback_tracking(&tracked_paths, silent);

    Ok(Some(RollbackRuntimeState {
        session_dir,
        manager,
        baseline,
        tracked_paths,
        atomic_temp_before,
        session_id,
    }))
}

pub(crate) fn finalize_supervised_exit(ctx: RollbackExitContext<'_>) -> Result<()> {
    let RollbackExitContext {
        audit_state,
        rollback_state,
        audit_snapshot_state,
        audit_tracked_paths,
        audit_recorder,
        audit_integrity_enabled,
        proxy_handle,
        executable_identity,
        audit_signer,
        redaction_policy,
        started,
        ended,
        command,
        exit_code,
        silent,
        rollback_prompt_disabled,
    } = ctx;

    let mut network_events = proxy_handle.map_or_else(
        Vec::new,
        nono_proxy::server::ProxyHandle::drain_audit_events,
    );
    let (audit_event_count, audit_integrity) = if let Some(recorder_mutex) = audit_recorder {
        let mut recorder = recorder_mutex
            .lock()
            .map_err(|_| nono::NonoError::Snapshot("Audit recorder lock poisoned".to_string()))?;
        for event in &network_events {
            recorder.record_network_event(event.clone())?;
        }
        recorder.record_session_ended(ended.to_string(), exit_code)?;
        let event_count = recorder.event_count();
        let integrity = if audit_integrity_enabled {
            recorder.finalize()
        } else {
            None
        };
        (event_count, integrity)
    } else {
        (0, None)
    };

    let scrubbed_command = nono::scrub_argv_with_policy(command, redaction_policy);
    let mut audit_saved = false;

    if let Some(RollbackRuntimeState {
        session_dir,
        mut manager,
        baseline,
        tracked_paths,
        atomic_temp_before,
        session_id: rb_session_id,
    }) = rollback_state
    {
        let (final_manifest, changes) = manager.create_incremental(&baseline)?;
        let merkle_roots = vec![baseline.merkle_root, final_manifest.merkle_root];

        let mut meta = nono::undo::SessionMetadata {
            session_id: rb_session_id,
            started: started.to_string(),
            ended: Some(ended.to_string()),
            command: scrubbed_command.clone(),
            executable_identity: executable_identity.cloned(),
            tracked_paths,
            snapshot_count: manager.snapshot_count(),
            exit_code: Some(exit_code),
            merkle_roots,
            network_events: std::mem::take(&mut network_events),
            audit_event_count,
            audit_integrity: audit_integrity.clone(),
            audit_attestation: None,
        };
        if let Some(signer) = audit_signer {
            meta.audit_attestation = Some(write_audit_attestation(
                attestation_session_dir(&session_dir, audit_state),
                &meta,
                signer,
                redaction_policy,
            )?);
        }
        manager.save_session_metadata(&meta)?;
        if let Some(audit_state) = audit_state {
            nono::undo::SnapshotManager::write_session_metadata(&audit_state.session_dir, &meta)?;
            audit_ledger::append_session(&meta)?;
        }
        audit_saved = true;

        if !changes.is_empty() {
            output::print_rollback_session_summary(&changes, silent);

            if !rollback_prompt_disabled && !silent {
                let _ = rollback_ui::review_and_restore(&manager, &baseline, &changes);
            }
        }

        let _ = manager.cleanup_new_atomic_temp_files(&atomic_temp_before);
    }

    if !audit_saved && let Some(audit_state) = audit_state {
        let (tracked_paths, merkle_roots) = match audit_snapshot_state {
            Some(snap) => {
                let final_root = snap.manager.compute_merkle_root()?;
                (snap.tracked_paths, vec![snap.baseline_root, final_root])
            }
            None => (audit_tracked_paths, Vec::new()),
        };
        let mut meta = nono::undo::SessionMetadata {
            session_id: audit_state.session_id.clone(),
            started: started.to_string(),
            ended: Some(ended.to_string()),
            command: scrubbed_command,
            executable_identity: executable_identity.cloned(),
            tracked_paths,
            snapshot_count: 0,
            exit_code: Some(exit_code),
            merkle_roots,
            network_events,
            audit_event_count,
            audit_integrity,
            audit_attestation: None,
        };
        if let Some(signer) = audit_signer {
            meta.audit_attestation = Some(write_audit_attestation(
                &audit_state.session_dir,
                &meta,
                signer,
                redaction_policy,
            )?);
        }
        nono::undo::SnapshotManager::write_session_metadata(&audit_state.session_dir, &meta)?;
        audit_ledger::append_session(&meta)?;
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::audit_attestation::{
        AUDIT_ATTESTATION_BUNDLE_FILENAME, signer_from_key_pair, verify_audit_attestation,
        write_audit_attestation,
    };
    use crate::test_env::{ENV_LOCK, EnvVarGuard};
    use nono::trust;
    use nono::undo::{AuditIntegritySummary, SessionMetadata};
    use nono::{CapabilitySet, CapabilitySource, FsCapability};
    use std::fs;

    #[test]
    fn create_audit_state_returns_none_when_disabled() {
        let result = create_audit_state(true, None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn create_audit_state_creates_session_when_enabled() {
        let _env_lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().to_string_lossy().to_string();
        let _env = EnvVarGuard::set_all(&[("HOME", &home)]);
        let audit_root = crate::audit_session::audit_root().unwrap();
        let state = create_audit_state(false, None).unwrap().unwrap();

        assert!(!state.session_id.is_empty());
        assert!(state.session_dir.exists());
        assert!(state.session_dir.starts_with(audit_root));
    }

    #[test]
    fn ensure_session_dir_creates_dir_in_custom_destination() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().to_path_buf();

        let session_id = format!(
            "{}-{}",
            chrono::Local::now().format("%Y%m%d-%H%M%S"),
            std::process::id()
        );
        let session_dir = ensure_rollback_session_dir(&session_id, Some(&dest)).unwrap();

        assert!(!session_id.is_empty());
        assert!(session_dir.exists());
        assert!(session_dir.starts_with(tmp.path()));
    }

    #[test]
    fn ensure_session_dir_id_contains_pid() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().to_path_buf();

        let session_id = format!(
            "{}-{}",
            chrono::Local::now().format("%Y%m%d-%H%M%S"),
            std::process::id()
        );
        let _ = ensure_rollback_session_dir(&session_id, Some(&dest)).unwrap();

        let pid = std::process::id().to_string();
        assert!(
            session_id.contains(&pid),
            "session_id '{session_id}' should contain pid '{pid}'"
        );
    }

    #[cfg(unix)]
    #[test]
    fn ensure_session_dir_sets_0700_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().to_path_buf();

        let session_id = format!(
            "{}-{}",
            chrono::Local::now().format("%Y%m%d-%H%M%S"),
            std::process::id()
        );
        let session_dir = ensure_rollback_session_dir(&session_id, Some(&dest)).unwrap();

        let mode = std::fs::metadata(&session_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "session dir should have 0700 permissions");
    }

    #[test]
    fn derive_audit_tracked_paths_include_readonly_user_directories() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let readonly = tmp.path().join("readonly");
        let writable = tmp.path().join("writable");
        let system = tmp.path().join("system");
        let file = tmp.path().join("tracked.txt");
        fs::create_dir_all(&readonly).expect("create readonly dir");
        fs::create_dir_all(&writable).expect("create writable dir");
        fs::create_dir_all(&system).expect("create system dir");
        fs::write(&file, b"content").expect("write tracked file");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: readonly.clone(),
            resolved: readonly.clone(),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::Profile,
        });
        caps.add_fs(FsCapability {
            original: writable.clone(),
            resolved: writable.clone(),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::Profile,
        });
        caps.add_fs(FsCapability {
            original: system.clone(),
            resolved: system.clone(),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::System,
        });
        caps.add_fs(FsCapability {
            original: file.clone(),
            resolved: file,
            access: AccessMode::ReadWrite,
            is_file: true,
            source: CapabilitySource::Profile,
        });

        assert_eq!(derive_audit_tracked_paths(&caps), vec![readonly, writable]);
    }

    #[test]
    fn derive_snapshot_tracked_paths_include_only_writable_user_directories() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let tracked = tmp.path().join("tracked");
        let system = tmp.path().join("system");
        let readonly = tmp.path().join("readonly");
        let file = tmp.path().join("tracked.txt");
        fs::create_dir_all(&tracked).expect("create tracked dir");
        fs::create_dir_all(&system).expect("create system dir");
        fs::create_dir_all(&readonly).expect("create readonly dir");
        fs::write(&file, b"content").expect("write tracked file");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: tracked.clone(),
            resolved: tracked.clone(),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::Profile,
        });
        caps.add_fs(FsCapability {
            original: system.clone(),
            resolved: system.clone(),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::System,
        });
        caps.add_fs(FsCapability {
            original: readonly.clone(),
            resolved: readonly.clone(),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::Profile,
        });
        caps.add_fs(FsCapability {
            original: file.clone(),
            resolved: file,
            access: AccessMode::ReadWrite,
            is_file: true,
            source: CapabilitySource::Profile,
        });

        assert_eq!(derive_snapshot_tracked_paths(&caps), vec![tracked]);
    }

    #[test]
    fn initialize_audit_snapshots_captures_filesystem_state_without_rollback_storage() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let tracked = tmp.path().join("tracked");
        fs::create_dir_all(&tracked).expect("create tracked");
        fs::write(tracked.join("file.txt"), b"before").expect("write file");

        let caps = CapabilitySet::new()
            .allow_path(&tracked, AccessMode::ReadWrite)
            .expect("allow tracked");
        let audit_state = AuditState {
            session_id: "test-session".to_string(),
            session_dir: tmp.path().join("session"),
        };
        fs::create_dir_all(&audit_state.session_dir).expect("create session");

        let snapshot_state = initialize_audit_snapshots(
            &caps,
            &audit_state,
            &RollbackLaunchOptions {
                audit_integrity: true,
                ..RollbackLaunchOptions::default()
            },
        )
        .expect("initialize audit snapshots")
        .expect("snapshot state");

        fs::write(tracked.join("file.txt"), b"after").expect("modify file");
        let modified_root = snapshot_state
            .manager
            .compute_merkle_root()
            .expect("compute modified root");

        assert_eq!(snapshot_state.tracked_paths.len(), 1);
        assert!(
            snapshot_state.tracked_paths[0].ends_with("tracked"),
            "expected tracked root, got {:?}",
            snapshot_state.tracked_paths
        );
        assert_ne!(snapshot_state.baseline_root, modified_root);
    }

    #[test]
    fn prefer_workdir_path_moves_covering_workdir_to_front() {
        let mut tracked_paths = vec![
            PathBuf::from("/Users/example/.claude"),
            PathBuf::from("/Users/example/project"),
            PathBuf::from("/Users/example/.cache/claude"),
        ];

        prefer_workdir_path(
            &mut tracked_paths,
            Some(std::path::Path::new("/Users/example/project")),
        );

        assert_eq!(tracked_paths[0], PathBuf::from("/Users/example/project"));
    }

    #[test]
    fn rollback_attestation_is_written_to_audit_dir_when_present() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let rollback_dir = tmp.path().join("rollback-session");
        let audit_dir = tmp.path().join("audit-session");
        fs::create_dir_all(&rollback_dir).expect("create rollback dir");
        fs::create_dir_all(&audit_dir).expect("create audit dir");

        let key_pair = trust::generate_signing_key().expect("generate signing key");
        let signer = signer_from_key_pair(key_pair).expect("build signer");

        let metadata = SessionMetadata {
            session_id: "sess-rollback-audit".to_string(),
            started: "2026-04-22T12:00:00Z".to_string(),
            ended: Some("2026-04-22T12:00:01Z".to_string()),
            command: vec!["/bin/pwd".to_string()],
            executable_identity: None,
            tracked_paths: vec![PathBuf::from("/tmp/project")],
            snapshot_count: 1,
            exit_code: Some(0),
            merkle_roots: Vec::new(),
            network_events: Vec::new(),
            audit_event_count: 2,
            audit_integrity: Some(AuditIntegritySummary {
                hash_algorithm: "sha256".to_string(),
                event_count: 2,
                chain_head: nono::undo::ContentHash::from_bytes([0x11; 32]),
                merkle_root: nono::undo::ContentHash::from_bytes([0x22; 32]),
            }),
            audit_attestation: None,
        };

        let summary = write_audit_attestation(
            attestation_session_dir(
                &rollback_dir,
                Some(&AuditState {
                    session_id: metadata.session_id.clone(),
                    session_dir: audit_dir.clone(),
                }),
            ),
            &metadata,
            &signer,
            &nono::ScrubPolicy::secure_default(),
        )
        .expect("write attestation");

        let mut attested_metadata = metadata.clone();
        attested_metadata.audit_attestation = Some(summary);

        assert!(
            !rollback_dir
                .join(AUDIT_ATTESTATION_BUNDLE_FILENAME)
                .exists()
        );
        assert!(audit_dir.join(AUDIT_ATTESTATION_BUNDLE_FILENAME).exists());

        let verification =
            verify_audit_attestation(&audit_dir, &attested_metadata, None).expect("verify");
        assert!(verification.signature_verified);
        assert!(verification.verification_error.is_none());
    }
}
