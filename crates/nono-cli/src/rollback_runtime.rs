use crate::audit_attestation::{sign_session_attestation, AuditSigner};
use crate::audit_integrity::AuditRecorder;
use crate::launch_runtime::{rollback_base_exclusions, RollbackLaunchOptions};
use crate::{config, output, rollback_preflight, rollback_session, rollback_ui};
use nono::undo::{ExecutableIdentity, RollbackStatus};
use nono::{AccessMode, CapabilitySet, NonoError, Result};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Mutex;
use tracing::warn;

pub(crate) struct AuditState {
    pub(crate) session_id: String,
    /// Audit-side directory: `<audit_root>/<id>/`. Always populated when
    /// `--audit-integrity` is requested (per Phase 27.2 D-27.2-01). The
    /// signed audit-attestation bundle and the audit-events ledger always
    /// land under this path so they outlive `rm -rf <rollback_root>/<id>/`.
    pub(crate) session_dir: PathBuf,
    /// Rollback-side directory: `<rollback_root>/<id>/`. `Some` only when
    /// `--rollback` is active. Snapshot artifacts (`changes/`, `snapshots/`,
    /// `session.json`) land here, preserving the pre-Phase-27.2 snapshot
    /// storage layout while `session_dir` is repointed to the audit root
    /// for the bundle-target migration (D-27.2-01).
    pub(crate) rollback_dir: Option<PathBuf>,
}

pub(crate) type RollbackRuntimeState = (
    nono::undo::SnapshotManager,
    nono::undo::SnapshotManifest,
    Vec<PathBuf>,
    HashSet<PathBuf>,
);

/// Lightweight snapshot state for audit-only sessions (no rollback).
///
/// Captures pre-execution merkle root so the audit trail includes a
/// cryptographic commitment to filesystem state even when rollback
/// restore is not enabled.
pub(crate) struct AuditSnapshotState {
    pub(crate) manager: nono::undo::SnapshotManager,
    pub(crate) baseline_root: nono::undo::ContentHash,
    pub(crate) tracked_paths: Vec<PathBuf>,
}

pub(crate) struct RollbackExitContext<'a> {
    pub(crate) audit_state: Option<&'a AuditState>,
    pub(crate) rollback_state: Option<RollbackRuntimeState>,
    /// The rollback status recorded at session start (from `initialize_rollback_state`).
    pub(crate) rollback_status: RollbackStatus,
    /// Plan 22-05a Decision 5 minimal scope: the audit-integrity recorder
    /// (when `--audit-integrity` is set). `finalize_supervised_exit` emits the
    /// `session_ended` event and calls `finalize()` to populate
    /// `audit_event_count` + `audit_integrity` on `SessionMetadata`. `None`
    /// when audit-integrity was not requested (zero-overhead path; existing
    /// callers see byte-identical behavior to pre-22-05a).
    pub(crate) audit_recorder: Option<&'a std::sync::Arc<Mutex<AuditRecorder>>>,
    /// Upstream 4ec61c29: lightweight pre/post Merkle root capture for
    /// audit-only sessions. When `Some`, `finalize_supervised_exit`
    /// recomputes the root post-execution and stores both roots in
    /// `SessionMetadata.merkle_roots` for tamper-evidence (no full
    /// snapshot storage overhead).
    pub(crate) audit_snapshot_state: Option<AuditSnapshotState>,
    /// Upstream 02ee0bd1 AUD-03 SHA-256 portion: canonical path + SHA-256
    /// of the launched binary, captured by `exec_identity::compute()`
    /// before sandbox apply for supervised sessions only. Persisted into
    /// `SessionMetadata.executable_identity`. The Windows signature-trust
    /// addition is reserved for Plan 22-05b (sibling field; no mutation
    /// of this type).
    pub(crate) executable_identity: Option<ExecutableIdentity>,
    /// Upstream 6ecade2e (AUD-02): when `--audit-sign-key` is set,
    /// `finalize_supervised_exit` signs the audit-integrity Merkle root +
    /// chain head + session id and writes
    /// `<session_dir>/audit-attestation.bundle`. The resulting
    /// `AuditAttestationSummary` is persisted into
    /// `SessionMetadata.audit_attestation`. `None` when attestation was
    /// not requested.
    pub(crate) audit_signer: Option<&'a AuditSigner>,
    pub(crate) proxy_handle: Option<&'a nono_proxy::server::ProxyHandle>,
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

pub(crate) fn create_audit_state(
    rollback_requested: bool,
    rollback_disabled: bool,
    audit_disabled: bool,
    audit_integrity_requested: bool,
    rollback_destination: Option<&PathBuf>,
) -> Result<Option<AuditState>> {
    if audit_disabled {
        return Ok(None);
    }
    let rollback_active = rollback_requested && !rollback_disabled;
    // Plan 22-05a Decision 5 minimal scope: when --audit-integrity is set
    // without --rollback, create an audit-only session under
    // ~/.nono/audit/<id> via crate::audit_session::ensure_audit_session_dir.
    // This keeps audit sessions namespaced separately from rollback sessions
    // (per upstream 4f9552ec restructuring). When --rollback is active, fall
    // back to the existing rollback root path for backward compatibility.
    if !rollback_active && !audit_integrity_requested {
        return Ok(None);
    }

    let session_id = format!(
        "{}-{}",
        chrono::Local::now().format("%Y%m%d-%H%M%S"),
        std::process::id()
    );

    // Phase 27.2 D-27.2-01 (Option A): the audit attestation bundle ALWAYS
    // lands at <audit_root>/<id>/audit-attestation.bundle regardless of
    // --rollback. This closes the non-repudiation hole where
    // `rm -rf <rollback>/<id>/` would delete the bundle along with the
    // snapshot. Snapshot files (changes/, snapshots/, session.json) continue
    // to live under <rollback>/<id>/ when --rollback is set; only the
    // bundle (and the audit-events ledger that the bundle signs) move.
    // ADR: docs/architecture/audit-bundle-target.md (supersedes Plan 22-05a
    // Decision 5 "for backward compatibility" dual-location rationale).
    let session_dir = crate::audit_session::ensure_audit_session_dir(&session_id)?;

    // When --rollback is active, ALSO create <rollback_root>/<id>/ for the
    // SnapshotManager (which stores `changes/`, `snapshots/`, `session.json`
    // under its `session_dir` argument). The created path is exposed via
    // AuditState.rollback_dir; it is NOT bound to session_dir and is NOT
    // the attestation-bundle target.
    //
    // Deviation note (Plan 27.2-02 Rule 1): the plan's interfaces block
    // claimed snapshot creation uses a separate variable (not
    // AuditState.session_dir). At execution time, two SnapshotManager::new
    // call sites (initialize_rollback_state, initialize_audit_snapshots)
    // were found to consume audit_state.session_dir for snapshot-storage
    // root. Naively repointing session_dir to the audit dir would have
    // moved snapshot artifacts under <audit_root>/<id>/ — violating the
    // must_have "snapshot files continue to land under <rollback_root>/<id>/".
    // CONTEXT § Claude's Discretion permits this minimal-diff: expose the
    // rollback path as AuditState.rollback_dir and route the rollback-active
    // SnapshotManager call site through it.
    // BL-02 fix (27.2-REVIEW): the canonical rollback root differs from
    // `nono_home_dir().join(".nono").join("rollbacks")` on Windows
    // production (`%LOCALAPPDATA%\nono\rollbacks` vs
    // `%USERPROFILE%\.nono\rollbacks`). Route through
    // `ensure_rollback_session_dir`, which uses `rollback_session::rollback_root()`
    // — the same helper that `discover_sessions` / `nono rollback list` /
    // `restore` consult — so combo sessions stay visible to the rollback
    // commands.
    let rollback_dir = if rollback_active {
        let dir =
            crate::audit_session::ensure_rollback_session_dir(&session_id, rollback_destination)?;
        Some(dir)
    } else {
        None
    };

    Ok(Some(AuditState {
        session_id,
        session_dir,
        rollback_dir,
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

/// Derive snapshot tracked paths from capabilities: user-granted writable
/// directories. Upstream 9db06336 split the derivation in two — these
/// snapshot paths are the strictly-writable subset used for filesystem
/// hashing and rollback snapshots.
///
/// (Plan 22-05a Task 8: kept the existing `derive_tracked_paths` name as
/// the legacy alias so the Task 3 callsite in `initialize_audit_snapshots`
/// keeps working without refactor; new audit-broader callers use
/// `derive_audit_tracked_paths` below.)
fn derive_tracked_paths(caps: &CapabilitySet) -> Vec<PathBuf> {
    caps.fs_capabilities()
        .iter()
        .filter(|cap| {
            !cap.is_file
                && matches!(cap.access, AccessMode::Write | AccessMode::ReadWrite)
                && matches!(cap.source, nono::CapabilitySource::User)
        })
        .map(|cap| cap.resolved.clone())
        .collect()
}

/// Derive audit tracked paths from capabilities: user-granted directories
/// (writable AND read-only). Upstream 9db06336 introduced this broader
/// selector so `audit list` can group sessions by scope rather than by
/// the strictly-writable subset that rollback uses.
#[allow(dead_code)]
pub(crate) fn derive_audit_tracked_paths(caps: &CapabilitySet) -> Vec<PathBuf> {
    caps.fs_capabilities()
        .iter()
        .filter(|cap| !cap.is_file && cap.source.is_user_intent())
        .map(|cap| cap.resolved.clone())
        .collect()
}

/// Initialize lightweight audit snapshots for merkle root computation.
///
/// When rollback is not requested but audit is active, this captures a
/// pre-execution merkle root so the audit trail includes a cryptographic
/// commitment to filesystem state.
pub(crate) fn initialize_audit_snapshots(
    caps: &CapabilitySet,
    audit_state: &AuditState,
) -> Result<Option<AuditSnapshotState>> {
    let tracked_paths = derive_tracked_paths(caps);
    if tracked_paths.is_empty() {
        return Ok(None);
    }

    let exclusion_config = nono::undo::ExclusionConfig {
        use_gitignore: true,
        exclude_patterns: rollback_vcs_exclusions(),
        exclude_globs: Vec::new(),
        force_include: Vec::new(),
    };
    let gitignore_root = tracked_paths
        .first()
        .cloned()
        .unwrap_or_else(|| PathBuf::from("."));
    let exclusion = nono::undo::ExclusionFilter::new(exclusion_config, &gitignore_root)?;

    let manager = nono::undo::SnapshotManager::new(
        audit_state.session_dir.clone(),
        tracked_paths.clone(),
        exclusion,
        nono::undo::WalkBudget::default(),
    )?;

    let baseline_root = manager.compute_merkle_root()?;

    Ok(Some(AuditSnapshotState {
        manager,
        baseline_root,
        tracked_paths,
    }))
}

/// Initialize rollback state for a supervised session.
///
/// Returns `Ok((Some(state), RollbackStatus::Available))` on success, or
/// `Ok((None, RollbackStatus::Skipped | RollbackStatus::FailedWarningOnly))` with a
/// warning emitted to stderr if baseline snapshot capture fails (D-04: failure-warning-only).
/// Callers must record the returned `RollbackStatus` in `SessionMetadata`.
///
/// # Decision alignment
///
/// - D-01: Uses the existing Merkle-tree rollback engine.
/// - D-02: Snapshots all granted write-capable paths for the session scope.
/// - D-03: Soft-limit warnings remain visible and do not turn fatal.
/// - D-04: Snapshot initialization failures warn and execution continues.
pub(crate) fn initialize_rollback_state(
    rollback: &RollbackLaunchOptions,
    caps: &CapabilitySet,
    audit_state: Option<&AuditState>,
    silent: bool,
) -> Result<(Option<RollbackRuntimeState>, RollbackStatus)> {
    if !rollback.requested || rollback.disabled {
        return Ok((None, RollbackStatus::Skipped));
    }

    enforce_rollback_limits(silent);

    let Some(audit_state) = audit_state else {
        return Ok((None, RollbackStatus::Skipped));
    };

    let tracked_paths = derive_tracked_paths(caps);

    if tracked_paths.is_empty() {
        return Ok((None, RollbackStatus::Skipped));
    }

    let mut patterns = if rollback.track_all {
        rollback_vcs_exclusions()
    } else {
        rollback_base_exclusions()
    };
    patterns.extend(rollback.exclude_patterns.iter().cloned());
    patterns.sort_unstable();
    patterns.dedup();
    let base_patterns = patterns.clone();
    let exclusion_config = nono::undo::ExclusionConfig {
        use_gitignore: true,
        exclude_patterns: patterns,
        exclude_globs: rollback.exclude_globs.clone(),
        force_include: rollback.include.clone(),
    };
    let gitignore_root = tracked_paths
        .first()
        .cloned()
        .unwrap_or_else(|| PathBuf::from("."));
    let mut exclusion = match nono::undo::ExclusionFilter::new(exclusion_config, &gitignore_root) {
        Ok(e) => e,
        Err(e) => {
            let reason = format!("exclusion filter init failed: {e}");
            warn!("Rollback unavailable: {reason}");
            if !silent {
                eprintln!(
                    "  [nono] Warning: rollback unavailable for this session ({reason}). \
                     Execution will continue without snapshot capability."
                );
            }
            return Ok((None, RollbackStatus::FailedWarningOnly { reason }));
        }
    };

    if !rollback.track_all {
        let preflight_result =
            rollback_preflight::run_preflight(&tracked_paths, &exclusion, &rollback.skip_dirs);

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
                let updated_config = nono::undo::ExclusionConfig {
                    use_gitignore: true,
                    exclude_patterns: all_patterns,
                    exclude_globs: rollback.exclude_globs.clone(),
                    force_include: rollback.include.clone(),
                };
                exclusion = match nono::undo::ExclusionFilter::new(updated_config, &gitignore_root)
                {
                    Ok(e) => e,
                    Err(e) => {
                        let reason = format!("exclusion filter update failed: {e}");
                        warn!("Rollback unavailable: {reason}");
                        if !silent {
                            eprintln!(
                                "  [nono] Warning: rollback unavailable for this session ({reason}). \
                                 Execution will continue without snapshot capability."
                            );
                        }
                        return Ok((None, RollbackStatus::FailedWarningOnly { reason }));
                    }
                };

                if !silent {
                    rollback_preflight::print_auto_exclude_notice(
                        &auto_excluded,
                        &preflight_result,
                    );
                }
            }
        }
    }

    // D-04: snapshot manager init failure → warning-only, execution continues.
    //
    // Phase 27.2 D-27.2-01: snapshot artifacts (`changes/`, `snapshots/`,
    // `session.json`) MUST land at `<rollback_root>/<id>/` so the audit
    // attestation bundle's relocation to `<audit_root>/<id>/` does not also
    // move snapshot storage. `audit_state.rollback_dir` is `Some` whenever
    // `initialize_rollback_state` reaches this point: the early-return at
    // `if !rollback.requested || rollback.disabled` gates rollback-inactive
    // callers out, and `create_audit_state` populates `rollback_dir` under
    // the same condition (`rollback_active`). The `unwrap_or_else` fallback
    // to `session_dir` is a defense-in-depth failsafe; under correct gating
    // it never fires.
    let snapshot_session_dir = audit_state
        .rollback_dir
        .clone()
        .unwrap_or_else(|| audit_state.session_dir.clone());
    let mut manager = match nono::undo::SnapshotManager::new(
        snapshot_session_dir,
        tracked_paths.clone(),
        exclusion,
        nono::undo::WalkBudget::default(),
    ) {
        Ok(m) => m,
        Err(e) => {
            let reason = format!("snapshot manager init failed: {e}");
            warn!("Rollback unavailable: {reason}");
            if !silent {
                eprintln!(
                    "  [nono] Warning: rollback unavailable for this session ({reason}). \
                     Execution will continue without snapshot capability."
                );
            }
            return Ok((None, RollbackStatus::FailedWarningOnly { reason }));
        }
    };

    // D-04: baseline capture failure → warning-only, execution continues.
    match manager.create_baseline() {
        Ok(baseline) => {
            let atomic_temp_before = manager.collect_atomic_temp_files();
            output::print_rollback_tracking(&tracked_paths, silent);
            Ok((
                Some((manager, baseline, tracked_paths, atomic_temp_before)),
                RollbackStatus::Available,
            ))
        }
        Err(e) => {
            let reason = format!("{e}");
            warn!("Rollback baseline capture failed: {reason}. Continuing without rollback.");
            if !silent {
                eprintln!(
                    "  [nono] Warning: rollback baseline capture failed ({reason}). \
                     Execution will continue; rollback will not be available for this session."
                );
            }
            Ok((None, RollbackStatus::FailedWarningOnly { reason }))
        }
    }
}

/// Error variant carrying partial restore results.
///
/// Used to surface which files could not be restored (e.g., locked on Windows)
/// without claiming full rollback success.
#[derive(Debug)]
pub(crate) struct PartialRestoreError {
    /// Changes that were applied successfully.
    pub applied: Vec<nono::undo::Change>,
    /// Per-file errors (path → error message).
    pub failures: Vec<(PathBuf, String)>,
}

impl std::fmt::Display for PartialRestoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "partial rollback: {} file(s) applied, {} file(s) failed",
            self.applied.len(),
            self.failures.len()
        )?;
        for (path, reason) in &self.failures {
            write!(f, "\n  {} — {}", path.display(), reason)?;
        }
        Ok(())
    }
}

impl std::error::Error for PartialRestoreError {}

impl From<PartialRestoreError> for NonoError {
    fn from(e: PartialRestoreError) -> Self {
        NonoError::Snapshot(e.to_string())
    }
}

pub(crate) fn finalize_supervised_exit(ctx: RollbackExitContext<'_>) -> Result<()> {
    let RollbackExitContext {
        audit_state,
        rollback_state,
        rollback_status,
        audit_recorder,
        audit_snapshot_state,
        executable_identity,
        audit_signer,
        proxy_handle,
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

    // Plan 22-05a Decision 5 minimal scope: emit the trailing
    // `session_ended` event before the recorder is finalized so the
    // hash-chain commits to the exit code. `finalize()` returns
    // `Some(AuditIntegritySummary)` whenever ANY event was appended.
    // T-22-05a-03 mitigation: this flush completes BEFORE
    // `AppliedLabelsGuard::drop` triggers (the guard is owned by callers
    // upstream of `execute_supervised`; this fn runs synchronously inside
    // `execute_supervised` before its return).
    let (audit_event_count, audit_integrity_summary) = if let Some(mutex) = audit_recorder {
        let mut recorder = mutex
            .lock()
            .map_err(|_| NonoError::Snapshot("Audit recorder lock poisoned".to_string()))?;
        recorder.record_session_ended(ended.to_string(), exit_code)?;
        (recorder.event_count(), recorder.finalize())
    } else {
        (0, None)
    };

    // Upstream 6ecade2e (AUD-02): sign the integrity summary if a signer
    // was prepared. Bundle is written to `<session_dir>/audit-attestation.bundle`
    // BEFORE the SessionMetadata write so the metadata's
    // `audit_attestation` field can record the resulting summary.
    let audit_attestation_summary =
        match (audit_signer, audit_integrity_summary.as_ref(), audit_state) {
            (Some(signer), Some(summary), Some(state)) => Some(sign_session_attestation(
                signer,
                &state.session_dir,
                &state.session_id,
                summary,
            )?),
            _ => None,
        };

    let mut audit_saved = false;

    if let Some((mut manager, baseline, tracked_paths, atomic_temp_before)) = rollback_state {
        let (final_manifest, changes) = manager.create_incremental(&baseline)?;
        let merkle_roots = vec![baseline.merkle_root, final_manifest.merkle_root];

        let meta = nono::undo::SessionMetadata {
            session_id: audit_state
                .map(|state| state.session_id.clone())
                .unwrap_or_default(),
            started: started.to_string(),
            ended: Some(ended.to_string()),
            command: command.to_vec(),
            executable_identity: executable_identity.clone(),
            tracked_paths,
            snapshot_count: manager.snapshot_count(),
            exit_code: Some(exit_code),
            merkle_roots,
            network_events: std::mem::take(&mut network_events),
            audit_event_count,
            audit_integrity: audit_integrity_summary.clone(),
            audit_attestation: audit_attestation_summary.clone(),
            rollback_status: RollbackStatus::Available,
        };
        manager.save_session_metadata(&meta)?;
        audit_saved = true;

        // BL-01 fix (27.2-REVIEW): when rollback snapshots live at a
        // different dir from audit-attestation bundles, mirror session.json
        // to the audit dir so `audit_session::load_session` finds combo
        // sessions by their audit-side ID. The audit-only branch below
        // already writes to `audit_state.session_dir` directly; this branch
        // covers the `--rollback --audit-integrity` combo case.
        if let Some(state) = audit_state {
            if state.rollback_dir.is_some() {
                nono::undo::SnapshotManager::write_session_metadata(&state.session_dir, &meta)?;
            }
        }

        if !changes.is_empty() {
            output::print_rollback_session_summary(&changes, silent);

            if !rollback_prompt_disabled && !silent {
                let _ = rollback_ui::review_and_restore(&manager, &baseline, &changes);
            }
        }

        let _ = manager.cleanup_new_atomic_temp_files(&atomic_temp_before);
    }

    // Audit-only path: no rollback snapshots, but still compute pre/post
    // merkle roots for tamper-evidence when audit snapshot state is
    // available (upstream 4ec61c29). The audit-integrity ledger summary is
    // populated alongside via `audit_event_count` / `audit_integrity_summary`.
    if !audit_saved {
        if let Some(audit_state) = audit_state {
            let (merkle_roots, tracked_paths) = match audit_snapshot_state {
                Some(snap) => {
                    let final_root = snap.manager.compute_merkle_root()?;
                    (vec![snap.baseline_root, final_root], snap.tracked_paths)
                }
                None => (Vec::new(), Vec::new()),
            };
            let meta = nono::undo::SessionMetadata {
                session_id: audit_state.session_id.clone(),
                started: started.to_string(),
                ended: Some(ended.to_string()),
                command: command.to_vec(),
                executable_identity,
                tracked_paths,
                snapshot_count: 0,
                exit_code: Some(exit_code),
                merkle_roots,
                network_events,
                audit_event_count,
                audit_integrity: audit_integrity_summary,
                audit_attestation: audit_attestation_summary,
                rollback_status,
            };
            nono::undo::SnapshotManager::write_session_metadata(&audit_state.session_dir, &meta)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_restore_error_display_names_failed_paths() {
        let err = PartialRestoreError {
            applied: vec![],
            failures: vec![(
                PathBuf::from("C:/project/locked.txt"),
                "The process cannot access the file because it is being used by another process"
                    .to_string(),
            )],
        };
        let msg = err.to_string();
        assert!(
            msg.contains("locked.txt"),
            "Error message should name the locked path, got: {msg}"
        );
        assert!(
            msg.contains("partial rollback"),
            "Error message should describe partial rollback, got: {msg}"
        );
    }

    #[test]
    fn partial_restore_error_counts() {
        let err = PartialRestoreError {
            applied: vec![],
            failures: vec![
                (PathBuf::from("a.txt"), "locked".to_string()),
                (PathBuf::from("b.txt"), "locked".to_string()),
            ],
        };
        let msg = err.to_string();
        assert!(
            msg.contains("2 file(s) failed"),
            "Should count 2 failures, got: {msg}"
        );
    }

    #[test]
    fn partial_restore_error_converts_to_nono_error() {
        let err = PartialRestoreError {
            applied: vec![],
            failures: vec![(PathBuf::from("x.txt"), "locked".to_string())],
        };
        let nono_err: NonoError = err.into();
        assert!(nono_err.to_string().contains("partial rollback"));
    }

    #[test]
    fn rollback_status_skipped_when_rollback_disabled() {
        // When rollback is not requested, status should be Skipped.
        let status = RollbackStatus::Skipped;
        assert!(!status.is_available());
        assert_eq!(status.display_label(), "audit-only");
    }

    #[test]
    fn rollback_status_failed_warning_only_records_reason() {
        let reason = "baseline capture failed: disk full".to_string();
        let status = RollbackStatus::FailedWarningOnly {
            reason: reason.clone(),
        };
        assert!(!status.is_available());
        assert_eq!(status.display_label(), "audit-only (capture failed)");

        // Verify serde round-trip preserves reason
        let json = serde_json::to_string(&status).expect("serialize");
        let parsed: RollbackStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, status);
    }
}
