use crate::audit_attestation::prepare_audit_signer;
use crate::audit_integrity::AuditRecorder;
use crate::launch_runtime::{
    ProxyLaunchOptions, ResourceLimits, RollbackLaunchOptions, SessionLaunchOptions,
    TrustLaunchOptions,
};
#[cfg(not(target_os = "windows"))]
use crate::protected_paths;
use crate::rollback_runtime::{
    create_audit_state, initialize_audit_snapshots, initialize_rollback_state,
    warn_if_rollback_flags_ignored, AuditState,
};
use crate::{
    exec_strategy, output, pty_proxy, session, terminal_approval, trust_intercept,
    DETACHED_SESSION_ID_ENV,
};
use nono::{CapabilitySet, Result};
use std::sync::Mutex;

struct SessionRuntimeState {
    started: String,
    short_session_id: String,
    session_guard: Option<session::SessionGuard>,
    pty_pair: Option<pty_proxy::PtyPair>,
}

pub(crate) struct SupervisedRuntimeContext<'a> {
    pub(crate) config: &'a exec_strategy::ExecConfig<'a>,
    pub(crate) caps: &'a CapabilitySet,
    pub(crate) command: &'a [String],
    pub(crate) capability_elevation: bool,
    pub(crate) session: &'a SessionLaunchOptions,
    pub(crate) rollback: &'a RollbackLaunchOptions,
    pub(crate) trust: &'a TrustLaunchOptions,
    pub(crate) proxy: &'a ProxyLaunchOptions,
    pub(crate) proxy_handle: Option<&'a nono_proxy::server::ProxyHandle>,
    /// AUD-03 SHA-256 portion (upstream 02ee0bd1): canonical path + SHA-256
    /// of the launched binary, computed in `execution_runtime` before
    /// sandbox apply. `None` for Direct/Monitor strategies.
    pub(crate) executable_identity: Option<&'a nono::undo::ExecutableIdentity>,
    pub(crate) silent: bool,
    /// Resource limits (CPU / memory / timeout / process-count) populated from
    /// `ExecutionFlags.resource_limits`. On Windows, Task 2 of Plan 16-01 will
    /// consume these via `apply_resource_limits`; Plan 16-02 Task 1 uses the
    /// `timeout` field for the supervisor-side wall-clock timer. On Unix this
    /// is read only by `warn_unix_resource_limits` at run start.
    pub(crate) resource_limits: &'a ResourceLimits,
    /// Plan 18.1-03 G-06: the loaded profile (if any) that resolves the
    /// per-handle-type AIPC allowlist widening. `None` means no profile →
    /// the Windows supervisor uses the hard-coded D-05 defaults only. This
    /// enables `nono run --profile <widened>` to actually consume the
    /// widened `capabilities.aipc` allowlist end-to-end at request-dispatch
    /// time. Unused on non-Windows per D-21 (kept non-cfg-gated so the
    /// cross-platform caller `execution_runtime.rs` does not need a
    /// conditional struct-literal).
    pub(crate) loaded_profile: Option<&'a crate::profile::Profile>,
}

fn build_supervisor_session_id(audit_state: Option<&AuditState>) -> String {
    audit_state
        .map(|state| state.session_id.clone())
        .unwrap_or_else(|| {
            format!(
                "supervised-{}-{}",
                std::process::id(),
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
            )
        })
}

fn create_trust_interceptor(
    trust: &TrustLaunchOptions,
) -> Option<trust_intercept::TrustInterceptor> {
    if !trust.interception_active {
        return None;
    }

    match trust.policy.clone() {
        Some(policy) => {
            match trust_intercept::TrustInterceptor::new(policy, trust.scan_root.clone()) {
                Ok(interceptor) => Some(interceptor),
                Err(e) => {
                    tracing::warn!("Trust interceptor pattern compilation failed: {e}");
                    eprintln!(
                        "  WARNING: Runtime instruction file verification disabled (pattern error: {e})"
                    );
                    None
                }
            }
        }
        None => None,
    }
}

/// Determine whether the supervised session should allocate a ConPTY/PTY pair.
///
/// Non-Windows: allocate when detached-start is requested (so the supervisor owns
/// a PTY the child writes into for `nono attach`) or when the caller asked for an
/// interactive PTY (`nono shell`).
///
/// Windows: allocate only for interactive sessions (`nono shell`). Detached supervisors
/// on Windows must not allocate a `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` because combining
/// it with `DETACHED_PROCESS` causes console-application grandchildren to exit with
/// `STATUS_DLL_INIT_FAILED (0xC0000142)`. See `.planning/debug/resolved/windows-supervised-exec-cascade.md`.
fn should_allocate_pty(session: &SessionLaunchOptions) -> bool {
    if cfg!(target_os = "windows") {
        session.interactive_pty
    } else {
        session.detached_start || session.interactive_pty
    }
}

fn create_session_runtime_state(
    command: &[String],
    caps: &CapabilitySet,
    session: &SessionLaunchOptions,
    audit_state: Option<&AuditState>,
    resource_limits: &crate::launch_runtime::ResourceLimits,
) -> Result<SessionRuntimeState> {
    let started = chrono::Local::now().to_rfc3339();
    let short_session_id = std::env::var(DETACHED_SESSION_ID_ENV)
        .ok()
        .filter(|id| !id.is_empty())
        .unwrap_or_else(session::generate_session_id);
    let session_record = session::SessionRecord {
        session_id: short_session_id.clone(),
        name: Some(
            session
                .session_name
                .clone()
                .unwrap_or_else(session::generate_random_name),
        ),
        supervisor_pid: std::process::id(),
        child_pid: 0,
        started: started.clone(),
        started_epoch: session::current_process_start_epoch(),
        status: session::SessionStatus::Running,
        attachment: if session.detached_start {
            session::SessionAttachment::Detached
        } else {
            session::SessionAttachment::Attached
        },
        exit_code: None,
        command: command.to_vec(),
        profile: session.profile_name.clone(),
        workdir: std::env::current_dir().unwrap_or_default(),
        network: match caps.network_mode() {
            nono::NetworkMode::Blocked => "blocked".to_string(),
            nono::NetworkMode::AllowAll => "allowed".to_string(),
            nono::NetworkMode::ProxyOnly { port, .. } => format!("proxy (localhost:{port})"),
        },
        job_object_name: if cfg!(target_os = "windows") {
            Some(format!(r"Local\nono-session-{}", short_session_id))
        } else {
            None
        },
        rollback_session: audit_state.map(|state| state.session_id.clone()),
        limits: session::ResourceLimitsRecord::from_resource_limits(resource_limits),
    };
    let session_guard = Some(session::SessionGuard::new(session_record)?);
    let pty_pair = if should_allocate_pty(session) {
        Some(pty_proxy::open_pty()?)
    } else {
        None
    };

    Ok(SessionRuntimeState {
        started,
        short_session_id,
        session_guard,
        pty_pair,
    })
}

pub(crate) fn execute_supervised_runtime(ctx: SupervisedRuntimeContext<'_>) -> Result<i32> {
    let SupervisedRuntimeContext {
        config,
        caps,
        command,
        capability_elevation,
        session,
        rollback,
        trust,
        proxy,
        proxy_handle,
        executable_identity,
        silent,
        resource_limits,
        loaded_profile,
    } = ctx;

    // Plan 18.1-03 G-06 wiring: UNION the hard-coded D-05 defaults with the
    // loaded profile's `capabilities.aipc` widening. No profile → pure
    // default (byte-identical to pre-fix behavior). `?` propagates
    // `NonoError::ProfileParse` if an unknown widening token reaches
    // runtime re-validation (should be prevented by
    // `validate_profile_aipc_tokens` at parse time — belt-and-braces
    // idempotent revalidation). The result is cheap to clone and is
    // consumed by the Windows `SupervisorConfig` literal below.
    let aipc_allowlist = match loaded_profile {
        Some(profile) => profile.resolve_aipc_allowlist()?,
        None => crate::profile::AipcResolvedAllowlist::default(),
    };
    // Silence unused warning on non-Windows where the field is not consumed
    // yet (D-21 Windows-only). The resolution call above still runs for its
    // `?` validation side-effect — cheap and consistent across platforms.
    #[cfg(not(target_os = "windows"))]
    let _ = &aipc_allowlist;

    // Emit per-flag "not enforced on this platform" warnings on Unix before any
    // spawn work. On Windows this is a no-op — Task 2 of Plan 16-01 applies the
    // kernel limits via `apply_resource_limits` inside `spawn_windows_child`.
    exec_strategy::warn_unix_resource_limits(resource_limits, silent);

    output::print_applying_sandbox(silent);

    let audit_state = create_audit_state(
        rollback.requested,
        rollback.disabled,
        rollback.audit_disabled,
        rollback.audit_integrity,
        rollback.destination.as_ref(),
    )?;
    warn_if_rollback_flags_ignored(rollback, silent);

    // Plan 22-05a Decision 5 minimal scope: instantiate the audit-integrity
    // recorder when --audit-integrity is set and an audit session was created.
    // The recorder lives for the lifetime of the supervised execution; its
    // session_started event is emitted here, the session_ended event +
    // finalize() are triggered in `finalize_supervised_exit` (called from
    // exec_strategy). Capability-decision and URL-open hooks are deferred to
    // follow-up cherry-picks (4ec61c29..9db06336). Mutex follows upstream
    // 4f9552ec to permit future concurrent emissions from the supervisor IPC
    // dispatcher without revisiting the ownership shape.
    // Phase 23 D-01: promote `Mutex<AuditRecorder>` to
    // `Arc<Mutex<AuditRecorder>>` so the recorder can cross the Windows
    // capability-pipe thread boundary (per 23-PATTERNS.md § 3b).
    // Cross-platform consumers see only the additional `Arc` wrapper
    // (D-21 invariance preserved).
    let audit_recorder = if rollback.audit_integrity {
        audit_state
            .as_ref()
            .map(|state| {
                AuditRecorder::new(state.session_dir.clone())
                    .map(|r| std::sync::Arc::new(Mutex::new(r)))
            })
            .transpose()?
    } else {
        None
    };

    // Plan 22-05a Task 7 (upstream 6ecade2e): when --audit-sign-key is set,
    // resolve the URI through the keystore (fail-closed if missing) and
    // hand the signer to `finalize_supervised_exit` via RollbackExitContext.
    let audit_signer = match rollback.audit_sign_key.as_deref() {
        Some(key_ref) if rollback.audit_integrity => Some(prepare_audit_signer(key_ref)?),
        _ => None,
    };
    let (rollback_state, rollback_status) =
        initialize_rollback_state(rollback, caps, audit_state.as_ref(), silent)?;

    // Upstream 4ec61c29: when rollback is not active but audit is, compute
    // a pre-execution merkle root so the audit trail has a cryptographic
    // commitment to filesystem state. The captured state is finalized via
    // `compute_merkle_root()` at session end inside `finalize_supervised_exit`.
    // Note: fork's `initialize_rollback_state` returns `(Option<state>, RollbackStatus)`
    // (vs upstream's `Option<state>`), so the gating uses `rollback_state.is_none()`
    // on the tuple's first element.
    let audit_snapshot_state = if rollback_state.is_none() {
        match audit_state.as_ref() {
            Some(state) => initialize_audit_snapshots(caps, state)?,
            None => None,
        }
    } else {
        None
    };

    // Shared Arc so both the synchronous Unix path (takes &dyn) and the
    // Windows capability pipe server thread (takes Arc<dyn +Send+Sync>)
    // can use the same backend instance. Plan 11-02 wires this on Windows.
    let approval_backend: std::sync::Arc<terminal_approval::TerminalApproval> =
        std::sync::Arc::new(terminal_approval::TerminalApproval);
    let supervisor_session_id = build_supervisor_session_id(audit_state.as_ref());
    #[cfg(not(target_os = "windows"))]
    let protected_roots = protected_paths::ProtectedRoots::from_defaults()?;
    #[cfg(not(target_os = "windows"))]
    let supervisor_cfg = exec_strategy::SupervisorConfig {
        protected_roots: protected_roots.as_paths(),
        approval_backend: approval_backend.as_ref(),
        session_id: &supervisor_session_id,
        attach_initial_client: !session.detached_start,
        detach_sequence: session.detach_sequence.as_deref(),
        open_url_origins: &proxy.open_url_origins,
        open_url_allow_localhost: proxy.open_url_allow_localhost,
        allow_launch_services_active: proxy.allow_launch_services_active,
        #[cfg(target_os = "linux")]
        proxy_port: match caps.network_mode() {
            nono::NetworkMode::ProxyOnly { port, .. } => *port,
            _ => 0,
        },
        #[cfg(target_os = "linux")]
        proxy_bind_ports: match caps.network_mode() {
            nono::NetworkMode::ProxyOnly { bind_ports, .. } => bind_ports.clone(),
            _ => Vec::new(),
        },
    };
    #[cfg(target_os = "windows")]
    let supervisor_cfg = exec_strategy::SupervisorConfig {
        session_id: &supervisor_session_id,
        requested_features: nono::Sandbox::windows_supervisor_support(
            nono::WindowsSupervisorContext {
                rollback_snapshots: rollback.requested && !rollback.disabled,
                proxy_filtering: proxy.active,
                runtime_capability_expansion: capability_elevation,
                runtime_trust_interception: trust.interception_active,
            },
        )
        .requested_feature_labels(),
        support: nono::Sandbox::windows_supervisor_support(nono::WindowsSupervisorContext {
            rollback_snapshots: rollback.requested && !rollback.disabled,
            proxy_filtering: proxy.active,
            runtime_capability_expansion: capability_elevation,
            runtime_trust_interception: trust.interception_active,
        }),
        // Plan 11-02: the Windows `SupervisorConfig.approval_backend` is an
        // owned `Arc<dyn ApprovalBackend + Send + Sync>` that the capability
        // pipe server thread clones into itself. `TerminalApproval` on
        // Windows now opens `\\.\CONIN$` (plan 11-02 Task 1) and
        // fail-secure denies when no console is attached.
        approval_backend: approval_backend.clone()
            as std::sync::Arc<dyn nono::ApprovalBackend + Send + Sync>,
        interactive_shell: session.interactive_pty && !session.detached_start,
        session_token: config.session_token.as_deref(),
        cap_pipe_rendezvous_path: config.cap_pipe_rendezvous_path.as_deref(),
        // Debug session `supervisor-pipe-access-denied`: thread the same
        // per-session restricting SID that `launch.rs` feeds into
        // `CreateRestrictedToken(..., WRITE_RESTRICTED, ..., &session_sid, ...)`
        // through to the capability pipe server's DACL so the child's
        // second-pass access check succeeds.
        session_sid: config.session_sid.clone(),
        // Phase 18.1 Plan 18.1-03 G-06: live profile-resolved allowlist.
        // UNION of hard-coded D-05 defaults with the loaded profile's
        // `capabilities.aipc` widening (via `Profile::resolve_aipc_allowlist`).
        // `None` profile → pure defaults (byte-identical pre-fix behavior).
        // The dispatcher's per-kind helpers consult this at mask / role /
        // direction validation time. End-to-end wiring closes G-06 and
        // resolves Plan 18-03 Deferred Issue #1.
        aipc_allowlist: aipc_allowlist.clone(),
    };

    let trust_interceptor = create_trust_interceptor(trust);
    let session_runtime = create_session_runtime_state(
        command,
        caps,
        session,
        audit_state.as_ref(),
        resource_limits,
    )?;
    let SessionRuntimeState {
        started,
        short_session_id,
        mut session_guard,
        pty_pair,
    } = session_runtime;

    // Plan 22-05a Decision 5 minimal scope: emit the session_started event
    // before handing off to `execute_supervised`. The matching session_ended
    // event is emitted from `finalize_supervised_exit` once the child has
    // exited (see `RollbackExitContext.audit_recorder`).
    if let Some(recorder_mutex) = audit_recorder.as_ref() {
        let mut recorder = recorder_mutex
            .lock()
            .map_err(|_| nono::NonoError::Snapshot("Audit recorder lock poisoned".to_string()))?;
        recorder.record_session_started(started.clone(), command.to_vec())?;
    }

    if !session.detached_start {
        output::finish_status_line_for_handoff(silent);
    }

    let exit_code = {
        let mut on_fork = |child_pid: u32| {
            if let Some(ref mut guard) = session_guard {
                guard.set_child_pid(child_pid);
            }
        };
        #[cfg(not(target_os = "windows"))]
        {
            exec_strategy::execute_supervised(
                config,
                Some(&supervisor_cfg),
                trust_interceptor,
                Some(&mut on_fork),
                pty_pair,
                Some(&short_session_id),
                audit_state,
                rollback_state,
                rollback_status,
                audit_recorder.as_ref(),
                audit_snapshot_state,
                executable_identity.cloned(),
                audit_signer.as_ref(),
                proxy_handle,
                command,
                &started,
                silent,
                rollback.prompt_disabled,
            )?
        }
        #[cfg(target_os = "windows")]
        {
            exec_strategy::execute_supervised(
                config,
                Some(&supervisor_cfg),
                trust_interceptor,
                Some(&mut on_fork),
                pty_pair,
                Some(&short_session_id),
                audit_state,
                rollback_state,
                rollback_status,
                audit_recorder.as_ref(),
                audit_snapshot_state,
                executable_identity.cloned(),
                audit_signer.as_ref(),
                proxy_handle,
                command,
                &started,
                silent,
                rollback.prompt_disabled,
                resource_limits,
            )?
        }
    };
    if let Some(ref mut guard) = session_guard {
        guard.set_exited(exit_code);
    }
    // Note: fork delegates `finalize_supervised_exit` to `execute_supervised`
    // (it's called from inside exec_strategy.rs / exec_strategy_windows/mod.rs
    // where the `audit_snapshot_state` is threaded via RollbackExitContext).
    // Upstream 4ec61c29 placed the finalize call here; in the fork the
    // audit_snapshot_state is forwarded through `execute_supervised` instead.

    Ok(exit_code)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session(detached: bool, interactive: bool) -> SessionLaunchOptions {
        SessionLaunchOptions {
            detached_start: detached,
            interactive_pty: interactive,
            ..SessionLaunchOptions::default()
        }
    }

    #[test]
    fn interactive_sessions_always_allocate_pty() {
        assert!(should_allocate_pty(&make_session(false, true)));
        assert!(should_allocate_pty(&make_session(true, true)));
    }

    #[test]
    fn non_detached_non_interactive_never_allocates_pty() {
        assert!(!should_allocate_pty(&make_session(false, false)));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_detached_supervisor_does_not_allocate_pty() {
        // Detached + non-interactive on Windows must skip PTY allocation to avoid
        // PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE + DETACHED_PROCESS → 0xC0000142.
        assert!(!should_allocate_pty(&make_session(true, false)));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn unix_detached_supervisor_allocates_pty() {
        // Unix supervisors still open a PTY in detached mode so attach-side clients
        // can read child output through the supervisor's PTY pair.
        assert!(should_allocate_pty(&make_session(true, false)));
    }
}
