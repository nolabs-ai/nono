use crate::audit_attestation::AuditSigner;
use crate::audit_integrity::AuditRecorder;
use crate::launch_runtime::{
    ProxyLaunchOptions, RollbackLaunchOptions, SessionLaunchOptions, TrustLaunchOptions,
};
use crate::rollback_runtime::{
    create_audit_state, finalize_supervised_exit, initialize_audit_snapshots,
    initialize_rollback_state, warn_if_rollback_flags_ignored, AuditState, RollbackExitContext,
};
use crate::{
    exec_strategy, output, protected_paths, pty_proxy, session, terminal_approval, trust_intercept,
    DETACHED_SESSION_ID_ENV,
};
use colored::Colorize;
use nono::undo::ExecutableIdentity;
use nono::{CapabilitySet, Result};
use std::io::IsTerminal;
use std::sync::{Arc, Mutex};

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
    pub(crate) session: &'a SessionLaunchOptions,
    pub(crate) rollback: &'a RollbackLaunchOptions,
    pub(crate) trust: &'a TrustLaunchOptions,
    pub(crate) proxy: &'a ProxyLaunchOptions,
    pub(crate) proxy_handle: Option<&'a nono_proxy::server::ProxyHandle>,
    pub(crate) executable_identity: Option<&'a ExecutableIdentity>,
    pub(crate) audit_signer: Option<&'a AuditSigner>,
    pub(crate) redaction_policy: &'a nono::ScrubPolicy,
    pub(crate) silent: bool,
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
                        "  {}",
                        format!(
                            "WARNING: Runtime instruction file verification disabled \
                         (pattern error: {e})"
                        )
                        .yellow()
                    );
                    None
                }
            }
        }
        None => None,
    }
}

fn create_session_runtime_state(
    command: &[String],
    caps: &CapabilitySet,
    session: &SessionLaunchOptions,
    audit_state: Option<&AuditState>,
    redaction_policy: &nono::ScrubPolicy,
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
        command: nono::scrub_argv_with_policy(command, redaction_policy),
        profile: session.profile_name.clone(),
        workdir: std::env::current_dir().unwrap_or_default(),
        network: match caps.network_mode() {
            nono::NetworkMode::Blocked => "blocked".to_string(),
            nono::NetworkMode::AllowAll => "allowed".to_string(),
            nono::NetworkMode::ProxyOnly { port, .. } => format!("proxy (localhost:{port})"),
        },
        rollback_session: audit_state.map(|state| state.session_id.clone()),
    };
    let session_guard = Some(session::SessionGuard::new(session_record)?);
    let pty_pair = if should_open_supervised_pty(
        session.detached_start,
        std::io::stdin().is_terminal(),
        std::io::stdout().is_terminal(),
        std::io::stderr().is_terminal(),
    ) {
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

fn should_open_supervised_pty(
    detached_start: bool,
    stdin_is_terminal: bool,
    stdout_is_terminal: bool,
    stderr_is_terminal: bool,
) -> bool {
    detached_start || (stdin_is_terminal && stdout_is_terminal && stderr_is_terminal)
}

pub(crate) fn execute_supervised_runtime(ctx: SupervisedRuntimeContext<'_>) -> Result<i32> {
    let SupervisedRuntimeContext {
        config,
        caps,
        command,
        session,
        rollback,
        trust,
        proxy,
        proxy_handle,
        executable_identity,
        audit_signer,
        redaction_policy,
        silent,
    } = ctx;

    output::print_applying_sandbox(silent);

    let audit_state = create_audit_state(rollback.audit_disabled, rollback.destination.as_ref())?;
    warn_if_rollback_flags_ignored(rollback, silent);

    // Create the session guard (writes session file) and PTY pair BEFORE
    // rollback initialization.  Rollback's baseline snapshot can take many
    // seconds on large repos.  In detached mode the launcher is polling for
    // the session file and attach socket — if we delay session registration
    // until after the baseline walk, the 30-second startup timeout can fire
    // before the session becomes attachable.
    let trust_interceptor = create_trust_interceptor(trust);
    let session_runtime = create_session_runtime_state(
        command,
        caps,
        session,
        audit_state.as_ref(),
        redaction_policy,
    )?;
    let SessionRuntimeState {
        started,
        short_session_id,
        mut session_guard,
        pty_pair,
    } = session_runtime;

    let audit_tracked_paths = crate::rollback_runtime::derive_audit_tracked_paths(caps);
    let rollback_state = initialize_rollback_state(rollback, caps, audit_state.as_ref(), silent)?;
    let audit_snapshot_state = if rollback_state.is_none() && rollback.audit_integrity {
        match audit_state.as_ref() {
            Some(state) => initialize_audit_snapshots(caps, state, rollback)?,
            None => None,
        }
    } else {
        None
    };
    let audit_recorder: Option<Arc<Mutex<AuditRecorder>>> = if audit_state.is_some()
        && !rollback.no_audit_integrity
    {
        audit_state
            .as_ref()
            .map(|state| {
                AuditRecorder::new_with_policy(state.session_dir.clone(), redaction_policy.clone())
                    .map(|r| Arc::new(Mutex::new(r)))
            })
            .transpose()?
    } else {
        None
    };
    if let Some(recorder_mutex) = audit_recorder.as_ref() {
        let mut recorder = recorder_mutex
            .lock()
            .map_err(|_| nono::NonoError::Snapshot("Audit recorder lock poisoned".to_string()))?;
        recorder.record_session_started(started.clone(), command.to_vec())?;
    }

    // Stream network audit events into the recorder as they occur. Without
    // this, events sit in the proxy's in-memory buffer until session exit and
    // are lost on crash or once `MAX_AUDIT_EVENTS` is reached.
    //
    // Streaming is best-effort: if the writer thread fails to spawn we log
    // and continue with the legacy "drain at session_ended" path rather than
    // aborting the run. The session still gets a complete audit log on
    // clean shutdown; only the crash-durability and unbounded-buffer wins
    // are forfeited.
    if let (Some(recorder_mutex), Some(handle)) = (audit_recorder.as_ref(), proxy_handle) {
        match crate::audit_integrity::RecorderStreamingSink::new(Arc::clone(recorder_mutex)) {
            Ok(sink) => {
                let sink: Arc<dyn nono_proxy::audit::NetworkAuditSink> = Arc::new(sink);
                if handle.set_audit_streaming_sink(sink).is_err() {
                    tracing::warn!(
                        "Network audit streaming sink already attached; refusing to overwrite"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to start network audit streaming writer; continuing without live \
                     streaming (events will still be drained at session end): {}",
                    e
                );
            }
        }
    }

    let protected_roots = protected_paths::ProtectedRoots::from_defaults()?;
    let approval_backend = terminal_approval::TerminalApproval;
    let supervisor_session_id = build_supervisor_session_id(audit_state.as_ref());
    let supervisor_cfg = exec_strategy::SupervisorConfig {
        protected_roots: protected_roots.as_paths(),
        approval_backend: &approval_backend,
        session_id: &supervisor_session_id,
        attach_initial_client: !session.detached_start,
        detach_sequence: session.detach_sequence.as_deref(),
        open_url_origins: &proxy.open_url_origins,
        open_url_allow_localhost: proxy.open_url_allow_localhost,
        audit_recorder: audit_recorder.as_deref(),
        redaction_policy,
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

    let exit_code = {
        let mut on_fork = |child_pid: u32| {
            if let Some(ref mut guard) = session_guard {
                guard.set_child_pid(child_pid);
            }
        };
        exec_strategy::execute_supervised(
            config,
            Some(&supervisor_cfg),
            trust_interceptor,
            Some(&mut on_fork),
            pty_pair,
            Some(&short_session_id),
        )?
    };
    if let Some(ref mut guard) = session_guard {
        guard.set_exited(exit_code);
    }
    let ended = chrono::Local::now().to_rfc3339();
    finalize_supervised_exit(RollbackExitContext {
        audit_state: audit_state.as_ref(),
        rollback_state,
        audit_snapshot_state,
        audit_tracked_paths,
        audit_recorder: audit_recorder.as_deref(),
        audit_integrity_enabled: !rollback.no_audit_integrity,
        proxy_handle,
        executable_identity,
        audit_signer,
        redaction_policy,
        started: &started,
        ended: &ended,
        command,
        exit_code,
        silent,
        rollback_prompt_disabled: rollback.prompt_disabled,
    })?;

    Ok(exit_code)
}

#[cfg(test)]
mod tests {
    use super::should_open_supervised_pty;

    #[test]
    fn supervised_pty_is_used_for_attached_terminals() {
        assert!(should_open_supervised_pty(false, true, true, true));
        assert!(!should_open_supervised_pty(false, false, true, true));
        assert!(!should_open_supervised_pty(false, true, false, true));
        assert!(!should_open_supervised_pty(false, true, true, false));
    }

    #[test]
    fn supervised_pty_is_always_used_for_detached_start() {
        assert!(should_open_supervised_pty(true, false, false, false));
    }
}
