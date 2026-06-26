use crate::audit_attestation::AuditSigner;
use crate::audit_integrity::AuditRecorder;
use crate::launch_runtime::{
    ProxyLaunchOptions, RollbackLaunchOptions, SessionLaunchOptions, TrustLaunchOptions,
};
use crate::rollback_runtime::{
    AuditState, RollbackExitContext, create_audit_state, finalize_supervised_exit,
    initialize_audit_snapshots, initialize_rollback_state, warn_if_rollback_flags_ignored,
};
use crate::{
    DETACHED_SESSION_ID_ENV, exec_strategy, output, protected_paths, pty_proxy, session,
    terminal_approval, trust_intercept,
};
use colored::Colorize;
use nono::undo::ExecutableIdentity;
use nono::{CapabilitySet, Result};
use std::io::IsTerminal;
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
    let audit_recorder = if audit_state.is_some() && !rollback.no_audit_integrity {
        audit_state
            .as_ref()
            .map(|state| {
                AuditRecorder::new_with_policy(state.session_dir.clone(), redaction_policy.clone())
                    .map(Mutex::new)
            })
            .transpose()?
    } else {
        None
    };
    let supervisor_network_audit_events = audit_state
        .as_ref()
        .map(|_| std::sync::Mutex::new(Vec::new()));
    if let Some(recorder_mutex) = audit_recorder.as_ref() {
        let mut recorder = recorder_mutex
            .lock()
            .map_err(|_| nono::NonoError::Snapshot("Audit recorder lock poisoned".to_string()))?;
        recorder.record_session_started(started.clone(), command.to_vec())?;
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
        audit_recorder: audit_recorder.as_ref(),
        network_audit_events: supervisor_network_audit_events.as_ref(),
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
        #[cfg(target_os = "linux")]
        unix_socket_allowlist: caps.unix_socket_capabilities(),
        #[cfg(target_os = "linux")]
        linux_network_notify_mode: if config.seccomp_proxy_fallback {
            exec_strategy::LinuxNetworkNotifyMode::ProxyOnly
        } else {
            exec_strategy::LinuxNetworkNotifyMode::AfUnixOnly
        },
    };

    // Resource enforcement: Linux cgroup v2. When a limit is requested, the leaf
    // is created pre-fork from those limits, or the run fails closed
    // (`CgroupLeaf::create` errors) if a delegated cgroup v2 subtree is
    // unavailable — we never run a requested limit unenforced. The child
    // self-attaches to the leaf (see `resource_procs_fd` below); dropping
    // `cgroup_leaf` tears it down.
    #[cfg(target_os = "linux")]
    let cgroup_leaf = match caps.resource_limits() {
        Some(limits) if !limits.is_empty() => {
            Some(crate::resource_cgroup::CgroupLeaf::create(limits)?)
        }
        _ => None,
    };

    // No cgroup enforcement off Linux yet — fail closed rather than run a
    // requested limit unprotected (macOS gets its own backend later).
    #[cfg(not(target_os = "linux"))]
    if caps
        .resource_limits()
        .is_some_and(|limits| !limits.is_empty())
    {
        return Err(nono::NonoError::SandboxInit(
            "resource: resource limits are only enforced on Linux (cgroup v2) in this build"
                .to_string(),
        ));
    }

    // The child self-attaches to the resource cgroup through this fd: it is
    // opened in the parent so the forked child inherits it and can cage itself
    // before it can fork/exec, closing the post-fork race that a parent-side
    // attach would leave open. The leaf (and thus the fd) lives until the end
    // of this function, where dropping it tears the cgroup down.
    #[cfg(target_os = "linux")]
    let resource_procs_fd = cgroup_leaf.as_ref().map(|leaf| leaf.procs_raw_fd());
    #[cfg(not(target_os = "linux"))]
    let resource_procs_fd: Option<std::os::fd::RawFd> = None;

    let exit_code = {
        // `on_fork` runs in the parent the instant the child is forked, with the
        // child's pid; we use it to record the pid on the session. The resource
        // cgroup attach is done by the child itself (see `resource_procs_fd`
        // above), not here, so there is no escape window to close from the parent.
        let mut on_fork = |child_pid: u32| {
            if let Some(ref mut guard) = session_guard {
                guard.set_child_pid(child_pid);
            }
        };

        // Post-mortem hook (Linux, and ONLY when a resource cgroup leaf exists).
        // If a memory cap was requested and the kernel OOM-killed the sandbox for
        // crossing it, the child comes back as a bare SIGKILL (exit 137) with no
        // explanation. Read the leaf's OOM evidence while it still exists and
        // print a precise diagnostic, so a cap breach is loud rather than silent.
        // Returning `true` suppresses the generic "killed by SIGKILL" footer.
        //
        // A run with no memory limit installs NO hook (`None`), so it takes the
        // exact pre-feature path with no per-run hook call at all.
        #[cfg(target_os = "linux")]
        let install_exit_diag = cgroup_leaf.is_some();
        #[cfg(target_os = "linux")]
        let mut on_exit_diag_fn = |code: i32| -> bool {
            // The diagnostic explains the bare SIGKILL the kernel delivers when
            // the whole sandbox is OOM-killed for crossing the cap (exit code
            // 128 + SIGKILL = 137). Only look at that exit: an unrelated failure
            // must not get a spurious "killed by the kernel" story, nor have its
            // real footer suppressed, just because an individual descendant was
            // OOM-reaped earlier in the run.
            const OOM_SIGKILL_EXIT: i32 = 128 + nix::libc::SIGKILL;
            if code != OOM_SIGKILL_EXIT {
                return false;
            }
            match cgroup_leaf.as_ref().and_then(|leaf| leaf.oom_report()) {
                Some(report) => {
                    crate::output::print_oom_diagnostic(&report, silent);
                    true
                }
                None => false,
            }
        };
        #[cfg(target_os = "linux")]
        let on_exit_diag: Option<&mut dyn FnMut(i32) -> bool> = if install_exit_diag {
            Some(&mut on_exit_diag_fn)
        } else {
            None
        };
        #[cfg(not(target_os = "linux"))]
        let on_exit_diag: Option<&mut dyn FnMut(i32) -> bool> = None;

        exec_strategy::execute_supervised(
            config,
            Some(&supervisor_cfg),
            trust_interceptor,
            Some(&mut on_fork),
            pty_pair,
            Some(&short_session_id),
            resource_procs_fd,
            on_exit_diag,
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
        audit_recorder: audit_recorder.as_ref(),
        supervisor_network_audit_events: supervisor_network_audit_events.as_ref(),
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
