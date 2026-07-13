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
    pub(crate) proxy: Option<&'a ProxyLaunchOptions>,
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
    let short_session_id = session
        .session_id
        .clone()
        .or_else(|| {
            std::env::var(DETACHED_SESSION_ID_ENV)
                .ok()
                .filter(|id| !id.is_empty())
        })
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

/// The error returned when a memory limit is requested on a platform that can't
/// enforce one (no cgroup v2). Compiled off-Linux (where the branch above uses it)
/// and under `test` so a Linux host can still pin the variant and message — the
/// branch can't run there, but the contract shouldn't silently regress.
#[cfg(any(not(target_os = "linux"), test))]
fn resource_limits_unsupported_platform() -> nono::NonoError {
    nono::NonoError::UnsupportedPlatform(
        "resource limits are only enforced on Linux (cgroup v2) in this build".to_string(),
    )
}

/// True only for the exit code a whole-sandbox OOM kill produces (128 + SIGKILL =
/// 137). Gating the memory-cap diagnostic on this keeps a clean exit, an ordinary
/// crash, or a different signal from borrowing the "out of memory" story.
#[cfg(target_os = "linux")]
const fn is_oom_sigkill_exit(exit_code: i32) -> bool {
    exit_code == 128 + nix::libc::SIGKILL
}

/// An "ordinary" failure exit: the program itself returned a non-zero code and was
/// NOT killed by a signal (signal deaths are `128 + signo`, i.e. `> 128`). This is the
/// only exit shape consistent with a refused `fork`/`clone` (EAGAIN) surfacing — a
/// clean exit (0) means the program recovered, and a signal death means something
/// *killed* the tree, which the pids cap never does. `128` itself is not a signal
/// death (e.g. git uses it for fatal errors), so it counts as an ordinary failure.
#[cfg(target_os = "linux")]
const fn is_ordinary_failure_exit(exit_code: i32) -> bool {
    exit_code > 0 && exit_code <= 128
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

    let audit_state = create_audit_state(
        rollback.audit_disabled,
        rollback.destination.as_ref(),
        session.session_id.as_deref(),
    )?;
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
    let audit_recorder = if audit_state.is_some() {
        audit_state
            .as_ref()
            .map(|state| {
                AuditRecorder::new_with_policy(state.session_dir.clone(), redaction_policy.clone())
                    .map(|recorder| Arc::new(Mutex::new(recorder)))
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
        #[cfg(target_os = "linux")]
        if let Some(tool_sandbox_runtime) = config.tool_sandbox_runtime {
            recorder.record_sandbox_runtime_event(
                crate::audit_integrity::SandboxRuntimeAuditEvent {
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    platform: "linux".to_string(),
                    landlock_abi: Some(tool_sandbox_runtime.landlock_abi_version().to_string()),
                    landlock_execute_enforced: Some(true),
                    tool_sandbox_active: true,
                },
            )?;
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
        open_url_origins: proxy
            .and_then(|p| p.open_url.as_ref())
            .map(|o| o.origins.as_slice())
            .unwrap_or(&[]),
        open_url_allow_localhost: proxy
            .and_then(|p| p.open_url.as_ref())
            .map(|o| o.allow_localhost)
            .unwrap_or(false),
        audit_recorder: audit_recorder.clone(),
        network_audit_events: supervisor_network_audit_events.as_ref(),
        redaction_policy,
        allow_launch_services_active: proxy
            .and_then(|p| p.open_url.as_ref())
            .map(|o| o.allow_launch_services)
            .unwrap_or(false),
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
        seccomp_policy: config.seccomp_policy,
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        tool_sandbox_runtime: config.tool_sandbox_runtime,
    };

    // Resource enforcement (Linux cgroup v2): a requested limit creates the leaf
    // pre-fork. With no delegated cgroup v2 subtree, `CgroupLeaf::create` errors and
    // the run fails closed rather than run the limit unenforced. The child
    // self-attaches (see `resource_procs_fd` below); dropping `cgroup_leaf` tears it
    // down.
    #[cfg(target_os = "linux")]
    let cgroup_leaf = match caps.resource_limits() {
        Some(limits) if !limits.is_empty() => Some(
            // Log the fail-closed path: a requested cap we couldn't set up aborts
            // the run rather than letting it proceed unenforced.
            crate::resource_cgroup::CgroupLeaf::create(limits).inspect_err(|e| {
                tracing::error!(
                    "resource: could not set up the memory cgroup; refusing to run unconfined: {e}"
                );
            })?,
        ),
        _ => None,
    };

    // No cgroup enforcement off Linux yet — fail closed rather than run a
    // requested limit unprotected (macOS gets its own backend later).
    #[cfg(not(target_os = "linux"))]
    if caps
        .resource_limits()
        .is_some_and(|limits| !limits.is_empty())
    {
        return Err(resource_limits_unsupported_platform());
    }

    // The fd the child self-attaches through: opened in the parent so the forked
    // child inherits it and cages itself before it can fork/exec — closing the
    // post-fork race a parent-side attach would leave open. The leaf (and fd) live
    // to the end of this function.
    #[cfg(target_os = "linux")]
    let resource_procs_fd = cgroup_leaf.as_ref().map(|leaf| leaf.procs_raw_fd());
    #[cfg(not(target_os = "linux"))]
    let resource_procs_fd: Option<std::os::fd::RawFd> = None;

    let exit_code = {
        // Runs in the parent the instant the child is forked, with the child's pid;
        // records it on the session. The cgroup attach is the child's own job (see
        // `resource_procs_fd` above), so there's no parent-side escape window here.
        let mut on_fork = |child_pid: u32| {
            if let Some(ref mut guard) = session_guard {
                guard.set_child_pid(child_pid);
            }
        };

        // Post-mortem hook, installed only when a resource cgroup leaf exists. It reads
        // the leaf's kernel evidence and prints a precise diagnostic, so a resource
        // breach is loud, not silent. Returning `true` means "I explained this exit" and
        // suppresses the generic path-permissions footer; it never changes the exit code.
        #[cfg(target_os = "linux")]
        let on_exit_diag_fn = |code: i32| -> bool {
            // Memory path: an OOM kill arrives as a bare SIGKILL (exit 137) with no
            // explanation. Only 137 counts — a crash (139) or SIGTERM (143) must not
            // borrow the "out of memory" story. Explain it only if we can prove the kill.
            if is_oom_sigkill_exit(code)
                && let Some(report) = cgroup_leaf.as_ref().and_then(|leaf| leaf.oom_report())
            {
                crate::output::print_oom_diagnostic(&report, silent);
                return true;
            }
            // Process-cap path: a pids breach kills nothing — the offending fork just
            // returns EAGAIN, which the program surfaces as an ordinary non-zero exit.
            // Its cumulative `max` counter only proves the cap was touched, not that it
            // caused THIS exit, so we surface it (phrased as "may explain") solely on an
            // ordinary failure exit — never on a clean or signal-killed run.
            if is_ordinary_failure_exit(code)
                && let Some(report) = cgroup_leaf.as_ref().and_then(|leaf| leaf.pids_report())
            {
                crate::output::print_pids_diagnostic(&report, silent);
                return true;
            }
            false
        };
        // No leaf, no hook (`None`) — the exact pre-feature path.
        #[cfg(target_os = "linux")]
        let on_exit_diag = cgroup_leaf.is_some().then_some(on_exit_diag_fn);
        #[cfg(not(target_os = "linux"))]
        let on_exit_diag: Option<fn(i32) -> bool> = None;

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
        audit_recorder: audit_recorder.as_deref(),
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

    /// Off-Linux, a requested memory limit is refused with UnsupportedPlatform (not
    /// SandboxInit), so it maps to the right diagnostic/exit and reads naturally.
    /// Pinned on every host so the variant can't silently regress, even though the
    /// branch that returns it only compiles off-Linux.
    #[test]
    fn off_platform_resource_error_is_unsupported_platform() {
        let err = super::resource_limits_unsupported_platform();
        assert!(matches!(err, nono::NonoError::UnsupportedPlatform(_)));
        assert!(err.to_string().contains("only enforced on Linux"));
    }

    /// The memory-cap diagnostic fires only on exit 137 (the whole-sandbox OOM
    /// kill). Pins that a clean exit, an ordinary crash (SIGSEGV -> 139), or a
    /// SIGTERM (-> 143) is NOT mistaken for an out-of-memory kill. (The other half
    /// of the gate — a watchdog-timeout SIGKILL, also 137, suppressed via
    /// !killed_by_timeout — lives in exec_strategy and is covered by review.)
    #[test]
    #[cfg(target_os = "linux")]
    fn only_exit_137_is_treated_as_an_oom_kill() {
        use super::is_oom_sigkill_exit;
        assert!(is_oom_sigkill_exit(137), "128 + SIGKILL(9) = 137");
        assert!(!is_oom_sigkill_exit(0), "clean exit is not an OOM kill");
        assert!(
            !is_oom_sigkill_exit(1),
            "ordinary failure is not an OOM kill"
        );
        assert!(
            !is_oom_sigkill_exit(139),
            "SIGSEGV crash (128+11) is not an OOM kill"
        );
        assert!(
            !is_oom_sigkill_exit(143),
            "SIGTERM (128+15) is not an OOM kill"
        );
    }

    /// The pids-cap diagnostic is surfaced only on an ordinary failure exit: a clean
    /// exit means the program recovered from the EAGAIN, and a signal death means the
    /// tree was killed (which the pids cap never does). `128` counts as ordinary (git
    /// uses it for fatal errors); `> 128` is a signal death.
    #[test]
    #[cfg(target_os = "linux")]
    fn only_an_ordinary_failure_exit_is_blamed_on_the_pids_cap() {
        use super::is_ordinary_failure_exit;
        assert!(
            is_ordinary_failure_exit(1),
            "a plain non-zero exit could be a refused fork surfacing"
        );
        assert!(
            is_ordinary_failure_exit(128),
            "128 (e.g. git fatal) is an ordinary failure, not a signal death"
        );
        assert!(
            !is_ordinary_failure_exit(0),
            "a clean exit means the program recovered from EAGAIN"
        );
        assert!(
            !is_ordinary_failure_exit(137),
            "SIGKILL (128+9) killed the tree; the pids cap never kills"
        );
        assert!(
            !is_ordinary_failure_exit(143),
            "SIGTERM (128+15) is a kill, not a fork failure"
        );
    }

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
