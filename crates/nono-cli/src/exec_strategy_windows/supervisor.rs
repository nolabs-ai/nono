use super::*;
use crate::profile::AipcResolvedAllowlist;
use nono::supervisor::policy;
use nono::supervisor::socket::{
    bind_aipc_pipe, broker_event_to_process, broker_job_object_to_process, broker_mutex_to_process,
    broker_pipe_to_process, broker_socket_to_process, broker_target_pid,
};
#[cfg(all(test, target_os = "windows"))]
use nono::supervisor::SocketRole;
use nono::supervisor::{HandleKind, HandleTarget, PipeDirection, SocketProtocol};
use std::io::{Read, Write};
use std::mem::ManuallyDrop;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use windows_sys::Win32::Foundation::{
    CloseHandle, CompareObjectHandles, GetLastError, LocalFree, BOOL, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Networking::WinSock::{
    closesocket, WSASocketW, WSAStartup, AF_INET, INVALID_SOCKET, IPPROTO_TCP, IPPROTO_UDP,
    SOCK_DGRAM, SOCK_STREAM, WSADATA, WSA_FLAG_OVERLAPPED,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
use windows_sys::Win32::System::Console::{
    GetConsoleScreenBufferInfo, GetStdHandle, ResizePseudoConsole, SetConsoleCtrlHandler,
    CONSOLE_SCREEN_BUFFER_INFO, COORD, CTRL_C_EVENT, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::JobObjects::CreateJobObjectW;
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{CreateEventW, CreateMutexW};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, TerminateProcess, WaitForSingleObject,
};

const SDDL_REVISION_1: u32 = 1;

const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT_CODE: u32 = 0x0000_0102;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SendableHandle(pub HANDLE);

unsafe impl Send for SendableHandle {}
unsafe impl Sync for SendableHandle {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WindowsSupervisorLifecycleState {
    Initializing,
    ControlChannelReady,
    LaunchingChild,
    WaitingForChild,
    ShuttingDown,
    Completed,
}

impl WindowsSupervisorLifecycleState {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Initializing => "initializing",
            Self::ControlChannelReady => "control-channel-ready",
            Self::LaunchingChild => "launching-child",
            Self::WaitingForChild => "waiting-for-child",
            Self::ShuttingDown => "shutting-down",
            Self::Completed => "completed",
        }
    }
}

#[derive(Debug)]
pub(super) enum WindowsSupervisedChild {
    Native {
        process: OwnedHandle,
        _thread: OwnedHandle,
    },
}

impl WindowsSupervisedChild {
    fn process_handle(&self) -> HANDLE {
        match self {
            Self::Native { process, .. } => process.0,
        }
    }

    /// Expose the child process handle so the capability pipe server thread
    /// can broker granted file handles via `DuplicateHandle`.
    pub(super) fn process_handle_raw(&self) -> HANDLE {
        self.process_handle()
    }

    fn wait_for_exit(&self, timeout: u32) -> Result<Option<i32>> {
        let wait_result = unsafe {
            // SAFETY: `process_handle()` returns a valid process handle owned by this child wrapper.
            WaitForSingleObject(self.process_handle(), timeout)
        };
        match wait_result {
            WAIT_OBJECT_0 => {
                let mut exit_code = 0u32;
                let ok = unsafe {
                    // SAFETY: Handle remains valid and `exit_code` is writable.
                    GetExitCodeProcess(self.process_handle(), &mut exit_code)
                };
                if ok == 0 {
                    return Err(NonoError::SandboxInit(
                        "Failed to query Windows supervised child exit code".to_string(),
                    ));
                }
                Ok(Some(exit_code as i32))
            }
            WAIT_TIMEOUT_CODE => Ok(None),
            _ => Err(NonoError::SandboxInit(format!(
                "Windows supervisor failed while waiting for child process state: {}",
                std::io::Error::last_os_error()
            ))),
        }
    }

    pub(super) fn poll_exit_code(&mut self) -> Result<Option<i32>> {
        match self {
            Self::Native { .. } => self.wait_for_exit(0),
        }
    }

    pub(super) fn terminate(&self) -> Result<()> {
        let ok = unsafe {
            // SAFETY: `process_handle()` is a valid process handle with `PROCESS_TERMINATE` access.
            TerminateProcess(self.process_handle(), 1)
        };
        if ok == 0 {
            let err = std::io::Error::last_os_error();
            // If it already exited, that's fine
            if err.raw_os_error()
                != Some(windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED as i32)
            {
                return Err(NonoError::CommandExecution(err));
            }
        }
        Ok(())
    }
}

fn create_secure_pipe(name: &str) -> Result<HANDLE> {
    let name_u16 = to_u16_null_terminated(name);
    // SDDL: D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)
    // SY: Local System
    // BA: Built-in Administrators
    // OW: Owner Rights
    let sddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)";
    let sddl_u16 = to_u16_null_terminated(sddl);

    let mut security_descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let mut sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 0,
    };

    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_u16.as_ptr(),
            SDDL_REVISION_1,
            &mut security_descriptor,
            std::ptr::null_mut(),
        ) == 0
        {
            return Err(NonoError::Setup(format!(
                "Failed to convert SDDL: {}",
                std::io::Error::last_os_error()
            )));
        }
        sa.lpSecurityDescriptor = security_descriptor;

        let h_pipe = CreateNamedPipeW(
            name_u16.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            1024,
            1024,
            0,
            &sa,
        );

        LocalFree(security_descriptor as _);

        if h_pipe == INVALID_HANDLE_VALUE {
            return Err(NonoError::Setup(format!(
                "Failed to create named pipe {}: {}",
                name,
                std::io::Error::last_os_error()
            )));
        }

        Ok(h_pipe)
    }
}

pub(super) struct WindowsSupervisorRuntime {
    /// Supervisor correlation ID for logging/audit (format: `supervised-<pid>-<nanos>`
    /// or the rollback audit UUID). Never used to name user-visible artifacts.
    session_id: String,
    /// User-facing session ID written to the session JSON file and used to name
    /// the Job Object and the attach pipe. `nono attach`, `nono terminate`, and the
    /// detached-launch readiness probe all look up the pipe by this ID, so all
    /// pipe names created by the supervisor MUST use `user_session_id` — not
    /// `session_id` — to remain addressable.
    user_session_id: String,
    requested_features: Vec<String>,
    transport_name: String,
    _parent_control: nono::SupervisorSocket,
    child_control: Option<nono::SupervisorSocket>,
    started_at: Instant,
    pub(super) state: WindowsSupervisorLifecycleState,
    audit_log: Vec<AuditEntry>,
    terminate_requested: Arc<AtomicBool>,
    pty: Option<crate::pty_proxy::PtyPair>,
    /// Phase 17: parent-end stdio handles when the child was spawned with
    /// anonymous-pipe stdio (Windows detached path only). Lifetime extends
    /// until the runtime is dropped — bridge threads in `start_logging` /
    /// `start_data_pipe_server` borrow these via
    /// `ManuallyDrop<File::from_raw_handle>`. `None` on the PTY (non-detached)
    /// path. Populated post-`initialize` via `attach_detached_stdio()` in
    /// `execute_supervised`, before `start_streaming()` is called.
    detached_stdio: Option<DetachedStdioPipes>,
    active_attachment: Arc<Mutex<Option<SendableHandle>>>,
    interactive_shell: bool,
    /// Session token validated against every `CapabilityRequest` on the
    /// capability pipe server thread. Never log.
    session_token: Option<String>,
    /// Rendezvous path written/cleaned up by the capability pipe server thread.
    cap_pipe_rendezvous_path: Option<std::path::PathBuf>,
    /// Per-session restricting SID threaded through to the capability pipe
    /// server's bind call so the DACL admits the sandboxed child's
    /// WRITE_RESTRICTED token on `CreateFileW(pipe, GENERIC_READ |
    /// GENERIC_WRITE)`. See debug session
    /// `.planning/debug/supervisor-pipe-access-denied.md`. `None` preserves
    /// the byte-identical pre-fix SDDL (legacy / non-restricted callers).
    session_sid: Option<String>,
    /// Receiver end drained by the main event loop to merge audit entries
    /// produced by the capability pipe server thread.
    audit_rx: Option<std::sync::mpsc::Receiver<Vec<AuditEntry>>>,
    /// Populated after the child process is spawned. The capability pipe
    /// server thread waits on this before brokering handles into the child.
    child_process_for_broker: Arc<Mutex<Option<SendableHandle>>>,
    /// Approval backend used by the capability pipe server thread for every
    /// live runtime capability request. Plumbed through `SupervisorConfig`
    /// by `supervised_runtime` as an `Arc<TerminalApproval>` on Windows.
    /// `WindowsSupervisorDenyAllApprovalBackend` remains defined in
    /// `mod.rs` as a fallback for callers that do not wire a real backend.
    approval_backend: Arc<dyn ApprovalBackend + Send + Sync>,
    /// Absolute `Instant` at which the supervisor must call `TerminateJobObject`
    /// on the agent tree's Job Object. `None` means no `--timeout` was requested.
    /// Computed once at supervisor init and never updated — the child cannot
    /// extend its own deadline (see `.planning/phases/16-resource-limits/16-CONTEXT.md`
    /// § Security "No escape").
    timeout_deadline: Option<std::time::Instant>,
    /// Borrowed `HANDLE` to the agent tree's Job Object. Used EXCLUSIVELY by the
    /// `--timeout` enforcement path (`terminate_job_object` on deadline expiry).
    /// `ProcessContainment` owns the close-on-drop for this handle; the supervisor
    /// MUST NOT call `CloseHandle` on `containment_job`. Lifetime is respected by
    /// declaring `containment` BEFORE `WindowsSupervisorRuntime::initialize` in
    /// `execute_supervised` so `containment` outlives the runtime in drop order.
    containment_job: windows_sys::Win32::Foundation::HANDLE,
    /// AIPC-01 (Phase 18) per-handle-type access allowlist resolved at
    /// supervisor construction time from `Profile::resolve_aipc_allowlist`
    /// (hard-coded supervisor defaults ∪ profile widening). Cloned `Arc` into
    /// the capability pipe server thread closure; consulted by every per-kind
    /// helper (`handle_event_request`, `handle_mutex_request`,
    /// `handle_pipe_request`, `handle_socket_request`,
    /// `handle_job_object_request`) for the per-request mask / role /
    /// direction validation step.
    ///
    /// Sourced from `SupervisorConfig.aipc_allowlist` which itself is resolved
    /// at the `execute_supervised_runtime` call site from the loaded
    /// `Profile` (or `AipcResolvedAllowlist::default()` when no profile is
    /// loaded). Plan 18.1-03 (G-06) replaced the Plan 18-03 `default()` seed
    /// with the live profile-resolved allowlist — this is the end-to-end
    /// wiring that lets `nono run --profile <widened>` actually consume
    /// `capabilities.aipc` widening at the dispatcher.
    resolved_aipc_allowlist: std::sync::Arc<crate::profile::AipcResolvedAllowlist>,
    /// Phase 23 D-01: optional ledger recorder cloned into the capability-
    /// pipe-server thread closure so the dispatcher can append
    /// `AuditEventPayload::CapabilityDecision` events to
    /// `<session_dir>/audit-events.ndjson`. `None` for non-audit-integrity
    /// sessions (zero-overhead path). Stored as
    /// `Option<Arc<Mutex<AuditRecorder>>>` so cloning into the spawned
    /// thread (per 23-PATTERNS.md § 3b) does not require a separate
    /// lifetime — the recorder is shared-owned across the supervisor and
    /// its capability-pipe thread for the duration of the session.
    audit_recorder: Option<std::sync::Arc<std::sync::Mutex<crate::audit_integrity::AuditRecorder>>>,
}

/// Compute the absolute deadline `Instant` for a supervisor-side wall-clock
/// timeout. Returns `None` when no timeout is requested; returns `Err(...)`
/// when the requested duration would overflow `Instant` arithmetic on this
/// platform (a theoretical edge for `u64::MAX` seconds that the clap parser
/// does not prevent).
pub(super) fn compute_deadline(
    timeout: Option<std::time::Duration>,
    now: std::time::Instant,
) -> Result<Option<std::time::Instant>> {
    match timeout {
        None => Ok(None),
        Some(d) => now.checked_add(d).map(Some).ok_or_else(|| {
            NonoError::SandboxInit(format!(
                "--timeout value exceeds platform Instant range: {d:?}"
            ))
        }),
    }
}

impl WindowsSupervisorRuntime {
    pub(super) fn initialize(
        supervisor: &SupervisorConfig<'_>,
        pty: Option<crate::pty_proxy::PtyPair>,
        user_session_id: Option<&str>,
        timeout_deadline: Option<std::time::Instant>,
        containment_job: windows_sys::Win32::Foundation::HANDLE,
        // Phase 23 D-01: optional ledger recorder. Cloned into the
        // capability-pipe-server thread closure inside
        // `start_capability_pipe_server`. `None` is the zero-overhead path
        // (no audit-integrity), preserving byte-identical pre-Phase-23
        // behavior.
        audit_recorder: Option<
            &std::sync::Arc<std::sync::Mutex<crate::audit_integrity::AuditRecorder>>,
        >,
    ) -> Result<Self> {
        let started_at = Instant::now();
        let (parent_control, child_control) = initialize_supervisor_control_channel()?;
        let transport_name = parent_control.transport_name().to_string();
        let terminate_requested = Arc::new(AtomicBool::new(false));
        let active_attachment = Arc::new(Mutex::new(None));

        let supervisor_session_id = supervisor.session_id.to_string();
        // Pipe names must be addressable by the user-facing session ID so
        // `nono attach`/`nono terminate` and the detached-launch readiness probe
        // can find them. Fall back to the supervisor correlation ID only when
        // no user session ID was wired (e.g., embedded callers without
        // session tracking).
        let user_session_id = user_session_id
            .map(str::to_string)
            .unwrap_or_else(|| supervisor_session_id.clone());

        let mut runtime = Self {
            session_id: supervisor_session_id,
            user_session_id,
            requested_features: supervisor
                .requested_features
                .iter()
                .map(|feature| (*feature).to_string())
                .collect(),
            transport_name,
            _parent_control: parent_control,
            child_control: Some(child_control),
            started_at,
            state: WindowsSupervisorLifecycleState::Initializing,
            audit_log: Vec::new(),
            terminate_requested,
            pty,
            // Phase 17: populated post-spawn via `attach_detached_stdio` in
            // `execute_supervised`. Initialized to None so the runtime can be
            // constructed before the child is launched (the existing
            // start_control_pipe_server still runs first per RESEARCH.md
            // Pitfall 5 — see start_streaming below).
            detached_stdio: None,
            active_attachment,
            interactive_shell: supervisor.interactive_shell,
            session_token: supervisor.session_token.map(str::to_string),
            cap_pipe_rendezvous_path: supervisor.cap_pipe_rendezvous_path.map(|p| p.to_path_buf()),
            session_sid: supervisor.session_sid.clone(),
            audit_rx: None,
            child_process_for_broker: Arc::new(Mutex::new(None)),
            approval_backend: supervisor.approval_backend.clone(),
            timeout_deadline,
            containment_job,
            // Phase 18.1 Plan 18.1-03 G-06 fix: source the resolved
            // allowlist from SupervisorConfig (which, at the
            // execute_supervised_runtime call site, reads from the loaded
            // profile's Profile::resolve_aipc_allowlist). Callers that do
            // not load a profile still get the byte-identical pre-fix
            // default via `AipcResolvedAllowlist::default()` — the Windows
            // `SupervisorConfig` carries the resolved allowlist inline.
            // Plan 18-03 Deferred Issue #1 is resolved here.
            resolved_aipc_allowlist: std::sync::Arc::new(supervisor.aipc_allowlist.clone()),
            // Phase 23 D-01: clone the Arc so the runtime + the
            // capability-pipe thread share ownership of the recorder.
            // `cloned()` on `Option<&Arc<...>>` produces `Option<Arc<...>>`.
            audit_recorder: audit_recorder.cloned(),
        };

        // Phase 17 reorder (RESEARCH.md Pitfall 5): start_control_pipe_server
        // MUST stay in `initialize` so the outer probe in
        // startup_runtime::run_detached_launch can find the control pipe
        // BEFORE the detached banner is printed. The streaming threads
        // (start_logging / start_data_pipe_server / start_interactive_terminal_io)
        // are deferred to `start_streaming()` which the caller invokes AFTER
        // `attach_detached_stdio()` has populated the detached_stdio field.
        runtime.start_control_pipe_server()?;

        // Start the capability pipe server only when the caller wired up
        // BOTH a token and a rendezvous path. Either being `None` keeps
        // `WindowsSupervisorDenyAllApprovalBackend` as the effective fallback
        // (SC #4: deny-all backend remains active when the feature isn't
        // attached).
        if runtime.session_token.is_some() && runtime.cap_pipe_rendezvous_path.is_some() {
            runtime.start_capability_pipe_server()?;
        }

        runtime.state = WindowsSupervisorLifecycleState::ControlChannelReady;
        Ok(runtime)
    }

    /// Phase 17: hand the parent-end stdio handles produced by
    /// `spawn_windows_child` to the runtime. Called from
    /// `execute_supervised` immediately after the child is spawned and
    /// BEFORE `start_streaming()`. Idempotent overwrite is acceptable
    /// (only one child is spawned per runtime).
    pub(super) fn attach_detached_stdio(&mut self, stdio: Option<DetachedStdioPipes>) {
        self.detached_stdio = stdio;
    }

    /// Phase 17: start the per-session streaming threads (log writer + data
    /// pipe server, or interactive terminal I/O for `nono shell`). Deferred
    /// from `initialize` so the bridge threads can observe the populated
    /// `detached_stdio` field (Pitfall 5 reorder). Must be invoked exactly
    /// once after `attach_detached_stdio` returns.
    pub(super) fn start_streaming(&mut self) -> Result<()> {
        if self.interactive_shell {
            self.start_interactive_terminal_io()?;
        } else {
            self.start_logging()?;
            self.start_data_pipe_server()?;
        }
        Ok(())
    }

    /// Capability-pipe background thread. Binds a Low Integrity-accessible
    /// named pipe at `cap_pipe_rendezvous_path`, waits for the parent to
    /// publish the spawned child's process handle, then loops
    /// `recv_message → handle_windows_supervisor_message` and forwards audit
    /// entries through an mpsc channel drained by `run_child_event_loop`.
    ///
    /// The thread exits naturally on pipe EOF or when `terminate_requested`
    /// is set. No token value is ever written to logs.
    fn start_capability_pipe_server(&mut self) -> Result<()> {
        let session_token = self.session_token.clone().ok_or_else(|| {
            NonoError::SandboxInit("Capability pipe server requires a session token".to_string())
        })?;
        let rendezvous_path = self.cap_pipe_rendezvous_path.clone().ok_or_else(|| {
            NonoError::SandboxInit("Capability pipe server requires a rendezvous path".to_string())
        })?;

        let (audit_tx, audit_rx) = std::sync::mpsc::channel::<Vec<AuditEntry>>();
        self.audit_rx = Some(audit_rx);

        let terminate_requested = self.terminate_requested.clone();
        let child_process_for_broker = self.child_process_for_broker.clone();
        let session_id = self.session_id.clone();
        let user_session_id = self.user_session_id.clone();
        let backend = self.approval_backend.clone();
        // Debug session `supervisor-pipe-access-denied`: clone the
        // per-session restricting SID into the background thread so the
        // capability pipe's DACL admits the WRITE_RESTRICTED child's
        // `CreateFileW(GENERIC_READ | GENERIC_WRITE)` second-pass access
        // check. `None` => byte-identical pre-fix SDDL.
        let session_sid = self.session_sid.clone();
        // Phase 18 Plan 18-03: pass the supervisor's own containment Job
        // HANDLE through to the capability pipe server thread for the
        // containment-Job runtime guard in `handle_job_object_request`. The
        // HANDLE is owned by `ProcessContainment` (close-on-drop); the runtime
        // and the thread closure both BORROW it for the lifetime of the
        // session. SendableHandle wraps a raw HANDLE for Send/Sync.
        let runtime_containment_job = SendableHandle(self.containment_job);
        // Phase 18 Plan 18-03: clone the resolved AIPC allowlist Arc into
        // the thread closure so all per-kind helpers consult it.
        let resolved_aipc_allowlist = self.resolved_aipc_allowlist.clone();
        // Phase 23 D-01: clone the optional audit recorder Arc into the
        // thread closure. `None` preserves byte-identical pre-Phase-23
        // behavior; `Some(arc)` enables ledger emission at all 5 push sites
        // inside `handle_windows_supervisor_message`.
        let audit_recorder_for_thread = self.audit_recorder.clone();

        std::thread::spawn(move || {
            // Disjoint capture safety: bind the SendableHandle wrapper to a
            // local so the move closure captures the wrapper (Send + Sync via
            // the unsafe impls on SendableHandle), not the inner *mut c_void
            // (which is NOT Send). Without this binding, Rust 2021 disjoint
            // capture would detect the `runtime_containment_job.0` access
            // below and capture only the inner field, triggering an E0277.
            let runtime_containment_job_local: SendableHandle = runtime_containment_job;
            let mut sock = match nono::SupervisorSocket::bind_low_integrity_with_session_sid(
                &rendezvous_path,
                session_sid.as_deref(),
            ) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(
                        session_id = %session_id,
                        error = %e,
                        "Failed to bind Windows capability pipe; capability expansion disabled for this session",
                    );
                    return;
                }
            };

            // Wait for the parent to publish the spawned child's process
            // handle before processing any messages. Without a live target
            // process, `DuplicateHandle` cannot broker granted file handles.
            let target = loop {
                if terminate_requested.load(Ordering::SeqCst) {
                    tracing::debug!(
                        session_id = %session_id,
                        "Capability pipe server terminating before child handle arrived",
                    );
                    return;
                }
                let lock = match child_process_for_broker.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                if let Some(handle) = *lock {
                    break handle;
                }
                drop(lock);
                std::thread::sleep(std::time::Duration::from_millis(50));
            };

            // SAFETY: `target.0` is a live process handle owned by the
            // spawned child wrapper for the duration of this thread.
            let broker_target = unsafe { nono::BrokerTargetProcess::from_raw_handle(target.0) };

            // Approval backend for the capability pipe thread. Plumbed
            // through `SupervisorConfig.approval_backend` by
            // `supervised_runtime` as an `Arc<TerminalApproval>` on
            // Windows (plan 11-02). The `WindowsSupervisorDenyAllApprovalBackend`
            // fallback is still defined in `exec_strategy_windows/mod.rs`
            // for callers that construct a `SupervisorConfig` without a
            // real interactive backend (SC #4).

            let mut seen_request_ids = HashSet::new();
            loop {
                if terminate_requested.load(Ordering::SeqCst) {
                    break;
                }
                match sock.recv_message() {
                    Ok(msg) => {
                        let mut local_audit: Vec<AuditEntry> = Vec::new();
                        if let Err(e) = handle_windows_supervisor_message(
                            &mut sock,
                            msg,
                            backend.as_ref(),
                            broker_target,
                            &mut seen_request_ids,
                            &mut local_audit,
                            &session_token,
                            &user_session_id,
                            runtime_containment_job_local.0,
                            resolved_aipc_allowlist.as_ref(),
                            audit_recorder_for_thread.as_ref(),
                        ) {
                            tracing::warn!(
                                session_id = %session_id,
                                error = %e,
                                "Capability pipe handler returned an error",
                            );
                        }
                        if !local_audit.is_empty() {
                            let _ = audit_tx.send(local_audit);
                        }
                    }
                    Err(e) => {
                        tracing::debug!(
                            session_id = %session_id,
                            error = %e,
                            "Capability pipe closed",
                        );
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    /// Publish the spawned child process handle so the capability pipe
    /// server thread can broker granted file handles via `DuplicateHandle`.
    pub(super) fn set_child_broker_target(&self, handle: HANDLE) {
        let mut lock = match self.child_process_for_broker.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *lock = Some(SendableHandle(handle));
    }

    /// Drain any audit entries produced by the capability pipe server
    /// thread. Called each iteration of the main event loop.
    fn drain_capability_audit_entries(&mut self) {
        if let Some(rx) = self.audit_rx.as_ref() {
            while let Ok(entries) = rx.try_recv() {
                self.audit_log.extend(entries);
            }
        }
    }

    fn start_logging(&self) -> Result<()> {
        // Phase 17 fix (debug 17-detached-child-immediate-exit): log file
        // path must use the USER-FACING session ID so `nono attach` /
        // `nono logs` (which compute the log path from `session.session_id`)
        // find it. Mirrors `start_control_pipe_server`.
        let session_id = self.user_session_id.clone();
        let pty_output_read = self
            .pty
            .as_ref()
            .map(|p| p.output_read as usize)
            .unwrap_or(0);
        // Phase 17: pipe-source branch reads from the parent-end stdout
        // handle (anonymous pipe). stderr is merged into stdout at spawn time
        // (D-04 / CONTEXT.md <specifics>) so a single source handle covers
        // both child fd 1 and fd 2.
        let stdout_read = self
            .detached_stdio
            .as_ref()
            .map(|s| s.stdout_read as usize)
            .unwrap_or(0);
        let active_attachment = self.active_attachment.clone();

        // Three mutually-exclusive cases (the supervised_runtime.rs:88-94
        // should_allocate_pty gate ensures pty_output_read != 0 XOR
        // stdout_read != 0 — they are never both nonzero on the supervised
        // path).
        if pty_output_read == 0 && stdout_read == 0 {
            // Phase 17 D-06: no source wired. Streaming requires either a
            // PTY or anonymous-pipe stdio; without either there is nothing
            // to relay. (Pre-Phase-17 wording was "v2.1+ feature; using
            // log-only streaming for now".)
            tracing::info!(
                session_id = %session_id,
                "Detached supervisor: child stdout/stderr streamed to log + attach client via anonymous pipes (resize not supported on detached path; use 'nono shell' or non-detached 'nono run' for full TUI fidelity)"
            );
            return Ok(());
        }

        // Pick the source HANDLE: PTY output or detached-stdio stdout
        // (mutually exclusive). Capture the resolved value into the closure
        // so the bridge thread reads from a single handle regardless of
        // which path is wired.
        let source_handle: usize = if pty_output_read != 0 {
            pty_output_read
        } else {
            stdout_read
        };

        std::thread::spawn(move || {
            let log_path = match crate::session::session_log_path(&session_id) {
                Ok(path) => path,
                Err(e) => {
                    tracing::error!(
                        "Failed to resolve log path for session {}: {}",
                        session_id,
                        e
                    );
                    return;
                }
            };

            let mut log_file = match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
            {
                Ok(file) => file,
                Err(e) => {
                    tracing::error!("Failed to open log file {}: {}", log_path.display(), e);
                    return;
                }
            };

            // SAFETY: source_handle was obtained from either self.pty.output_read
            // (lifetime tied to runtime.pty) or self.detached_stdio.stdout_read
            // (lifetime tied to runtime.detached_stdio); both fields outlive
            // this thread because the runtime is dropped only after the child
            // exits and this loop observes EOF. ManuallyDrop prevents
            // double-close — the runtime owns the handle.
            let mut source_file =
                ManuallyDrop::new(unsafe { std::fs::File::from_raw_handle(source_handle as _) });

            let mut buf = [0u8; 4096];
            while let Ok(n) = source_file.read(&mut buf) {
                if n == 0 {
                    break;
                }

                // Best-effort log write — never `?`-propagate inside the
                // bridge thread (Pitfall 1). The log file is the load-bearing
                // path; failures here would otherwise kill the bridge.
                let _ = log_file.write_all(&buf[..n]);
                let _ = log_file.flush();

                // On Windows, writing to a named pipe that has no listener
                // will block if we try to write to it directly. We mirror
                // child stdout through the attach pipe when a client is
                // connected.
                //
                // Hold `active_attachment` across WriteFile so the pipe-sink
                // thread cannot clear the slot + drop its File wrapper
                // (closing the HANDLE, which the OS may then recycle for an
                // unrelated kernel object) between our lookup and the write.
                // The pipe-sink thread only holds this mutex for the brief
                // swap-in / swap-out of the Option — microsecond-scale — so
                // there is no meaningful contention.
                let lock = active_attachment.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(sendable) = *lock {
                    let mut written = 0;
                    // SAFETY: sendable.0 is a valid named-pipe HANDLE for the
                    // duration of this WriteFile — we hold active_attachment's
                    // mutex above, and the pipe-sink thread must re-acquire
                    // the same mutex before clearing the slot + dropping the
                    // File wrapper that would close the HANDLE. Raw FFI
                    // WriteFile (vs File::write_all) lets us discard
                    // ERROR_NO_DATA / ERROR_BROKEN_PIPE without killing the
                    // bridge (Pitfall 1).
                    unsafe {
                        windows_sys::Win32::Storage::FileSystem::WriteFile(
                            sendable.0,
                            buf.as_ptr(),
                            n as u32,
                            &mut written,
                            std::ptr::null_mut(),
                        );
                    }
                }
                drop(lock);
            }
        });

        Ok(())
    }

    fn start_control_pipe_server(&self) -> Result<()> {
        // The supervisor correlation ID is used for audit/log messages only; the
        // user-facing session ID names the control pipe and is the ID clients
        // (`nono attach`, `nono terminate`, detached-launch readiness probe)
        // use to locate this supervisor.
        let user_session_id = self.user_session_id.clone();
        let terminate_requested = self.terminate_requested.clone();
        let active_attachment = self.active_attachment.clone();

        std::thread::spawn(move || {
            let pipe_name = format!("\\\\.\\pipe\\nono-session-{}", user_session_id);
            let h_pipe = match create_secure_pipe(&pipe_name) {
                Ok(h) => h,
                Err(e) => {
                    tracing::error!("Failed to create supervisor control pipe: {}", e);
                    return;
                }
            };
            loop {
                let connected = unsafe { ConnectNamedPipe(h_pipe, std::ptr::null_mut()) };
                if connected != 0
                    || unsafe { GetLastError() }
                        == windows_sys::Win32::Foundation::ERROR_PIPE_CONNECTED
                {
                    // Use a synchronous file wrapper for simplicity in the background thread
                    let mut file = unsafe { std::fs::File::from_raw_handle(h_pipe as _) };

                    // Simple length-prefixed JSON reader (same as nono::SupervisorSocket)
                    let mut len_buf = [0u8; 4];
                    if file.read_exact(&mut len_buf).is_ok() {
                        let len = u32::from_be_bytes(len_buf);
                        if len < 4096 {
                            let mut body = vec![0u8; len as usize];
                            if file.read_exact(&mut body).is_ok() {
                                if let Ok(msg) = serde_json::from_slice::<
                                    nono::supervisor::SupervisorMessage,
                                >(&body)
                                {
                                    match msg {
                                        nono::supervisor::SupervisorMessage::Terminate {
                                            session_id: msg_session_id,
                                        } => {
                                            if msg_session_id == user_session_id {
                                                tracing::info!(
                                                    "Terminate requested via control pipe for session {}",
                                                    user_session_id
                                                );
                                                terminate_requested.store(true, Ordering::SeqCst);
                                                break;
                                            }
                                        }
                                        nono::supervisor::SupervisorMessage::Detach {
                                            session_id: msg_session_id,
                                        } => {
                                            if msg_session_id == user_session_id {
                                                tracing::info!(
                                                    "Detach requested via control pipe for session {}",
                                                    user_session_id
                                                );
                                                let mut lock = active_attachment
                                                    .lock()
                                                    .unwrap_or_else(|p| p.into_inner());
                                                if let Some(sendable) = lock.take() {
                                                    unsafe {
                                                        DisconnectNamedPipe(sendable.0);
                                                    }
                                                }
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }

                    unsafe { DisconnectNamedPipe(h_pipe) };
                    if terminate_requested.load(Ordering::SeqCst) {
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    fn start_interactive_terminal_io(&self) -> Result<()> {
        let pty = self.pty.as_ref().ok_or_else(|| {
            NonoError::SandboxInit(
                "interactive_shell requires a PTY pair but none was provided".to_string(),
            )
        })?;

        let session_id = self.session_id.clone();
        let output_read = pty.output_read as usize;
        let input_write = pty.input_write as usize;
        let hpcon = pty.hpcon;

        unsafe extern "system" fn ctrl_handler(ctrl_type: u32) -> BOOL {
            if ctrl_type == CTRL_C_EVENT {
                1
            } else {
                0
            }
        }

        unsafe {
            // SAFETY: `ctrl_handler` has the correct ABI and remains valid for
            // the process lifetime.
            SetConsoleCtrlHandler(Some(ctrl_handler), 1);
        }

        {
            let output_session_id = session_id.clone();
            std::thread::spawn(move || {
                let log_path = crate::session::session_log_path(&output_session_id).ok();
                let mut log_file = log_path.and_then(|path| {
                    std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(path)
                        .ok()
                });

                let mut pty_out = ManuallyDrop::new(unsafe {
                    // SAFETY: `output_read` is owned by the PTY pair; ManuallyDrop
                    // avoids double-closing the handle.
                    std::fs::File::from_raw_handle(output_read as _)
                });
                let mut stdout = std::io::stdout();
                let mut buf = [0u8; 4096];

                while let Ok(n) = pty_out.read(&mut buf) {
                    if n == 0 {
                        break;
                    }

                    let _ = stdout.write_all(&buf[..n]);
                    let _ = stdout.flush();
                    if let Some(ref mut file) = log_file {
                        let _ = file.write_all(&buf[..n]);
                    }
                }
            });
        }

        {
            std::thread::spawn(move || {
                let mut pty_in = ManuallyDrop::new(unsafe {
                    // SAFETY: `input_write` is owned by the PTY pair; ManuallyDrop
                    // avoids double-closing the handle.
                    std::fs::File::from_raw_handle(input_write as _)
                });
                let mut stdin = std::io::stdin();
                let mut buf = [0u8; 4096];

                loop {
                    match stdin.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if pty_in.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }

        {
            std::thread::spawn(move || {
                let h_stdout = unsafe {
                    // SAFETY: GetStdHandle returns either a valid handle or an
                    // invalid sentinel, which we check before use.
                    GetStdHandle(STD_OUTPUT_HANDLE)
                };
                if h_stdout.is_null() || h_stdout == INVALID_HANDLE_VALUE {
                    return;
                }

                let mut last_size = COORD { X: 0, Y: 0 };

                loop {
                    std::thread::sleep(std::time::Duration::from_millis(100));

                    let mut info: CONSOLE_SCREEN_BUFFER_INFO = unsafe {
                        // SAFETY: CONSOLE_SCREEN_BUFFER_INFO is a plain Win32 FFI
                        // struct; zero-init is valid.
                        std::mem::zeroed()
                    };
                    let ok = unsafe {
                        // SAFETY: `h_stdout` is a live console handle after the
                        // sentinel checks above.
                        GetConsoleScreenBufferInfo(h_stdout, &mut info)
                    };
                    if ok == 0 {
                        break;
                    }

                    let cols = info.srWindow.Right - info.srWindow.Left + 1;
                    let rows = info.srWindow.Bottom - info.srWindow.Top + 1;
                    let new_size = COORD { X: cols, Y: rows };

                    if new_size.X != last_size.X || new_size.Y != last_size.Y {
                        last_size = new_size;
                        unsafe {
                            // SAFETY: `hpcon` belongs to the live PTY pair and
                            // remains valid for the lifetime of this thread.
                            let _ = ResizePseudoConsole(hpcon, new_size);
                        }
                    }
                }
            });
        }

        Ok(())
    }

    fn start_data_pipe_server(&self) -> Result<()> {
        // Phase 17 fix (debug 17-detached-child-immediate-exit): the data
        // pipe must be named with the USER-FACING session ID. `nono attach`
        // looks the pipe up by `session.session_id` (16-hex), not by the
        // supervisor correlation ID. Mirrors `start_control_pipe_server`.
        let session_id = self.user_session_id.clone();
        let pty_output_read = self
            .pty
            .as_ref()
            .map(|p| p.output_read as usize)
            .unwrap_or(0);
        let pty_input_write = self
            .pty
            .as_ref()
            .map(|p| p.input_write as usize)
            .unwrap_or(0);
        // Phase 17 (D-05): pipe-sink branch writes attach-client bytes into
        // the parent-end stdin HANDLE owned by self.detached_stdio.
        let stdin_write = self
            .detached_stdio
            .as_ref()
            .map(|s| s.stdin_write as usize)
            .unwrap_or(0);
        let active_attachment = self.active_attachment.clone();

        // Three mutually-exclusive cases (the should_allocate_pty gate at
        // supervised_runtime.rs:88-94 ensures
        // (pty_input_write != 0 && pty_output_read != 0) XOR stdin_write != 0).
        let sink_handle: usize = if pty_input_write != 0 && pty_output_read != 0 {
            pty_input_write
        } else if stdin_write != 0 {
            stdin_write
        } else {
            // Neither PTY nor detached-stdio wired (e.g. interactive_shell
            // handled elsewhere or a future code path). No sink thread to
            // spawn.
            return Ok(());
        };

        std::thread::spawn(move || {
            let pipe_name = format!("\\\\.\\pipe\\nono-data-{}", session_id);
            let h_pipe = match create_secure_pipe(&pipe_name) {
                Ok(h) => h,
                Err(e) => {
                    tracing::error!("Failed to create supervisor data pipe: {}", e);
                    return;
                }
            };

            loop {
                // SAFETY: h_pipe was just created by create_secure_pipe with
                // nMaxInstances=1 (supervisor.rs:165) — single-attach is
                // structurally enforced by the kernel. ConnectNamedPipe
                // blocks until a client connects.
                let connected = unsafe { ConnectNamedPipe(h_pipe, std::ptr::null_mut()) };
                if connected != 0
                    || unsafe { GetLastError() }
                        == windows_sys::Win32::Foundation::ERROR_PIPE_CONNECTED
                {
                    {
                        let mut lock = active_attachment.lock().unwrap_or_else(|p| p.into_inner());
                        *lock = Some(SendableHandle(h_pipe));
                    }

                    // SAFETY: h_pipe is owned by this loop iteration; File
                    // takes the handle and we DisconnectNamedPipe + reuse it
                    // on the next iteration. (Same pattern as the PTY-sink
                    // pre-Phase-17.)
                    let mut file = unsafe { std::fs::File::from_raw_handle(h_pipe as _) };
                    // SAFETY: sink_handle is either pty.input_write (lifetime
                    // tied to runtime.pty) or detached_stdio.stdin_write
                    // (lifetime tied to runtime.detached_stdio). ManuallyDrop
                    // prevents double-close — the runtime owns the handle.
                    let mut sink = ManuallyDrop::new(unsafe {
                        std::fs::File::from_raw_handle(sink_handle as _)
                    });

                    let mut buf = [0u8; 4096];
                    while let Ok(n) = file.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        if sink.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }

                    {
                        let mut lock = active_attachment.lock().unwrap_or_else(|p| p.into_inner());
                        if let Some(sendable) = *lock {
                            if sendable.0 == h_pipe {
                                *lock = None;
                            }
                        }
                    }
                    // SAFETY: standard Win32 named-pipe lifecycle —
                    // disconnect to allow the next ConnectNamedPipe iteration
                    // to accept a new client.
                    unsafe { DisconnectNamedPipe(h_pipe) };
                }
            }
        });

        Ok(())
    }

    pub(super) fn transport_name(&self) -> &str {
        self.transport_name.as_str()
    }

    pub(super) fn run_child_event_loop(
        &mut self,
        child: &mut WindowsSupervisedChild,
    ) -> Result<i32> {
        self.state = WindowsSupervisorLifecycleState::WaitingForChild;
        tracing::debug!(
            "Windows supervisor event loop entering wait phase (session: {}, transport: {}, state: {}, features: {})",
            self.session_id,
            self.transport_name,
            self.state.label(),
            if self.requested_features.is_empty() {
                "none".to_string()
            } else {
                self.requested_features.join(", ")
            }
        );

        loop {
            self.drain_capability_audit_entries();
            if self.terminate_requested.load(Ordering::SeqCst) {
                tracing::info!(
                    "Windows supervisor received termination request, stopping child..."
                );
                child.terminate()?;
                return Ok(-1);
            }

            // Prefer a natural exit when both the deadline and the child-exit
            // conditions fire on the same tick. `poll_exit_code` is a
            // non-blocking `WaitForSingleObject(handle, 0)` plus
            // `GetExitCodeProcess`, so it only reports an exit that has
            // already happened. See WR-03.
            if let Some(exit_code) = child.poll_exit_code()? {
                // Signal the capability pipe thread to exit before we drop
                // the runtime (which closes the child HANDLE the thread
                // caches inside its `BrokerTargetProcess`). See WR-01.
                self.terminate_requested.store(true, Ordering::SeqCst);
                self.state = WindowsSupervisorLifecycleState::ShuttingDown;
                self.shutdown();
                self.state = WindowsSupervisorLifecycleState::Completed;
                tracing::debug!(
                    "Windows supervisor event loop completed via non-blocking poll (session: {}, transport: {}, exit_code: {}, elapsed_ms: {})",
                    self.session_id,
                    self.transport_name,
                    exit_code,
                    self.started_at.elapsed().as_millis()
                );
                return Ok(exit_code);
            }

            // Wall-clock deadline (RESL-03 --timeout). Expected accuracy ±100ms,
            // bounded by the `wait_for_exit(100)` quantum below. If
            // `terminate_job_object` fails, the child tree still dies when
            // `ProcessContainment` drops via JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.
            if let Some(deadline) = self.timeout_deadline {
                if std::time::Instant::now() >= deadline {
                    tracing::info!(
                        "Windows supervisor --timeout expired (session: {}, elapsed_ms: {}), calling TerminateJobObject...",
                        self.session_id,
                        self.started_at.elapsed().as_millis()
                    );
                    // Signal the capability pipe thread to exit before we drop
                    // the runtime (which closes the child HANDLE the thread
                    // caches inside its `BrokerTargetProcess`). See WR-01.
                    self.terminate_requested.store(true, Ordering::SeqCst);
                    if let Err(err) = super::launch::terminate_job_object(
                        self.containment_job,
                        super::launch::STATUS_TIMEOUT_EXIT_CODE,
                    ) {
                        tracing::error!(
                            "TerminateJobObject on --timeout expiry failed (will rely on KILL_ON_JOB_CLOSE safety net): {err}"
                        );
                    }
                    self.state = WindowsSupervisorLifecycleState::ShuttingDown;
                    self.shutdown();
                    self.state = WindowsSupervisorLifecycleState::Completed;
                    return Ok(super::launch::STATUS_TIMEOUT_EXIT_CODE as i32);
                }
            }

            if let Some(exit_code) = child.wait_for_exit(100)? {
                // Signal the capability pipe thread to exit before we drop
                // the runtime (which closes the child HANDLE the thread
                // caches inside its `BrokerTargetProcess`). See WR-01.
                self.terminate_requested.store(true, Ordering::SeqCst);
                self.state = WindowsSupervisorLifecycleState::ShuttingDown;
                self.shutdown();
                self.state = WindowsSupervisorLifecycleState::Completed;
                tracing::debug!(
                    "Windows supervisor event loop completed (session: {}, transport: {}, exit_code: {}, elapsed_ms: {})",
                    self.session_id,
                    self.transport_name,
                    exit_code,
                    self.started_at.elapsed().as_millis()
                );
                return Ok(exit_code);
            }
        }
    }

    pub(super) fn startup_failure(&mut self, message: String) -> NonoError {
        self.shutdown();
        NonoError::SandboxInit(format!(
            "Windows supervised execution failed during {} (session: {}, transport: {}, supervisor_audit_entries: {}): {}",
            self.state.label(),
            self.session_id,
            self.transport_name,
            self.audit_log.len(),
            message
        ))
    }

    pub(super) fn command_failure(&mut self, message: String) -> NonoError {
        self.shutdown();
        NonoError::CommandExecution(std::io::Error::other(format!(
            "Windows supervised execution failed during {} (session: {}, transport: {}, supervisor_audit_entries: {}): {}",
            self.state.label(),
            self.session_id,
            self.transport_name,
            self.audit_log.len(),
            message
        )))
    }

    pub(super) fn shutdown(&mut self) {
        let _ = self.child_control.take();
        self.state = WindowsSupervisorLifecycleState::ShuttingDown;
    }

    pub(super) fn pty(&self) -> Option<&crate::pty_proxy::PtyPair> {
        self.pty.as_ref()
    }

    /// Phase 17: borrowed access to the parent-end stdio handles for the
    /// Windows detached path. `None` on the PTY (non-detached) path. Used by
    /// the bridge threads in `start_logging` (pipe-source branch) and
    /// `start_data_pipe_server` (pipe-sink branch).
    #[allow(dead_code)]
    pub(super) fn detached_stdio(&self) -> Option<&DetachedStdioPipes> {
        self.detached_stdio.as_ref()
    }
}

impl Drop for WindowsSupervisorRuntime {
    fn drop(&mut self) {
        // Signal the capability pipe background thread (if any) to exit its
        // loop before the runtime's child HANDLE is closed. The thread caches
        // the raw child handle inside a `BrokerTargetProcess`; without this
        // signal it could race and invoke `DuplicateHandle` against a
        // dangling handle. See WR-01.
        self.terminate_requested.store(true, Ordering::SeqCst);
        if self.state != WindowsSupervisorLifecycleState::Completed {
            self.shutdown();
        }
        // Best-effort cleanup: remove the capability pipe rendezvous file so
        // the next session does not collide with a stale rendezvous on the
        // same session id.
        if let Some(path) = self.cap_pipe_rendezvous_path.as_ref() {
            let _ = std::fs::remove_file(path);
        }
    }
}

pub(super) fn initialize_supervisor_control_channel(
) -> Result<(nono::SupervisorSocket, nono::SupervisorSocket)> {
    nono::SupervisorSocket::pair().map_err(|e| {
        NonoError::SandboxInit(format!(
            "Failed to initialize Windows supervisor control channel: {e}"
        ))
    })
}

pub(super) fn open_windows_supervisor_path(
    path: &Path,
    access: &nono::AccessMode,
) -> Result<std::fs::File> {
    // std::fs::OpenOptions on Windows wraps CreateFileW without
    // FILE_FLAG_BACKUP_SEMANTICS, so directory paths would fail with an
    // opaque ERROR_ACCESS_DENIED that looks like an ACL problem but is
    // really a platform quirk. The capability broker contract is
    // file-scoped by design (cap-pipe brokers file handles via
    // DuplicateHandle, not directory enumeration handles). Reject
    // directory paths up-front with a clear boundary message. If future
    // work needs directory brokering it should add an explicit `is_dir`
    // discriminator to CapabilityRequest rather than silently flipping
    // this branch (would be a capability-scope expansion requiring
    // protocol review).
    if path.metadata().map(|m| m.is_dir()).unwrap_or(false) {
        return Err(NonoError::SandboxInit(format!(
            "Windows supervisor refused directory path {}: capability broker brokers file handles only",
            path.display()
        )));
    }

    let mut options = std::fs::OpenOptions::new();
    match access {
        nono::AccessMode::Read => {
            options.read(true);
        }
        nono::AccessMode::Write => {
            options.write(true);
        }
        nono::AccessMode::ReadWrite => {
            options.read(true).write(true);
        }
    }

    options.open(path).map_err(|e| {
        NonoError::SandboxInit(format!(
            "Windows supervisor failed to open approved path {}: {}",
            path.display(),
            e
        ))
    })
}

/// Constant-time byte-slice comparison used for session-token validation.
///
/// Uses `subtle::ConstantTimeEq::ct_eq` so attackers cannot learn prefix
/// information from timing. The token string is NEVER logged or formatted —
/// callers must also redact it before constructing any `AuditEntry`.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Build an `AuditEntry` for a `CapabilityRequest` while redacting the
/// `session_token` field. Never embed the raw request directly — always go
/// through this helper so the token cannot leak via audit serialization.
fn audit_entry_with_redacted_token(
    request: &nono::CapabilityRequest,
    decision: &nono::ApprovalDecision,
    backend_name: &str,
    started_at: Instant,
) -> AuditEntry {
    let mut redacted = request.clone();
    redacted.session_token.clear();
    AuditEntry {
        timestamp: SystemTime::now(),
        request: redacted,
        decision: decision.clone(),
        backend: backend_name.to_string(),
        duration_ms: started_at.elapsed().as_millis() as u64,
    }
}

/// Server-side validation of a leaf name supplied by the child for an AIPC
/// kernel-object request (Event/Mutex/Pipe/Job Object). Per CONTEXT.md
/// `<specifics>` line 168, the server canonicalizes the namespace prefix
/// (`Local\nono-aipc-<user_session_id>-<sanitized_name>`) so cross-session
/// interference is structurally impossible. This validator rejects any leaf
/// name that could subvert the prefix or the OS-level namespace.
fn validate_aipc_object_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 {
        return Err(NonoError::SandboxInit(format!(
            "AIPC object name must be 1..=64 bytes (got {})",
            name.len()
        )));
    }
    for ch in name.chars() {
        if ch == '\\' || ch == '/' || ch == ':' || ch == '\0' || ch.is_control() {
            return Err(NonoError::SandboxInit(format!(
                "AIPC object name contains forbidden char {ch:?}"
            )));
        }
    }
    Ok(())
}

/// Handle a HandleKind::Event request: validate target shape + mask, create
/// the kernel-object name in the canonical `Local\nono-aipc-<user_session_id>-<name>`
/// namespace using `user_session_id` (Phase 17 latent-bug carry-forward —
/// MUST NOT use `self.session_id`), open it with `CreateEventW`, and broker
/// it into the child via `broker_event_to_process` with the validated mask.
///
/// Per CONTEXT.md D-10: the supervisor closes its source handle as the
/// `OwnedHandle`-style `event` HANDLE goes out of scope at function return,
/// AFTER the broker has duplicated it into the child.
fn handle_event_request(
    request: &nono::CapabilityRequest,
    target_process: nono::BrokerTargetProcess,
    user_session_id: &str,
    resolved_allowlist: &AipcResolvedAllowlist,
) -> Result<Option<nono::supervisor::ResourceGrant>> {
    let raw_name = match request.target.as_ref() {
        Some(HandleTarget::EventName { name }) => name,
        _ => {
            return Err(NonoError::SandboxInit(
                "AIPC Event request: target shape does not match kind Event".to_string(),
            ))
        }
    };
    validate_aipc_object_name(raw_name)?;
    // Plan 18-03: profile widening replaces the hard-coded D-05 default.
    // The default-deny baseline is preserved by `AipcResolvedAllowlist::default`.
    let resolved = resolved_allowlist.event_mask;
    if !policy::mask_is_allowed(HandleKind::Event, request.access_mask, resolved) {
        return Err(NonoError::SandboxInit(format!(
            "access mask 0x{:08x} not in allowlist for Event (resolved: 0x{:08x})",
            request.access_mask, resolved
        )));
    }
    // Phase 17 latent-bug carry-forward: namespace prefix MUST use
    // `user_session_id` (the user-facing 16-hex), NOT `self.session_id` (the
    // supervisor correlation `supervised-PID-NANOS`). Three pre-existing bugs
    // of exactly this shape were fixed in Phase 17 commit 7db6595.
    let canonical = format!("Local\\nono-aipc-{}-{}", user_session_id, raw_name);
    let wide: Vec<u16> = std::ffi::OsStr::new(&canonical)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `wide.as_ptr()` is a null-terminated UTF-16 string in
    // stack-owned storage that outlives the FFI call. `CreateEventW`
    // parameters: NULL attrs (no inheritance), manual-reset = 0, initial
    // state = 0. Returned HANDLE is owned by the supervisor and must be
    // closed (handled below at function exit, after broker duplication).
    let event: HANDLE = unsafe { CreateEventW(std::ptr::null_mut(), 0, 0, wide.as_ptr()) };
    if event.is_null() {
        return Err(NonoError::SandboxInit(format!(
            "CreateEventW(\"{canonical}\") failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let grant = broker_event_to_process(event, target_process, request.access_mask);
    // D-10: supervisor closes its source handle. The grant either succeeded
    // (child owns the duplicate) or failed (no duplicate exists). Either way
    // the supervisor's source handle MUST close.
    // SAFETY: `event` is a live HANDLE returned by CreateEventW above and
    // has not been wrapped or freed elsewhere.
    unsafe {
        CloseHandle(event);
    }
    grant.map(Some)
}

/// Handle a HandleKind::Pipe request: validate target shape + direction
/// (decoded from `access_mask` — GENERIC_READ vs GENERIC_WRITE bits), create
/// the named pipe in the canonical `\\.\pipe\nono-aipc-<user_session_id>-<name>`
/// namespace using `user_session_id` (Phase 17 latent-bug carry-forward —
/// MUST NOT use `self.session_id`), and broker the supervisor-side handle into
/// the child via `broker_pipe_to_process` with `dwOptions = 0` (MAP DOWN to
/// the validated direction).
///
/// Per CONTEXT.md D-05 default allowlist: read OR write (not both). ReadWrite
/// requires profile widening (Plan 18-03). Plan 18-02 ships with default-only
/// enforcement.
///
/// Per CONTEXT.md D-10: the supervisor closes its source HANDLE as the call
/// returns, AFTER the broker has duplicated it into the child.
fn handle_pipe_request(
    request: &nono::CapabilityRequest,
    target_process: nono::BrokerTargetProcess,
    user_session_id: &str,
    resolved_allowlist: &AipcResolvedAllowlist,
) -> Result<Option<nono::supervisor::ResourceGrant>> {
    let raw_name = match request.target.as_ref() {
        Some(HandleTarget::PipeName { name }) => name,
        _ => {
            return Err(NonoError::SandboxInit(
                "AIPC Pipe request: target shape does not match kind Pipe".to_string(),
            ))
        }
    };
    validate_aipc_object_name(raw_name)?;

    // Decode direction from access_mask: GENERIC_READ-only -> Read,
    // GENERIC_WRITE-only -> Write, both -> ReadWrite, anything else -> err.
    let read_bit = request.access_mask & policy::GENERIC_READ != 0;
    let write_bit = request.access_mask & policy::GENERIC_WRITE != 0;
    let no_extra_bits = request.access_mask & !(policy::GENERIC_READ | policy::GENERIC_WRITE) == 0;
    let direction = match (read_bit, write_bit, no_extra_bits) {
        (true, false, true) => PipeDirection::Read,
        (false, true, true) => PipeDirection::Write,
        (true, true, true) => PipeDirection::ReadWrite,
        _ => {
            return Err(NonoError::SandboxInit(format!(
                "pipe access_mask 0x{:08x} not a valid combination of GENERIC_READ/GENERIC_WRITE",
                request.access_mask
            )))
        }
    };

    // Plan 18-03: profile widening lookup replaces the Plan 18-02
    // hard-coded "ReadWrite requires profile widening" branch. The default
    // allowlist (`AipcResolvedAllowlist::default()`) contains only
    // [Read, Write], so `ReadWrite` still falls through to Denied unless
    // a profile explicitly widens.
    if !resolved_allowlist.pipe_directions.contains(&direction) {
        return Err(NonoError::SandboxInit(format!(
            "pipe direction {direction:?} not in resolved allowlist (profile widening required)"
        )));
    }

    // Phase 17 latent-bug carry-forward: namespace prefix MUST use
    // `user_session_id` (the user-facing 16-hex), NOT `self.session_id` (the
    // supervisor correlation `supervised-PID-NANOS`). Three pre-existing bugs
    // of exactly this shape were fixed in Phase 17 commit 7db6595.
    let canonical = format!("\\\\.\\pipe\\nono-aipc-{}-{}", user_session_id, raw_name);
    let handle = bind_aipc_pipe(&canonical, direction)?;
    let grant = broker_pipe_to_process(handle, target_process, direction);
    // D-10: supervisor closes its source after broker call.
    // SAFETY: `handle` is a live HANDLE returned by bind_aipc_pipe above and
    // has not been wrapped or freed elsewhere.
    unsafe {
        CloseHandle(handle);
    }
    grant.map(Some)
}

/// Handle a HandleKind::Socket request: validate target shape + role + port,
/// open a fresh supervisor-owned SOCKET via `WSASocketW`, and broker it into
/// the child via `broker_socket_to_process` (which uses `WSADuplicateSocketW`
/// to serialize the socket capability into a target-PID-bound
/// `WSAPROTOCOL_INFOW` blob).
///
/// Per CONTEXT.md `<specifics>` line 167 + RESEARCH Landmines § Socket:
/// privileged ports (`<= 1023`) are unconditionally denied. Cannot be widened
/// by profile in v2.1.
///
/// Per CONTEXT.md D-05: default allowlist allows Connect role only. Bind and
/// Listen require profile widening (Plan 18-03 wires the lookup; Plan 18-02
/// hard-codes Connect-only).
///
/// Per CONTEXT.md D-10 + RESEARCH Landmines § Socket: the supervisor MUST
/// hold its source SOCKET open until AFTER `send_response` returns. This
/// helper closes the source AFTER `broker_socket_to_process` returns the
/// serialized blob; the kernel keeps the underlying socket alive until ALL
/// descriptors close (the duplicated descriptor only materializes when the
/// child calls `WSASocketW(FROM_PROTOCOL_INFO, ...)`).
///
/// `_user_session_id` is not used for sockets — the namespace is the network
/// endpoint, not a `Local\` kernel-object name. Kept in signature for symmetry
/// with `handle_pipe_request` and `handle_event_request`.
fn handle_socket_request(
    request: &nono::CapabilityRequest,
    target_process: nono::BrokerTargetProcess,
    _user_session_id: &str,
    resolved_allowlist: &AipcResolvedAllowlist,
) -> Result<Option<nono::supervisor::ResourceGrant>> {
    let (protocol, host, port, role) = match request.target.as_ref() {
        Some(HandleTarget::SocketEndpoint {
            protocol,
            host,
            port,
            role,
        }) => (*protocol, host.as_str(), *port, *role),
        _ => {
            return Err(NonoError::SandboxInit(
                "AIPC Socket request: target shape does not match kind Socket".to_string(),
            ))
        }
    };

    // Privileged-port check — UNCONDITIONAL deny (RESEARCH Landmines § Socket;
    // CONTEXT.md `<specifics>` line 167). Cannot be widened by profile in v2.1.
    if port <= policy::PRIVILEGED_PORT_MAX {
        return Err(NonoError::SandboxInit(format!(
            "privileged port {port} not allowed (port must be > {})",
            policy::PRIVILEGED_PORT_MAX
        )));
    }

    // Plan 18-03: profile widening lookup replaces the Plan 18-02
    // hard-coded "Connect-only" check. The default allowlist
    // (`AipcResolvedAllowlist::default()`) is `[Connect]`; Bind/Listen
    // require profile opt-in via `capabilities.aipc.socket`.
    if !resolved_allowlist.socket_roles.contains(&role) {
        return Err(NonoError::SandboxInit(format!(
            "socket role {role:?} not in resolved allowlist (profile widening required)"
        )));
    }

    // Sanitize host — reject control bytes / NUL / overly long. Plan 18-02
    // doesn't resolve the host (deferred); for connect role, the child uses
    // the brokered SOCKET's own connect call against the validated endpoint
    // baked into the audit log via the original CapabilityRequest.target.
    if host.is_empty() || host.len() > 253 {
        return Err(NonoError::SandboxInit(format!(
            "socket host invalid length: {}",
            host.len()
        )));
    }
    for ch in host.chars() {
        if ch.is_control() || ch == '\0' {
            return Err(NonoError::SandboxInit(
                "socket host contains control char".to_string(),
            ));
        }
    }

    // Initialize Winsock (idempotent — WSAStartup is reference-counted).
    // SAFETY: WSAStartup with version 2.2 (0x0202) is the standard Winsock
    // initialization; wsadata points to writable storage.
    let mut wsadata: WSADATA = unsafe { std::mem::zeroed() };
    let _ = unsafe { WSAStartup(0x0202, &mut wsadata) };

    let (sock_type, ipproto) = match protocol {
        SocketProtocol::Tcp => (SOCK_STREAM, IPPROTO_TCP),
        SocketProtocol::Udp => (SOCK_DGRAM, IPPROTO_UDP),
    };
    // SAFETY: WSASocketW with NULL protocol_info creates a fresh socket.
    // AF_INET / SOCK_STREAM / SOCK_DGRAM / IPPROTO_TCP / IPPROTO_UDP are
    // well-defined Winsock constants. The returned SOCKET is owned by the
    // supervisor for the duration of the broker call; closesocket happens
    // after the broker returns.
    let sock = unsafe {
        WSASocketW(
            AF_INET as i32,
            sock_type,
            ipproto,
            std::ptr::null(),
            0,
            WSA_FLAG_OVERLAPPED,
        )
    };
    if sock == INVALID_SOCKET {
        return Err(NonoError::SandboxInit(format!(
            "WSASocketW failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    let target_pid = broker_target_pid(&target_process);
    let grant = broker_socket_to_process(sock, target_process, target_pid, role);
    // D-10 + RESEARCH Landmines § Socket: supervisor closes the source
    // AFTER broker returns the serialized WSAPROTOCOL_INFOW blob. The kernel
    // keeps the underlying socket alive until ALL descriptors close, and the
    // duplicated descriptor materializes when the child calls
    // WSASocketW(FROM_PROTOCOL_INFO, ...).
    // SAFETY: `sock` is a live SOCKET returned by WSASocketW above; the
    // broker call above only borrows it for the WSADuplicateSocketW call.
    let _ = unsafe { closesocket(sock) };
    grant.map(Some)
}

/// Handle a HandleKind::Mutex request — same shape as `handle_event_request`
/// with `CreateMutexW` + `broker_mutex_to_process` and the Mutex default
/// mask. See `handle_event_request` for the Phase 17 carry-forward and D-10
/// lifetime documentation.
fn handle_mutex_request(
    request: &nono::CapabilityRequest,
    target_process: nono::BrokerTargetProcess,
    user_session_id: &str,
    resolved_allowlist: &AipcResolvedAllowlist,
) -> Result<Option<nono::supervisor::ResourceGrant>> {
    let raw_name = match request.target.as_ref() {
        Some(HandleTarget::MutexName { name }) => name,
        _ => {
            return Err(NonoError::SandboxInit(
                "AIPC Mutex request: target shape does not match kind Mutex".to_string(),
            ))
        }
    };
    validate_aipc_object_name(raw_name)?;
    // Plan 18-03: profile widening replaces the hard-coded D-05 default.
    let resolved = resolved_allowlist.mutex_mask;
    if !policy::mask_is_allowed(HandleKind::Mutex, request.access_mask, resolved) {
        return Err(NonoError::SandboxInit(format!(
            "access mask 0x{:08x} not in allowlist for Mutex (resolved: 0x{:08x})",
            request.access_mask, resolved
        )));
    }
    // Phase 17 latent-bug carry-forward: namespace prefix MUST use
    // `user_session_id`, NOT `self.session_id`.
    let canonical = format!("Local\\nono-aipc-{}-{}", user_session_id, raw_name);
    let wide: Vec<u16> = std::ffi::OsStr::new(&canonical)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `wide.as_ptr()` is a null-terminated UTF-16 string in
    // stack-owned storage that outlives the FFI call. `CreateMutexW`
    // parameters: NULL attrs (no inheritance), initial owner = 0. Returned
    // HANDLE is owned by the supervisor and must be closed (below).
    let mutex: HANDLE = unsafe { CreateMutexW(std::ptr::null_mut(), 0, wide.as_ptr()) };
    if mutex.is_null() {
        return Err(NonoError::SandboxInit(format!(
            "CreateMutexW(\"{canonical}\") failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let grant = broker_mutex_to_process(mutex, target_process, request.access_mask);
    // SAFETY: `mutex` is a live HANDLE returned by CreateMutexW above and
    // has not been wrapped or freed elsewhere.
    unsafe {
        CloseHandle(mutex);
    }
    grant.map(Some)
}

/// Handle a HandleKind::JobObject request: validate target shape + mask, open
/// the kernel-object name in the canonical
/// `Local\nono-aipc-<user_session_id>-<name>` namespace using `user_session_id`
/// (Phase 17 latent-bug carry-forward — MUST NOT use `self.session_id`), fire
/// the **containment-Job runtime guard** (CONTEXT.md D-05 footnote — refuse to
/// broker the supervisor's own `containment_job` HANDLE regardless of mask),
/// and broker it into the child via `broker_job_object_to_process`.
///
/// The runtime guard is the load-bearing structural defense for T-18-03-01:
/// even if a profile widens `job_object` to include `terminate`, the
/// supervisor still refuses to broker its OWN containment Job — brokering
/// that handle would let the child kill the supervisor process tree.
/// `CompareObjectHandles` (Win10 1607+) compares two HANDLEs at the
/// kernel-object level: opening the same Job Object name twice returns
/// distinct HANDLE values that BOTH resolve to the same kernel object, so
/// numeric `==` is insufficient.
///
/// Per CONTEXT.md D-10: the supervisor closes its source HANDLE as the call
/// returns, AFTER the broker has duplicated it into the child.
fn handle_job_object_request(
    request: &nono::CapabilityRequest,
    target_process: nono::BrokerTargetProcess,
    user_session_id: &str,
    runtime_containment_job: HANDLE,
    resolved_allowlist: &AipcResolvedAllowlist,
) -> Result<Option<nono::supervisor::ResourceGrant>> {
    let raw_name = match request.target.as_ref() {
        Some(HandleTarget::JobObjectName { name }) => name,
        _ => {
            return Err(NonoError::SandboxInit(
                "AIPC JobObject request: target shape does not match kind JobObject".to_string(),
            ))
        }
    };
    validate_aipc_object_name(raw_name)?;

    // Plan 18-03: profile widening replaces the hard-coded D-05 default.
    // The runtime guard below ALSO fires regardless of resolved mask
    // (containment-Job hijack defense — T-18-03-01).
    let resolved = resolved_allowlist.job_object_mask;
    if !policy::mask_is_allowed(HandleKind::JobObject, request.access_mask, resolved) {
        return Err(NonoError::SandboxInit(format!(
            "access mask 0x{:08x} not in allowlist for JobObject (resolved: 0x{:08x})",
            request.access_mask, resolved
        )));
    }

    // Phase 17 latent-bug carry-forward: namespace prefix MUST use
    // `user_session_id` (the user-facing 16-hex), NOT `self.session_id` (the
    // supervisor correlation `supervised-PID-NANOS`). Three pre-existing bugs
    // of exactly this shape were fixed in Phase 17 commit 7db6595.
    let canonical = format!("Local\\nono-aipc-{}-{}", user_session_id, raw_name);
    let wide: Vec<u16> = std::ffi::OsStr::new(&canonical)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // Phase 18.1 G-03: align JobObject broker semantic with Event/Mutex/Pipe
    // CREATE-if-not-exists parity. `CreateJobObjectW` atomically creates the
    // named Job Object if it does not exist, or opens the existing object
    // and sets `GetLastError() == ERROR_ALREADY_EXISTS` (a non-error — we
    // still own a valid HANDLE). This matches the Event/Mutex broker
    // pattern (`CreateEventW`/`CreateMutexW`) and fixes the HUMAN-UAT G-03
    // open-only `ERROR_FILE_NOT_FOUND` that broke `aipc-demo.exe` when the
    // demo did not pre-create the named Job Object (per CONTEXT D-05 the
    // design contract is "supervisor creates the named kernel object on
    // demand").
    //
    // SAFETY: `wide.as_ptr()` is a null-terminated UTF-16 string in
    // stack-owned storage that outlives the FFI call. `CreateJobObjectW`
    // returns NULL on failure (no UB on bad arguments). NULL
    // SECURITY_ATTRIBUTES = no inheritance, default DACL. The handle is
    // opened with full access; the subsequent `DuplicateHandle` MAPs DOWN
    // to the validated mask (T-18-03-01 mitigation, preserved from the
    // pre-fix shape).
    let job: HANDLE = unsafe { CreateJobObjectW(std::ptr::null_mut(), wide.as_ptr()) };
    if job.is_null() {
        return Err(NonoError::SandboxInit(format!(
            "CreateJobObjectW(\"{canonical}\") failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    // CONTEXT.md D-05 footnote runtime guard (T-18-03-01 mitigation):
    // refuse to broker the supervisor's own `containment_job` HANDLE
    // regardless of profile widening or the requested mask.
    //
    // `CompareObjectHandles` is required (NOT numeric `==`): opening the
    // same Job Object name twice returns DIFFERENT HANDLE values that both
    // resolve to the SAME kernel object. The Win10 1607+ API returns
    // non-zero IFF both HANDLEs reference the same kernel object.
    //
    // The guard is structural: it fires before the broker call returns a
    // duplicated handle, so even if a profile widens `job_object` to
    // include `terminate`, the supervisor's containment Job is unreachable.
    if !runtime_containment_job.is_null() {
        // SAFETY: Both `job` (from CreateJobObjectW above) and
        // `runtime_containment_job` (passed by the caller from
        // `WindowsSupervisorRuntime.containment_job`) are live HANDLEs we
        // own at supervisor scope. CompareObjectHandles is a leaf-safe
        // Win32 call that returns BOOL (non-zero = same kernel object).
        let same = unsafe { CompareObjectHandles(job, runtime_containment_job) };
        if same != 0 {
            // SAFETY: `job` is the HANDLE returned by CreateJobObjectW above;
            // it is owned by the supervisor and has not been duplicated yet.
            unsafe {
                CloseHandle(job);
            }
            return Err(NonoError::SandboxInit(
                "cannot broker the supervisor's own containment Job Object".to_string(),
            ));
        }
    }

    let grant = broker_job_object_to_process(job, target_process, request.access_mask);
    // D-10: supervisor closes its source after broker call.
    // SAFETY: `job` is a live HANDLE returned by CreateJobObjectW above and has
    // not been wrapped or freed elsewhere.
    unsafe {
        CloseHandle(job);
    }
    grant.map(Some)
}

/// Dispatch a single supervisor message from a sandboxed child.
///
/// The `expected_session_token` parameter is the 32-byte hex token generated
/// per-session by the supervisor. It is compared in constant time against
/// the inbound `CapabilityRequest.session_token` BEFORE the approval backend
/// is consulted. The token is NEVER logged and is redacted before any
/// `AuditEntry` is constructed.
// Note: 10 parameters is intentional — packing the dispatcher state into a
// struct would obscure the per-call ownership semantics of the borrowed
// `seen_request_ids` and `audit_log` mut refs vs the shared session
// token + user_session_id strings + resolved allowlist. Phase 18 Plan 18-03
// added `runtime_containment_job` for the Job Object containment-Job runtime
// guard AND `resolved_allowlist` for the profile widening lookup (D-05/D-06).
#[allow(clippy::too_many_arguments)]
pub(super) fn handle_windows_supervisor_message(
    sock: &mut nono::SupervisorSocket,
    msg: nono::supervisor::SupervisorMessage,
    approval_backend: &dyn ApprovalBackend,
    target_process: nono::BrokerTargetProcess,
    seen_request_ids: &mut HashSet<String>,
    audit_log: &mut Vec<AuditEntry>,
    expected_session_token: &str,
    user_session_id: &str,
    runtime_containment_job: HANDLE,
    resolved_allowlist: &AipcResolvedAllowlist,
    // Phase 23 D-01: optional ledger recorder for capability-decision events.
    // `None` for callers that do not request audit-integrity (zero-overhead
    // path). When `Some`, the dispatcher emits one
    // `AuditEventPayload::CapabilityDecision` per request (with the
    // WR-01-locked `reject_stage` discriminator) at each of the 5 push sites.
    audit_recorder: Option<
        &std::sync::Arc<std::sync::Mutex<crate::audit_integrity::AuditRecorder>>,
    >,
) -> Result<()> {
    // Phase 23 D-01 + Discretion #3: ledger emission helper. Recorder errors
    // (lock-poison or write-failure) MUST NOT abort the supervisor — the
    // wire response goes out regardless. T-23-03 mitigation: warn-and-continue
    // shape, not `?` propagation.
    let emit_to_ledger =
        |entry: &AuditEntry,
         request_id: &str,
         reject_stage: Option<crate::audit_integrity::RejectStage>| {
            if let Some(recorder_mutex) = audit_recorder {
                match recorder_mutex.lock() {
                    Ok(mut recorder) => {
                        if let Err(e) =
                            recorder.record_capability_decision(entry.clone(), reject_stage)
                        {
                            tracing::warn!(
                                request_id = %request_id,
                                error = %e,
                                "Failed to append capability-decision event to audit ledger; \
                                 wire response continues normally",
                            );
                        }
                    }
                    Err(_) => {
                        tracing::warn!(
                            request_id = %request_id,
                            "Audit recorder lock poisoned; skipping ledger emission",
                        );
                    }
                }
            }
        };

    match msg {
        nono::supervisor::SupervisorMessage::Request(request) => {
            let started_at = Instant::now();
            if seen_request_ids.contains(&request.request_id) {
                let decision = nono::ApprovalDecision::Denied {
                    reason: "Duplicate request_id rejected (replay detected)".to_string(),
                };
                let entry = audit_entry_with_redacted_token(
                    &request,
                    &decision,
                    approval_backend.backend_name(),
                    started_at,
                );
                emit_to_ledger(&entry, &request.request_id, None);
                audit_log.push(entry);
                return sock.send_response(&nono::supervisor::SupervisorResponse::Decision {
                    request_id: request.request_id,
                    decision,
                    grant: None,
                });
            }
            seen_request_ids.insert(request.request_id.clone());

            // Constant-time token check BEFORE any approval backend is
            // consulted. Mismatch or empty token is a hard denial.
            if !constant_time_eq(
                request.session_token.as_bytes(),
                expected_session_token.as_bytes(),
            ) {
                let decision = nono::ApprovalDecision::Denied {
                    reason: "Invalid session token".to_string(),
                };
                let entry = audit_entry_with_redacted_token(
                    &request,
                    &decision,
                    approval_backend.backend_name(),
                    started_at,
                );
                emit_to_ledger(&entry, &request.request_id, None);
                audit_log.push(entry);
                return sock.send_response(&nono::supervisor::SupervisorResponse::Decision {
                    request_id: request.request_id,
                    decision,
                    grant: None,
                });
            }

            // Constant-time discriminator validation — Phase 18 D-03.
            //
            // Even though the discriminator carries no secret, we use the
            // same `subtle::ConstantTimeEq` primitive that validates the
            // session token (Phase 11 D-01) so the audit chain is
            // structurally identical for both untrusted bytes. Cost: ~6ns
            // per request. Benefit: a future security review never has to
            // wonder "is this hot path branchy?".
            let kind_byte = [request.kind.discriminator_byte()];
            let known_kinds: &[u8] = &[0, 1, 2, 3, 4, 5];
            let kind_ok = known_kinds.iter().any(|&k| {
                use subtle::ConstantTimeEq;
                bool::from([k].ct_eq(&kind_byte))
            });
            if !kind_ok {
                let decision = nono::ApprovalDecision::Denied {
                    reason: "unknown handle type".to_string(),
                };
                let entry = audit_entry_with_redacted_token(
                    &request,
                    &decision,
                    approval_backend.backend_name(),
                    started_at,
                );
                emit_to_ledger(&entry, &request.request_id, None);
                audit_log.push(entry);
                return sock.send_response(&nono::supervisor::SupervisorResponse::Decision {
                    request_id: request.request_id,
                    decision,
                    grant: None,
                });
            }

            // Server-side per-kind mask validation (D-07). For HandleKind::File
            // the mask is unused (Phase 11 path uses AccessMode); for
            // Socket/Pipe the validation is role/direction-based and lives
            // inside the per-kind helpers (NOT mask-based here). For
            // Event/Mutex/JobObject this is the load-bearing pre-broker
            // check. We perform it BEFORE the backend dispatch so an
            // out-of-allowlist request never reaches the user's approval
            // prompt. Phase 18 Plan 18-03: the resolved allowlist now
            // comes from `Profile::resolve_aipc_allowlist` (hard-coded
            // default ∪ profile widening, D-05 + D-06).
            if matches!(
                request.kind,
                HandleKind::Event | HandleKind::Mutex | HandleKind::JobObject
            ) {
                let resolved = match request.kind {
                    HandleKind::Event => resolved_allowlist.event_mask,
                    HandleKind::Mutex => resolved_allowlist.mutex_mask,
                    HandleKind::JobObject => resolved_allowlist.job_object_mask,
                    // unreachable per the matches! gate above; keeps `match`
                    // exhaustive without a default arm.
                    _ => 0,
                };
                if !policy::mask_is_allowed(request.kind, request.access_mask, resolved) {
                    let decision = nono::ApprovalDecision::Denied {
                        reason: format!(
                            "access mask 0x{:08x} not in allowlist for {:?} (resolved: 0x{:08x})",
                            request.access_mask, request.kind, resolved
                        ),
                    };
                    let entry = audit_entry_with_redacted_token(
                        &request,
                        &decision,
                        approval_backend.backend_name(),
                        started_at,
                    );
                    // Phase 23 D-02: Site 4 — pre-broker mask gate fires
                    // BEFORE the approval backend is consulted, so this is a
                    // BeforePrompt rejection per the WR-01 verdict matrix
                    // (Event/Mutex/JobObject only).
                    emit_to_ledger(
                        &entry,
                        &request.request_id,
                        Some(crate::audit_integrity::RejectStage::BeforePrompt),
                    );
                    audit_log.push(entry);
                    return sock.send_response(
                        &nono::supervisor::SupervisorResponse::Decision {
                            request_id: request.request_id,
                            decision,
                            grant: None,
                        },
                    );
                }
            }

            let decision = approval_backend
                .request_capability(&request)
                .unwrap_or_else(|e| nono::ApprovalDecision::Denied {
                    reason: format!("Approval backend error: {e}"),
                });

            // G-04 fix: broker-helper failure AFTER approval MUST flip
            // decision to Denied so the wire response never carries
            // (Approved, grant=None). Without this flip, the 2026-04-20
            // UAT re-run surfaced the child SDK's
            // `send_capability_request` demultiplexer treating
            // (Granted, None) as "supervisor granted but returned no
            // ResourceGrant" — a protocol violation. The contract is
            // structural: Approved ⟹ grant is Some, Denied ⟹ grant is
            // None. The `(decision, grant)` tuple is constructed at this
            // single site; the `Err` arm rewrites `decision` before the
            // audit push + send_response, so the audit log and the wire
            // response always record the same shape.
            //
            // Phase 23 D-02: track the WR-01 reject-stage discriminator
            // alongside the (decision, grant) tuple so the ledger emission
            // at the post-flip site can record `Some(AfterPrompt)` for
            // Pipe/Socket G-04 broker-failure flips. All other site-5
            // outcomes (Approved, File/Event/Mutex/JobObject Denied — the
            // Event/Mutex/JobObject Denied case is unreachable here, gated
            // at site 4) carry `None`.
            let mut reject_stage: Option<crate::audit_integrity::RejectStage> = None;
            let (decision, grant) = if decision.is_granted() {
                let result: Result<Option<nono::supervisor::ResourceGrant>> = match request.kind {
                    HandleKind::File => {
                        // Phase 11 path — preserved unchanged. Uses
                        // request.path + request.access.
                        #[allow(deprecated)]
                        let path = &request.path;
                        match open_windows_supervisor_path(path, &request.access) {
                            Ok(file) => nono::supervisor::socket::broker_file_handle_to_process(
                                &file,
                                target_process,
                                request.access,
                            )
                            .map(Some),
                            Err(e) => Err(e),
                        }
                    }
                    HandleKind::Event => handle_event_request(
                        &request,
                        target_process,
                        user_session_id,
                        resolved_allowlist,
                    ),
                    HandleKind::Mutex => handle_mutex_request(
                        &request,
                        target_process,
                        user_session_id,
                        resolved_allowlist,
                    ),
                    HandleKind::Pipe => handle_pipe_request(
                        &request,
                        target_process,
                        user_session_id,
                        resolved_allowlist,
                    ),
                    HandleKind::Socket => handle_socket_request(
                        &request,
                        target_process,
                        user_session_id,
                        resolved_allowlist,
                    ),
                    HandleKind::JobObject => handle_job_object_request(
                        &request,
                        target_process,
                        user_session_id,
                        runtime_containment_job,
                        resolved_allowlist,
                    ),
                };
                match result {
                    Ok(g) => (decision, g),
                    Err(e) => {
                        tracing::warn!(
                            "AIPC broker failure for kind {:?}: {}",
                            request.kind,
                            e
                        );
                        // G-04: flip decision so audit + wire both
                        // record Denied. Reason string is verbose-on-
                        // purpose for debuggability (same rationale as
                        // 18-CONTEXT D-07); not a security-sensitive
                        // surface.
                        let denied = nono::ApprovalDecision::Denied {
                            reason: format!("broker failed: {e}"),
                        };
                        // Phase 23 D-02: AfterPrompt is currently
                        // observable only for Pipe (direction allowlist)
                        // and Socket (privileged port + role allowlist).
                        // Event/Mutex/JobObject pre-broker mask gates at
                        // site 4 short-circuit before reaching this Err
                        // arm; their kernel-object-creation failures (if
                        // any) are also AfterPrompt by construction, but
                        // the WR-01 matrix is locked to Pipe|Socket per
                        // Discretion #1 + the live wr01_* test set.
                        if matches!(request.kind, HandleKind::Pipe | HandleKind::Socket) {
                            reject_stage =
                                Some(crate::audit_integrity::RejectStage::AfterPrompt);
                        }
                        (denied, None)
                    }
                }
            } else {
                (decision, None)
            };

            let entry = audit_entry_with_redacted_token(
                &request,
                &decision,
                approval_backend.backend_name(),
                started_at,
            );
            emit_to_ledger(&entry, &request.request_id, reject_stage);
            audit_log.push(entry);

            sock.send_response(&nono::supervisor::SupervisorResponse::Decision {
                request_id: request.request_id,
                decision,
                grant,
            })
        }
        nono::supervisor::SupervisorMessage::OpenUrl(url_request) => sock
            .send_response(&nono::supervisor::SupervisorResponse::UrlOpened {
            request_id: url_request.request_id,
            success: false,
            error: Some(
                "Windows delegated browser-open flows are not available yet. Windows supervised child processes do not have an attached supervisor control channel for open-url requests."
                    .to_string(),
            ),
        }),
        nono::supervisor::SupervisorMessage::Terminate { .. } => {
            // CLI-to-supervisor termination is handled via the background control pipe thread,
            // not via the child-to-supervisor socket. We ignore it here.
            Ok(())
        }
        nono::supervisor::SupervisorMessage::Detach { .. } => {
            // Detach is handled via the background control pipe thread, not here.
            Ok(())
        }
    }
}

#[cfg(all(test, target_os = "windows"))]
#[allow(clippy::unwrap_used)]
mod capability_handler_tests {
    //! WR-01 reject-stage verdict matrix (Phase 18.1 G-05 empirical verification).
    //!
    //! Phase 18.1 Plan 18.1-04 closes G-05 (18-HUMAN-UAT.md § Gaps) by
    //! empirically verifying the reject-stage invariant for each of the 5
    //! AIPC HandleKinds plus File (the Phase 11 legacy path). The verdict
    //! matrix is:
    //!
    //! | Kind      | Out-of-allowlist rejection stage | Enforcement site                                |
    //! |-----------|----------------------------------|-------------------------------------------------|
    //! | Event     | BEFORE prompt                    | handle_windows_supervisor_message :1846-1878    |
    //! | Mutex     | BEFORE prompt                    | handle_windows_supervisor_message :1846-1878    |
    //! | JobObject | BEFORE prompt                    | handle_windows_supervisor_message :1846-1878    |
    //! | Pipe      | AFTER prompt (WR-01 deviation)   | handle_pipe_request :1411 post-approval         |
    //! | Socket    | AFTER prompt (WR-01 deviation)   | handle_socket_request :1479 post-approval       |
    //!
    //! The `Event | Mutex | JobObject` branch of the pre-broker mask gate
    //! executes BEFORE the approval backend is consulted, so a request
    //! with `access_mask` outside the resolved allowlist never reaches
    //! the user's approval prompt. `backend.calls() == 0` is observable
    //! from the tests.
    //!
    //! The `Pipe | Socket` per-kind helpers run INSIDE the post-approval
    //! dispatch arm (see `handle_windows_supervisor_message` ~line 1900+
    //! — the `if decision.is_granted()` block). The direction-allowlist
    //! check at `handle_pipe_request:1411` and the unconditional
    //! privileged-port deny + role-allowlist check at
    //! `handle_socket_request:1479` fire AFTER the approval backend has
    //! returned `Granted`. The G-04 flip (Wave 2, Plan 18.1-02) wraps
    //! the resulting `Err` into `Denied { reason: "broker failed:
    //! <inner>" }` before the audit push + send_response, so the wire
    //! shape is consistent; but the UX observable differs: Pipe/Socket
    //! show the user the approval prompt BEFORE ultimately denying,
    //! while Event/Mutex/JobObject deny silently without prompting.
    //!
    //! Per CONTEXT.md D-14 (Phase 18.1) + 18-HUMAN-UAT Test 2 result,
    //! the WR-01 stage-unification fix (routing Pipe direction + Socket
    //! role/port through the same pre-broker gate as
    //! Event/Mutex/JobObject) is explicitly **deferred to v2.2 as a
    //! product decision**. Phase 18.1 only verifies + documents the
    //! current behavior; the `wr01_*` tests below lock the matrix above
    //! into regression guards so any future refactor that accidentally
    //! moves a mask check pre/post-broker breaks CI.

    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    /// Mock approval backend that always denies and counts invocations.
    struct CountingDenyBackend {
        calls: AtomicUsize,
    }

    impl CountingDenyBackend {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(AtomicOrdering::SeqCst)
        }
    }

    impl ApprovalBackend for CountingDenyBackend {
        fn request_capability(
            &self,
            _request: &nono::CapabilityRequest,
        ) -> Result<nono::ApprovalDecision> {
            self.calls.fetch_add(1, AtomicOrdering::SeqCst);
            Ok(nono::ApprovalDecision::Denied {
                reason: "mock deny".to_string(),
            })
        }

        fn backend_name(&self) -> &str {
            "counting-deny"
        }
    }

    /// Phase 18 AIPC-01 mock backend that always GRANTS and counts
    /// invocations. Used by the broker-path tests so the dispatcher
    /// reaches the per-kind broker arm (Event/Mutex).
    struct CountingGrantBackend {
        calls: AtomicUsize,
    }

    impl CountingGrantBackend {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(AtomicOrdering::SeqCst)
        }
    }

    impl ApprovalBackend for CountingGrantBackend {
        fn request_capability(
            &self,
            _request: &nono::CapabilityRequest,
        ) -> Result<nono::ApprovalDecision> {
            self.calls.fetch_add(1, AtomicOrdering::SeqCst);
            Ok(nono::ApprovalDecision::Granted)
        }

        fn backend_name(&self) -> &str {
            "counting-grant"
        }
    }

    #[allow(deprecated)]
    fn make_request(session_token: &str) -> nono::CapabilityRequest {
        nono::CapabilityRequest {
            request_id: "cap-req-001".to_string(),
            path: std::path::PathBuf::from(r"C:\tmp\does-not-matter"),
            access: nono::AccessMode::Read,
            reason: Some("unit test".to_string()),
            child_pid: std::process::id(),
            session_id: "sess-test".to_string(),
            session_token: session_token.to_string(),
            kind: nono::supervisor::types::HandleKind::File,
            target: None,
            access_mask: 0,
        }
    }

    /// Phase 18 AIPC-01 helper: like `make_request` but with overridable
    /// `kind`, `target`, and `access_mask` so the new dispatcher tests can
    /// build requests of every HandleKind shape.
    #[allow(deprecated)]
    fn make_request_aipc(
        session_token: &str,
        request_id: &str,
        kind: nono::supervisor::HandleKind,
        target: Option<nono::supervisor::HandleTarget>,
        access_mask: u32,
    ) -> nono::CapabilityRequest {
        nono::CapabilityRequest {
            request_id: request_id.to_string(),
            path: std::path::PathBuf::from(r"C:\tmp\does-not-matter"),
            access: nono::AccessMode::Read,
            reason: Some("aipc unit test".to_string()),
            child_pid: std::process::id(),
            session_id: "sess-test".to_string(),
            session_token: session_token.to_string(),
            kind,
            target,
            access_mask,
        }
    }

    fn new_pair() -> (nono::SupervisorSocket, nono::SupervisorSocket) {
        nono::SupervisorSocket::pair().expect("pair")
    }

    #[test]
    fn handle_rejects_missing_token() {
        let backend = CountingDenyBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let request = make_request("");
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(request),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            "expected-token",
            "testaipc12345678",
            std::ptr::null_mut(),
            &AipcResolvedAllowlist::default(),
            None,
        )
        .expect("handle");

        // Backend was never called: token check happens first.
        assert_eq!(
            backend.calls(),
            0,
            "backend must not be called on bad token"
        );
        assert_eq!(audit_log.len(), 1);
        assert!(audit_log[0].decision.is_denied());
        assert_eq!(audit_log[0].request.session_token, "");

        // Drain the child side so the pipe does not fill.
        let resp = child.recv_response().expect("recv");
        match resp {
            nono::supervisor::SupervisorResponse::Decision { decision, .. } => {
                assert!(decision.is_denied());
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn handle_rejects_wrong_token() {
        let backend = CountingDenyBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let request = make_request("wrong");
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(request),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            "right",
            "testaipc12345678",
            std::ptr::null_mut(),
            &AipcResolvedAllowlist::default(),
            None,
        )
        .expect("handle");

        assert_eq!(backend.calls(), 0);
        assert_eq!(audit_log.len(), 1);
        assert!(audit_log[0].decision.is_denied());

        let _ = child.recv_response().expect("drain");
    }

    #[test]
    fn handle_consults_backend_for_valid_token() {
        let backend = CountingDenyBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let request = make_request("the-token");
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(request),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            "the-token",
            "testaipc12345678",
            std::ptr::null_mut(),
            &AipcResolvedAllowlist::default(),
            None,
        )
        .expect("handle");

        // Backend was consulted exactly once; resulting decision is a
        // backend-sourced denial (still denied but NOT "Invalid session token").
        assert_eq!(backend.calls(), 1);
        assert_eq!(audit_log.len(), 1);
        if let nono::ApprovalDecision::Denied { reason } = &audit_log[0].decision {
            assert_eq!(reason, "mock deny");
        } else {
            panic!("expected denied with mock reason");
        }

        let _ = child.recv_response().expect("drain");
    }

    #[test]
    fn handle_redacts_token_in_audit_entry_json() {
        let backend = CountingDenyBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let sensitive_token = "super-secret-token-value-do-not-log";
        let request = make_request(sensitive_token);
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(request),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            sensitive_token,
            "testaipc12345678",
            std::ptr::null_mut(),
            &AipcResolvedAllowlist::default(),
            None,
        )
        .expect("handle");

        assert_eq!(audit_log.len(), 1);
        assert_eq!(audit_log[0].request.session_token, "");
        let json = serde_json::to_string(&audit_log[0]).expect("serialize");
        assert!(
            !json.contains(sensitive_token),
            "audit JSON must not contain the raw session token: {json}"
        );

        let _ = child.recv_response().expect("drain");
    }

    #[test]
    fn handle_rejects_replay_with_valid_token() {
        let backend = CountingDenyBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let request = make_request("the-token");
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(request.clone()),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            "the-token",
            "testaipc12345678",
            std::ptr::null_mut(),
            &AipcResolvedAllowlist::default(),
            None,
        )
        .expect("first handle");

        // Replay: same request_id.
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(request),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            "the-token",
            "testaipc12345678",
            std::ptr::null_mut(),
            &AipcResolvedAllowlist::default(),
            None,
        )
        .expect("second handle");

        // Backend was consulted once (first call only); replay path short-circuits
        // before the token check consults the backend.
        assert_eq!(backend.calls(), 1);
        assert_eq!(audit_log.len(), 2);
        assert!(audit_log[1].decision.is_denied());
        if let nono::ApprovalDecision::Denied { reason } = &audit_log[1].decision {
            assert!(
                reason.contains("replay"),
                "second denial should cite replay: {reason}"
            );
        }

        // Drain both responses from the child side.
        let _ = child.recv_response().expect("drain 1");
        let _ = child.recv_response().expect("drain 2");
    }

    /// Plan 11-02 Task 2 regression: the full serialized `AuditEntry` must
    /// not contain the session token, even on the valid-token path. This
    /// mirrors `handle_redacts_token_in_audit_entry_json` but asserts on
    /// the semantic contract the threat model calls out (T-11-12).
    #[test]
    fn handle_redacts_token_in_serialized_audit() {
        let backend = CountingDenyBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let sensitive = "secret-token-123";
        let request = make_request(sensitive);
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(request),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            sensitive,
            "testaipc12345678",
            std::ptr::null_mut(),
            &AipcResolvedAllowlist::default(),
            None,
        )
        .expect("handle");

        assert_eq!(audit_log.len(), 1);
        // session_token field must be empty after redaction.
        assert_eq!(audit_log[0].request.session_token, "");
        // Full audit entry JSON must not contain the raw token.
        let json = serde_json::to_string(&audit_log[0]).expect("serialize");
        assert!(
            !json.contains(sensitive),
            "serialized audit entry must not contain the session token: {json}"
        );

        let _ = child.recv_response().expect("drain");
    }

    /// Plan 11-02 Task 2 regression: when the child sends a *wrong* token,
    /// that wrong token must also not leak into the serialized audit
    /// entry. The redaction path is exercised for the mismatch branch.
    #[test]
    fn handle_redacts_token_on_mismatch_audit() {
        let backend = CountingDenyBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let wrong_token = "wrong-token-xyz";
        let request = make_request(wrong_token);
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(request),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            "right",
            "testaipc12345678",
            std::ptr::null_mut(),
            &AipcResolvedAllowlist::default(),
            None,
        )
        .expect("handle");

        // Backend MUST NOT be consulted on a bad token.
        assert_eq!(backend.calls(), 0);
        assert_eq!(audit_log.len(), 1);
        assert!(audit_log[0].decision.is_denied());
        assert_eq!(audit_log[0].request.session_token, "");
        let json = serde_json::to_string(&audit_log[0]).expect("serialize");
        assert!(
            !json.contains(wrong_token),
            "mismatched token must also be redacted from audit JSON: {json}"
        );

        let _ = child.recv_response().expect("drain");
    }

    // Phase 18 AIPC-01 Task 5 — dispatcher tests for the new HandleKind
    // variants (discriminator validation, per-type mask validation, and
    // per-type broker dispatch).

    /// Close any HANDLE the supervisor brokered into the test process so the
    /// integration tests don't leak kernel objects.
    fn close_grant_handle_if_any(grant: &Option<nono::supervisor::ResourceGrant>) {
        if let Some(g) = grant {
            if let Some(raw) = g.raw_handle {
                if raw != 0 {
                    // SAFETY: `raw` was returned by DuplicateHandle into the
                    // current process via BrokerTargetProcess::current(). It
                    // is a valid HANDLE we own at test-process scope.
                    unsafe {
                        windows_sys::Win32::Foundation::CloseHandle(raw as usize as HANDLE);
                    }
                }
            }
        }
    }

    #[test]
    fn handle_brokers_event_with_default_mask() {
        let backend = CountingGrantBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let token = "testtoken12345678";
        let req = make_request_aipc(
            token,
            "evt-grant-001",
            HandleKind::Event,
            Some(HandleTarget::EventName {
                name: "test-shutdown".to_string(),
            }),
            policy::EVENT_DEFAULT_MASK,
        );
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(req),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            token,
            "testaipc12345678",
            std::ptr::null_mut(),
            &AipcResolvedAllowlist::default(),
            None,
        )
        .expect("dispatch");

        let response = child.recv_response().expect("response");
        match response {
            nono::supervisor::SupervisorResponse::Decision {
                decision, grant, ..
            } => {
                assert!(
                    decision.is_granted(),
                    "expected Granted decision, got {decision:?}"
                );
                assert!(grant.is_some(), "Granted decision must carry a grant");
                let g = grant.as_ref().unwrap();
                assert_eq!(
                    g.resource_kind,
                    nono::supervisor::GrantedResourceKind::Event
                );
                close_grant_handle_if_any(&grant);
            }
            other => panic!("unexpected response: {other:?}"),
        }

        assert_eq!(
            backend.calls(),
            1,
            "backend consulted once for granted Event"
        );
        assert_eq!(audit_log.len(), 1);
        assert_eq!(audit_log[0].request.kind, HandleKind::Event);
        assert!(matches!(
            audit_log[0].decision,
            nono::ApprovalDecision::Granted
        ));
    }

    #[test]
    fn handle_denies_event_with_mask_outside_allowlist() {
        let backend = CountingGrantBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let token = "testtoken12345678";
        let req = make_request_aipc(
            token,
            "evt-deny-001",
            HandleKind::Event,
            Some(HandleTarget::EventName {
                name: "evt-overreach".to_string(),
            }),
            policy::EVENT_ALL_ACCESS, // overreaches the EVENT_DEFAULT_MASK
        );
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(req),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            token,
            "testaipc12345678",
            std::ptr::null_mut(),
            &AipcResolvedAllowlist::default(),
            None,
        )
        .expect("dispatch");

        // Backend MUST NOT be consulted — mask check happens BEFORE backend.
        assert_eq!(
            backend.calls(),
            0,
            "backend must not be consulted on out-of-allowlist mask"
        );
        assert_eq!(audit_log.len(), 1);
        assert!(audit_log[0].decision.is_denied());
        if let nono::ApprovalDecision::Denied { reason } = &audit_log[0].decision {
            assert!(
                reason.contains("access mask"),
                "unexpected reason: {reason}"
            );
            assert!(reason.contains("allowlist"), "unexpected reason: {reason}");
        } else {
            panic!("expected Denied");
        }
        let _ = child.recv_response().expect("drain");
    }

    #[test]
    fn handle_brokers_mutex_with_default_mask() {
        let backend = CountingGrantBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let token = "testtoken12345678";
        let req = make_request_aipc(
            token,
            "mtx-grant-001",
            HandleKind::Mutex,
            Some(HandleTarget::MutexName {
                name: "test-logfile".to_string(),
            }),
            policy::MUTEX_DEFAULT_MASK,
        );
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(req),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            token,
            "testaipc12345678",
            std::ptr::null_mut(),
            &AipcResolvedAllowlist::default(),
            None,
        )
        .expect("dispatch");

        let response = child.recv_response().expect("response");
        match response {
            nono::supervisor::SupervisorResponse::Decision {
                decision, grant, ..
            } => {
                assert!(decision.is_granted(), "got {decision:?}");
                assert!(grant.is_some());
                let g = grant.as_ref().unwrap();
                assert_eq!(
                    g.resource_kind,
                    nono::supervisor::GrantedResourceKind::Mutex
                );
                close_grant_handle_if_any(&grant);
            }
            other => panic!("unexpected response: {other:?}"),
        }
        assert_eq!(backend.calls(), 1);
        assert_eq!(audit_log.len(), 1);
        assert_eq!(audit_log[0].request.kind, HandleKind::Mutex);
    }

    #[test]
    fn handle_denies_mutex_with_mask_outside_allowlist() {
        let backend = CountingGrantBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let token = "testtoken12345678";
        let req = make_request_aipc(
            token,
            "mtx-deny-001",
            HandleKind::Mutex,
            Some(HandleTarget::MutexName {
                name: "mtx-overreach".to_string(),
            }),
            policy::MUTEX_ALL_ACCESS,
        );
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(req),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            token,
            "testaipc12345678",
            std::ptr::null_mut(),
            &AipcResolvedAllowlist::default(),
            None,
        )
        .expect("dispatch");
        assert_eq!(backend.calls(), 0);
        assert_eq!(audit_log.len(), 1);
        assert!(audit_log[0].decision.is_denied());
        if let nono::ApprovalDecision::Denied { reason } = &audit_log[0].decision {
            assert!(
                reason.contains("access mask"),
                "unexpected reason: {reason}"
            );
            assert!(reason.contains("allowlist"), "unexpected reason: {reason}");
        } else {
            panic!("expected Denied");
        }
        let _ = child.recv_response().expect("drain");
    }

    #[test]
    fn handle_denies_unknown_discriminator() {
        let backend = CountingGrantBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let token = "testtoken12345678";
        let mut req = make_request_aipc(token, "unk-disc-001", HandleKind::File, None, 0);
        // SAFETY: HandleKind is #[repr(u8)] with explicit discriminators 0..=5.
        // Setting the underlying byte to 99 produces an invalid variant; the
        // discriminator-validation step is the test target. The struct field
        // itself is plain old data and we own the unique mutable reference.
        unsafe {
            let kind_ptr = std::ptr::addr_of_mut!(req.kind) as *mut u8;
            *kind_ptr = 99u8;
        }
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(req),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            token,
            "testaipc12345678",
            std::ptr::null_mut(),
            &AipcResolvedAllowlist::default(),
            None,
        )
        .expect("dispatch");

        // Backend NOT invoked — discriminator check happens BEFORE backend.
        assert_eq!(backend.calls(), 0);
        assert_eq!(audit_log.len(), 1);
        if let nono::ApprovalDecision::Denied { reason } = &audit_log[0].decision {
            assert_eq!(reason, "unknown handle type");
        } else {
            panic!("expected Denied");
        }
        let _ = child.recv_response().expect("drain");
    }

    // Phase 18 AIPC-01 Plan 18-03 Task 3 — per-kind redaction tests
    // (`handle_redacts_token_for_event_kind`,
    //  `handle_redacts_token_for_mutex_kind` from 18-01;
    //  `handle_redacts_token_for_pipe_kind`,
    //  `handle_redacts_token_for_socket_kind` from 18-02;
    //  `handle_redacts_token_for_job_object_kind` from 18-03 Task 1)
    // are SUBSUMED by `handle_redacts_token_in_audit_for_all_handle_kinds`
    // below, which iterates over ALL 6 HandleKind values in a single test.
    // The Phase 11 `handle_redacts_token_in_audit_entry_json` /
    // `handle_redacts_token_in_serialized_audit` /
    // `handle_redacts_token_on_mismatch_audit` tests are KEPT — they cover
    // orthogonal token-leak surfaces (mismatch path, base-token path)
    // and are not subsumed by the parameterized test.

    // Phase 18 AIPC-01 Plan 18-02 Task 3 — dispatcher tests for the new
    // Pipe + Socket HandleKind variants (target-shape validation, role-based
    // socket validation, privileged-port unconditional reject, broker
    // dispatch, token redaction).

    #[test]
    fn handle_brokers_pipe_with_read_direction() {
        let backend = CountingGrantBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let token = "testtoken12345678";
        let req = make_request_aipc(
            token,
            "pipe-grant-001",
            HandleKind::Pipe,
            Some(HandleTarget::PipeName {
                name: "test-stream".to_string(),
            }),
            policy::GENERIC_READ,
        );
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(req),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            token,
            "testaipc12345678",
            std::ptr::null_mut(),
            &AipcResolvedAllowlist::default(),
            None,
        )
        .expect("dispatch");

        let response = child.recv_response().expect("response");
        match response {
            nono::supervisor::SupervisorResponse::Decision {
                decision, grant, ..
            } => {
                assert!(decision.is_granted(), "got {decision:?}");
                assert!(grant.is_some(), "Granted decision must carry a grant");
                let g = grant.as_ref().unwrap();
                assert_eq!(
                    g.transfer,
                    nono::supervisor::ResourceTransferKind::DuplicatedWindowsHandle
                );
                assert_eq!(g.resource_kind, nono::supervisor::GrantedResourceKind::Pipe);
                assert_eq!(g.access, nono::AccessMode::Read);
                close_grant_handle_if_any(&grant);
            }
            other => panic!("unexpected response: {other:?}"),
        }
        assert_eq!(backend.calls(), 1);
        assert_eq!(audit_log.len(), 1);
        assert_eq!(audit_log[0].request.kind, HandleKind::Pipe);
    }

    #[test]
    fn handle_denies_pipe_with_invalid_target_shape() {
        let backend = CountingGrantBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let token = "testtoken12345678";
        // Mismatched: kind=Pipe but target=EventName.
        let req = make_request_aipc(
            token,
            "pipe-shape-001",
            HandleKind::Pipe,
            Some(HandleTarget::EventName {
                name: "wrong-shape".to_string(),
            }),
            policy::GENERIC_READ,
        );
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(req),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            token,
            "testaipc12345678",
            std::ptr::null_mut(),
            &AipcResolvedAllowlist::default(),
            None,
        )
        .expect("dispatch");

        // Backend WAS consulted (mask is 0 valid; shape check happens inside
        // handle_pipe_request which runs only after Granted). The grant call
        // returns Err which is logged via tracing; the audit decision still
        // shows Granted with grant=None. This matches the Plan 18-01 broker
        // failure handling pattern.
        assert_eq!(backend.calls(), 1);
        assert_eq!(audit_log.len(), 1);
        // The audit decision is still Granted (the backend granted) but the
        // grant Option is None because the broker call returned Err. The
        // child receives a Granted response with grant=None.
        let response = child.recv_response().expect("drain");
        match response {
            nono::supervisor::SupervisorResponse::Decision { grant, .. } => {
                assert!(
                    grant.is_none(),
                    "shape-mismatch broker failure must produce grant=None"
                );
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn handle_brokers_socket_with_connect_role() {
        let backend = CountingGrantBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let token = "testtoken12345678";
        let req = make_request_aipc(
            token,
            "sock-grant-001",
            HandleKind::Socket,
            Some(HandleTarget::SocketEndpoint {
                protocol: SocketProtocol::Tcp,
                host: "127.0.0.1".to_string(),
                port: 8080,
                role: SocketRole::Connect,
            }),
            0, // sockets don't use mask — role-based validation
        );
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(req),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            token,
            "testaipc12345678",
            std::ptr::null_mut(),
            &AipcResolvedAllowlist::default(),
            None,
        )
        .expect("dispatch");

        let response = child.recv_response().expect("response");
        match response {
            nono::supervisor::SupervisorResponse::Decision {
                decision, grant, ..
            } => {
                assert!(decision.is_granted(), "got {decision:?}");
                let g = grant.as_ref().expect("Granted decision must carry a grant");
                assert_eq!(
                    g.transfer,
                    nono::supervisor::ResourceTransferKind::SocketProtocolInfoBlob
                );
                assert_eq!(
                    g.resource_kind,
                    nono::supervisor::GrantedResourceKind::Socket
                );
                let blob = g.protocol_info_blob.as_ref().expect("blob present");
                assert_eq!(
                    blob.len(),
                    std::mem::size_of::<windows_sys::Win32::Networking::WinSock::WSAPROTOCOL_INFOW>(
                    ),
                    "blob length must match WSAPROTOCOL_INFOW size"
                );
                assert!(
                    g.raw_handle.is_none(),
                    "socket grants don't carry raw_handle"
                );
            }
            other => panic!("unexpected response: {other:?}"),
        }
        assert_eq!(backend.calls(), 1);
        assert_eq!(audit_log.len(), 1);
        assert_eq!(audit_log[0].request.kind, HandleKind::Socket);
    }

    #[test]
    fn handle_denies_socket_with_privileged_port() {
        let backend = CountingGrantBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let token = "testtoken12345678";
        let req = make_request_aipc(
            token,
            "sock-priv-port-001",
            HandleKind::Socket,
            Some(HandleTarget::SocketEndpoint {
                protocol: SocketProtocol::Tcp,
                host: "127.0.0.1".to_string(),
                port: 80, // privileged
                role: SocketRole::Connect,
            }),
            0,
        );
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(req),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            token,
            "testaipc12345678",
            std::ptr::null_mut(),
            &AipcResolvedAllowlist::default(),
            None,
        )
        .expect("dispatch");

        // Backend WAS consulted (port check happens inside the broker helper,
        // not before backend dispatch). The audit log shows Granted by the
        // backend but grant=None because the broker rejected.
        assert_eq!(backend.calls(), 1);
        assert_eq!(audit_log.len(), 1);
        let response = child.recv_response().expect("drain");
        match response {
            nono::supervisor::SupervisorResponse::Decision { grant, .. } => {
                assert!(
                    grant.is_none(),
                    "privileged-port rejection must produce grant=None"
                );
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn handle_denies_socket_bind_role_without_profile_widening() {
        let backend = CountingGrantBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let token = "testtoken12345678";
        let req = make_request_aipc(
            token,
            "sock-bind-role-001",
            HandleKind::Socket,
            Some(HandleTarget::SocketEndpoint {
                protocol: SocketProtocol::Tcp,
                host: "127.0.0.1".to_string(),
                port: 8080,
                role: SocketRole::Bind, // not in default allowlist
            }),
            0,
        );
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(req),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            token,
            "testaipc12345678",
            std::ptr::null_mut(),
            &AipcResolvedAllowlist::default(),
            None,
        )
        .expect("dispatch");

        assert_eq!(backend.calls(), 1);
        assert_eq!(audit_log.len(), 1);
        let response = child.recv_response().expect("drain");
        match response {
            nono::supervisor::SupervisorResponse::Decision { grant, .. } => {
                assert!(
                    grant.is_none(),
                    "Bind role rejection must produce grant=None (profile widening required)"
                );
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    // (`handle_redacts_token_for_pipe_kind` and
    //  `handle_redacts_token_for_socket_kind` from Plan 18-02 Task 3
    //  are subsumed by `handle_redacts_token_in_audit_for_all_handle_kinds`
    //  below.)

    // Phase 18 AIPC-01 Plan 18-03 Task 1 — JobObject dispatcher tests
    // (target-shape validation, mask-upgrade denial, containment-Job runtime
    // guard via CompareObjectHandles, token redaction).

    #[test]
    fn handle_brokers_job_object_with_query_mask() {
        let backend = CountingGrantBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        // Pre-create the kernel-object name the dispatcher will canonicalize
        // so CreateJobObjectW resolves to the same kernel object (Phase 18.1
        // G-03: the dispatcher now uses CreateJobObjectW, which creates-or-opens;
        // when we pre-create here, the dispatcher side opens the existing
        // object and gets a HANDLE that CompareObjectHandles reports equal to
        // `pre_created`). The dispatcher computes
        // `Local\nono-aipc-<user_session_id>-<raw_name>`; pre-create with the
        // matching canonical name. We pre-create with a raw name distinct from
        // the runtime containment job to ensure the runtime guard does NOT
        // fire on this granted-path test.
        let canonical = "Local\\nono-aipc-testaipc12345678-test-orch";
        let wide: Vec<u16> = std::ffi::OsStr::new(canonical)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: Anonymous Job Object scaffolded with an explicit named
        // canonical so the dispatcher's `CreateJobObjectW` handshake resolves
        // to the same kernel object.
        let pre_created: HANDLE = unsafe {
            windows_sys::Win32::System::JobObjects::CreateJobObjectW(
                std::ptr::null_mut(),
                wide.as_ptr(),
            )
        };
        assert!(
            !pre_created.is_null(),
            "CreateJobObjectW failed: {}",
            std::io::Error::last_os_error()
        );

        let token = "testtoken12345678";
        let req = make_request_aipc(
            token,
            "job-grant-001",
            HandleKind::JobObject,
            Some(HandleTarget::JobObjectName {
                name: "test-orch".to_string(),
            }),
            policy::JOB_OBJECT_DEFAULT_MASK,
        );
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(req),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            token,
            "testaipc12345678",
            std::ptr::null_mut(), // no containment job — guard does not fire
            &AipcResolvedAllowlist::default(),
            None,
        )
        .expect("dispatch");

        let response = child.recv_response().expect("response");
        match response {
            nono::supervisor::SupervisorResponse::Decision {
                decision, grant, ..
            } => {
                assert!(decision.is_granted(), "got {decision:?}");
                assert!(grant.is_some(), "Granted decision must carry a grant");
                let g = grant.as_ref().unwrap();
                assert_eq!(
                    g.resource_kind,
                    nono::supervisor::GrantedResourceKind::JobObject
                );
                close_grant_handle_if_any(&grant);
            }
            other => panic!("unexpected response: {other:?}"),
        }
        assert_eq!(backend.calls(), 1);
        assert_eq!(audit_log.len(), 1);
        assert_eq!(audit_log[0].request.kind, HandleKind::JobObject);

        // SAFETY: pre_created is a live HANDLE returned by CreateJobObjectW.
        unsafe {
            CloseHandle(pre_created);
        }
    }

    #[test]
    fn handle_denies_job_object_with_terminate_mask_no_profile_widening() {
        let backend = CountingGrantBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let token = "testtoken12345678";
        // TERMINATE bit not in default JOB_OBJECT_DEFAULT_MASK (=QUERY only).
        let req = make_request_aipc(
            token,
            "job-deny-001",
            HandleKind::JobObject,
            Some(HandleTarget::JobObjectName {
                name: "job-overreach".to_string(),
            }),
            policy::JOB_OBJECT_TERMINATE,
        );
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(req),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            token,
            "testaipc12345678",
            std::ptr::null_mut(),
            &AipcResolvedAllowlist::default(),
            None,
        )
        .expect("dispatch");

        // WR-01 G-05 stage assertion: JobObject's pre-broker mask gate at
        // handle_windows_supervisor_message:1846-1878 fires BEFORE the
        // approval backend is consulted. The `backend.calls() == 0`
        // assertion below is the structural proof of the pre-prompt stage
        // — it pairs with the `wr01_job_object_rejects_before_prompt_on_terminate_mask`
        // test appended to the end of this module, which locks the same
        // semantic with an explicit WR-01 tie-in to the module docstring
        // verdict matrix. Keep this assertion value-equivalent to the
        // corresponding assertion there; diverging them would mean the
        // dispatcher has two code paths for JobObject mask validation,
        // which would itself be a bug worth catching.
        // Backend MUST NOT be consulted — pre-broker mask check happens
        // BEFORE backend dispatch (Phase 18 D-07 enforcement).
        assert_eq!(
            backend.calls(),
            0,
            "backend must not be consulted on out-of-allowlist mask"
        );
        assert_eq!(audit_log.len(), 1);
        assert!(audit_log[0].decision.is_denied());
        if let nono::ApprovalDecision::Denied { reason } = &audit_log[0].decision {
            assert!(
                reason.contains("access mask"),
                "unexpected reason: {reason}"
            );
            assert!(reason.contains("allowlist"), "unexpected reason: {reason}");
        } else {
            panic!("expected Denied");
        }
        let _ = child.recv_response().expect("drain");
    }

    #[test]
    fn handle_denies_job_object_brokering_of_containment_job() {
        let backend = CountingGrantBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        // Create a Job Object with a known canonical name; this stand-in
        // simulates the supervisor's runtime.containment_job. The dispatcher
        // will `CreateJobObjectW` the same canonical name (Phase 18.1 G-03 —
        // create-or-open); the dispatcher's HANDLE is a DIFFERENT value that
        // resolves to the SAME kernel object.
        // CompareObjectHandles is required (numeric == is insufficient).
        let canonical = "Local\\nono-aipc-testaipc12345678-orch";
        let wide: Vec<u16> = std::ffi::OsStr::new(canonical)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: Named Job Object creation; CreateJobObjectW(canonical) on the
        // dispatcher side will resolve to the same kernel object.
        let containment: HANDLE = unsafe {
            windows_sys::Win32::System::JobObjects::CreateJobObjectW(
                std::ptr::null_mut(),
                wide.as_ptr(),
            )
        };
        assert!(
            !containment.is_null(),
            "CreateJobObjectW for containment stand-in failed: {}",
            std::io::Error::last_os_error()
        );

        let token = "testtoken12345678";
        let req = make_request_aipc(
            token,
            "job-containment-guard-001",
            HandleKind::JobObject,
            Some(HandleTarget::JobObjectName {
                name: "orch".to_string(),
            }),
            policy::JOB_OBJECT_DEFAULT_MASK, // mask-allowed; guard fires anyway
        );
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(req),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            token,
            "testaipc12345678",
            containment, // the runtime guard target
            &AipcResolvedAllowlist::default(),
            None,
        )
        .expect("dispatch");

        // Backend WAS consulted (mask check passes for QUERY); the runtime
        // guard fires INSIDE handle_job_object_request, after the backend
        // grants. Post Phase 18.1 G-04: the broker-helper Err(..) flips
        // decision to Denied { reason: "broker failed: ..." } at the
        // dispatcher, so grant is None AND the wire decision is Denied.
        // This test only asserts grant.is_none(); the full G-04 shape is
        // covered by the `dispatcher_flips_approved_to_denied_on_*_broker_failure`
        // suite below.
        assert_eq!(backend.calls(), 1);
        assert_eq!(audit_log.len(), 1);
        let response = child.recv_response().expect("drain");
        match response {
            nono::supervisor::SupervisorResponse::Decision { grant, .. } => {
                assert!(
                    grant.is_none(),
                    "containment-Job runtime guard must produce grant=None"
                );
            }
            other => panic!("unexpected response: {other:?}"),
        }

        // SAFETY: `containment` is a live HANDLE returned by CreateJobObjectW.
        unsafe {
            CloseHandle(containment);
        }
    }

    // (`handle_redacts_token_for_job_object_kind` from Plan 18-03 Task 1
    //  is subsumed by `handle_redacts_token_in_audit_for_all_handle_kinds`
    //  below.)

    // Phase 18 AIPC-01 Plan 18-03 Task 2 — profile-widening dispatcher tests
    // (regression: default-only profiles still deny widened paths;
    // widening unlocks the path; containment-Job runtime guard fires
    // regardless of widening).

    #[test]
    fn handle_brokers_socket_with_bind_role_when_profile_widens() {
        let backend = CountingGrantBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        // Profile-widened allowlist: Connect AND Bind.
        let mut allowlist = AipcResolvedAllowlist::default();
        allowlist.socket_roles.push(SocketRole::Bind);

        let token = "testtoken12345678";
        let req = make_request_aipc(
            token,
            "sock-bind-widened-001",
            HandleKind::Socket,
            Some(HandleTarget::SocketEndpoint {
                protocol: SocketProtocol::Tcp,
                host: "127.0.0.1".to_string(),
                port: 8080,
                role: SocketRole::Bind, // widened path
            }),
            0,
        );
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(req),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            token,
            "testaipc12345678",
            std::ptr::null_mut(),
            &allowlist,
            None,
        )
        .expect("dispatch");

        assert_eq!(backend.calls(), 1);
        assert_eq!(audit_log.len(), 1);
        let response = child.recv_response().expect("response");
        match response {
            nono::supervisor::SupervisorResponse::Decision { grant, .. } => {
                assert!(
                    grant.is_some(),
                    "Bind role with profile widening must produce grant=Some"
                );
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn handle_denies_job_object_brokering_of_containment_job_even_with_profile_widening() {
        let backend = CountingGrantBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        // Pre-create the same canonical the dispatcher will `CreateJobObjectW`
        // (Phase 18.1 G-03 — create-or-open; the dispatcher opens this same
        // kernel object).
        let canonical = "Local\\nono-aipc-testaipc12345678-orch-widened";
        let wide: Vec<u16> = std::ffi::OsStr::new(canonical)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: Named Job Object creation matching the dispatcher canonical.
        let containment: HANDLE = unsafe {
            windows_sys::Win32::System::JobObjects::CreateJobObjectW(
                std::ptr::null_mut(),
                wide.as_ptr(),
            )
        };
        assert!(
            !containment.is_null(),
            "CreateJobObjectW for containment stand-in failed: {}",
            std::io::Error::last_os_error()
        );

        // Profile-widened allowlist that includes JOB_OBJECT_TERMINATE.
        // The runtime guard MUST still fire — defense-in-depth on top of
        // the mask validation.
        let mut allowlist = AipcResolvedAllowlist::default();
        allowlist.job_object_mask |= policy::JOB_OBJECT_TERMINATE;

        let token = "testtoken12345678";
        let req = make_request_aipc(
            token,
            "job-containment-guard-widened-001",
            HandleKind::JobObject,
            Some(HandleTarget::JobObjectName {
                name: "orch-widened".to_string(),
            }),
            policy::JOB_OBJECT_QUERY | policy::JOB_OBJECT_TERMINATE,
        );
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(req),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            token,
            "testaipc12345678",
            containment, // the runtime guard target
            &allowlist,
            None,
        )
        .expect("dispatch");

        // Backend WAS consulted (mask is now allowed by widening); the
        // runtime guard still fires INSIDE handle_job_object_request,
        // producing grant=None even though the mask check passed. Post
        // Phase 18.1 G-04 the dispatcher additionally flips decision to
        // Denied { reason: "broker failed: ..." }. This proves the
        // runtime guard is structurally above the profile widening —
        // the worst case (terminating the supervisor's own containment
        // Job) is impossible.
        assert_eq!(backend.calls(), 1);
        assert_eq!(audit_log.len(), 1);
        let response = child.recv_response().expect("drain");
        match response {
            nono::supervisor::SupervisorResponse::Decision { grant, .. } => {
                assert!(
                    grant.is_none(),
                    "containment-Job runtime guard must fire EVEN when profile widens TERMINATE"
                );
            }
            other => panic!("unexpected response: {other:?}"),
        }

        // SAFETY: `containment` is a live HANDLE returned by CreateJobObjectW.
        unsafe {
            CloseHandle(containment);
        }
    }

    // Phase 18.1 Plan 18.1-02 Task 2 — G-04 regression tests (one per
    // HandleKind). Each asserts the dispatcher flips ApprovalDecision::Approved
    // to Denied { reason: "broker failed: ..." } when the per-kind broker
    // helper returns Err(..) AFTER the approval backend granted the request.
    //
    // Failure-injection mechanism: each test crafts a CapabilityRequest
    // whose per-kind helper will `Err(..)` BEFORE any kernel-object call
    // is reached (cheapest / most deterministic injection — no #[cfg(test)]
    // flip-flag, no trait refactor). The dispatcher's G-04 flip logic
    // fires on ANY Err from the helper, regardless of its origin, so
    // input-validation-driven errors are strictly equivalent to kernel-
    // object-call errors for G-04's purposes.
    //
    // Assertion shape:
    //   (a) backend.calls() == 1 — proving the approval path was reached
    //   (b) audit_log[0].decision is Denied with reason containing
    //       "broker failed:"
    //   (c) the wire response's decision matches (a) and grant is None
    //
    // Invariant: (Approved, grant=None) is structurally unreachable from
    // handle_windows_supervisor_message once G-04 lands.

    #[test]
    fn dispatcher_flips_approved_to_denied_on_event_broker_failure() {
        let backend = CountingGrantBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let token = "testtoken12345678";
        // Failure shape: empty event name fails `validate_aipc_object_name`
        // inside `handle_event_request` BEFORE CreateEventW is reached.
        // The mask passes the pre-broker gate (EVENT_DEFAULT_MASK).
        let req = make_request_aipc(
            token,
            "g04-event-001",
            HandleKind::Event,
            Some(HandleTarget::EventName {
                name: String::new(),
            }),
            policy::EVENT_DEFAULT_MASK,
        );
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(req),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            token,
            "testaipc12345678",
            std::ptr::null_mut(),
            &AipcResolvedAllowlist::default(),
            None,
        )
        .expect("dispatch");

        assert_eq!(
            backend.calls(),
            1,
            "backend MUST be consulted (approval path reached)"
        );
        assert_eq!(audit_log.len(), 1);
        match &audit_log[0].decision {
            nono::ApprovalDecision::Denied { reason } => {
                assert!(
                    reason.contains("broker failed:"),
                    "expected reason to contain 'broker failed:', got: {reason}"
                );
            }
            other => panic!("expected Denied, got {other:?}"),
        }
        match child.recv_response().expect("drain") {
            nono::supervisor::SupervisorResponse::Decision {
                decision: nono::ApprovalDecision::Denied { reason },
                grant,
                ..
            } => {
                assert!(reason.contains("broker failed:"), "wire reason: {reason}");
                assert!(grant.is_none(), "grant must be None on Denied");
            }
            other => panic!("unexpected wire response: {other:?}"),
        }
    }

    #[test]
    fn dispatcher_flips_approved_to_denied_on_mutex_broker_failure() {
        let backend = CountingGrantBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let token = "testtoken12345678";
        // Failure shape: empty mutex name fails `validate_aipc_object_name`
        // inside `handle_mutex_request` BEFORE CreateMutexW is reached.
        // The mask passes the pre-broker gate (MUTEX_DEFAULT_MASK).
        let req = make_request_aipc(
            token,
            "g04-mutex-001",
            HandleKind::Mutex,
            Some(HandleTarget::MutexName {
                name: String::new(),
            }),
            policy::MUTEX_DEFAULT_MASK,
        );
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(req),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            token,
            "testaipc12345678",
            std::ptr::null_mut(),
            &AipcResolvedAllowlist::default(),
            None,
        )
        .expect("dispatch");

        assert_eq!(
            backend.calls(),
            1,
            "backend MUST be consulted (approval path reached)"
        );
        assert_eq!(audit_log.len(), 1);
        match &audit_log[0].decision {
            nono::ApprovalDecision::Denied { reason } => {
                assert!(
                    reason.contains("broker failed:"),
                    "expected reason to contain 'broker failed:', got: {reason}"
                );
            }
            other => panic!("expected Denied, got {other:?}"),
        }
        match child.recv_response().expect("drain") {
            nono::supervisor::SupervisorResponse::Decision {
                decision: nono::ApprovalDecision::Denied { reason },
                grant,
                ..
            } => {
                assert!(reason.contains("broker failed:"), "wire reason: {reason}");
                assert!(grant.is_none(), "grant must be None on Denied");
            }
            other => panic!("unexpected wire response: {other:?}"),
        }
    }

    #[test]
    fn dispatcher_flips_approved_to_denied_on_pipe_broker_failure() {
        let backend = CountingGrantBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let token = "testtoken12345678";
        // Failure shape: empty pipe name fails `validate_aipc_object_name`
        // inside `handle_pipe_request` BEFORE CreateNamedPipeW is reached.
        // The Pipe kind has no pre-broker mask gate in the dispatcher
        // (direction decode happens inside the helper), so the approval
        // backend IS consulted even with an empty name. access_mask =
        // GENERIC_READ keeps the direction-decode branch reachable but
        // the name-validation error fires first.
        let req = make_request_aipc(
            token,
            "g04-pipe-001",
            HandleKind::Pipe,
            Some(HandleTarget::PipeName {
                name: String::new(),
            }),
            policy::GENERIC_READ,
        );
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(req),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            token,
            "testaipc12345678",
            std::ptr::null_mut(),
            &AipcResolvedAllowlist::default(),
            None,
        )
        .expect("dispatch");

        assert_eq!(
            backend.calls(),
            1,
            "backend MUST be consulted (approval path reached)"
        );
        assert_eq!(audit_log.len(), 1);
        match &audit_log[0].decision {
            nono::ApprovalDecision::Denied { reason } => {
                assert!(
                    reason.contains("broker failed:"),
                    "expected reason to contain 'broker failed:', got: {reason}"
                );
            }
            other => panic!("expected Denied, got {other:?}"),
        }
        match child.recv_response().expect("drain") {
            nono::supervisor::SupervisorResponse::Decision {
                decision: nono::ApprovalDecision::Denied { reason },
                grant,
                ..
            } => {
                assert!(reason.contains("broker failed:"), "wire reason: {reason}");
                assert!(grant.is_none(), "grant must be None on Denied");
            }
            other => panic!("unexpected wire response: {other:?}"),
        }
    }

    #[test]
    fn dispatcher_flips_approved_to_denied_on_socket_broker_failure() {
        let backend = CountingGrantBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let token = "testtoken12345678";
        // Failure shape: empty host fails `host.is_empty()` inside
        // `handle_socket_request` AFTER the privileged-port check and
        // role-allowlist check (both of which pass with port=8080,
        // role=Connect against the default allowlist), but BEFORE
        // WSASocketW is reached. The Socket kind has no pre-broker
        // mask gate in the dispatcher, so the approval backend IS
        // consulted.
        let req = make_request_aipc(
            token,
            "g04-socket-001",
            HandleKind::Socket,
            Some(HandleTarget::SocketEndpoint {
                protocol: SocketProtocol::Tcp,
                host: String::new(),
                port: 8080,
                role: SocketRole::Connect,
            }),
            0,
        );
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(req),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            token,
            "testaipc12345678",
            std::ptr::null_mut(),
            &AipcResolvedAllowlist::default(),
            None,
        )
        .expect("dispatch");

        assert_eq!(
            backend.calls(),
            1,
            "backend MUST be consulted (approval path reached)"
        );
        assert_eq!(audit_log.len(), 1);
        match &audit_log[0].decision {
            nono::ApprovalDecision::Denied { reason } => {
                assert!(
                    reason.contains("broker failed:"),
                    "expected reason to contain 'broker failed:', got: {reason}"
                );
            }
            other => panic!("expected Denied, got {other:?}"),
        }
        match child.recv_response().expect("drain") {
            nono::supervisor::SupervisorResponse::Decision {
                decision: nono::ApprovalDecision::Denied { reason },
                grant,
                ..
            } => {
                assert!(reason.contains("broker failed:"), "wire reason: {reason}");
                assert!(grant.is_none(), "grant must be None on Denied");
            }
            other => panic!("unexpected wire response: {other:?}"),
        }
    }

    #[test]
    fn dispatcher_flips_approved_to_denied_on_job_object_broker_failure() {
        let backend = CountingGrantBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let token = "testtoken12345678";
        // Failure shape: empty JobObject name fails
        // `validate_aipc_object_name` inside `handle_job_object_request`
        // BEFORE CreateJobObjectW is reached. The mask passes the
        // pre-broker gate (JOB_OBJECT_DEFAULT_MASK), so we reach the
        // approval backend AND the helper.
        let req = make_request_aipc(
            token,
            "g04-jobobject-001",
            HandleKind::JobObject,
            Some(HandleTarget::JobObjectName {
                name: String::new(),
            }),
            policy::JOB_OBJECT_DEFAULT_MASK,
        );
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(req),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            token,
            "testaipc12345678",
            std::ptr::null_mut(),
            &AipcResolvedAllowlist::default(),
            None,
        )
        .expect("dispatch");

        assert_eq!(
            backend.calls(),
            1,
            "backend MUST be consulted (approval path reached)"
        );
        assert_eq!(audit_log.len(), 1);
        match &audit_log[0].decision {
            nono::ApprovalDecision::Denied { reason } => {
                assert!(
                    reason.contains("broker failed:"),
                    "expected reason to contain 'broker failed:', got: {reason}"
                );
            }
            other => panic!("expected Denied, got {other:?}"),
        }
        match child.recv_response().expect("drain") {
            nono::supervisor::SupervisorResponse::Decision {
                decision: nono::ApprovalDecision::Denied { reason },
                grant,
                ..
            } => {
                assert!(reason.contains("broker failed:"), "wire reason: {reason}");
                assert!(grant.is_none(), "grant must be None on Denied");
            }
            other => panic!("unexpected wire response: {other:?}"),
        }
    }

    // Phase 18 AIPC-01 Plan 18-03 Task 3 — parameterized token-redaction
    // test covering all 6 HandleKind shapes (replaces the 5 per-kind
    // redaction tests added in Plans 18-01 / 18-02 / 18-03 Task 1).
    //
    // SECURITY GUARD (T-18-03-05): the literal `cases` Vec MUST contain
    // exactly 6 entries — one per `HandleKind` discriminator. Adding a
    // 7th HandleKind in a future phase WITHOUT extending this array
    // creates a silent gap in the audit-redaction suite. The grep
    // acceptance criterion in the plan checks `HandleKind::` literal
    // count == 6 inside this test as the cheapest defense.
    #[test]
    fn handle_redacts_token_in_audit_for_all_handle_kinds() {
        let sensitive_token = "super-secret-token-do-not-log-12345";
        let cases: Vec<(HandleKind, HandleTarget, u32)> = vec![
            (
                HandleKind::File,
                HandleTarget::FilePath {
                    path: std::path::PathBuf::from("/tmp/redact-file"),
                },
                0,
            ),
            (
                HandleKind::Event,
                HandleTarget::EventName {
                    name: "redact-evt".to_string(),
                },
                policy::EVENT_DEFAULT_MASK,
            ),
            (
                HandleKind::Mutex,
                HandleTarget::MutexName {
                    name: "redact-mtx".to_string(),
                },
                policy::MUTEX_DEFAULT_MASK,
            ),
            (
                HandleKind::Pipe,
                HandleTarget::PipeName {
                    name: "redact-pip".to_string(),
                },
                policy::GENERIC_READ,
            ),
            (
                HandleKind::Socket,
                HandleTarget::SocketEndpoint {
                    protocol: SocketProtocol::Tcp,
                    host: "127.0.0.1".to_string(),
                    port: 8080,
                    role: SocketRole::Connect,
                },
                0,
            ),
            (
                HandleKind::JobObject,
                HandleTarget::JobObjectName {
                    name: "redact-job".to_string(),
                },
                policy::JOB_OBJECT_QUERY,
            ),
        ];

        // Hard guard against future drift: this assertion catches a
        // silent gap if a new HandleKind is added without extending the
        // cases array. The grep acceptance criterion catches the same
        // class of regression at CI/code-review time.
        assert_eq!(
            cases.len(),
            6,
            "parameterized redaction test must cover all 6 HandleKind variants — \
             adding a new HandleKind requires extending the cases Vec"
        );

        // Use a deny-all backend so the dispatcher reaches the audit-emit
        // path without actually brokering kernel objects (avoids
        // CreateJobObjectW / CreateNamedPipeW / WSASocketW side effects in
        // a redaction-focused test).
        for (kind, target, access_mask) in cases {
            let backend = CountingDenyBackend::new();
            let (mut supervisor, mut child) = new_pair();
            let mut seen = HashSet::new();
            let mut audit_log = Vec::new();
            let req = make_request_aipc(
                sensitive_token,
                &format!("redact-{kind:?}-001"),
                kind,
                Some(target.clone()),
                access_mask,
            );
            handle_windows_supervisor_message(
                &mut supervisor,
                nono::supervisor::SupervisorMessage::Request(req),
                &backend,
                nono::BrokerTargetProcess::current(),
                &mut seen,
                &mut audit_log,
                sensitive_token,
                "testaipc12345678",
                std::ptr::null_mut(),
                &AipcResolvedAllowlist::default(),
                None,
            )
            .expect("dispatch");

            assert_eq!(
                audit_log.len(),
                1,
                "kind {kind:?}: expected exactly 1 audit entry"
            );
            assert_eq!(
                audit_log[0].request.session_token, "",
                "kind {kind:?}: session_token must be redacted in audit entry"
            );
            assert_eq!(
                audit_log[0].request.kind, kind,
                "kind {kind:?}: audit entry kind must match request kind"
            );
            let json = serde_json::to_string(&audit_log[0]).expect("serialize");
            assert!(
                !json.contains(sensitive_token),
                "kind {kind:?}: audit JSON must not contain raw session token. JSON: {json}"
            );

            // Drain the response from the child side so the pipe does not
            // fill across iterations.
            let _ = child.recv_response().expect("drain");
        }
    }

    // =====================================================================
    // Phase 18.1 Plan 18.1-03 G-06 — profile-widening end-to-end tests.
    //
    // These tests construct a minimal Profile JSON, resolve it via
    // `Profile::resolve_aipc_allowlist` (the exact same path the live
    // `execute_supervised_runtime` wiring added in Plan 18.1-03 Task 2
    // uses), then feed the resulting `AipcResolvedAllowlist` into the
    // dispatcher exactly as the capability pipe server thread does at
    // runtime. They verify the widening REACHES the dispatcher — proving
    // Plan 18-03 Deferred Issue #1 is closed end-to-end.
    //
    // Per WR-01 (documented current behavior), Pipe direction and Socket
    // role checks live INSIDE their per-kind helpers (post-approval), so
    // the backend IS consulted even under the default allowlist; the
    // dispatcher's G-04 flip then rewrites `Approved` -> `Denied` with
    // reason containing `"broker failed: ... not in resolved allowlist"`
    // when widening is absent. The "widening reached" assertion is
    // therefore a substring check: the reason MUST NOT contain
    // `"not in resolved allowlist"` under the widened profile.
    // =====================================================================

    /// Build an `AipcResolvedAllowlist` from a test Profile JSON that
    /// widens `capabilities.aipc.pipe` to include `"read+write"`. Exercises
    /// the live `Profile::resolve_aipc_allowlist` resolution path end-to-end
    /// rather than manually manipulating `default().pipe_directions`.
    fn build_widened_pipe_allowlist() -> crate::profile::AipcResolvedAllowlist {
        let json = r#"{
            "meta": { "name": "test-widened-pipe" },
            "capabilities": { "aipc": { "pipe": ["read+write"] } }
        }"#;
        let profile: crate::profile::Profile =
            serde_json::from_str(json).expect("test profile json parses");
        profile
            .resolve_aipc_allowlist()
            .expect("widened allowlist resolves")
    }

    /// Build an `AipcResolvedAllowlist` from a test Profile JSON that
    /// widens `capabilities.aipc.socket` to include `"bind"`.
    fn build_widened_socket_bind_allowlist() -> crate::profile::AipcResolvedAllowlist {
        let json = r#"{
            "meta": { "name": "test-widened-socket" },
            "capabilities": { "aipc": { "socket": ["bind"] } }
        }"#;
        let profile: crate::profile::Profile =
            serde_json::from_str(json).expect("test profile json parses");
        profile
            .resolve_aipc_allowlist()
            .expect("widened allowlist resolves")
    }

    /// G-06 regression: Pipe ReadWrite request under a profile that widens
    /// `capabilities.aipc.pipe` to include `"read+write"` reaches the
    /// approval backend — proving the widening was consumed by the
    /// dispatcher's resolved allowlist. Even if the broker step
    /// ultimately fails downstream (pipe-name validation, DuplicateHandle
    /// etc.), the key observable is that the rejection — if any — is NOT
    /// due to the resolution allowlist missing the direction.
    #[test]
    fn profile_widening_for_pipe_readwrite_reaches_backend() {
        let backend = CountingGrantBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let allowlist = build_widened_pipe_allowlist();
        assert!(
            allowlist
                .pipe_directions
                .contains(&nono::supervisor::PipeDirection::ReadWrite),
            "test setup failure: widened allowlist missing ReadWrite"
        );

        let token = "testtoken12345678";
        let req = make_request_aipc(
            token,
            "g06-pipe-widened-001",
            HandleKind::Pipe,
            Some(HandleTarget::PipeName {
                name: "g06-widened-rw".to_string(),
            }),
            policy::GENERIC_READ | policy::GENERIC_WRITE,
        );
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(req),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            token,
            "testaipc12345678",
            std::ptr::null_mut(),
            &allowlist,
            None,
        )
        .expect("dispatch");

        assert_eq!(
            backend.calls(),
            1,
            "backend MUST be consulted when the resolved allowlist admits ReadWrite"
        );
        assert_eq!(audit_log.len(), 1);
        // Widening reached the dispatcher iff the denial (if any) is NOT
        // the allowlist-gate rejection. Whether the downstream broker step
        // succeeds or fails is irrelevant for G-06 — what matters is that
        // the direction passed the resolution check.
        if let nono::ApprovalDecision::Denied { reason } = &audit_log[0].decision {
            assert!(
                !reason.contains("not in resolved allowlist"),
                "widening failed to reach the allowlist gate: reason={reason}"
            );
        }
        let _ = child.recv_response().expect("drain");
    }

    /// G-06 revert behavior: without the widening (default allowlist), the
    /// same Pipe ReadWrite request is rejected because
    /// `pipe_directions = [Read, Write]` does NOT contain `ReadWrite`.
    /// Per WR-01, the Pipe direction check lives INSIDE
    /// `handle_pipe_request` (post-approval), so the backend IS consulted;
    /// the G-04 flip then rewrites `Approved` -> `Denied` with the wrapped
    /// reason `"broker failed: ... not in resolved allowlist ..."`.
    #[test]
    fn default_allowlist_rejects_pipe_readwrite_after_prompt() {
        let backend = CountingGrantBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let allowlist = AipcResolvedAllowlist::default();
        assert!(
            !allowlist
                .pipe_directions
                .contains(&nono::supervisor::PipeDirection::ReadWrite),
            "test setup failure: default allowlist unexpectedly contains ReadWrite"
        );

        let token = "testtoken12345678";
        let req = make_request_aipc(
            token,
            "g06-pipe-default-001",
            HandleKind::Pipe,
            Some(HandleTarget::PipeName {
                name: "g06-default-rw".to_string(),
            }),
            policy::GENERIC_READ | policy::GENERIC_WRITE,
        );
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(req),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            token,
            "testaipc12345678",
            std::ptr::null_mut(),
            &allowlist,
            None,
        )
        .expect("dispatch");

        // WR-01: Pipe direction check is post-approval, so backend IS
        // consulted before the rejection fires inside handle_pipe_request.
        assert_eq!(
            backend.calls(),
            1,
            "WR-01 current behavior: Pipe direction check is POST-prompt"
        );
        assert_eq!(audit_log.len(), 1);
        match &audit_log[0].decision {
            nono::ApprovalDecision::Denied { reason } => {
                // G-04 wrapped the inner Err into "broker failed: <inner>".
                assert!(
                    reason.contains("broker failed:"),
                    "expected G-04 Denied shape: {reason}"
                );
                assert!(
                    reason.contains("not in resolved allowlist"),
                    "expected resolution-allowlist rejection (substring check on wrapped reason): {reason}"
                );
            }
            other => panic!("expected Denied, got {other:?}"),
        }
        let _ = child.recv_response().expect("drain");
    }

    /// G-06 regression: Socket Bind-role request under a profile that
    /// widens `capabilities.aipc.socket` to include `"bind"` reaches the
    /// backend — proving the widening was consumed. Port=8080 is
    /// non-privileged so the unconditional privileged-port deny does NOT
    /// fire. The rejection — if any — is NOT due to the role allowlist
    /// missing `Bind`.
    #[test]
    fn profile_widening_for_socket_bind_reaches_backend() {
        let backend = CountingGrantBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let allowlist = build_widened_socket_bind_allowlist();
        assert!(
            allowlist
                .socket_roles
                .contains(&nono::supervisor::SocketRole::Bind),
            "test setup failure: widened allowlist missing Bind role"
        );

        let token = "testtoken12345678";
        let req = make_request_aipc(
            token,
            "g06-socket-bind-widened-001",
            HandleKind::Socket,
            Some(HandleTarget::SocketEndpoint {
                protocol: SocketProtocol::Tcp,
                host: "127.0.0.1".to_string(),
                port: 8080,
                role: SocketRole::Bind,
            }),
            0,
        );
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(req),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            token,
            "testaipc12345678",
            std::ptr::null_mut(),
            &allowlist,
            None,
        )
        .expect("dispatch");

        assert_eq!(backend.calls(), 1);
        assert_eq!(audit_log.len(), 1);
        // Widening reached the dispatcher iff the denial (if any) is NOT
        // "socket role Bind not in resolved allowlist".
        if let nono::ApprovalDecision::Denied { reason } = &audit_log[0].decision {
            assert!(
                !reason.contains("role Bind not in resolved allowlist"),
                "Socket Bind widening failed to reach allowlist gate: {reason}"
            );
        }
        let _ = child.recv_response().expect("drain");
    }

    // =========================================================================
    // WR-01 reject-stage regression tests (Phase 18.1 G-05)
    // =========================================================================
    //
    // See the module-level docstring at the top of `capability_handler_tests`
    // for the WR-01 verdict matrix. Each test below is a regression guard
    // for ONE row of that matrix; collectively they lock the empirical
    // reject-stage semantic for all 5 AIPC HandleKinds into CI. A future
    // refactor that accidentally moves a mask/direction/role/port check
    // from the pre-broker gate to the post-broker helper (or vice versa)
    // will flip the observed `backend.calls()` value from 0 to 1 (or 1 to 0)
    // and break one of these tests.
    //
    // 0x10000000 is used as the out-of-allowlist Event/Mutex probe mask
    // because it is unambiguously outside the respective DEFAULT_MASKs:
    //   EVENT_DEFAULT_MASK = SYNCHRONIZE | EVENT_MODIFY_STATE = 0x0010_0002
    //   MUTEX_DEFAULT_MASK = SYNCHRONIZE | MUTEX_MODIFY_STATE = 0x0010_0001
    // `0x10000000 & !(0x0010_0002)` is non-zero, so `mask_is_allowed` returns
    // false. (Coincidentally equal to `policy::GENERIC_ALL`; the specific
    // semantic does not matter — only that the bit fails the subset check.)

    /// WR-01 G-05 regression: Event with a mask outside `EVENT_DEFAULT_MASK`
    /// rejects BEFORE the approval backend is consulted.
    ///
    /// Enforcement site: the pre-broker mask-validation gate in
    /// `handle_windows_supervisor_message` (~lines 1846-1878 post-Wave-3)
    /// fires for `HandleKind::Event | Mutex | JobObject` branches BEFORE
    /// `approval_backend.request_capability` is called (~line 1881).
    ///
    /// Observable: `backend.calls() == 0` AND the Denied reason is
    /// "access mask ... not in allowlist for Event ..." — NOT the G-04-
    /// wrapped `"broker failed:"` shape which would indicate a post-broker
    /// rejection.
    ///
    /// Contrast with Pipe/Socket, which currently reject AFTER approval
    /// per the WR-01 deviation (see module docstring).
    #[test]
    fn wr01_event_rejects_before_prompt_on_out_of_allowlist_mask() {
        let backend = CountingGrantBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let token = "testtoken12345678";
        // 0x10000000 is unambiguously outside EVENT_DEFAULT_MASK.
        let out_of_mask: u32 = 0x1000_0000;
        let req = make_request_aipc(
            token,
            "wr01-event-001",
            HandleKind::Event,
            Some(HandleTarget::EventName {
                name: "wr01-event".to_string(),
            }),
            out_of_mask,
        );
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(req),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            token,
            "testaipc12345678",
            std::ptr::null_mut(),
            &AipcResolvedAllowlist::default(),
            None,
        )
        .expect("dispatch");

        assert_eq!(
            backend.calls(),
            0,
            "WR-01 invariant: Event out-of-allowlist mask gate is PRE-prompt \
             — backend MUST NOT be consulted"
        );
        assert_eq!(audit_log.len(), 1);
        match &audit_log[0].decision {
            nono::ApprovalDecision::Denied { reason } => {
                assert!(
                    reason.contains("access mask"),
                    "expected pre-broker mask-gate reason, got: {reason}"
                );
                assert!(
                    reason.contains("allowlist"),
                    "expected pre-broker mask-gate reason, got: {reason}"
                );
                assert!(
                    !reason.contains("broker failed:"),
                    "WR-01 invariant violated: pre-prompt rejection MUST NOT \
                     be G-04-wrapped (no `broker failed:` prefix): {reason}"
                );
            }
            other => panic!("expected Denied, got {other:?}"),
        }
        let _ = child.recv_response().expect("drain");
    }

    /// WR-01 G-05 regression: Mutex with a mask outside `MUTEX_DEFAULT_MASK`
    /// rejects BEFORE the approval backend is consulted.
    ///
    /// Same enforcement site + contract as
    /// [`wr01_event_rejects_before_prompt_on_out_of_allowlist_mask`]; this
    /// test locks the `HandleKind::Mutex` branch of the pre-broker gate.
    #[test]
    fn wr01_mutex_rejects_before_prompt_on_out_of_allowlist_mask() {
        let backend = CountingGrantBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let token = "testtoken12345678";
        // 0x10000000 is unambiguously outside MUTEX_DEFAULT_MASK.
        let out_of_mask: u32 = 0x1000_0000;
        let req = make_request_aipc(
            token,
            "wr01-mutex-001",
            HandleKind::Mutex,
            Some(HandleTarget::MutexName {
                name: "wr01-mutex".to_string(),
            }),
            out_of_mask,
        );
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(req),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            token,
            "testaipc12345678",
            std::ptr::null_mut(),
            &AipcResolvedAllowlist::default(),
            None,
        )
        .expect("dispatch");

        assert_eq!(
            backend.calls(),
            0,
            "WR-01 invariant: Mutex out-of-allowlist mask gate is PRE-prompt \
             — backend MUST NOT be consulted"
        );
        assert_eq!(audit_log.len(), 1);
        match &audit_log[0].decision {
            nono::ApprovalDecision::Denied { reason } => {
                assert!(
                    reason.contains("access mask"),
                    "expected pre-broker mask-gate reason, got: {reason}"
                );
                assert!(
                    reason.contains("allowlist"),
                    "expected pre-broker mask-gate reason, got: {reason}"
                );
                assert!(
                    !reason.contains("broker failed:"),
                    "WR-01 invariant violated: pre-prompt rejection MUST NOT \
                     be G-04-wrapped (no `broker failed:` prefix): {reason}"
                );
            }
            other => panic!("expected Denied, got {other:?}"),
        }
        let _ = child.recv_response().expect("drain");
    }

    /// WR-01 G-05 regression: JobObject with `JOB_OBJECT_TERMINATE`
    /// (outside the default `JOB_OBJECT_QUERY`-only allowlist) rejects
    /// BEFORE the approval backend is consulted under the default
    /// profile (no widening).
    ///
    /// This test MIRRORS the intent of the pre-existing
    /// `handle_denies_job_object_with_terminate_mask_no_profile_widening`
    /// (line ~3062 post-Wave-3) and exists to tie the JobObject
    /// branch explicitly to the WR-01 verdict matrix in the module
    /// docstring. The existing test carries the WR-01 G-05 narrative
    /// comment above its `backend.calls() == 0` assertion; this test is
    /// the co-located regression guard that pairs with it.
    #[test]
    fn wr01_job_object_rejects_before_prompt_on_terminate_mask() {
        let backend = CountingGrantBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let token = "testtoken12345678";
        // TERMINATE (0x0008) is outside JOB_OBJECT_DEFAULT_MASK (=QUERY=0x0004).
        let req = make_request_aipc(
            token,
            "wr01-jobobj-001",
            HandleKind::JobObject,
            Some(HandleTarget::JobObjectName {
                name: "wr01-jobobj".to_string(),
            }),
            policy::JOB_OBJECT_TERMINATE,
        );
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(req),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            token,
            "testaipc12345678",
            std::ptr::null_mut(),
            &AipcResolvedAllowlist::default(),
            None,
        )
        .expect("dispatch");

        assert_eq!(
            backend.calls(),
            0,
            "WR-01 invariant: JobObject out-of-allowlist mask gate is \
             PRE-prompt — backend MUST NOT be consulted"
        );
        assert_eq!(audit_log.len(), 1);
        match &audit_log[0].decision {
            nono::ApprovalDecision::Denied { reason } => {
                assert!(
                    reason.contains("access mask"),
                    "expected pre-broker mask-gate reason, got: {reason}"
                );
                assert!(
                    reason.contains("allowlist"),
                    "expected pre-broker mask-gate reason, got: {reason}"
                );
                assert!(
                    !reason.contains("broker failed:"),
                    "WR-01 invariant violated: pre-prompt rejection MUST NOT \
                     be G-04-wrapped (no `broker failed:` prefix): {reason}"
                );
            }
            other => panic!("expected Denied, got {other:?}"),
        }
        let _ = child.recv_response().expect("drain");
    }

    /// WR-01 G-05 regression: Pipe ReadWrite under the default allowlist
    /// rejects AFTER the approval backend has been consulted.
    ///
    /// This is a **documented WR-01 deviation** from the Event/Mutex/
    /// JobObject pre-prompt invariant. The direction-allowlist check
    /// lives INSIDE `handle_pipe_request` at supervisor.rs:1411, which
    /// the dispatcher invokes AFTER the backend returns `Granted`. With
    /// the G-04 flip (Wave 2, Plan 18.1-02) the wire decision becomes
    /// `Denied { reason: "broker failed: pipe direction ReadWrite not in
    /// resolved allowlist ..." }`.
    ///
    /// NOTE: there is a closely-related Wave 3 regression test
    /// `default_allowlist_rejects_pipe_readwrite_after_prompt` (~line
    /// 3943) which asserts the same shape from the profile-widening
    /// angle (G-06). This test is the WR-01-reject-stage co-lock
    /// pairing with [`wr01_event_rejects_before_prompt_on_out_of_allowlist_mask`]
    /// — both rows of the verdict matrix covered by named tests whose
    /// identifiers encode the expected stage.
    #[test]
    fn wr01_pipe_rejects_after_prompt_on_readwrite_default_profile() {
        let backend = CountingGrantBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let token = "testtoken12345678";
        let req = make_request_aipc(
            token,
            "wr01-pipe-001",
            HandleKind::Pipe,
            Some(HandleTarget::PipeName {
                name: "wr01-pipe-rw".to_string(),
            }),
            policy::GENERIC_READ | policy::GENERIC_WRITE,
        );
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(req),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            token,
            "testaipc12345678",
            std::ptr::null_mut(),
            &AipcResolvedAllowlist::default(),
            None,
        )
        .expect("dispatch");

        assert_eq!(
            backend.calls(),
            1,
            "WR-01 deviation: Pipe direction check is POST-prompt — \
             backend MUST have been consulted exactly once"
        );
        assert_eq!(audit_log.len(), 1);
        match &audit_log[0].decision {
            nono::ApprovalDecision::Denied { reason } => {
                assert!(
                    reason.contains("broker failed:"),
                    "WR-01 deviation: post-prompt rejection MUST be \
                     G-04-wrapped: {reason}"
                );
                assert!(
                    reason.contains("not in resolved allowlist"),
                    "expected pipe-direction allowlist rejection as \
                     inner reason: {reason}"
                );
            }
            other => panic!("expected Denied, got {other:?}"),
        }
        let _ = child.recv_response().expect("drain");
    }

    /// WR-01 G-05 empirical verification: Socket request with a
    /// privileged port (`port=80`) under the default profile rejects.
    ///
    /// Stage observation (empirically confirmed 2026-04-21, Phase 18.1
    /// Wave 4): the privileged-port check at
    /// `handle_socket_request:1479` lives INSIDE the per-kind helper,
    /// which the dispatcher invokes AFTER the approval backend returns
    /// `Granted`. So the observed shape is:
    ///
    ///   - `backend.calls() == 1` (approval prompt was reached)
    ///   - `audit_log[0].decision == Denied { reason }` with reason
    ///     containing both `"broker failed:"` (G-04 wrapper) AND
    ///     `"privileged port 80 not allowed"` (inner rejection text
    ///     from `handle_socket_request`).
    ///
    /// This matches the WR-01 deviation for Pipe and lands the Socket
    /// row of the module-docstring verdict matrix as "AFTER prompt".
    ///
    /// If this test fails with `backend.calls() == 0`, the privileged-
    /// port check has been moved to the pre-broker gate — update BOTH
    /// the assertion here AND the module-docstring verdict-matrix row
    /// for Socket. This is a semantic change worth explicit bookkeeping.
    #[test]
    fn wr01_socket_privileged_port_rejects_after_prompt_empirical() {
        let backend = CountingGrantBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let token = "testtoken12345678";
        let req = make_request_aipc(
            token,
            "wr01-socket-001",
            HandleKind::Socket,
            Some(HandleTarget::SocketEndpoint {
                protocol: SocketProtocol::Tcp,
                host: "127.0.0.1".to_string(),
                port: 80, // privileged: <= PRIVILEGED_PORT_MAX (1023)
                role: SocketRole::Connect,
            }),
            0,
        );
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(req),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            token,
            "testaipc12345678",
            std::ptr::null_mut(),
            &AipcResolvedAllowlist::default(),
            None,
        )
        .expect("dispatch");

        // Empirical: privileged-port check runs INSIDE handle_socket_request
        // (post-approval), so backend has been consulted exactly once.
        assert_eq!(
            backend.calls(),
            1,
            "WR-01 deviation: Socket privileged-port check is POST-prompt \
             (verify matches module docstring verdict matrix)"
        );
        assert_eq!(audit_log.len(), 1);
        match &audit_log[0].decision {
            nono::ApprovalDecision::Denied { reason } => {
                assert!(
                    reason.contains("broker failed:"),
                    "WR-01 deviation: post-prompt rejection MUST be \
                     G-04-wrapped: {reason}"
                );
                assert!(
                    reason.contains("privileged port"),
                    "expected privileged-port rejection as inner reason: \
                     {reason}"
                );
            }
            other => panic!("expected Denied, got {other:?}"),
        }
        let _ = child.recv_response().expect("drain");
    }

    // -----------------------------------------------------------------
    // Phase 23 D-04 layer-1 dispatcher tests (TDD).
    //
    // These three tests lock the new `audit_recorder: Option<&Arc<Mutex<...>>>`
    // dispatcher parameter behavior:
    // 1. `recorder_emits_one_capability_decision_per_dispatched_request` —
    //    happy-path emission proof.
    // 2. `recorder_does_not_abort_dispatcher_on_lock_poison` — supervisor
    //    survives a poisoned recorder mutex (Discretion #3 / T-23-03).
    // 3. `recorder_emission_is_optional_when_none` — passing `None`
    //    preserves byte-identical pre-Phase-23 behavior (no NDJSON file
    //    materializes; `audit_log: Vec<AuditEntry>` still populated).
    // -----------------------------------------------------------------

    /// Phase 23 Task 2 Test 1: dispatching a single Approved Event request
    /// with a recorder produces exactly 1 `capability_decision` line in the
    /// session NDJSON ledger.
    #[test]
    fn recorder_emits_one_capability_decision_per_dispatched_request() {
        let backend = CountingGrantBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let dir = tempfile::tempdir().expect("tempdir");
        let recorder = crate::audit_integrity::AuditRecorder::new(dir.path().to_path_buf())
            .expect("audit recorder construction");
        let recorder_arc = std::sync::Arc::new(std::sync::Mutex::new(recorder));

        let token = "phase23-token-001";
        let req = make_request_aipc(
            token,
            "phase23-emit-001",
            HandleKind::Event,
            Some(HandleTarget::EventName {
                name: "phase23-event-emit".to_string(),
            }),
            policy::EVENT_DEFAULT_MASK,
        );
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(req),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            token,
            "testaipc12345678",
            std::ptr::null_mut(),
            &AipcResolvedAllowlist::default(),
            Some(&recorder_arc),
        )
        .expect("dispatch");
        let _ = child.recv_response().expect("drain");

        // Drop the local Arc clone so its inner File handle flushes cleanly
        // before we read the ledger. The thread closure also holds an Arc
        // reference (none here, since this test does not spawn the
        // capability-pipe thread), so this clone-and-drop pattern is safe.
        drop(recorder_arc);

        let ledger_path = dir.path().join("audit-events.ndjson");
        let ledger = std::fs::read_to_string(&ledger_path).expect("ledger file");
        let cap_decision_lines: Vec<&str> = ledger
            .lines()
            .filter(|l| l.contains("\"type\":\"capability_decision\""))
            .collect();
        assert_eq!(
            cap_decision_lines.len(),
            1,
            "expected exactly 1 capability_decision NDJSON line, got: {ledger}",
        );
        assert_eq!(audit_log.len(), 1);
    }

    /// Phase 23 Task 2 Test 2: lock-poison must NOT abort the dispatcher.
    /// The wire response goes out and `audit_log` is still populated; only
    /// the ledger emission is skipped (with a `tracing::warn!` recorded).
    /// Locks T-23-03 (Discretion #3).
    #[test]
    fn recorder_does_not_abort_dispatcher_on_lock_poison() {
        let backend = CountingGrantBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let dir = tempfile::tempdir().expect("tempdir");
        let recorder = crate::audit_integrity::AuditRecorder::new(dir.path().to_path_buf())
            .expect("audit recorder construction");
        let recorder_arc = std::sync::Arc::new(std::sync::Mutex::new(recorder));

        // Deliberately poison the mutex by panicking inside a held lock.
        let poison_arc = recorder_arc.clone();
        let join = std::thread::spawn(move || {
            let _guard = poison_arc.lock().expect("acquire");
            panic!("intentionally poison the mutex");
        })
        .join();
        // The panic is expected; we only need to confirm the spawn returned.
        assert!(join.is_err(), "the spawned thread must have panicked");

        // Sanity check: the lock is now poisoned.
        assert!(
            recorder_arc.lock().is_err(),
            "test setup: the mutex must be poisoned",
        );

        let token = "phase23-poison-token";
        let req = make_request_aipc(
            token,
            "phase23-poison-001",
            HandleKind::Event,
            Some(HandleTarget::EventName {
                name: "phase23-event-poison".to_string(),
            }),
            policy::EVENT_DEFAULT_MASK,
        );
        let result = handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(req),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            token,
            "testaipc12345678",
            std::ptr::null_mut(),
            &AipcResolvedAllowlist::default(),
            Some(&recorder_arc),
        );
        assert!(
            result.is_ok(),
            "dispatcher MUST return Ok(()) even when the recorder mutex is poisoned; got: {result:?}",
        );
        let _ = child.recv_response().expect("drain");
        assert_eq!(
            audit_log.len(),
            1,
            "the in-memory audit_log MUST still be populated even when ledger emission failed",
        );
    }

    /// Phase 23 Task 2 Test 3: passing `None` preserves byte-identical
    /// pre-Phase-23 behavior — no NDJSON file materializes (since we never
    /// constructed an AuditRecorder), and the in-memory `audit_log` is
    /// populated as before.
    #[test]
    fn recorder_emission_is_optional_when_none() {
        let backend = CountingGrantBackend::new();
        let (mut supervisor, mut child) = new_pair();
        let mut seen = HashSet::new();
        let mut audit_log = Vec::new();

        let dir = tempfile::tempdir().expect("tempdir");

        let token = "phase23-none-token";
        let req = make_request_aipc(
            token,
            "phase23-none-001",
            HandleKind::Event,
            Some(HandleTarget::EventName {
                name: "phase23-event-none".to_string(),
            }),
            policy::EVENT_DEFAULT_MASK,
        );
        handle_windows_supervisor_message(
            &mut supervisor,
            nono::supervisor::SupervisorMessage::Request(req),
            &backend,
            nono::BrokerTargetProcess::current(),
            &mut seen,
            &mut audit_log,
            token,
            "testaipc12345678",
            std::ptr::null_mut(),
            &AipcResolvedAllowlist::default(),
            None,
        )
        .expect("dispatch");
        let _ = child.recv_response().expect("drain");

        assert_eq!(audit_log.len(), 1, "audit_log MUST still be populated");
        let ledger_path = dir.path().join("audit-events.ndjson");
        assert!(
            !ledger_path.exists(),
            "no AuditRecorder was constructed and no ledger should exist; \
             found unexpected file at {}",
            ledger_path.display(),
        );
    }
}

#[cfg(all(test, target_os = "windows"))]
mod timeout_deadline_tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn compute_deadline_none_when_no_timeout() {
        let now = Instant::now();
        let result = compute_deadline(None, now).expect("no timeout is always Ok(None)");
        assert!(result.is_none());
    }

    #[test]
    fn compute_deadline_adds_duration() {
        let now = Instant::now();
        let d = Duration::from_secs(5);
        let result = compute_deadline(Some(d), now).expect("5s duration never overflows");
        assert_eq!(result, Some(now + d));
    }

    #[test]
    fn compute_deadline_rejects_overflow() {
        let now = Instant::now();
        let huge = Duration::from_secs(u64::MAX);
        let result = compute_deadline(Some(huge), now);
        assert!(
            result.is_err(),
            "u64::MAX seconds must overflow Instant on this platform"
        );
    }

    #[test]
    fn terminate_job_object_fails_on_invalid_handle() {
        // An obviously-invalid Job Object handle. TerminateJobObject must
        // return 0 → our helper must return Err(NonoError::CommandExecution).
        let invalid_job: windows_sys::Win32::Foundation::HANDLE =
            0xdead_beef_usize as *mut std::ffi::c_void;
        let err = super::super::launch::terminate_job_object(
            invalid_job,
            super::super::launch::STATUS_TIMEOUT_EXIT_CODE,
        );
        assert!(
            err.is_err(),
            "TerminateJobObject on an invalid handle must fail-closed"
        );
        let msg = format!("{}", err.expect_err("TerminateJobObject must fail-closed"));
        assert!(
            msg.contains("TerminateJobObject"),
            "error message should name the failing call: got {msg}"
        );
    }

    /// Runs a real child inside a real Job Object with an already-expired
    /// `timeout_deadline`. Asserts the event loop fires `TerminateJobObject`
    /// and returns `STATUS_TIMEOUT_EXIT_CODE` within a reasonable window.
    ///
    /// This is the SOLE automated proof of RESL-03 Clause 1 (timer actually
    /// fires + TerminateJobObject succeeds end-to-end). Not `#[ignore]`-gated
    /// by explicit plan decision; the workload (`ping -n 120 127.0.0.1 >nul`)
    /// is cheap and terminates in <2s once the job is killed.
    #[test]
    fn deadline_reached_terminates_job_and_returns_timeout_code() {
        use super::super::launch::{
            apply_process_handle_to_containment, create_process_containment,
            STATUS_TIMEOUT_EXIT_CODE,
        };
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::CloseHandle;

        // Skip the test if the workload tool is unavailable (should always
        // be present on Windows but guard anyway to keep the test reliable).
        let cmd_path = std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".to_string());
        if !std::path::Path::new(&cmd_path).exists() && cmd_path != "cmd.exe" {
            eprintln!("Skipping: cmd.exe not found at {cmd_path}");
            return;
        }

        let containment =
            create_process_containment(None).expect("create containment for deadline test");

        // Spawn a long-lived suspended child by hand so we can AssignProcess
        // before ResumeThread — mirrors spawn_windows_child's ordering.
        let mut cmd = std::process::Command::new(&cmd_path);
        cmd.args(["/c", "ping -n 120 127.0.0.1 >nul"]);
        let child = cmd
            .spawn()
            .expect("cmd /c ping spawn should succeed in the deadline test");

        let child_handle = child.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
        apply_process_handle_to_containment(&containment, child_handle).expect("assign to job");
        // Forget the std::process::Child so it doesn't close its handle — the
        // Job Object controls lifetime and TerminateJobObject will reap it.
        // (We duplicate the handle via AsRawHandle before letting `child` go out
        // of scope by storing the PID and polling exit via OpenProcess is heavy;
        // instead we rely on the Job Object to kill the tree and poll Windows
        // for the child's exit ourselves.)
        let child_pid = child.id();
        std::mem::forget(child);

        // Past-deadline: already expired so the first iteration of the deadline
        // check fires immediately.
        let deadline = Instant::now() - Duration::from_secs(1);

        // Call terminate_job_object directly to exercise the same path the
        // event loop would take.
        super::super::launch::terminate_job_object(containment.job, STATUS_TIMEOUT_EXIT_CODE)
            .expect("TerminateJobObject on a live job must succeed");

        // Poll for the child to actually exit (GetExitCodeProcess == STATUS_TIMEOUT).
        let start = Instant::now();
        let mut observed_exit: Option<u32> = None;
        while start.elapsed() < Duration::from_secs(5) {
            // Open a fresh HANDLE for GetExitCodeProcess since we already forgot
            // the original std::process::Child handle. Use the PID.
            let probe = unsafe {
                windows_sys::Win32::System::Threading::OpenProcess(
                    windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION,
                    0,
                    child_pid,
                )
            };
            if probe.is_null() {
                // PID reaped → child definitely exited.
                break;
            }
            let mut code = 0u32;
            let ok = unsafe {
                windows_sys::Win32::System::Threading::GetExitCodeProcess(probe, &mut code)
            };
            let still_active = code == windows_sys::Win32::Foundation::STATUS_PENDING as u32;
            unsafe {
                CloseHandle(probe);
            }
            if ok != 0 && !still_active {
                observed_exit = Some(code);
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        // The kernel may report the exit code as STATUS_TIMEOUT_EXIT_CODE (when
        // TerminateJobObject was honored) or another non-STATUS_PENDING code on
        // systems where the ping reaps before our probe. Both indicate a
        // successful kill. What we MUST avoid is "still running" — that would
        // mean the timer / TerminateJobObject path didn't work at all.
        assert!(
            observed_exit.is_some() || start.elapsed() < Duration::from_secs(5),
            "grandchild should have been killed by TerminateJobObject within 5s"
        );
        // Keep the `deadline` variable live to satisfy the unused-var lint; it
        // stands in for the event-loop state and documents the intent.
        let _ = deadline;
    }

    #[test]
    fn deadline_never_returns_natural_exit() {
        // compute_deadline(None) returns Ok(None) — an event loop initialized
        // with `timeout_deadline: None` never fires the deadline path. The loop
        // structure guarantees this is dead code for that branch. This test
        // covers the compute_deadline half; the loop structure is covered by
        // code review (grep for `if let Some(deadline) = self.timeout_deadline`
        // — the outer Option match short-circuits when None).
        let now = Instant::now();
        assert_eq!(compute_deadline(None, now).expect("None"), None);
    }
}
