//! Execution strategy for sandboxed commands.
//!
//! This module defines how nono executes commands within the sandbox.
//! The strategy determines the process model and what features are available.
//!
//! # Async-Signal-Safety
//!
//! The Supervised strategy uses `fork()` to create a child process. After fork in a
//! multi-threaded program, the child can only safely call async-signal-safe functions
//! until `exec()`. This module carefully prepares all data in the parent (where
//! allocation is safe) and uses only raw libc calls in the child.

mod env_sanitization;
#[cfg(target_os = "linux")]
mod supervisor_linux;

use crate::startup_prompt::{print_terminal_safe_stderr, prompt_startup_termination_for_child};
use crate::{DETACHED_CWD_PROMPT_RESPONSE_ENV, DETACHED_LAUNCH_ENV, DETACHED_SESSION_ID_ENV};
use nix::libc;
use nix::sys::signal::{self, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};
use nono::supervisor::{ApprovalDecision, AuditEntry, SupervisorMessage, SupervisorResponse};
use nono::{
    ApprovalBackend, CapabilitySet, DenialReason, DenialRecord, DiagnosticFormatter,
    DiagnosticMode, NonoError, Result, Sandbox, SupervisorSocket,
};
use std::collections::HashSet;
use std::ffi::{CString, OsStr};
use std::os::fd::FromRawFd;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

pub(crate) use env_sanitization::is_dangerous_env_var;
use env_sanitization::should_skip_env_var;
pub(crate) use env_sanitization::validate_env_var_patterns;

/// Resolve a program name to its absolute path.
///
/// This should be called BEFORE the sandbox is applied to ensure the program
/// can be found even if its directory is not in the sandbox's allowed paths.
///
/// # Errors
/// Returns an error if the program cannot be found in PATH or as a valid path.
pub fn resolve_program(program: &str) -> Result<PathBuf> {
    which::which(program).map_err(|e| {
        NonoError::CommandExecution(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{}: {}", program, e),
        ))
    })
}

/// Maximum threads allowed when keyring backend is active.
/// Main thread (1) + up to 3 keyring threads for D-Bus/Security.framework.
const MAX_KEYRING_THREADS: usize = 4;
/// Maximum threads allowed when crypto library thread pool is active.
/// Main thread (1) + tokio proxy workers (2) + aws-lc-rs ECDSA pool (4).
/// When --network-profile is used with trust scanning, both the proxy runtime
/// and crypto verification threads may be active simultaneously.
const MAX_CRYPTO_THREADS: usize = 7;
/// Hard cap on retained denial records to prevent memory exhaustion.
const MAX_DENIAL_RECORDS: usize = 1000;
/// Hard cap on request IDs tracked for replay detection.
const MAX_TRACKED_REQUEST_IDS: usize = 4096;

fn offer_profile_save_for_child(
    pty: Option<&mut crate::pty_proxy::PtyProxy>,
    policy_explanations: &[nono::diagnostic::PolicyExplanation],
    error_observation: &nono::diagnostic::ErrorObservation,
    caps: &CapabilitySet,
    command: &[String],
    compared_profile: Option<&str>,
) -> Result<()> {
    if let Some(proxy) = pty {
        let _released_terminal = proxy.release_terminal_for_prompt();
        return crate::profile_save_runtime::offer_save_run_profile(
            policy_explanations,
            error_observation,
            caps,
            command,
            compared_profile,
        );
    }

    crate::profile_save_runtime::offer_save_run_profile(
        policy_explanations,
        error_observation,
        caps,
        command,
        compared_profile,
    )
}

/// Linux procfs context for resolving child-relative procfs paths in the supervisor.
///
/// `/proc/self/...` must refer to the sandboxed child process, not the unsandboxed
/// supervisor. For seccomp interceptions we may also know the calling TID, which
/// lets us resolve `/proc/thread-self/...` accurately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcfsAccessContext {
    process_pid: u32,
    thread_pid: Option<u32>,
}

impl ProcfsAccessContext {
    fn new(process_pid: u32, thread_pid: Option<u32>) -> Self {
        Self {
            process_pid,
            thread_pid,
        }
    }
}

/// Threading context for fork safety validation.
///
/// After loading secrets from the system keystore, the keyring crate may leave
/// background threads running (for D-Bus/Security.framework communication).
/// Similarly, cryptographic verification (aws-lc-rs ECDSA) spawns idle thread
/// pool workers. These threads are benign for our fork+exec pattern because:
/// - They don't hold locks that the main thread or child process needs
/// - The child immediately calls exec(), clearing all thread state
/// - The parent's threads continue independently
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThreadingContext {
    /// Enforce single-threaded execution (default).
    /// Fork will fail if thread count > 1.
    #[default]
    Strict,

    /// Allow elevated thread count for known-safe keyring backends.
    /// Fork proceeds if thread count <= MAX_KEYRING_THREADS.
    /// Keyring threads are idle XPC dispatch workers (macOS) or D-Bus workers
    /// (Linux) after the synchronous keyring call completes — parked, not
    /// holding allocator locks. Safe for Supervised mode's post-fork
    /// Sandbox::apply() allocation.
    KeyringExpected,

    /// Allow elevated thread count for crypto library thread pools.
    /// Spawned by trust scan's ECDSA verification (aws-lc-rs) and keystore
    /// public key lookup. These are idle pool workers parked on condvars,
    /// NOT holding allocator locks — safe for supervised mode's post-fork
    /// Sandbox::apply() allocation.
    CryptoExpected,
}

/// Execution strategy for running sandboxed commands.
///
/// Each strategy provides different trade-offs between security,
/// functionality, and complexity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExecStrategy {
    /// Direct exec: apply sandbox, then exec into command.
    /// nono ceases to exist after exec.
    ///
    /// - Minimal attack surface (no persistent parent)
    /// - No diagnostic footer on error
    /// - No rollback support
    /// - Used by `nono wrap` for scripts and embedding
    Direct,

    /// Supervised mode: fork first, sandbox only child.
    /// Parent is unsandboxed.
    ///
    /// - Larger attack surface (requires hardening)
    /// - Diagnostic footer on non-zero exit
    /// - Undo support (parent can write snapshots)
    /// - IPC for capability expansion
    /// - Default for `nono shell`
    /// - Used by `nono run` when a parent process is required
    #[default]
    Supervised,
}

/// Configuration for command execution.
pub struct ExecConfig<'a> {
    /// The command to execute (program + args).
    pub command: &'a [String],
    /// Pre-resolved absolute path to the program.
    /// This is resolved BEFORE the sandbox is applied to ensure the program
    /// can be found even if its directory is not in the sandbox's allowed paths.
    pub resolved_program: &'a std::path::Path,
    /// Capabilities for the sandbox.
    pub caps: &'a CapabilitySet,
    /// Environment variables to set.
    pub env_vars: Vec<(&'a str, &'a str)>,
    /// Path to the capability state file.
    pub cap_file: &'a std::path::Path,
    /// Directory the child process should start in.
    pub current_dir: &'a std::path::Path,
    /// Whether to suppress diagnostic output.
    pub no_diagnostics: bool,
    /// Threading context for fork safety validation.
    pub threading: ThreadingContext,
    /// Paths that are write-protected (signed instruction files).
    pub protected_paths: &'a [std::path::PathBuf],
    /// Base profile name to derive a saved user patch from after run-time denials.
    pub profile_save_base: Option<&'a str>,
    /// Optional startup timeout for known interactive CLIs that were launched
    /// without their recommended built-in profile.
    pub startup_timeout: Option<StartupTimeoutConfig<'a>>,
    /// Whether runtime capability elevation is enabled.
    /// When true, the child installs seccomp-notify and the parent can grant
    /// capabilities at runtime. On macOS this is currently unused.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub capability_elevation: bool,
    /// Whether the seccomp proxy-only network fallback is needed.
    /// Set by the parent before fork when Landlock ABI lacks AccessNet
    /// and ProxyOnly network mode is requested. Both child and parent
    /// use this flag to coordinate: child installs the proxy filter and
    /// sends the notify fd; parent expects to receive it.
    #[cfg(target_os = "linux")]
    pub seccomp_proxy_fallback: bool,
    /// Allow-list of environment variable names. When set, only variables
    /// matching an exact name or prefix pattern (e.g. `"AWS_*"`) are
    /// passed to the child. Nono-injected credentials always bypass this.
    pub allowed_env_vars: Option<Vec<String>>,
    /// Deny-list of environment variable names. Variables matching an exact
    /// name or prefix pattern (e.g. `"GITHUB_*"`) are stripped even if they
    /// also appear in `allowed_env_vars`. Nono-injected credentials bypass this.
    pub denied_env_vars: Option<Vec<String>>,
}

#[derive(Clone, Copy)]
pub struct StartupTimeoutConfig<'a> {
    pub timeout: Duration,
    pub program: &'a str,
    pub profile: &'a str,
}

/// Configuration for supervisor IPC in supervised execution mode.
///
/// When provided to [`execute_supervised()`], the supervisor creates a Unix
/// socket pair before fork, passes the child end to the child process via
/// the `NONO_SUPERVISOR_FD` environment variable, and runs an IPC event loop
/// in the parent that handles capability expansion requests from the
/// sandboxed child.
pub struct SupervisorConfig<'a> {
    /// Protected nono state roots that must never be granted dynamically.
    pub protected_roots: &'a [std::path::PathBuf],
    /// Backend for approval decisions (terminal prompt, webhook, policy engine)
    pub approval_backend: &'a dyn ApprovalBackend,
    /// Session identifier used for audit correlation.
    pub session_id: &'a str,
    /// Whether the launching terminal should be attached immediately.
    pub attach_initial_client: bool,
    /// Configured in-band PTY detach sequence.
    pub detach_sequence: Option<&'a [u8]>,
    /// Allowed URL origins for supervisor-delegated browser opens (from profile).
    /// Empty means no URLs are allowed.
    pub open_url_origins: &'a [String],
    /// Whether to allow http://localhost and http://127.0.0.1 URLs.
    pub open_url_allow_localhost: bool,
    /// Optional append-only audit recorder for supervisor events.
    pub audit_recorder: Option<&'a Mutex<crate::audit_integrity::AuditRecorder>>,
    /// Whether direct LaunchServices opening is enabled for this session.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub allow_launch_services_active: bool,
    /// Proxy port allowed for seccomp proxy-only fallback (0 = not active).
    #[cfg(target_os = "linux")]
    pub proxy_port: u16,
    /// Bind ports allowed for seccomp proxy-only fallback.
    #[cfg(target_os = "linux")]
    pub proxy_bind_ports: Vec<u16>,
}

#[cfg(target_os = "macos")]
fn should_install_macos_open_shim(supervisor: Option<&SupervisorConfig<'_>>) -> bool {
    supervisor.is_some_and(|cfg| !cfg.allow_launch_services_active)
}

#[cfg(target_os = "linux")]
const fn linux_child_requires_dumpable(
    capability_elevation: bool,
    seccomp_proxy_fallback: bool,
) -> bool {
    capability_elevation || seccomp_proxy_fallback
}

/// Execute a command using the Direct strategy (exec, nono disappears).
///
/// This is the original behavior: apply sandbox, then exec into the command.
/// nono ceases to exist after exec() succeeds.
pub fn execute_direct(config: &ExecConfig<'_>) -> Result<()> {
    let cmd_args = &config.command[1..];

    info!(
        "Executing (direct): {} {:?}",
        config.resolved_program.display(),
        cmd_args
    );

    let mut cmd = Command::new(config.resolved_program);
    cmd.env_clear();
    cmd.current_dir(config.current_dir);

    for (key, value) in std::env::vars() {
        if should_skip_env_var(
            &key,
            &config.env_vars,
            &[
                "NONO_CAP_FILE",
                DETACHED_LAUNCH_ENV,
                DETACHED_SESSION_ID_ENV,
                DETACHED_CWD_PROMPT_RESPONSE_ENV,
            ],
        ) {
            continue;
        }
        if let Some(ref denied) = config.denied_env_vars {
            if env_sanitization::is_env_var_denied(&key, denied) {
                continue;
            }
        }
        if let Some(ref allowed) = config.allowed_env_vars {
            if !env_sanitization::is_env_var_allowed(&key, allowed) {
                continue;
            }
        }
        cmd.env(&key, &value);
    }

    cmd.args(cmd_args).env("NONO_CAP_FILE", config.cap_file);

    for (key, value) in &config.env_vars {
        cmd.env(key, value);
    }

    let err = cmd.exec();

    // exec() only returns if there's an error
    Err(NonoError::CommandExecution(err))
}

/// Execute a command using the Supervised strategy (fork first, sandbox only child).
///
/// Forks first and applies the sandbox only in the child. The parent remains
/// unsandboxed, enabling rollback snapshots and IPC capability expansion.
///
/// # Security Properties
///
/// - Child is sandboxed with full restrictions
/// - Parent is NOT sandboxed - requires additional hardening:
///   - Linux: parent is made non-dumpable immediately after fork. The child is
///     made non-dumpable unless seccomp-driven runtime inspection needs
///     `/proc/PID/mem` access. Failure is fatal.
///   - macOS: PT_DENY_ATTACH applied in parent immediately after fork (not inherited
///     across fork on macOS). Failure is fatal - child is killed and error returned.
///
/// # Sandbox Application in Child
///
/// The child calls `Sandbox::apply()` after fork, which allocates memory (generating
/// Seatbelt profile strings on macOS, opening Landlock PathFds on Linux). This is safe
/// because we validate threading context before fork — known-safe thread contexts
/// (keyring workers, crypto pool) are idle and not holding allocator locks.
///
/// # Process Flow
///
/// 1. Prepare all data for exec in parent (CString conversion)
/// 2. Verify threading context allows fork
/// 3. Fork into parent and child
/// 4. Child: apply Landlock, install seccomp-notify, close inherited FDs, exec
/// 5. Parent: apply PR_SET_DUMPABLE(0) + PT_DENY_ATTACH, receive seccomp fd, run supervisor loop
///
/// Does NOT pipe stdout/stderr. The child inherits the parent's terminal directly,
/// preserving TTY semantics for interactive programs (e.g., Claude Code, vim).
/// The parent prints diagnostics and rollback UI after the child exits.
pub fn execute_supervised(
    config: &ExecConfig<'_>,
    supervisor: Option<&SupervisorConfig<'_>>,
    trust_interceptor: Option<crate::trust_intercept::TrustInterceptor>,
    on_fork: Option<&mut dyn FnMut(u32)>,
    pty_pair: Option<crate::pty_proxy::PtyPair>,
    pty_session_id: Option<&str>,
) -> Result<i32> {
    let program = &config.command[0];
    let cmd_args = &config.command[1..];

    info!("Executing (supervised): {} {:?}", program, cmd_args);

    // Use pre-resolved program path (resolved before fork)
    let program_path = config.resolved_program;

    // Convert program path to CString for execve
    let program_c = CString::new(program_path.to_string_lossy().as_bytes())
        .map_err(|_| NonoError::SandboxInit("Program path contains null byte".to_string()))?;
    let current_dir_c = CString::new(config.current_dir.as_os_str().as_bytes())
        .map_err(|_| NonoError::SandboxInit("Working directory contains null byte".to_string()))?;

    // Build argv: [program, args..., NULL]
    let mut argv_c: Vec<CString> = Vec::with_capacity(1 + cmd_args.len());
    argv_c.push(program_c.clone());
    for arg in cmd_args {
        argv_c.push(CString::new(arg.as_bytes()).map_err(|_| {
            NonoError::SandboxInit(format!("Argument contains null byte: {}", arg))
        })?);
    }

    // Create supervisor socket pair only when the exec'd child actually needs
    // to talk back to the unsandboxed parent. The supervised parent/session
    // model still works without this socket: attach/detach uses the PTY proxy
    // and diagnostics come from the parent wait path. On Linux, avoiding a raw
    // inherited supervisor socket for the common "plain supervised run" path
    // improves compatibility with CLIs that abort on unexpected inherited fds.
    #[cfg(target_os = "linux")]
    let needs_child_ipc = supervisor.is_some()
        && (config.capability_elevation
            || config.seccomp_proxy_fallback
            || trust_interceptor.is_some());

    #[cfg(not(target_os = "linux"))]
    let needs_child_ipc = supervisor.is_some();

    let socket_pair = if needs_child_ipc {
        Some(SupervisorSocket::pair()?)
    } else {
        None
    };
    let child_sock_fd: Option<i32> = socket_pair.as_ref().map(|(_, c)| c.as_raw_fd());

    // Build environment: inherit current env + add our vars
    let mut env_c: Vec<CString> = Vec::new();

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let mut browser_shim: Option<BrowserShim> = None;

    // Copy current environment, filtering dangerous and overridden vars
    for (key, value) in std::env::vars_os() {
        if let (Some(k), Some(v)) = (key.to_str(), value.to_str()) {
            if should_skip_env_var(
                k,
                &config.env_vars,
                &[
                    "NONO_CAP_FILE",
                    "NONO_SUPERVISOR_FD",
                    DETACHED_LAUNCH_ENV,
                    DETACHED_SESSION_ID_ENV,
                    DETACHED_CWD_PROMPT_RESPONSE_ENV,
                ],
            ) {
                continue;
            }
            if let Some(ref denied) = config.denied_env_vars {
                if env_sanitization::is_env_var_denied(k, denied) {
                    continue;
                }
            }
            if let Some(ref allowed) = config.allowed_env_vars {
                if !env_sanitization::is_env_var_allowed(k, allowed) {
                    continue;
                }
            }
            if let Ok(cstr) = CString::new(format!("{}={}", k, v)) {
                env_c.push(cstr);
            }
        }
    }

    // Add NONO_CAP_FILE
    if let Some(cap_file_str) = config.cap_file.to_str() {
        if let Ok(cstr) = CString::new(format!("NONO_CAP_FILE={}", cap_file_str)) {
            env_c.push(cstr);
        }
    }

    // Add user-specified environment variables (secrets, etc.)
    for (key, value) in &config.env_vars {
        let mut kv = Vec::with_capacity(key.len() + 1 + value.len() + 1);
        kv.extend_from_slice(key.as_bytes());
        kv.push(b'=');
        kv.extend_from_slice(value.as_bytes());
        if let Ok(cstr) = CString::new(kv) {
            env_c.push(cstr);
        }
    }

    // Delegate URL opens to the unsandboxed supervisor.
    //
    // On Linux, child processes inherit Landlock restrictions so the browser
    // can't access its own config directories. xdg-open and the Node.js `open`
    // package respect the BROWSER env var, so we set it to our helper.
    //
    // On macOS, the Node.js `open` package ignores BROWSER and always spawns
    // `/usr/bin/open`. Seatbelt blocks that from launching URLs. Instead, we
    // create a shim script named `open` in a temp directory and prepend it to
    // PATH so the npm `open` package hits our shim first.
    if supervisor.is_some() {
        if let Ok(nono_exe) = std::env::current_exe() {
            #[cfg(target_os = "linux")]
            {
                if let Some(fd) = child_sock_fd {
                    if let Some(shim) = create_linux_browser_shim(&nono_exe, fd) {
                        let browser_cmd = format!("BROWSER={}", shim.launcher.display());
                        if let Ok(cstr) = CString::new(browser_cmd) {
                            env_c.push(cstr);
                        }
                        browser_shim = Some(shim);
                    }
                }
            }

            #[cfg(target_os = "macos")]
            {
                if should_install_macos_open_shim(supervisor) {
                    // Create a shim `open` script that delegates to nono open-url-helper.
                    // The npm `open` package spawns `open <url>` on macOS; by placing our
                    // shim earlier in PATH, we intercept the call.
                    if let Some(fd) = child_sock_fd {
                        if let Some(shim) = create_open_shim(&nono_exe, fd) {
                            // Prepend shim dir to PATH and also set BROWSER for any tool
                            // that does respect it.
                            let current_path = std::env::var("PATH").unwrap_or_default();
                            let new_path =
                                format!("PATH={}:{current_path}", shim.dir.path().display());
                            if let Ok(cstr) = CString::new(new_path) {
                                // Remove existing PATH from env_c, then add our modified one
                                env_c.retain(|c| !c.as_bytes().starts_with(b"PATH="));
                                env_c.push(cstr);
                            }
                            let browser_cmd = format!("BROWSER={}", shim.launcher.display());
                            if let Ok(cstr) = CString::new(browser_cmd) {
                                env_c.push(cstr);
                            }
                            browser_shim = Some(shim);
                        }
                    }
                }
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let _keep_browser_shim_alive = browser_shim;

    // Create null-terminated pointer arrays for execve
    let argv_ptrs: Vec<*const libc::c_char> = argv_c
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    let envp_ptrs: Vec<*const libc::c_char> = env_c
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    // Validate threading before fork.
    // Supervised mode applies sandbox in child (allocates), so threads holding
    // allocator locks would cause deadlock. Both KeyringExpected and CryptoExpected
    // threads are safe: keyring threads are idle XPC dispatch workers (macOS) or
    // D-Bus workers (Linux) parked after the synchronous call completes; crypto
    // threads are idle aws-lc-rs pool workers parked on condvars. Neither holds
    // allocator locks.
    let thread_count = get_thread_count()?;
    match (config.threading, thread_count) {
        (_, 1) => {}
        (ThreadingContext::KeyringExpected, n) if n <= MAX_KEYRING_THREADS => {
            debug!(
                "Supervised fork with {} threads (keyring workers, idle after sync call)",
                n
            );
        }
        (ThreadingContext::CryptoExpected, n) if n <= MAX_CRYPTO_THREADS => {
            debug!(
                "Supervised fork with {} threads (crypto pool workers, idle on condvar)",
                n
            );
        }
        (ThreadingContext::Strict, n) => {
            return Err(NonoError::SandboxInit(format!(
                "Cannot fork in supervised mode: process has {} threads (expected 1). \
                 This is a bug - fork() requires single-threaded execution.",
                n
            )));
        }
        (ThreadingContext::KeyringExpected, n) => {
            return Err(NonoError::SandboxInit(format!(
                "Cannot fork: process has {} threads (max {} with keyring). \
                 Unexpected threading detected.",
                n, MAX_KEYRING_THREADS
            )));
        }
        (ThreadingContext::CryptoExpected, n) => {
            return Err(NonoError::SandboxInit(format!(
                "Cannot fork: process has {} threads (max {} with crypto pool). \
                 Unexpected threading detected.",
                n, MAX_CRYPTO_THREADS
            )));
        }
    }

    // NOTE: We do not set PR_SET_DUMPABLE(0) before fork because the parent may
    // need to inspect the child's memory for seccomp-notify requests. Instead,
    // the parent hardens itself immediately after fork and the child hardens
    // itself after sandbox/filter setup whenever procfs inspection is not
    // required.

    // PTY pair is prepared by the caller so sessions can be detached and
    // reattached independently of capability elevation.
    let pty_slave_fd = pty_pair.as_ref().map(|p| p.slave.as_raw_fd());

    // Compute child's FD keep list: PTY slave (if elevation) + supervisor socket fd
    let mut child_keep_fds: Vec<i32> = Vec::new();
    if let Some(fd) = pty_slave_fd {
        child_keep_fds.push(fd);
    }
    if let Some(fd) = child_sock_fd {
        child_keep_fds.push(fd);
    }

    // Compute max FD in parent (get_max_fd may allocate on Linux)
    let max_fd = get_max_fd();

    // Clear any stale forwarding target before forking.
    clear_signal_forwarding_target();

    // SAFETY: fork() is safe here because we validated threading context.
    // Child will call Sandbox::apply() which allocates, but this is safe
    // because the child is single-threaded (validated above).
    let fork_result = unsafe { fork() };

    match fork_result {
        Ok(ForkResult::Child) => {
            #[cfg(target_os = "linux")]
            let mut child_caps = config.caps.clone();
            #[cfg(target_os = "linux")]
            child_caps.remap_procfs_self_references(std::process::id(), None);
            #[cfg(target_os = "linux")]
            child_caps.widen_procfs_self_to_proc();
            #[cfg(target_os = "linux")]
            let effective_caps: &CapabilitySet = &child_caps;

            #[cfg(target_os = "macos")]
            let mut child_caps = config.caps.clone();
            #[cfg(target_os = "macos")]
            if supervisor.is_some() {
                child_caps.set_seatbelt_debug_deny(true);
            }
            #[cfg(target_os = "macos")]
            let effective_caps: &CapabilitySet = &child_caps;

            #[cfg(all(not(target_os = "linux"), not(target_os = "macos")))]
            let effective_caps: &CapabilitySet = config.caps;

            // CHILD: Set up PTY, apply sandbox, then exec.
            //
            // The child applies the sandbox itself before exec.
            // Sandbox::apply() allocates (Seatbelt profile generation, Landlock
            // PathFd opens) but this is safe because we validated single-threaded
            // execution before fork, giving us a clean heap.

            // The supervisor socket must survive exec into the sandboxed command,
            // and later into any helper (`open-url-helper`) that needs to speak
            // IPC back to the unsandboxed parent. `UnixStream::pair()` creates
            // fds with close-on-exec set, so clear it on the child end here.
            if let Some(fd) = child_sock_fd {
                if let Err(e) = clear_close_on_exec(fd) {
                    let detail = format!(
                        "nono: failed to clear close-on-exec on supervisor socket: {}\n",
                        e
                    );
                    let msg = detail.as_bytes();
                    unsafe {
                        libc::write(
                            libc::STDERR_FILENO,
                            msg.as_ptr().cast::<libc::c_void>(),
                            msg.len(),
                        );
                        libc::_exit(126);
                    }
                }
            }

            // Set up PTY slave as the child's controlling terminal (elevation only).
            // This gives the child its own terminal so TUI apps can freely
            // change terminal modes without affecting the supervisor.
            // SAFETY: We are in the child after fork, slave_fd is valid.
            if let Some(slave_fd) = pty_slave_fd {
                unsafe { crate::pty_proxy::setup_child_pty(slave_fd) };
            }

            // Apply Landlock FIRST. Landlock's restrict_self() opens path fds
            // for rule creation, so it must run before seccomp-notify is installed.
            // (seccomp-notify traps ALL openat/openat2 syscalls, which would
            // intercept Landlock's own path opens and deadlock.)
            #[cfg(target_os = "linux")]
            {
                match Sandbox::apply(effective_caps) {
                    Ok(_fallback) => {}
                    Err(e) => {
                        let detail =
                            format!("nono: failed to apply sandbox in supervised child: {}\n", e);
                        let msg = detail.as_bytes();
                        unsafe {
                            libc::write(
                                libc::STDERR_FILENO,
                                msg.as_ptr().cast::<libc::c_void>(),
                                msg.len(),
                            );
                            libc::_exit(126);
                        }
                    }
                }
            }

            #[cfg(not(target_os = "linux"))]
            {
                if let Err(e) = Sandbox::apply(effective_caps) {
                    let detail =
                        format!("nono: failed to apply sandbox in supervised child: {}\n", e);
                    let msg = detail.as_bytes();
                    unsafe {
                        libc::write(
                            libc::STDERR_FILENO,
                            msg.as_ptr().cast::<libc::c_void>(),
                            msg.len(),
                        );
                        libc::_exit(126);
                    }
                }
            }

            // On Linux with capability elevation: install seccomp-notify filter
            // AFTER Landlock. The kernel evaluates seccomp before LSM hooks
            // regardless of installation order, so the security properties are
            // identical. All openat/openat2 from exec'd child are routed to
            // the supervisor, which can inject fds for approved paths.
            // Without elevation, seccomp is not installed — the child runs
            // with static Landlock capabilities only.
            //
            // On WSL2, seccomp user notification returns EBUSY because WSL2's
            // init already claims the notify listener. The main.rs guards should
            // have disabled these flags, but we check again as defense in depth.
            #[cfg(target_os = "linux")]
            {
                if config.capability_elevation && nono::sandbox::is_wsl2() {
                    let msg = b"nono: WSL2 detected, skipping seccomp-notify (capability elevation unavailable)\n";
                    unsafe {
                        libc::write(
                            libc::STDERR_FILENO,
                            msg.as_ptr().cast::<libc::c_void>(),
                            msg.len(),
                        );
                    }
                } else if config.capability_elevation {
                    if let Some(fd) = child_sock_fd {
                        match nono::sandbox::install_seccomp_notify() {
                            Ok(notify_fd) => {
                                if let Err(e) = nono::supervisor::socket::send_fd_via_socket(
                                    fd,
                                    notify_fd.as_raw_fd(),
                                ) {
                                    let detail = format!(
                                        "nono: failed to send seccomp notify fd to supervisor: {}\n",
                                        e
                                    );
                                    let msg = detail.as_bytes();
                                    unsafe {
                                        libc::write(
                                            libc::STDERR_FILENO,
                                            msg.as_ptr().cast::<libc::c_void>(),
                                            msg.len(),
                                        );
                                        libc::_exit(126);
                                    }
                                }
                            }
                            Err(e) => {
                                // seccomp not available -- proceed without transparent expansion
                                let detail = format!(
                                    "nono: seccomp-notify not available, expansion disabled: {}\n",
                                    e
                                );
                                let msg = detail.as_bytes();
                                unsafe {
                                    libc::write(
                                        libc::STDERR_FILENO,
                                        msg.as_ptr().cast::<libc::c_void>(),
                                        msg.len(),
                                    );
                                }
                            }
                        }
                    }
                }

                // If the parent determined that seccomp proxy fallback is needed
                // (Landlock ABI lacks AccessNet + ProxyOnly mode), install the
                // proxy filter and send its notify fd to the parent.
                // On WSL2 this flag should already be false (guarded in main.rs),
                // but check again to avoid EBUSY / _exit(126).
                if config.seccomp_proxy_fallback && nono::sandbox::is_wsl2() {
                    let msg = b"nono: WSL2 detected, skipping seccomp proxy filter (proxy network filtering unavailable)\n";
                    unsafe {
                        libc::write(
                            libc::STDERR_FILENO,
                            msg.as_ptr().cast::<libc::c_void>(),
                            msg.len(),
                        );
                    }
                } else if config.seccomp_proxy_fallback {
                    let has_bind = match effective_caps.network_mode() {
                        nono::NetworkMode::ProxyOnly { bind_ports, .. } => !bind_ports.is_empty(),
                        _ => false,
                    };
                    if let Some(fd) = child_sock_fd {
                        match nono::sandbox::install_seccomp_proxy_filter(has_bind) {
                            Ok(proxy_notify_fd) => {
                                if let Err(e) = nono::supervisor::socket::send_fd_via_socket(
                                    fd,
                                    proxy_notify_fd.as_raw_fd(),
                                ) {
                                    let detail = format!(
                                        "nono: failed to send proxy seccomp notify fd: {}\n",
                                        e
                                    );
                                    let msg = detail.as_bytes();
                                    unsafe {
                                        libc::write(
                                            libc::STDERR_FILENO,
                                            msg.as_ptr().cast::<libc::c_void>(),
                                            msg.len(),
                                        );
                                        libc::_exit(126);
                                    }
                                }
                            }
                            Err(e) => {
                                let detail =
                                    format!("nono: seccomp proxy filter not available: {}\n", e);
                                let msg = detail.as_bytes();
                                unsafe {
                                    libc::write(
                                        libc::STDERR_FILENO,
                                        msg.as_ptr().cast::<libc::c_void>(),
                                        msg.len(),
                                    );
                                    libc::_exit(126);
                                }
                            }
                        }
                    }
                }

                if !linux_child_requires_dumpable(
                    config.capability_elevation,
                    config.seccomp_proxy_fallback,
                ) {
                    use nix::sys::prctl;

                    if let Err(e) = prctl::set_dumpable(false) {
                        let detail = format!(
                            "nono: failed to set PR_SET_DUMPABLE(0) in supervised child: {}\n",
                            e
                        );
                        let msg = detail.as_bytes();
                        unsafe {
                            libc::write(
                                libc::STDERR_FILENO,
                                msg.as_ptr().cast::<libc::c_void>(),
                                msg.len(),
                            );
                            libc::_exit(126);
                        }
                    }
                }
            }

            #[cfg(target_os = "macos")]
            {
                const PT_DENY_ATTACH: libc::c_int = 31;
                unsafe {
                    libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut::<libc::c_char>(), 0);
                }
            }

            // Close inherited FDs (but keep stdin/stdout/stderr and supervisor socket)
            close_inherited_fds(max_fd, &child_keep_fds);

            // SAFETY: `current_dir_c` was prepared before fork and remains valid
            // for the lifetime of the child. `chdir` is async-signal-safe.
            let chdir_result = unsafe { libc::chdir(current_dir_c.as_ptr()) };
            if chdir_result != 0 {
                const MSG: &[u8] = b"nono: failed to enter child working directory\n";
                // SAFETY: `write` and `_exit` are async-signal-safe and we're in
                // the post-fork child path where higher-level Rust APIs are unsafe.
                unsafe {
                    libc::write(
                        libc::STDERR_FILENO,
                        MSG.as_ptr().cast::<libc::c_void>(),
                        MSG.len(),
                    );
                    libc::_exit(126);
                }
            }

            // Execute using pre-prepared CStrings (no allocation)
            unsafe {
                libc::execve(program_c.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
            }

            // execve only returns on error - exit without cleanup
            unsafe { libc::_exit(127) }
        }
        Ok(ForkResult::Parent { child }) => {
            if let Some(callback) = on_fork {
                callback(child.as_raw() as u32);
            }

            let mut pty_proxy = if let Some(pty) = pty_pair {
                drop(pty.slave);
                let session_id = pty_session_id
                    .or_else(|| supervisor.map(|s| s.session_id))
                    .unwrap_or("unknown");
                let attach_initial_client =
                    supervisor.map(|s| s.attach_initial_client).unwrap_or(true);
                let detach_sequence = supervisor.and_then(|s| s.detach_sequence);
                match crate::pty_proxy::PtyProxy::new(
                    pty.master,
                    session_id,
                    attach_initial_client,
                    detach_sequence,
                ) {
                    Ok(proxy) => Some(proxy),
                    Err(e) => {
                        let _ = signal::kill(child, Signal::SIGKILL);
                        let _ = waitpid(child, None);
                        return Err(NonoError::SandboxInit(format!(
                            "Failed to create PTY proxy: {}",
                            e
                        )));
                    }
                }
            } else {
                None
            };

            // Destructure socket pair: close child's end, keep supervisor's end
            let supervisor_sock = if let Some((sup, child_end)) = socket_pair {
                drop(child_end);
                Some(sup)
            } else {
                None
            };

            // PARENT: Apply ptrace hardening immediately. This is CRITICAL
            // because the parent is unsandboxed in Supervised mode.
            // Failure to harden is fatal - we kill the child and abort.

            // On Linux, set PR_SET_DUMPABLE(0) on the parent to prevent
            // ptrace attachment. The child stays dumpable only when
            // seccomp-driven procfs inspection is active.
            #[cfg(target_os = "linux")]
            {
                use nix::sys::prctl;
                if let Err(e) = prctl::set_dumpable(false) {
                    let _ = signal::kill(child, Signal::SIGKILL);
                    let _ = waitpid(child, None);
                    return Err(NonoError::SandboxInit(format!(
                        "Failed to verify PR_SET_DUMPABLE(0) on supervised parent: {}. \
                         Aborting: unsandboxed parent must not be ptrace-attachable.",
                        e
                    )));
                }
            }

            #[cfg(target_os = "macos")]
            {
                const PT_DENY_ATTACH: libc::c_int = 31;
                let result = unsafe {
                    libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut::<libc::c_char>(), 0)
                };
                if result != 0 {
                    let err = std::io::Error::last_os_error();
                    let _ = signal::kill(child, Signal::SIGKILL);
                    let _ = waitpid(child, None);
                    return Err(NonoError::SandboxInit(format!(
                        "Failed to set PT_DENY_ATTACH on supervised parent: {} (errno: {}). \
                         Aborting: unsandboxed parent must not be debugger-attachable.",
                        result, err
                    )));
                }
            }

            // On Linux with capability elevation: receive the seccomp notify fd
            // from the child. The child installed a seccomp-notify filter and
            // sent the fd via SCM_RIGHTS on the supervisor socket.
            // Only attempt recv when elevation is active (child sends the fd).
            #[cfg(target_os = "linux")]
            let seccomp_notify_fd: Option<OwnedFd> = if config.capability_elevation {
                if let Some(ref sup_sock) = supervisor_sock {
                    match sup_sock.recv_fd() {
                        Ok(fd) => {
                            debug!("Received seccomp notify fd from child");
                            Some(fd)
                        }
                        Err(e) => {
                            warn!("Failed to receive seccomp notify fd: {}", e);
                            None
                        }
                    }
                } else {
                    None
                }
            } else {
                None
            };

            // On Linux: if the parent determined seccomp proxy fallback is needed,
            // receive the proxy notify fd from the child. Only attempt recv when
            // we know the child will send it (both sides use the same flag).
            #[cfg(target_os = "linux")]
            let proxy_notify_fd: Option<OwnedFd> = if config.seccomp_proxy_fallback {
                if let Some(ref sup_sock) = supervisor_sock {
                    match sup_sock.recv_fd() {
                        Ok(fd) => {
                            debug!("Received proxy seccomp notify fd from child");
                            Some(fd)
                        }
                        Err(e) => {
                            warn!("Failed to receive proxy seccomp notify fd: {}", e);
                            None
                        }
                    }
                } else {
                    None
                }
            } else {
                None
            };

            // Set up signal forwarding.
            setup_signal_forwarding(child, pty_proxy.as_ref().map(|p| p.poll_fds().0));
            let _signal_forwarding_guard = SignalForwardingGuard;

            // NOTE: peer_pid() is NOT called here. For socketpair() created
            // before fork, LOCAL_PEERPID/SO_PEERCRED return the parent's own PID
            // (credentials are captured at creation time, not updated after fork).
            // Socketpairs are inherently secure: anonymous (no filesystem path),
            // only our forked child has the other end. peer_pid() is useful for
            // named sockets (bind/connect), not socketpair+fork.

            #[cfg(target_os = "macos")]
            let sandbox_log_collector = if supervisor.is_some() {
                let command_name = config
                    .command
                    .first()
                    .and_then(|c| std::path::Path::new(c).file_name())
                    .and_then(|n| n.to_str())
                    .map(str::to_string);
                crate::sandbox_log::SandboxLogCollector::start(child.as_raw(), command_name)
            } else {
                None
            };

            // Build initial-set path lookup for seccomp fast-path (Linux)
            // Stores (resolved_path, is_file) to distinguish file vs directory semantics:
            // - File capabilities: exact match only (no subpath access)
            // - Directory capabilities: subpath access allowed via starts_with
            #[cfg(target_os = "linux")]
            let initial_caps: Vec<supervisor_linux::InitialCapability> = {
                let mut supervisor_caps = config.caps.clone();
                supervisor_caps.remap_procfs_self_references(child.as_raw() as u32, None);
                supervisor_caps
                    .fs_capabilities()
                    .iter()
                    .map(|cap| supervisor_linux::InitialCapability {
                        path: cap.resolved.clone(),
                        access: cap.access,
                        is_file: cap.is_file,
                    })
                    .collect()
            };

            let (status, denials) =
                if let (Some(sup_cfg), Some(mut sup_sock)) = (supervisor, supervisor_sock) {
                    #[cfg(target_os = "linux")]
                    {
                        run_supervisor_loop(
                            child,
                            &mut sup_sock,
                            sup_cfg,
                            config.startup_timeout,
                            seccomp_notify_fd.as_ref(),
                            proxy_notify_fd.as_ref(),
                            &initial_caps,
                            trust_interceptor,
                            pty_proxy.as_mut(),
                        )?
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        run_supervisor_loop(
                            child,
                            &mut sup_sock,
                            sup_cfg,
                            config.startup_timeout,
                            trust_interceptor,
                            pty_proxy.as_mut(),
                        )?
                    }
                } else {
                    let status =
                        wait_for_child_with_pty(child, pty_proxy.as_mut(), config.startup_timeout)?;
                    (status, Vec::new())
                };

            // Close the attach listener immediately so no new attach
            // connections can sneak in during teardown.  Without this,
            // the kernel keeps accepting connections into the listen
            // backlog even though nobody is calling accept(), and the
            // attaching client gets EPIPE ("Broken pipe") when it
            // tries to send the handshake.
            if let Some(ref mut p) = pty_proxy {
                p.shutdown_attach_listener();
            }

            let exit_code = match status {
                WaitStatus::Exited(_, code) => {
                    debug!("Supervised child exited with code {}", code);
                    let by_signal = (129..=143).contains(&code);
                    if by_signal && !config.no_diagnostics {
                        print_terminal_safe_stderr("[nono] Session stopped.");
                    }
                    code
                }
                WaitStatus::Signaled(_, sig, _) => {
                    debug!("Supervised child killed by signal {}", sig);
                    if !config.no_diagnostics {
                        print_terminal_safe_stderr("[nono] Session stopped.");
                    }
                    128 + sig as i32
                }
                other => {
                    warn!("Unexpected wait status: {:?}", other);
                    1
                }
            };

            // Analyze PTY screen content for sandbox-related errors.
            let error_observation = pty_proxy
                .as_ref()
                .map(|p| {
                    nono::diagnostic::analyze_error_output(
                        &p.screen_plaintext(),
                        config.protected_paths,
                        Some(config.current_dir),
                    )
                })
                .unwrap_or_default();

            let mode = if supervisor.is_some() {
                DiagnosticMode::Supervised
            } else {
                DiagnosticMode::Standard
            };

            let should_print_diagnostics = !config.no_diagnostics
                && (exit_code != 0 || !denials.is_empty() || error_observation.has_findings());

            // Print diagnostic footer on non-zero exit or when the PTY
            // output shows a likely sandbox-related issue.
            if should_print_diagnostics {
                #[cfg(target_os = "macos")]
                let sandbox_violations = if supervisor.is_some() {
                    sandbox_log_collector
                        .map(crate::sandbox_log::SandboxLogCollector::finish)
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };
                #[cfg(not(target_os = "macos"))]
                let sandbox_violations = Vec::new();

                let diag_session_id = if supervisor.is_some() {
                    pty_session_id
                        .or_else(|| supervisor.map(|s| s.session_id))
                        .map(str::to_string)
                } else {
                    None
                };

                // Resolve policy explanations for denied paths so the
                // diagnostic can show group names and fix guidance inline.
                let policy_explanations =
                    build_policy_explanations(&denials, &sandbox_violations, config.caps);
                let prompt_policy_explanations = policy_explanations.clone();
                let prompt_error_observation = error_observation.clone();

                let mut formatter = DiagnosticFormatter::new(config.caps)
                    .with_mode(mode)
                    .with_denials(&denials)
                    .with_sandbox_violations(&sandbox_violations)
                    .with_protected_paths(config.protected_paths)
                    .with_error_observation(error_observation)
                    .with_current_dir(config.current_dir)
                    .with_session_id(diag_session_id)
                    .with_policy_explanations(policy_explanations);
                if let Some(program) = config.command.first() {
                    formatter = formatter.with_command(nono::diagnostic::CommandContext {
                        program: program.clone(),
                        resolved_path: config.resolved_program.to_path_buf(),
                        args: config.command.to_vec(),
                    });
                }
                let footer = formatter.format_footer(exit_code);
                crate::output::print_diagnostic_footer(&footer);

                if exit_code != 0 {
                    // Clear the forwarding target before prompting. The child is
                    // already dead; keeping CHILD_PID set would cause forward_signal
                    // to send Ctrl-C to the dead PID, swallowing it silently.
                    clear_signal_forwarding_target();
                    offer_profile_save_for_child(
                        pty_proxy.as_mut(),
                        &prompt_policy_explanations,
                        &prompt_error_observation,
                        config.caps,
                        config.command,
                        config.profile_save_base,
                    )?;
                }
            }

            Ok(exit_code)
        }
        Err(e) => Err(NonoError::SandboxInit(format!("fork() failed: {}", e))),
    }
}

/// Resolve policy explanations for denied paths by querying `query_path`.
///
/// This runs the same logic as `nono why` but inline, so the diagnostic
/// footer can show group names and fix guidance without asking the user
/// to run a separate command.
fn build_policy_explanations(
    denials: &[nono::diagnostic::DenialRecord],
    sandbox_violations: &[nono::SandboxViolation],
    caps: &nono::CapabilitySet,
) -> Vec<nono::diagnostic::PolicyExplanation> {
    use nono::diagnostic::PolicyExplanation;
    use nono::AccessMode;
    use std::collections::BTreeMap;

    // Merge access modes per path so a path denied for both Read and Write
    // produces a single ReadWrite query. Querying each (path, mode) pair
    // independently would let the first insert win and drop the other mode,
    // yielding an incomplete "Fix:" suggestion.
    let mut paths: BTreeMap<std::path::PathBuf, AccessMode> = BTreeMap::new();

    let merge = |existing: AccessMode, incoming: AccessMode| -> AccessMode {
        if existing == incoming {
            existing
        } else {
            AccessMode::ReadWrite
        }
    };

    for denial in denials {
        paths
            .entry(denial.path.clone())
            .and_modify(|a| *a = merge(*a, denial.access))
            .or_insert(denial.access);
    }

    for violation in sandbox_violations {
        let Some(access) = nono::diagnostic::seatbelt_operation_to_access(&violation.operation)
        else {
            continue;
        };
        let Some(target) = violation.target.as_ref() else {
            continue;
        };
        paths
            .entry(std::path::PathBuf::from(target))
            .and_modify(|a| *a = merge(*a, access))
            .or_insert(access);
    }

    let mut explanations = Vec::new();
    for (path, access) in paths {
        match crate::query_ext::query_path(&path, access, caps, &[]) {
            Ok(crate::query_ext::QueryResult::Denied {
                reason,
                details,
                policy_source,
                suggested_flag,
                ..
            }) => {
                explanations.push(PolicyExplanation {
                    path,
                    access,
                    reason,
                    details,
                    policy_source,
                    suggested_flag,
                });
            }
            Ok(crate::query_ext::QueryResult::Allowed { .. }) => {
                // Path is actually allowed by policy — the denial came from
                // a different layer (e.g. Landlock timing). Skip.
            }
            Ok(crate::query_ext::QueryResult::NotSandboxed { .. }) | Err(_) => {}
        }
    }

    explanations
}

/// Close inherited file descriptors, keeping stdin/stdout/stderr and specified FDs.
///
/// `max_fd` must be computed in the parent before fork (get_max_fd may allocate).
fn close_inherited_fds(max_fd: i32, keep_fds: &[i32]) {
    for fd in 3..=max_fd {
        if !keep_fds.contains(&fd) {
            unsafe { libc::close(fd) };
        }
    }
}

/// Get the maximum file descriptor number to iterate over.
fn get_max_fd() -> i32 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
            let max = entries
                .filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().to_str().and_then(|s| s.parse::<i32>().ok()))
                .max()
                .unwrap_or(1024);
            return max;
        }
    }

    let max = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    if max > 0 {
        std::cmp::min(max as i32, 65536)
    } else {
        1024
    }
}

/// Wait for child process while proxying PTY I/O.
fn wait_for_child_with_pty(
    child: Pid,
    pty: Option<&mut crate::pty_proxy::PtyProxy>,
    startup_timeout: Option<StartupTimeoutConfig<'_>>,
) -> Result<WaitStatus> {
    let pty = match pty {
        Some(pty) => pty,
        None => return wait_for_child_with_startup_timeout(child, startup_timeout),
    };
    let startup_deadline = startup_timeout.map(|cfg| (Instant::now() + cfg.timeout, cfg));
    let mut startup_prompted = false;

    loop {
        let (master_fd, client_fd, attach_fd, resize_fd) = pty.poll_fds();
        let mut pfds = [
            libc::pollfd {
                fd: master_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: client_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: attach_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: resize_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        let ret = unsafe { libc::poll(pfds.as_mut_ptr(), 4, 200) };

        if ret > 0 {
            if !handle_pty_poll_events(
                pty,
                pfds[0].revents,
                pfds[1].revents,
                pfds[2].revents,
                pfds[3].revents,
                "PTY wait loop",
            ) {
                break;
            }
        } else if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::Interrupted {
                warn!("poll() error in PTY wait loop: {}", err);
                break;
            }
        }

        let pause_requested = drain_pause_pipe();
        if pause_requested {
            pty.sync_current_terminal_winsize();
        }
        let in_band_detach_requested = pty.take_detach_request();
        handle_pty_detach_request(Some(pty), pause_requested, in_band_detach_requested);

        match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => {
                if let Some((deadline, timeout_cfg)) = startup_deadline {
                    let has_output = pty.has_observed_output();
                    if Instant::now() >= deadline && !has_output && !startup_prompted {
                        startup_prompted = true;
                        let terminate = prompt_startup_termination_for_child(
                            child,
                            timeout_cfg,
                            has_output,
                            Some(pty),
                        );
                        if terminate {
                            let _ = signal::kill(child, Signal::SIGKILL);
                            let status = wait_for_child(child)?;
                            return Ok(status);
                        }
                    }
                }
                continue;
            }
            Ok(WaitStatus::Stopped(_, sig)) => {
                debug!("Child stopped by signal {}, keeping supervisor alive", sig);
                continue;
            }
            Ok(WaitStatus::Continued(_)) => {
                debug!("Child continued, waiting for terminal exit");
                continue;
            }
            Ok(status) => return Ok(status),
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => {
                return Err(NonoError::SandboxInit(format!("waitpid() failed: {}", e)));
            }
        }
    }

    wait_for_child(child)
}

fn wait_for_child_with_startup_timeout(
    child: Pid,
    startup_timeout: Option<StartupTimeoutConfig<'_>>,
) -> Result<WaitStatus> {
    let startup_deadline = startup_timeout.map(|cfg| (Instant::now() + cfg.timeout, cfg));
    let mut startup_prompted = false;

    loop {
        match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => {
                if let Some((deadline, timeout_cfg)) = startup_deadline {
                    if Instant::now() >= deadline && !startup_prompted {
                        startup_prompted = true;
                        if prompt_startup_termination_for_child(child, timeout_cfg, true, None) {
                            let _ = signal::kill(child, Signal::SIGKILL);
                            return wait_for_child(child);
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            Ok(status) => return Ok(status),
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => {
                return Err(NonoError::SandboxInit(format!("waitpid() failed: {}", e)));
            }
        }
    }
}

/// Wait for child process, handling EINTR from signals.
fn wait_for_child(child: Pid) -> Result<WaitStatus> {
    loop {
        match waitpid(child, Some(WaitPidFlag::empty())) {
            Ok(status) => return Ok(status),
            Err(nix::errno::Errno::EINTR) => {
                // Interrupted by signal, retry
                continue;
            }
            Err(e) => {
                return Err(NonoError::SandboxInit(format!("waitpid() failed: {}", e)));
            }
        }
    }
}

/// Set up signal forwarding from parent to child.
///
/// Signals received by the parent are forwarded to the child process.
/// This ensures Ctrl+C, SIGTERM, etc. properly reach the sandboxed command.
///
/// # Process-Global State
///
/// This function uses process-global static storage for the child PID because
/// Unix signal handlers cannot access thread-local or instance-specific state.
/// This means:
///
/// - Only one `execute_supervised` invocation can be active at a time
/// - Concurrent calls from different threads would corrupt the child PID
/// - This is enforced by the thread count check in `execute_supervised`
///
/// This is acceptable because:
/// 1. `execute_supervised` is CLI code, not library code (per DESIGN-supervisor.md)
/// 2. The fork+wait model inherently requires single-threaded execution
/// 3. Library consumers would use `Sandbox::apply()` directly, not the fork machinery
fn setup_signal_forwarding(child: Pid, pty_master_fd: Option<i32>) {
    // ==================== SAFETY INVARIANT ====================
    // This static variable is ONLY safe because execute_supervised()
    // verifies single-threaded execution BEFORE calling this function.
    //
    // DO NOT call this function without first verifying:
    //   get_thread_count() == 1
    //
    // If threading is ever introduced before this point, this code
    // becomes a race condition where signals could be forwarded to
    // the wrong process (or a non-existent one).
    // ===========================================================
    //
    // Why this design:
    // - Unix signal handlers cannot access thread-local storage
    // - Unix signal handlers cannot access instance data
    // - The only safe option is process-global static storage
    // - AtomicI32 ensures atomic reads/writes
    CHILD_PID.store(child.as_raw(), std::sync::atomic::Ordering::SeqCst);
    PTY_MASTER_FD.store(
        pty_master_fd.unwrap_or(-1),
        std::sync::atomic::Ordering::SeqCst,
    );
    create_pause_pipe();

    // Install signal handlers for common signals
    // SAFETY: signal handlers are async-signal-safe (only call kill())
    unsafe {
        for sig in &[
            Signal::SIGINT,
            Signal::SIGTERM,
            Signal::SIGHUP,
            Signal::SIGQUIT,
            Signal::SIGUSR1,
        ] {
            if let Err(e) = signal::signal(*sig, signal::SigHandler::Handler(forward_signal)) {
                debug!("Failed to install handler for {:?}: {}", sig, e);
            }
        }

        if pty_master_fd.is_some() {
            if let Err(e) = signal::signal(
                Signal::SIGWINCH,
                signal::SigHandler::Handler(forward_signal),
            ) {
                debug!("Failed to install SIGWINCH handler: {:?}", e);
            }
        }
    }
}

static CHILD_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
static PTY_MASTER_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);
static PAUSE_PIPE_WRITE: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);
static PAUSE_PIPE_READ: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

fn create_pause_pipe() -> i32 {
    let mut fds = [0i32; 2];
    let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if ret != 0 {
        return -1;
    }
    unsafe {
        libc::fcntl(fds[0], libc::F_SETFL, libc::O_NONBLOCK);
        libc::fcntl(fds[1], libc::F_SETFL, libc::O_NONBLOCK);
        libc::fcntl(fds[0], libc::F_SETFD, libc::FD_CLOEXEC);
        libc::fcntl(fds[1], libc::F_SETFD, libc::FD_CLOEXEC);
    }
    PAUSE_PIPE_READ.store(fds[0], std::sync::atomic::Ordering::SeqCst);
    PAUSE_PIPE_WRITE.store(fds[1], std::sync::atomic::Ordering::SeqCst);
    fds[0]
}

fn drain_pause_pipe() -> bool {
    let read_fd = PAUSE_PIPE_READ.load(std::sync::atomic::Ordering::SeqCst);
    if read_fd < 0 {
        return false;
    }
    let mut buf = [0u8; 16];
    let n = unsafe { libc::read(read_fd, buf.as_mut_ptr().cast(), buf.len()) };
    n > 0
}

fn close_pause_pipe() {
    let r = PAUSE_PIPE_READ.swap(-1, std::sync::atomic::Ordering::SeqCst);
    let w = PAUSE_PIPE_WRITE.swap(-1, std::sync::atomic::Ordering::SeqCst);
    if r >= 0 {
        unsafe { libc::close(r) };
    }
    if w >= 0 {
        unsafe { libc::close(w) };
    }
}

extern "C" fn forward_signal(sig: libc::c_int) {
    let child_raw = CHILD_PID.load(std::sync::atomic::Ordering::SeqCst);
    if child_raw > 0 {
        if sig == libc::SIGWINCH {
            let master_fd = PTY_MASTER_FD.load(std::sync::atomic::Ordering::SeqCst);
            if master_fd >= 0 {
                let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
                unsafe {
                    if libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) == 0 {
                        libc::ioctl(master_fd, libc::TIOCSWINSZ as libc::c_ulong, &ws);
                    }
                }
            }
        } else if sig == libc::SIGUSR1 {
            let wfd = PAUSE_PIPE_WRITE.load(std::sync::atomic::Ordering::SeqCst);
            if wfd >= 0 {
                unsafe {
                    libc::write(wfd, b"P".as_ptr().cast(), 1);
                }
            }
        } else {
            unsafe {
                libc::kill(child_raw, sig);
            }
        }
    } else if matches!(
        sig,
        libc::SIGINT | libc::SIGTERM | libc::SIGHUP | libc::SIGQUIT
    ) {
        // No child to forward to (e.g. during the post-exit profile-save prompt).
        // For termination signals, restore the default handler and re-raise so
        // the signal takes its default action (terminating nono) rather than
        // being swallowed. Non-termination signals (SIGWINCH, SIGUSR1) are
        // ignored here — their forwarding targets (PTY master, pause pipe) are
        // already torn down.
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
    }
}

fn clear_signal_forwarding_target() {
    CHILD_PID.store(0, std::sync::atomic::Ordering::SeqCst);
    PTY_MASTER_FD.store(-1, std::sync::atomic::Ordering::SeqCst);
    close_pause_pipe();
}

fn detach_client_for_session(pty: &mut crate::pty_proxy::PtyProxy) -> bool {
    pty.detach()
}

fn restore_terminal_after_detach() {
    crate::pty_proxy::write_detach_terminal_reset(libc::STDOUT_FILENO);
    crate::pty_proxy::write_detach_notice(libc::STDERR_FILENO);
}

fn handle_pty_poll_events(
    pty: &mut crate::pty_proxy::PtyProxy,
    master_revents: libc::c_short,
    client_revents: libc::c_short,
    attach_revents: libc::c_short,
    resize_revents: libc::c_short,
    loop_name: &str,
) -> bool {
    if master_revents & libc::POLLIN != 0 && !pty.proxy_master_to_client() {
        debug!("Stopping {loop_name} after PTY master relay failure");
        return false;
    }
    if client_revents & libc::POLLIN != 0 && !pty.proxy_client_to_master() {
        debug!("Stopping {loop_name} after PTY client relay failure");
        return false;
    }
    if attach_revents & libc::POLLIN != 0 {
        pty.try_accept();
    }
    if resize_revents & libc::POLLIN != 0 {
        pty.apply_resize_update();
    }
    true
}

fn handle_pty_detach_request(
    pty: Option<&mut crate::pty_proxy::PtyProxy>,
    pause_requested: bool,
    in_band_detach_requested: bool,
) {
    if pause_requested {
        info!("PTY detach requested via SIGUSR1 control signal");
    }
    if in_band_detach_requested {
        info!("PTY detach requested via in-band key sequence");
    }
    if (pause_requested || in_band_detach_requested) && pty.is_some_and(detach_client_for_session) {
        restore_terminal_after_detach();
    }
}

struct SignalForwardingGuard;

impl Drop for SignalForwardingGuard {
    fn drop(&mut self) {
        clear_signal_forwarding_target();
    }
}
/// Get the current thread count for the process.
///
/// Used to verify single-threaded execution before fork().
/// Returns an error if the count cannot be determined, since fork()
/// safety depends on knowing the exact thread count.
fn get_thread_count() -> Result<usize> {
    #[cfg(target_os = "linux")]
    {
        // On Linux, read /proc/self/status for accurate thread count
        let status = std::fs::read_to_string("/proc/self/status").map_err(|e| {
            NonoError::SandboxInit(format!(
                "Cannot read /proc/self/status for thread count: {e}"
            ))
        })?;
        for line in status.lines() {
            if let Some(count_str) = line.strip_prefix("Threads:") {
                return count_str.trim().parse::<usize>().map_err(|e| {
                    NonoError::SandboxInit(format!("Cannot parse thread count: {e}"))
                });
            }
        }
        Err(NonoError::SandboxInit(
            "Thread count not found in /proc/self/status".to_string(),
        ))
    }

    #[cfg(target_os = "macos")]
    {
        // On macOS, use mach APIs to get thread count
        // SAFETY: These are read-only queries about our own process
        #[allow(deprecated)] // libc recommends mach2 crate, but this is a simple defensive check
        unsafe {
            let task = libc::mach_task_self();
            let mut thread_list: libc::thread_act_array_t = std::ptr::null_mut();
            let mut thread_count: libc::mach_msg_type_number_t = 0;

            // task_threads returns all threads in the task
            let result = libc::task_threads(task, &mut thread_list, &mut thread_count);

            if result == libc::KERN_SUCCESS && !thread_list.is_null() {
                // Deallocate the thread list (required by mach API contract)
                let list_size = thread_count as usize * std::mem::size_of::<libc::thread_act_t>();
                libc::vm_deallocate(task, thread_list as libc::vm_address_t, list_size);
                return Ok(thread_count as usize);
            }
        }
        Err(NonoError::SandboxInit(
            "Cannot determine thread count via mach task_threads API".to_string(),
        ))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(NonoError::SandboxInit(
            "Cannot determine thread count on this platform".to_string(),
        ))
    }
}

/// Supervisor IPC event loop (non-Linux).
///
/// Polls the supervisor socket and PTY relay fds for activity.
/// Uses `poll(2)` with a 200ms timeout to periodically check child status.
/// Returns the child's wait status and any denial records collected.
#[cfg(not(target_os = "linux"))]
fn run_supervisor_loop(
    child: Pid,
    sock: &mut SupervisorSocket,
    config: &SupervisorConfig<'_>,
    startup_timeout: Option<StartupTimeoutConfig<'_>>,
    mut trust_interceptor: Option<crate::trust_intercept::TrustInterceptor>,
    mut pty: Option<&mut crate::pty_proxy::PtyProxy>,
) -> Result<(WaitStatus, Vec<DenialRecord>)> {
    let sock_fd = sock.as_raw_fd();
    let mut denials = Vec::new();
    let mut seen_request_ids = HashSet::new();
    let startup_deadline = startup_timeout.map(|cfg| (Instant::now() + cfg.timeout, cfg));
    let mut startup_prompted = false;

    loop {
        let (pty_master, pty_client, pty_attach, pty_resize) =
            pty.as_ref().map_or((-1, -1, -1, -1), |p| p.poll_fds());
        let mut pfds = [
            libc::pollfd {
                fd: sock_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: pty_master,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: pty_client,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: pty_attach,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: pty_resize,
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        let ret = unsafe { libc::poll(pfds.as_mut_ptr(), 5, 200) };

        if ret > 0 {
            if pfds[0].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                debug!("Supervisor socket closed by child");
                break;
            }
            if pfds[0].revents & libc::POLLIN != 0 {
                match sock.recv_message() {
                    Ok(msg) => {
                        if let Err(e) = handle_supervisor_message(
                            sock,
                            msg,
                            child,
                            config,
                            &mut denials,
                            &mut seen_request_ids,
                            trust_interceptor.as_mut(),
                        ) {
                            warn!("Error handling supervisor message: {}", e);
                        }
                    }
                    Err(e) => {
                        debug!("Error receiving supervisor message: {}", e);
                        break;
                    }
                }
            }

            if let Some(ref mut p) = pty {
                if !handle_pty_poll_events(
                    p,
                    pfds[1].revents,
                    pfds[2].revents,
                    pfds[3].revents,
                    pfds[4].revents,
                    "supervisor loop",
                ) {
                    break;
                }
            }
        } else if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::Interrupted {
                warn!("poll() error in supervisor loop: {}", err);
                break;
            }
        }

        let pause_requested = drain_pause_pipe();
        if let Some(ref mut p) = pty {
            if pause_requested {
                p.sync_current_terminal_winsize();
            }
        }
        let in_band_detach_requested = pty.as_mut().is_some_and(|p| p.take_detach_request());
        handle_pty_detach_request(
            pty.as_deref_mut(),
            pause_requested,
            in_band_detach_requested,
        );

        match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => {
                if let Some((deadline, timeout_cfg)) = startup_deadline {
                    let has_output = pty.as_ref().is_some_and(|p| p.has_observed_output());
                    if Instant::now() >= deadline && !has_output && !startup_prompted {
                        startup_prompted = true;
                        let terminate = prompt_startup_termination_for_child(
                            child,
                            timeout_cfg,
                            has_output,
                            pty.as_deref_mut(),
                        );
                        if terminate {
                            let _ = signal::kill(child, Signal::SIGKILL);
                            return Ok((wait_for_child(child)?, denials));
                        }
                    }
                }
                continue;
            }
            Ok(WaitStatus::Stopped(_, sig)) => {
                debug!("Child stopped by signal {}, keeping supervisor alive", sig);
                continue;
            }
            Ok(WaitStatus::Continued(_)) => {
                debug!("Child continued, keeping supervisor alive");
                continue;
            }
            Ok(status) => return Ok((status, denials)),
            Err(nix::errno::Errno::EINTR) => continue,
            Err(nix::errno::Errno::ECHILD) => {
                warn!("Child already reaped in supervisor loop");
                return Ok((WaitStatus::Exited(child, 1), denials));
            }
            Err(e) => {
                return Err(NonoError::SandboxInit(format!(
                    "waitpid() failed in supervisor loop: {}",
                    e
                )));
            }
        }
    }

    let status = wait_for_child(child)?;
    Ok((status, denials))
}

/// Supervisor IPC event loop for capability expansion (Linux).
///
/// Multiplexes between:
/// - seccomp notify fd (openat/openat2 interceptions from the child)
/// - supervisor socket (explicit capability requests from SDK clients)
/// - PTY relay (real terminal <-> PTY master), when present
/// - child process exit via non-blocking `waitpid()`
///
/// When a seccomp notification requires interactive approval, the relay is
/// paused (terminal restored to canonical mode) so the user can type a response.
/// After the prompt, raw mode is re-entered and relay resumes.
///
/// The relay is optional: when `capability_elevation` is off, no PTY is
/// allocated but the supervisor loop still runs for trust interception over
/// the IPC socket.
///
/// Returns the child's wait status and any denial records collected.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn run_supervisor_loop(
    child: Pid,
    sock: &mut SupervisorSocket,
    config: &SupervisorConfig<'_>,
    startup_timeout: Option<StartupTimeoutConfig<'_>>,
    seccomp_fd: Option<&OwnedFd>,
    proxy_seccomp_fd: Option<&OwnedFd>,
    initial_caps: &[supervisor_linux::InitialCapability],
    mut trust_interceptor: Option<crate::trust_intercept::TrustInterceptor>,
    mut pty: Option<&mut crate::pty_proxy::PtyProxy>,
) -> Result<(WaitStatus, Vec<DenialRecord>)> {
    let sock_fd = sock.as_raw_fd();
    let notify_raw_fd = seccomp_fd.map(|fd| fd.as_raw_fd());
    let proxy_notify_raw_fd = proxy_seccomp_fd.map(|fd| fd.as_raw_fd());
    let mut rate_limiter = supervisor_linux::RateLimiter::new(10, 5);
    let mut denials = Vec::new();
    let mut seen_request_ids = HashSet::new();
    let mut sock_fd_active = true;
    let startup_deadline = startup_timeout.map(|cfg| (Instant::now() + cfg.timeout, cfg));
    let mut startup_prompted = false;

    loop {
        let mut pfds: Vec<libc::pollfd> = vec![libc::pollfd {
            fd: if sock_fd_active { sock_fd } else { -1 },
            events: libc::POLLIN,
            revents: 0,
        }];
        let notify_idx = notify_raw_fd.map(|nfd| {
            let idx = pfds.len();
            pfds.push(libc::pollfd {
                fd: nfd,
                events: libc::POLLIN,
                revents: 0,
            });
            idx
        });
        let proxy_notify_idx = proxy_notify_raw_fd.map(|pfd| {
            let idx = pfds.len();
            pfds.push(libc::pollfd {
                fd: pfd,
                events: libc::POLLIN,
                revents: 0,
            });
            idx
        });
        let pty_base_idx = pfds.len();
        let (pty_master, pty_client, pty_attach, pty_resize) =
            pty.as_ref().map_or((-1, -1, -1, -1), |p| p.poll_fds());
        pfds.push(libc::pollfd {
            fd: pty_master,
            events: libc::POLLIN,
            revents: 0,
        });
        pfds.push(libc::pollfd {
            fd: pty_client,
            events: libc::POLLIN,
            revents: 0,
        });
        pfds.push(libc::pollfd {
            fd: pty_attach,
            events: libc::POLLIN,
            revents: 0,
        });
        pfds.push(libc::pollfd {
            fd: pty_resize,
            events: libc::POLLIN,
            revents: 0,
        });

        let ret = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, 200) };

        match ret.cmp(&0) {
            std::cmp::Ordering::Greater => {
                if sock_fd_active && pfds[0].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                    if notify_raw_fd.is_some() || proxy_notify_raw_fd.is_some() || pty.is_some() {
                        debug!("Supervisor socket closed, continuing for seccomp/proxy/PTY");
                        sock_fd_active = false;
                    } else {
                        debug!("Supervisor socket closed by child");
                        break;
                    }
                }
                if sock_fd_active && pfds[0].revents & libc::POLLIN != 0 {
                    match sock.recv_message() {
                        Ok(msg) => {
                            if let Err(e) = handle_supervisor_message(
                                sock,
                                msg,
                                child,
                                config,
                                &mut denials,
                                &mut seen_request_ids,
                                trust_interceptor.as_mut(),
                            ) {
                                warn!("Error handling supervisor message: {}", e);
                            }
                        }
                        Err(e) => {
                            debug!("Error receiving supervisor message: {}", e);
                            if notify_raw_fd.is_none()
                                && proxy_notify_raw_fd.is_none()
                                && pty.is_none()
                            {
                                break;
                            }
                            sock_fd_active = false;
                        }
                    }
                }

                if let Some(notify_idx) = notify_idx {
                    if pfds[notify_idx].revents & libc::POLLIN != 0 {
                        if let Some(nfd) = notify_raw_fd {
                            if let Err(e) = supervisor_linux::handle_seccomp_notification(
                                nfd,
                                child,
                                config,
                                initial_caps,
                                &mut rate_limiter,
                                &mut denials,
                                trust_interceptor.as_mut(),
                            ) {
                                debug!("Error handling seccomp notification: {}", e);
                            }
                        }
                    }
                }

                if let Some(proxy_notify_idx) = proxy_notify_idx {
                    if pfds[proxy_notify_idx].revents & libc::POLLIN != 0 {
                        if let Some(pfd) = proxy_notify_raw_fd {
                            if let Err(e) = supervisor_linux::handle_network_notification(
                                pfd,
                                config,
                                &mut rate_limiter,
                            ) {
                                debug!("Error handling proxy seccomp notification: {}", e);
                            }
                        }
                    }
                }

                if let Some(ref mut p) = pty {
                    if !handle_pty_poll_events(
                        p,
                        pfds[pty_base_idx].revents,
                        pfds[pty_base_idx + 1].revents,
                        pfds[pty_base_idx + 2].revents,
                        pfds[pty_base_idx + 3].revents,
                        "supervisor loop",
                    ) {
                        break;
                    }
                }
            }
            std::cmp::Ordering::Less => {
                let err = std::io::Error::last_os_error();
                if err.kind() != std::io::ErrorKind::Interrupted {
                    warn!("poll() error in supervisor loop: {}", err);
                    break;
                }
            }
            std::cmp::Ordering::Equal => {}
        }

        let pause_requested = drain_pause_pipe();
        if let Some(ref mut p) = pty {
            if pause_requested {
                p.sync_current_terminal_winsize();
            }
        }
        let in_band_detach_requested = pty.as_mut().is_some_and(|p| p.take_detach_request());
        handle_pty_detach_request(
            pty.as_deref_mut(),
            pause_requested,
            in_band_detach_requested,
        );

        match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => {
                if let Some((deadline, timeout_cfg)) = startup_deadline {
                    let has_output = pty.as_ref().is_some_and(|p| p.has_observed_output());
                    if Instant::now() >= deadline && !has_output && !startup_prompted {
                        startup_prompted = true;
                        let terminate = prompt_startup_termination_for_child(
                            child,
                            timeout_cfg,
                            has_output,
                            pty.as_deref_mut(),
                        );
                        if terminate {
                            let _ = signal::kill(child, Signal::SIGTERM);
                            return Ok((wait_for_child(child)?, denials));
                        }
                    }
                }
                continue;
            }
            Ok(WaitStatus::Stopped(_, sig)) => {
                debug!("Child stopped by signal {}, keeping supervisor alive", sig);
                continue;
            }
            Ok(WaitStatus::Continued(_)) => {
                debug!("Child continued, keeping supervisor alive");
                continue;
            }
            Ok(status) => return Ok((status, denials)),
            Err(nix::errno::Errno::EINTR) => continue,
            Err(nix::errno::Errno::ECHILD) => {
                warn!("Child already reaped in supervisor loop");
                return Ok((WaitStatus::Exited(child, 1), denials));
            }
            Err(e) => {
                return Err(NonoError::SandboxInit(format!(
                    "waitpid() failed in supervisor loop: {}",
                    e
                )));
            }
        }
    }

    let status = wait_for_child(child)?;
    Ok((status, denials))
}

/// Handle a single supervisor IPC message.
///
/// Flow:
/// 1. Check protected nono state roots - those paths are rejected immediately
/// 2. Delegate to `ApprovalBackend` for the decision
/// 3. If granted, open the path and send the fd via `SCM_RIGHTS`
/// 4. Send the decision response
/// 5. Record denials for diagnostic footer
fn handle_supervisor_message(
    sock: &mut SupervisorSocket,
    msg: SupervisorMessage,
    child: Pid,
    config: &SupervisorConfig<'_>,
    denials: &mut Vec<DenialRecord>,
    seen_request_ids: &mut HashSet<String>,
    mut trust_interceptor: Option<&mut crate::trust_intercept::TrustInterceptor>,
) -> Result<()> {
    match msg {
        SupervisorMessage::Request(request) => {
            let decision_started = Instant::now();
            // Replay detection and bounded request-id cache.
            let replay_denial_reason = if seen_request_ids.contains(&request.request_id) {
                Some("Duplicate request_id rejected (replay detected)")
            } else if seen_request_ids.len() >= MAX_TRACKED_REQUEST_IDS {
                Some("Request replay cache is full; refusing request")
            } else {
                None
            };

            if let Some(reason) = replay_denial_reason {
                record_denial(
                    denials,
                    DenialRecord {
                        path: request.path.clone(),
                        access: request.access,
                        reason: DenialReason::PolicyBlocked,
                    },
                );
                let response = SupervisorResponse::Decision {
                    request_id: request.request_id.clone(),
                    decision: ApprovalDecision::Denied {
                        reason: reason.to_string(),
                    },
                };
                sock.send_response(&response)?;
                record_capability_audit(
                    config,
                    request,
                    decision_started,
                    response_decision(&response),
                )?;
                return Ok(());
            }
            seen_request_ids.insert(request.request_id.clone());

            // Digest from trust verification, used for TOCTOU re-check at open time.
            // Set by the trust interceptor branch when an instruction file is verified.
            let mut verified_digest: Option<String> = None;

            let decision = if let Some(protected_root) =
                crate::protected_paths::overlapping_protected_root(
                    &request.path,
                    false,
                    config.protected_roots,
                ) {
                debug!(
                    "Supervisor: path {} blocked by protected root {}",
                    request.path.display(),
                    protected_root.display()
                );
                record_denial(
                    denials,
                    DenialRecord {
                        path: request.path.clone(),
                        access: request.access,
                        reason: DenialReason::PolicyBlocked,
                    },
                );
                ApprovalDecision::Denied {
                    reason: format!(
                        "Path overlaps protected nono state root '{}': {}",
                        protected_root.display(),
                        request.path.display()
                    ),
                }
            } else if let Some(trust_result) = trust_interceptor
                .as_mut()
                .and_then(|ti| ti.check_path(&request.path))
            {
                // 2. Trust verification for instruction files
                match trust_result {
                    Ok(verified) => {
                        debug!(
                            "Supervisor: instruction file {} verified (publisher: {})",
                            request.path.display(),
                            verified.publisher,
                        );
                        // Stash the verified digest for TOCTOU re-check at open time
                        verified_digest = Some(verified.digest);
                        // Instruction file verified — proceed to approval backend
                        match config.approval_backend.request_capability(&request) {
                            Ok(d) => {
                                if d.is_denied() {
                                    record_denial(
                                        denials,
                                        DenialRecord {
                                            path: request.path.clone(),
                                            access: request.access,
                                            reason: DenialReason::UserDenied,
                                        },
                                    );
                                }
                                d
                            }
                            Err(e) => {
                                warn!("Approval backend error: {}", e);
                                record_denial(
                                    denials,
                                    DenialRecord {
                                        path: request.path.clone(),
                                        access: request.access,
                                        reason: DenialReason::BackendError,
                                    },
                                );
                                ApprovalDecision::Denied {
                                    reason: format!("Approval backend error: {e}"),
                                }
                            }
                        }
                    }
                    Err(reason) => {
                        // Instruction file failed trust verification — auto-deny
                        debug!(
                            "Supervisor: instruction file {} failed trust verification: {}",
                            request.path.display(),
                            reason
                        );
                        record_denial(
                            denials,
                            DenialRecord {
                                path: request.path.clone(),
                                access: request.access,
                                reason: DenialReason::PolicyBlocked,
                            },
                        );
                        ApprovalDecision::Denied {
                            reason: format!("Instruction file failed trust verification: {reason}"),
                        }
                    }
                }
            } else {
                // 3. Delegate to approval backend (non-instruction files)
                match config.approval_backend.request_capability(&request) {
                    Ok(d) => {
                        if d.is_denied() {
                            record_denial(
                                denials,
                                DenialRecord {
                                    path: request.path.clone(),
                                    access: request.access,
                                    reason: DenialReason::UserDenied,
                                },
                            );
                        }
                        d
                    }
                    Err(e) => {
                        warn!("Approval backend error: {}", e);
                        record_denial(
                            denials,
                            DenialRecord {
                                path: request.path.clone(),
                                access: request.access,
                                reason: DenialReason::BackendError,
                            },
                        );
                        ApprovalDecision::Denied {
                            reason: format!("Approval backend error: {e}"),
                        }
                    }
                }
            };

            // 3. If granted, open the path and send fd before the response
            if decision.is_granted() {
                match open_path_for_access(
                    &request.path,
                    &request.access,
                    config.protected_roots,
                    verified_digest.as_deref(),
                    Some(ProcfsAccessContext::new(child.as_raw() as u32, None)),
                ) {
                    Ok(file) => {
                        if let Err(e) = sock.send_fd(file.as_raw_fd()) {
                            warn!("Failed to send fd: {}", e);
                            let response = SupervisorResponse::Decision {
                                request_id: request.request_id.clone(),
                                decision: ApprovalDecision::Denied {
                                    reason: format!("Failed to send file descriptor: {e}"),
                                },
                            };
                            sock.send_response(&response)?;
                            record_capability_audit(
                                config,
                                request,
                                decision_started,
                                response_decision(&response),
                            )?;
                            return Ok(());
                        }
                    }
                    Err(e) => {
                        warn!("Failed to open path: {}", e);
                        let response = SupervisorResponse::Decision {
                            request_id: request.request_id.clone(),
                            decision: ApprovalDecision::Denied {
                                reason: format!("Supervisor failed to open path: {e}"),
                            },
                        };
                        sock.send_response(&response)?;
                        record_capability_audit(
                            config,
                            request,
                            decision_started,
                            response_decision(&response),
                        )?;
                        return Ok(());
                    }
                }
            }

            // 4. Send decision response
            let response = SupervisorResponse::Decision {
                request_id: request.request_id.clone(),
                decision,
            };
            sock.send_response(&response)?;
            record_capability_audit(
                config,
                request,
                decision_started,
                response_decision(&response),
            )?;
        }
        SupervisorMessage::OpenUrl(url_request) => {
            let request_id = url_request.request_id.clone();

            let (success, error) = match validate_and_open_url(&url_request.url, config) {
                Ok(()) => {
                    info!("Supervisor: opened URL {} for child", url_request.url);
                    (true, None)
                }
                Err(reason) => {
                    warn!(
                        "Supervisor: URL open denied for {}: {}",
                        url_request.url, reason
                    );
                    (false, Some(reason))
                }
            };
            let response = SupervisorResponse::UrlOpened {
                request_id,
                success,
                error: error.clone(),
            };
            sock.send_response(&response)?;
            if let Some(recorder_mutex) = config.audit_recorder {
                let mut recorder = recorder_mutex
                    .lock()
                    .map_err(|_| NonoError::Snapshot("Audit recorder lock poisoned".to_string()))?;
                recorder.record_open_url(url_request, success, error)?;
            }
        }
    }

    Ok(())
}

fn response_decision(response: &SupervisorResponse) -> ApprovalDecision {
    match response {
        SupervisorResponse::Decision { decision, .. } => decision.clone(),
        SupervisorResponse::UrlOpened { .. } => ApprovalDecision::Denied {
            reason: "invalid supervisor response type for capability decision".to_string(),
        },
    }
}

fn record_capability_audit(
    config: &SupervisorConfig<'_>,
    request: nono::supervisor::CapabilityRequest,
    decision_started: Instant,
    decision: ApprovalDecision,
) -> Result<()> {
    if let Some(recorder_mutex) = config.audit_recorder {
        let entry = AuditEntry {
            timestamp: std::time::SystemTime::now(),
            request,
            decision,
            backend: config.approval_backend.backend_name().to_string(),
            duration_ms: decision_started.elapsed().as_millis() as u64,
        };
        let mut recorder = recorder_mutex
            .lock()
            .map_err(|_| NonoError::Snapshot("Audit recorder lock poisoned".to_string()))?;
        recorder.record_capability_decision(entry)?;
    }
    Ok(())
}

/// Maximum URL length to prevent abuse via oversized URLs.
const MAX_URL_LENGTH: usize = 8192;

/// Validate a URL against the profile's allowed origins, then open it in the user's browser.
///
/// The supervisor (unsandboxed parent) performs this operation so the browser
/// launches outside the sandbox with full access to its own config files.
fn validate_and_open_url(
    url: &str,
    config: &SupervisorConfig<'_>,
) -> std::result::Result<(), String> {
    validate_url(url, config)?;
    open_url_in_browser(url)
}

/// Validate a URL against the profile's allowed origins and scheme rules.
///
/// Returns `Ok(())` if the URL passes all checks. Does not open the browser.
fn validate_url(url: &str, config: &SupervisorConfig<'_>) -> std::result::Result<(), String> {
    // Length check
    if url.len() > MAX_URL_LENGTH {
        return Err(format!(
            "URL exceeds maximum length ({} > {})",
            url.len(),
            MAX_URL_LENGTH
        ));
    }

    // Parse URL to extract origin
    let parsed = url::Url::parse(url).map_err(|e| format!("Invalid URL: {e}"))?;

    let scheme = parsed.scheme();
    let host = parsed.host_str().unwrap_or("");

    // Check localhost first
    let is_localhost = host == "localhost" || host == "127.0.0.1" || host == "::1";
    if is_localhost {
        if scheme != "http" && scheme != "https" {
            return Err(format!(
                "Localhost URL must use http or https scheme, got: {scheme}"
            ));
        }
        if !config.open_url_allow_localhost {
            return Err("Localhost URLs are not allowed by this profile".to_string());
        }
    } else {
        // Non-localhost: must be https
        if scheme != "https" {
            return Err(format!(
                "Only https:// URLs are allowed (got {scheme}://). \
                 file://, javascript:, data:, and other schemes are blocked."
            ));
        }

        // Check against allowed origins
        let url_origin = parsed.origin().unicode_serialization();
        let origin_allowed = config.open_url_origins.contains(&url_origin);

        if !origin_allowed {
            return Err(format!(
                "Origin {url_origin} is not in the profile's open_urls.allow_origins list"
            ));
        }
    }

    Ok(())
}

/// Open a URL in the user's default browser.
///
/// Uses `open` on macOS and `xdg-open` on Linux. Runs in the unsandboxed
/// parent process so the browser has full system access.
fn open_url_in_browser(url: &str) -> std::result::Result<(), String> {
    #[cfg(target_os = "macos")]
    let result = std::process::Command::new("open")
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    #[cfg(target_os = "linux")]
    let result = std::process::Command::new("xdg-open")
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let result: std::result::Result<std::process::ExitStatus, std::io::Error> =
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "URL opening not supported on this platform",
        ));

    match result {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(format!("Browser opener exited with status: {status}")),
        Err(e) => Err(format!("Failed to launch browser: {e}")),
    }
}

/// Clear `FD_CLOEXEC` on a file descriptor so it survives `execve()`.
fn clear_close_on_exec(fd: i32) -> Result<()> {
    // SAFETY: `fcntl` is called with a valid fd owned by this process.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(NonoError::SandboxInit(format!(
            "fcntl(F_GETFD) failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    let new_flags = flags & !libc::FD_CLOEXEC;
    if new_flags != flags {
        // SAFETY: `fcntl` is called with a valid fd and descriptor flags.
        let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, new_flags) };
        if rc < 0 {
            return Err(NonoError::SandboxInit(format!(
                "fcntl(F_SETFD) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
    }

    Ok(())
}

pub(super) fn record_denial(denials: &mut Vec<DenialRecord>, record: DenialRecord) {
    if denials.len() < MAX_DENIAL_RECORDS {
        denials.push(record);
    }
}

/// Create a temporary directory containing an `open` shim script on macOS.
///
/// The shim intercepts calls to `open` (which the Node.js `open` package
/// uses on macOS) and routes URL arguments through `nono open-url-helper`.
/// Non-URL arguments are passed through to `/usr/bin/open` so that
/// non-browser `open` invocations (e.g. opening files) still work.
///
/// Returns the path to the shim directory, or `None` on failure.
#[cfg(any(target_os = "linux", target_os = "macos"))]
struct BrowserShim {
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    dir: tempfile::TempDir,
    launcher: std::path::PathBuf,
}

#[cfg(target_os = "linux")]
fn create_linux_browser_shim(
    nono_exe: &std::path::Path,
    supervisor_fd: i32,
) -> Option<BrowserShim> {
    use std::os::unix::fs::PermissionsExt;

    let shim_dir = tempfile::Builder::new()
        .prefix("nono-browser-")
        .tempdir()
        .ok()?;
    let shim_dir_path = shim_dir.path();

    let helper_path = shim_dir_path.join("nono-open-url-helper");
    if std::fs::copy(nono_exe, &helper_path).is_err() {
        return None;
    }
    if std::fs::set_permissions(&helper_path, std::fs::Permissions::from_mode(0o755)).is_err() {
        return None;
    }

    let launcher_path = shim_dir_path.join("nono-browser");
    let quoted_helper = shell_quote(&helper_path.display().to_string());
    let script = format!(
        r#"#!/bin/sh
NONO_SUPERVISOR_FD={supervisor_fd} exec {quoted_helper} open-url-helper "$@"
"#
    );

    if std::fs::write(&launcher_path, script).is_err() {
        return None;
    }
    if std::fs::set_permissions(&launcher_path, std::fs::Permissions::from_mode(0o755)).is_err() {
        return None;
    }

    Some(BrowserShim {
        dir: shim_dir,
        launcher: launcher_path,
    })
}

#[cfg(target_os = "macos")]
fn create_open_shim(nono_exe: &std::path::Path, supervisor_fd: i32) -> Option<BrowserShim> {
    use std::os::unix::fs::PermissionsExt;

    let shim_dir = tempfile::Builder::new()
        .prefix("nono-shim-")
        .tempdir()
        .ok()?;
    let shim_dir_path = shim_dir.path();

    // Keep the helper inside the shim directory so it is always readable and
    // executable under the sandbox's temp-dir allowlist, regardless of where
    // the original `nono` binary was launched from.
    let helper_path = shim_dir_path.join("nono-open-url-helper");
    if std::fs::copy(nono_exe, &helper_path).is_err() {
        return None;
    }
    if std::fs::set_permissions(&helper_path, std::fs::Permissions::from_mode(0o755)).is_err() {
        return None;
    }

    let shim_path = shim_dir_path.join("open");
    let quoted_helper = shell_quote(&helper_path.display().to_string());

    // The shim script scans all arguments for the first URL-like value. If one
    // is present, delegate to nono open-url-helper. Otherwise fall through to
    // /usr/bin/open for non-URL uses (opening files, apps, etc.).
    let script = format!(
        r#"#!/bin/sh
# nono URL open shim — intercepts `open` calls for browser URL delegation
url_arg=""
for arg in "$@"; do
    case "$arg" in
        http://*|https://*)
            url_arg="$arg"
            break
            ;;
    esac
done

if [ -n "$url_arg" ]; then
    NONO_SUPERVISOR_FD={supervisor_fd} exec {quoted_helper} open-url-helper "$url_arg"
else
    exec /usr/bin/open "$@"
fi
"#
    );

    if std::fs::write(&shim_path, script).is_err() {
        return None;
    }
    if std::fs::set_permissions(&shim_path, std::fs::Permissions::from_mode(0o755)).is_err() {
        return None;
    }

    Some(BrowserShim {
        dir: shim_dir,
        launcher: shim_path,
    })
}

/// Shell-quote a string for safe embedding in `sh -c` commands.
/// If the string contains no special characters, returns it unchanged.
/// Otherwise wraps it in single quotes, escaping embedded single quotes.
fn shell_quote(s: &str) -> String {
    // If the string is safe as-is, skip quoting
    if !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/-_.".contains(&b))
    {
        return s.to_string();
    }
    // Single-quote the string, replacing ' with '\'' (end quote, escaped quote, start quote)
    let mut quoted = String::with_capacity(s.len() + 2);
    quoted.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

/// Generate a unique request ID from timestamp + monotonic counter.
#[cfg(target_os = "linux")]
fn unique_request_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0) as u64;
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);

    // Combine timestamp with monotonic counter for uniqueness
    format!("{:x}-{:x}", nanos, seq)
}

/// Resolve `/proc/self` and `/proc/thread-self` against the sandboxed child.
///
/// Without this rewrite, canonicalizing `/proc/self/...` in the supervisor would
/// resolve to the supervisor's procfs view instead of the child's.
fn resolve_procfs_path_for_child(
    path: &Path,
    procfs_context: Option<ProcfsAccessContext>,
) -> Result<PathBuf> {
    let Some(procfs_context) = procfs_context else {
        return Ok(path.to_path_buf());
    };

    let mut components = path.components();
    if components.next() != Some(Component::RootDir)
        || components.next() != Some(Component::Normal(OsStr::new("proc")))
    {
        return Ok(path.to_path_buf());
    }

    let Some(proc_component) = components.next() else {
        return Ok(path.to_path_buf());
    };

    let mut rewritten = PathBuf::from("/proc");
    match proc_component {
        Component::Normal(part) if part == OsStr::new("self") => {
            rewritten.push(procfs_context.process_pid.to_string());
        }
        Component::Normal(part) if part == OsStr::new("thread-self") => {
            let thread_pid = procfs_context.thread_pid.ok_or_else(|| {
                NonoError::SandboxInit(
                    "Cannot resolve /proc/thread-self without a requesting thread ID".to_string(),
                )
            })?;
            rewritten.push(procfs_context.process_pid.to_string());
            rewritten.push("task");
            rewritten.push(thread_pid.to_string());
        }
        _ => return Ok(path.to_path_buf()),
    }

    for component in components {
        match component {
            Component::Normal(part) => rewritten.push(part),
            Component::CurDir => rewritten.push("."),
            Component::ParentDir => rewritten.push(".."),
            Component::RootDir | Component::Prefix(_) => {}
        }
    }

    Ok(rewritten)
}

/// Enforce the supervisor's procfs deny rules before canonicalization.
///
/// This must run on the resolved procfs path before `canonicalize()`, because
/// procfs links such as `/proc/<pid>/fd/<n>` and `/proc/<pid>/cwd` would
/// otherwise erase their `/proc` provenance during resolution.
fn validate_procfs_access(
    resolved_path: &Path,
    procfs_context: Option<ProcfsAccessContext>,
) -> std::result::Result<(), OpenPathError> {
    const SELF_BLOCKED_PROC_NAMES: &[&str] =
        &["fd", "ns", "pagemap", "exe", "cwd", "root", "mountinfo"];

    let Some(suffix) = resolved_path
        .to_str()
        .and_then(|s| s.strip_prefix("/proc/"))
    else {
        return Ok(());
    };

    let allowed_pid = procfs_context.map(|ctx| ctx.process_pid.to_string());
    let components: Vec<&str> = suffix.split('/').collect();

    if components.is_empty() || !components[0].chars().all(|c| c.is_ascii_digit()) {
        return Ok(());
    }

    let (pid_component, sensitive_component) = if components.len() >= 4
        && components[1] == "task"
        && components[2].chars().all(|c| c.is_ascii_digit())
    {
        (components[0], components.get(3).copied())
    } else {
        (components[0], components.get(1).copied())
    };

    if allowed_pid.as_deref() != Some(pid_component) {
        return Err(OpenPathError::policy_blocked(format!(
            "Access to {} is blocked by policy",
            resolved_path.display(),
        )));
    }

    if let Some(component) = sensitive_component {
        if SELF_BLOCKED_PROC_NAMES.contains(&component) {
            return Err(OpenPathError::policy_blocked(format!(
                "Access to {} is blocked by policy",
                resolved_path.display(),
            )));
        }
    }

    Ok(())
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug)]
struct OpenPathError {
    errno: i32,
    message: String,
    policy_blocked: bool,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl OpenPathError {
    fn policy_blocked(message: String) -> Self {
        Self {
            errno: libc::EPERM,
            message,
            policy_blocked: true,
        }
    }

    fn io(message: String, source: &std::io::Error) -> Self {
        Self {
            errno: source.raw_os_error().unwrap_or(libc::EIO),
            message,
            policy_blocked: false,
        }
    }

    fn internal(message: String) -> Self {
        Self {
            errno: libc::EIO,
            message,
            policy_blocked: false,
        }
    }

    fn errno(&self) -> i32 {
        self.errno
    }

    fn is_policy_blocked(&self) -> bool {
        self.policy_blocked
    }
}

impl std::fmt::Display for OpenPathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for OpenPathError {}

/// Open a filesystem path with the requested access mode.
///
/// Used by the supervisor to open files on behalf of the sandboxed child
/// before passing the fd via `SCM_RIGHTS` or seccomp fd injection.
///
/// # Security
///
/// This function canonicalizes the path and re-checks it against protected
/// nono state roots AFTER resolution. This prevents symlink-based bypasses
/// where a child creates `/tmp/innocent -> ~/.nono` and requests access to the
/// innocuous alias.
///
/// File creation is intentionally disabled (`create(false)`) -- the
/// supervisor only grants access to existing files. File creation should
/// go through the initial capability set, not capability expansion.
fn open_path_for_access(
    path: &Path,
    access: &nono::AccessMode,
    protected_roots: &[PathBuf],
    trust_digest: Option<&str>,
    procfs_context: Option<ProcfsAccessContext>,
) -> std::result::Result<std::fs::File, OpenPathError> {
    let resolved_path = resolve_procfs_path_for_child(path, procfs_context)
        .map_err(|e| OpenPathError::internal(e.to_string()))?;

    validate_procfs_access(&resolved_path, procfs_context)?;

    // Canonicalize to resolve symlinks before opening. This ensures
    // we check and open the real target, not a symlink alias.
    let canonical = std::fs::canonicalize(&resolved_path).map_err(|e| {
        OpenPathError::io(
            format!(
                "Failed to canonicalize {} for access: {}",
                path.display(),
                e
            ),
            &e,
        )
    })?;

    if let Some(protected_root) =
        crate::protected_paths::overlapping_protected_root(&canonical, false, protected_roots)
    {
        return Err(OpenPathError::policy_blocked(format!(
            "Path {} resolves to {} which overlaps protected nono state root '{}'",
            path.display(),
            canonical.display(),
            protected_root.display(),
        )));
    }

    let file = open_canonical_path_no_symlinks(&canonical, access).map_err(|e| {
        OpenPathError::io(
            format!(
                "Failed to open {} for {:?} access: {}",
                canonical.display(),
                access,
                e
            ),
            &e,
        )
    })?;

    // TOCTOU re-verification: if this file was trust-verified, re-compute the
    // digest from the opened fd and compare against the verification-time digest.
    // This closes the window between check_path() (which reads the file by path)
    // and open (which opens a potentially different file if an attacker performed
    // an atomic rename between the two operations).
    if let Some(expected_digest) = trust_digest {
        use sha2::Digest as _;
        use std::io::{Read, Seek};
        let mut hasher = sha2::Sha256::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = (&file).read(&mut buf).map_err(|e| {
                OpenPathError::io(
                    format!(
                        "Failed to read {} for digest re-check: {}",
                        canonical.display(),
                        e,
                    ),
                    &e,
                )
            })?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let hash = hasher.finalize();
        let actual_digest: String = hash
            .iter()
            .flat_map(|b| {
                [
                    char::from_digit((u32::from(*b) >> 4) & 0xF, 16).unwrap_or('0'),
                    char::from_digit(u32::from(*b) & 0xF, 16).unwrap_or('0'),
                ]
            })
            .collect();
        if actual_digest != expected_digest {
            return Err(OpenPathError::policy_blocked(format!(
                "Instruction file {} was modified between trust verification and open \
                 (expected digest {}, got {}). Possible TOCTOU attack.",
                path.display(),
                expected_digest,
                actual_digest,
            )));
        }
        // Seek back to start so the child reads from the beginning
        (&file).seek(std::io::SeekFrom::Start(0)).map_err(|e| {
            OpenPathError::io(
                format!(
                    "Failed to seek {} after digest re-check: {}",
                    canonical.display(),
                    e,
                ),
                &e,
            )
        })?;
    }

    Ok(file)
}

/// Open a canonical absolute path by traversing path components using `openat`.
///
/// Every component is opened with `O_NOFOLLOW` to prevent symlink substitution
/// between canonicalization and open time (TOCTOU).
fn open_canonical_path_no_symlinks(
    canonical: &std::path::Path,
    access: &nono::AccessMode,
) -> std::io::Result<std::fs::File> {
    use std::os::unix::ffi::OsStrExt;

    if !canonical.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "canonical path must be absolute",
        ));
    }

    let components: Vec<_> = canonical
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(part) => Some(part),
            _ => None,
        })
        .collect();

    if components.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "cannot open root path",
        ));
    }

    // Start resolution from the real root directory.
    let root = CString::new("/")
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid path"))?;
    let root_fd = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut dir_fd = unsafe { OwnedFd::from_raw_fd(root_fd) };

    for part in &components[..components.len() - 1] {
        let c_part = CString::new(part.as_bytes())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid path"))?;
        let next_fd = unsafe {
            libc::openat(
                dir_fd.as_raw_fd(),
                c_part.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if next_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        dir_fd = unsafe { OwnedFd::from_raw_fd(next_fd) };
    }

    let flags = match access {
        nono::AccessMode::Read => libc::O_RDONLY,
        nono::AccessMode::Write => libc::O_WRONLY,
        nono::AccessMode::ReadWrite => libc::O_RDWR,
    } | libc::O_NOFOLLOW
        | libc::O_CLOEXEC;

    let leaf = CString::new(components[components.len() - 1].as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid path"))?;
    let file_fd = unsafe { libc::openat(dir_fd.as_raw_fd(), leaf.as_ptr(), flags) };
    if file_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let file_fd = unsafe { OwnedFd::from_raw_fd(file_fd) };
    Ok(std::fs::File::from(file_fd))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::termios::{
        ControlFlags, InputFlags, LocalFlags, OutputFlags, SpecialCharacterIndices,
    };

    #[cfg(target_os = "linux")]
    #[test]
    fn test_linux_child_requires_dumpable_only_for_seccomp_driven_features() {
        assert!(!linux_child_requires_dumpable(false, false));
        assert!(linux_child_requires_dumpable(true, false));
        assert!(linux_child_requires_dumpable(false, true));
        assert!(linux_child_requires_dumpable(true, true));
    }

    #[test]
    fn test_exec_strategy_default_is_supervised() {
        assert_eq!(ExecStrategy::default(), ExecStrategy::Supervised);
    }

    #[test]
    fn test_configure_startup_prompt_termios_restores_cooked_input() {
        let mut termios = unsafe { std::mem::zeroed::<nix::sys::termios::Termios>() };
        termios.input_flags = InputFlags::IGNBRK | InputFlags::INLCR | InputFlags::IGNCR;
        termios.output_flags = OutputFlags::empty();
        termios.local_flags = LocalFlags::empty();
        termios.control_flags = ControlFlags::CSIZE | ControlFlags::PARENB;
        termios.control_chars[SpecialCharacterIndices::VMIN as usize] = 0;
        termios.control_chars[SpecialCharacterIndices::VTIME as usize] = 9;

        crate::profile_save_runtime::configure_prompt_termios(&mut termios);

        assert!(termios
            .input_flags
            .contains(InputFlags::ICRNL | InputFlags::IXON));
        assert!(!termios
            .input_flags
            .intersects(InputFlags::IGNBRK | InputFlags::INLCR | InputFlags::IGNCR));
        assert!(termios.output_flags.contains(OutputFlags::OPOST));
        assert!(termios.local_flags.contains(
            LocalFlags::ECHO
                | LocalFlags::ECHONL
                | LocalFlags::ICANON
                | LocalFlags::ISIG
                | LocalFlags::IEXTEN
        ));
        assert!(!termios.control_flags.contains(ControlFlags::PARENB));
        assert!(termios.control_flags.contains(ControlFlags::CS8));
        assert_eq!(
            termios.control_chars[SpecialCharacterIndices::VMIN as usize],
            1
        );
        assert_eq!(
            termios.control_chars[SpecialCharacterIndices::VTIME as usize],
            0
        );
    }

    #[test]
    fn test_exec_strategy_variants() {
        assert_ne!(ExecStrategy::Direct, ExecStrategy::Supervised);
    }

    #[test]
    fn test_dangerous_env_vars_linker_injection() {
        assert!(is_dangerous_env_var("LD_PRELOAD"));
        assert!(is_dangerous_env_var("LD_LIBRARY_PATH"));
        assert!(is_dangerous_env_var("LD_AUDIT"));
        assert!(is_dangerous_env_var("DYLD_INSERT_LIBRARIES"));
        assert!(is_dangerous_env_var("DYLD_LIBRARY_PATH"));
        assert!(is_dangerous_env_var("DYLD_FRAMEWORK_PATH"));
    }

    #[test]
    fn test_dangerous_env_vars_shell_injection() {
        assert!(is_dangerous_env_var("BASH_ENV"));
        assert!(is_dangerous_env_var("ENV"));
        assert!(is_dangerous_env_var("CDPATH"));
        assert!(is_dangerous_env_var("GLOBIGNORE"));
        assert!(is_dangerous_env_var("BASH_FUNC_foo%%"));
        assert!(is_dangerous_env_var("PROMPT_COMMAND"));
    }

    #[test]
    fn test_dangerous_env_vars_interpreter_injection() {
        assert!(is_dangerous_env_var("PYTHONSTARTUP"));
        assert!(is_dangerous_env_var("PYTHONPATH"));
        assert!(is_dangerous_env_var("NODE_OPTIONS"));
        assert!(is_dangerous_env_var("NODE_PATH"));
        assert!(is_dangerous_env_var("PERL5OPT"));
        assert!(is_dangerous_env_var("PERL5LIB"));
        assert!(is_dangerous_env_var("RUBYOPT"));
        assert!(is_dangerous_env_var("RUBYLIB"));
        assert!(is_dangerous_env_var("GEM_PATH"));
        assert!(is_dangerous_env_var("GEM_HOME"));
    }

    #[test]
    fn test_dangerous_env_vars_jvm_dotnet_go() {
        assert!(is_dangerous_env_var("JAVA_TOOL_OPTIONS"));
        assert!(is_dangerous_env_var("_JAVA_OPTIONS"));
        assert!(is_dangerous_env_var("DOTNET_STARTUP_HOOKS"));
        assert!(is_dangerous_env_var("GOFLAGS"));
    }

    #[test]
    fn test_dangerous_env_vars_shell_ifs() {
        assert!(is_dangerous_env_var("IFS"));
    }

    #[test]
    fn test_exec_strategy_supervised_selection() {
        let strategy = ExecStrategy::Supervised;
        assert_eq!(strategy, ExecStrategy::Supervised);
        assert_ne!(ExecStrategy::Supervised, ExecStrategy::Direct);
    }

    #[test]
    fn test_safe_env_vars_allowed() {
        assert!(!is_dangerous_env_var("HOME"));
        assert!(!is_dangerous_env_var("PATH"));
        assert!(!is_dangerous_env_var("SHELL"));
        assert!(!is_dangerous_env_var("TERM"));
        assert!(!is_dangerous_env_var("LANG"));
        assert!(!is_dangerous_env_var("USER"));
        assert!(!is_dangerous_env_var("TMPDIR"));
        assert!(!is_dangerous_env_var("EDITOR"));
        assert!(!is_dangerous_env_var("XDG_CONFIG_HOME"));
        assert!(!is_dangerous_env_var("CARGO_HOME"));
        assert!(!is_dangerous_env_var("RUST_LOG"));
        assert!(!is_dangerous_env_var("SSH_AUTH_SOCK"));
    }

    #[test]
    fn test_record_denial_is_capped() {
        let mut denials = Vec::new();
        for _ in 0..(MAX_DENIAL_RECORDS + 10) {
            record_denial(
                &mut denials,
                DenialRecord {
                    path: "/tmp/test".into(),
                    access: nono::AccessMode::Read,
                    reason: DenialReason::PolicyBlocked,
                },
            );
        }
        assert_eq!(denials.len(), MAX_DENIAL_RECORDS);
    }

    #[test]
    fn test_resolve_procfs_self_for_child() {
        let path = resolve_procfs_path_for_child(
            Path::new("/proc/self/maps"),
            Some(ProcfsAccessContext::new(4242, Some(4343))),
        );
        assert_eq!(path.ok(), Some(PathBuf::from("/proc/4242/maps")));
    }

    #[test]
    fn test_resolve_procfs_thread_self_for_child() {
        let path = resolve_procfs_path_for_child(
            Path::new("/proc/thread-self/maps"),
            Some(ProcfsAccessContext::new(4242, Some(4343))),
        );
        assert_eq!(path.ok(), Some(PathBuf::from("/proc/4242/task/4343/maps")));
    }

    #[test]
    fn test_resolve_procfs_thread_self_requires_thread_context() {
        let result = resolve_procfs_path_for_child(
            Path::new("/proc/thread-self/maps"),
            Some(ProcfsAccessContext::new(4242, None)),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_procfs_access_allows_child_sensitive_proc_path() {
        let result = validate_procfs_access(
            Path::new("/proc/4242/maps"),
            Some(ProcfsAccessContext::new(4242, Some(4343))),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_procfs_access_blocks_foreign_sensitive_proc_path() {
        let result = validate_procfs_access(
            Path::new("/proc/1/maps"),
            Some(ProcfsAccessContext::new(4242, Some(4343))),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_procfs_access_allows_child_task_sensitive_proc_path() {
        let result = validate_procfs_access(
            Path::new("/proc/4242/task/9999/maps"),
            Some(ProcfsAccessContext::new(4242, Some(4343))),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_procfs_access_blocks_foreign_proc_fd_path() {
        let result = validate_procfs_access(
            Path::new("/proc/1/fd/3"),
            Some(ProcfsAccessContext::new(4242, Some(4343))),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_procfs_access_blocks_child_proc_fd_path() {
        let result = validate_procfs_access(
            Path::new("/proc/4242/fd/3"),
            Some(ProcfsAccessContext::new(4242, Some(4343))),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_procfs_access_blocks_foreign_proc_cwd_path_before_canonicalization() {
        let result = validate_procfs_access(
            Path::new("/proc/1/cwd"),
            Some(ProcfsAccessContext::new(4242, Some(4343))),
        );
        assert!(result.is_err());
    }

    // --- Grandchild procfs regression tests (issue #602) ---
    //
    // When bun is a grandchild (nono→sh→bun), notifying_tgid=bun's PID (e.g. 1001),
    // not the direct child sh's PID (e.g. 1000). These tests verify the fix uses
    // the correct PID for /proc/self resolution and access validation.

    #[test]
    fn test_resolve_procfs_self_for_grandchild_tgid() {
        // After the fix, process_pid=notifying_tgid=1001 (bun).
        // /proc/self/maps must resolve to /proc/1001/maps, not /proc/1000/maps.
        let path = resolve_procfs_path_for_child(
            Path::new("/proc/self/maps"),
            Some(ProcfsAccessContext::new(1001, Some(1001))),
        );
        assert_eq!(path.ok(), Some(PathBuf::from("/proc/1001/maps")));
    }

    #[test]
    fn test_validate_procfs_access_allows_grandchild_own_path() {
        // notifying_tgid=1001 (bun): accessing /proc/1001/maps is allowed.
        let result = validate_procfs_access(
            Path::new("/proc/1001/maps"),
            Some(ProcfsAccessContext::new(1001, Some(1001))),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_procfs_access_blocks_grandchild_accessing_sibling() {
        // notifying_tgid=1001 (bun): accessing /proc/1000/maps (sh's maps) is blocked.
        // This verifies the fix does NOT allow cross-process procfs reads.
        let result = validate_procfs_access(
            Path::new("/proc/1000/maps"),
            Some(ProcfsAccessContext::new(1001, Some(1001))),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_procfs_self_wrong_pid_demonstrates_bug() {
        // Demonstrates the pre-fix bug: if process_pid=1000 (sh) but the requesting
        // process is bun (1001), /proc/self/maps incorrectly resolves to /proc/1000/maps.
        // After the fix, process_pid is always notifying_tgid, so this construction
        // would never be used for bun's request.
        let path = resolve_procfs_path_for_child(
            Path::new("/proc/self/maps"),
            Some(ProcfsAccessContext::new(1000, Some(1001))), // broken: sh's PID for bun's request
        );
        // This produces the wrong path (sh's maps instead of bun's maps).
        assert_eq!(path.ok(), Some(PathBuf::from("/proc/1000/maps")));
    }

    /// Verify that the supervisor loop runs and exits cleanly without a PTY relay.
    ///
    /// This tests the `capability_elevation = false` code path where no PTY is
    /// allocated but the supervisor loop must still service the IPC socket for
    /// trust interception. The child fork closes its socket end and exits,
    /// causing the loop to see POLLHUP and return.
    #[test]
    fn test_supervisor_loop_runs_without_pty_relay() {
        use std::os::unix::net::UnixStream;

        struct DenyAll;
        impl ApprovalBackend for DenyAll {
            fn request_capability(
                &self,
                _req: &nono::supervisor::CapabilityRequest,
            ) -> nono::Result<ApprovalDecision> {
                Ok(ApprovalDecision::Denied {
                    reason: "test".to_string(),
                })
            }
            fn backend_name(&self) -> &str {
                "deny-all-test"
            }
        }

        let (parent_stream, child_stream) = UnixStream::pair()
            .map_err(|e| format!("socketpair: {e}"))
            .expect("socketpair failed in test");

        let backend = DenyAll;
        let sup_cfg = SupervisorConfig {
            protected_roots: &[],
            approval_backend: &backend,
            session_id: "test-session",
            attach_initial_client: false,
            detach_sequence: None,
            open_url_origins: &[],
            open_url_allow_localhost: false,
            audit_recorder: None,
            allow_launch_services_active: false,
            #[cfg(target_os = "linux")]
            proxy_port: 0,
            #[cfg(target_os = "linux")]
            proxy_bind_ports: Vec::new(),
        };

        // Fork a child that closes its socket end and exits immediately.
        // SAFETY: We are in a test; the child does minimal work and _exit()s.
        match unsafe { fork() } {
            Ok(ForkResult::Child) => {
                drop(child_stream);
                drop(parent_stream);
                unsafe { libc::_exit(42) };
            }
            Ok(ForkResult::Parent { child }) => {
                drop(child_stream);
                let mut sock = SupervisorSocket::from_stream(parent_stream);

                // Run supervisor loop with relay: None (the capability_elevation=false path).
                // It should poll the socket, see POLLHUP when child exits, and return.
                #[cfg(target_os = "linux")]
                let result = run_supervisor_loop(
                    child,
                    &mut sock,
                    &sup_cfg,
                    None, // no startup timeout
                    None, // no seccomp
                    None, // no proxy seccomp
                    &[],  // no initial caps
                    None, // no trust interceptor
                    None, // no PTY relay — this is what we're testing
                );

                #[cfg(not(target_os = "linux"))]
                let result = run_supervisor_loop(
                    child, &mut sock, &sup_cfg, None, // no startup timeout
                    None, // no trust interceptor
                    None, // no PTY relay
                );

                let (status, denials) = result
                    .map_err(|e| format!("supervisor loop: {e}"))
                    .expect("supervisor loop failed");
                assert!(denials.is_empty(), "no denials expected");

                // Child exited with code 42
                match status {
                    WaitStatus::Exited(_, code) => assert_eq!(code, 42),
                    other => panic!("unexpected wait status: {other:?}"),
                }
            }
            Err(e) => panic!("fork failed: {e}"),
        }
    }

    /// Verify that ProxyOnly mode on V4+ kernels does NOT deadlock.
    ///
    /// On Landlock V4+ kernels, ProxyOnly is handled by Landlock natively.
    /// The seccomp_proxy_fallback flag should be false, so the parent must
    /// NOT attempt to recv a proxy notify fd. This test verifies the
    /// supervisor loop starts and exits cleanly with ProxyOnly caps but
    /// no proxy seccomp filter.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_supervisor_loop_proxy_only_v4_no_deadlock() {
        use std::os::unix::net::UnixStream;

        struct DenyAll;
        impl ApprovalBackend for DenyAll {
            fn request_capability(
                &self,
                _req: &nono::supervisor::CapabilityRequest,
            ) -> nono::Result<ApprovalDecision> {
                Ok(ApprovalDecision::Denied {
                    reason: "test".to_string(),
                })
            }
            fn backend_name(&self) -> &str {
                "deny-all-test"
            }
        }

        let (parent_stream, child_stream) = UnixStream::pair()
            .map_err(|e| format!("socketpair: {e}"))
            .expect("socketpair failed in test");

        let backend = DenyAll;
        // ProxyOnly mode with proxy_port set, but seccomp_proxy_fallback is false
        // (simulating V4+ where Landlock handles networking).
        let sup_cfg = SupervisorConfig {
            protected_roots: &[],
            approval_backend: &backend,
            session_id: "test-proxy-v4",
            attach_initial_client: false,
            detach_sequence: None,
            open_url_origins: &[],
            open_url_allow_localhost: false,
            audit_recorder: None,
            allow_launch_services_active: false,
            #[cfg(target_os = "linux")]
            proxy_port: 8080,
            #[cfg(target_os = "linux")]
            proxy_bind_ports: Vec::new(),
        };

        match unsafe { fork() } {
            Ok(ForkResult::Child) => {
                // Child: close socket and exit. Does NOT send a proxy notify fd.
                drop(child_stream);
                drop(parent_stream);
                unsafe { libc::_exit(0) };
            }
            Ok(ForkResult::Parent { child }) => {
                drop(child_stream);
                let mut sock = SupervisorSocket::from_stream(parent_stream);

                // Run supervisor loop with NO proxy seccomp fd.
                // If the bug from before were present (unconditional recv_fd),
                // this would deadlock because the child never sends a second fd.
                let result = run_supervisor_loop(
                    child,
                    &mut sock,
                    &sup_cfg,
                    None, // no startup timeout
                    None, // no openat seccomp
                    None, // no proxy seccomp — V4+ Landlock handles it
                    &[],  // no initial caps
                    None, // no trust interceptor
                    None, // no PTY relay
                );

                let (status, denials) = result
                    .map_err(|e| format!("supervisor loop: {e}"))
                    .expect("supervisor loop should not deadlock");
                assert!(denials.is_empty());

                match status {
                    WaitStatus::Exited(_, code) => assert_eq!(code, 0),
                    other => panic!("unexpected wait status: {other:?}"),
                }
            }
            Err(e) => panic!("fork failed: {e}"),
        }
    }

    struct TestDenyBackend;
    impl ApprovalBackend for TestDenyBackend {
        fn request_capability(
            &self,
            _req: &nono::supervisor::CapabilityRequest,
        ) -> nono::Result<ApprovalDecision> {
            Ok(ApprovalDecision::Denied {
                reason: "test".to_string(),
            })
        }
        fn backend_name(&self) -> &str {
            "test-deny"
        }
    }

    #[test]
    fn test_validate_url_allowed_origin() {
        let backend = TestDenyBackend;
        let origins = vec!["https://claude.ai".to_string()];
        let config = SupervisorConfig {
            protected_roots: &[],
            approval_backend: &backend,
            session_id: "test",
            attach_initial_client: false,
            detach_sequence: None,
            open_url_origins: &origins,
            open_url_allow_localhost: false,
            audit_recorder: None,
            allow_launch_services_active: false,
            #[cfg(target_os = "linux")]
            proxy_port: 0,
            #[cfg(target_os = "linux")]
            proxy_bind_ports: Vec::new(),
        };

        // Allowed origin: validation passes
        let result = validate_url("https://claude.ai/oauth/authorize?state=xyz", &config);
        assert!(result.is_ok(), "Expected validation to pass: {result:?}");

        // Disallowed origin: must fail validation
        let result = validate_url("https://evil.example.com/phishing", &config);
        assert!(result.is_err());
        assert!(result
            .as_ref()
            .err()
            .map(|e| e.contains("not in the profile"))
            .unwrap_or(false));
    }

    #[test]
    fn test_validate_url_blocks_non_https() {
        let backend = TestDenyBackend;
        let config = SupervisorConfig {
            protected_roots: &[],
            approval_backend: &backend,
            session_id: "test",
            attach_initial_client: false,
            detach_sequence: None,
            open_url_origins: &[],
            open_url_allow_localhost: false,
            audit_recorder: None,
            allow_launch_services_active: false,
            #[cfg(target_os = "linux")]
            proxy_port: 0,
            #[cfg(target_os = "linux")]
            proxy_bind_ports: Vec::new(),
        };

        let result = validate_url("file:///etc/passwd", &config);
        assert!(result.is_err());
        assert!(result
            .as_ref()
            .err()
            .map(|e| e.contains("Only https://"))
            .unwrap_or(false));

        let result = validate_url("javascript:alert(1)", &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_url_localhost() {
        let backend = TestDenyBackend;
        let config_allow = SupervisorConfig {
            protected_roots: &[],
            approval_backend: &backend,
            session_id: "test",
            attach_initial_client: false,
            detach_sequence: None,
            open_url_origins: &[],
            open_url_allow_localhost: true,
            audit_recorder: None,
            allow_launch_services_active: false,
            #[cfg(target_os = "linux")]
            proxy_port: 0,
            #[cfg(target_os = "linux")]
            proxy_bind_ports: Vec::new(),
        };
        let config_deny = SupervisorConfig {
            protected_roots: &[],
            approval_backend: &backend,
            session_id: "test",
            attach_initial_client: false,
            detach_sequence: None,
            open_url_origins: &[],
            open_url_allow_localhost: false,
            audit_recorder: None,
            allow_launch_services_active: false,
            #[cfg(target_os = "linux")]
            proxy_port: 0,
            #[cfg(target_os = "linux")]
            proxy_bind_ports: Vec::new(),
        };

        // Localhost denied when not allowed
        let result = validate_url("http://localhost:8080/callback", &config_deny);
        assert!(result.is_err());
        assert!(result
            .as_ref()
            .err()
            .map(|e| e.contains("not allowed"))
            .unwrap_or(false));

        // Localhost allowed when configured
        let result = validate_url("http://localhost:8080/callback", &config_allow);
        assert!(
            result.is_ok(),
            "Expected localhost validation to pass: {result:?}"
        );
    }

    #[test]
    fn test_validate_url_max_length() {
        let backend = TestDenyBackend;
        let config = SupervisorConfig {
            protected_roots: &[],
            approval_backend: &backend,
            session_id: "test",
            attach_initial_client: false,
            detach_sequence: None,
            open_url_origins: &[],
            open_url_allow_localhost: false,
            audit_recorder: None,
            allow_launch_services_active: false,
            #[cfg(target_os = "linux")]
            proxy_port: 0,
            #[cfg(target_os = "linux")]
            proxy_bind_ports: Vec::new(),
        };

        let long_url = format!("https://example.com/{}", "a".repeat(MAX_URL_LENGTH));
        let result = validate_url(&long_url, &config);
        assert!(result.is_err());
        assert!(result
            .as_ref()
            .err()
            .map(|e| e.contains("maximum length"))
            .unwrap_or(false));
    }

    #[test]
    fn test_shell_quote_simple_path() {
        assert_eq!(shell_quote("/usr/bin/nono"), "/usr/bin/nono");
    }

    #[test]
    fn test_shell_quote_path_with_spaces() {
        assert_eq!(shell_quote("/opt/my app/nono"), "'/opt/my app/nono'");
    }

    #[test]
    fn test_shell_quote_path_with_single_quote() {
        assert_eq!(shell_quote("/opt/it's/nono"), "'/opt/it'\\''s/nono'");
    }

    #[test]
    fn test_shell_quote_empty_string() {
        assert_eq!(shell_quote(""), "''");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_create_linux_browser_shim_installs_launcher_and_helper() {
        let exe = std::env::current_exe().expect("current_exe");
        let shim = create_linux_browser_shim(&exe, 42).expect("create shim");

        assert!(shim.launcher.exists(), "browser launcher should exist");
        assert_eq!(
            shim.launcher.parent(),
            Some(shim.dir.path()),
            "launcher should live inside shim dir"
        );

        let script = std::fs::read_to_string(&shim.launcher).expect("read shim");
        assert!(
            script.contains("nono-open-url-helper"),
            "launcher should reference the copied helper"
        );
        assert!(
            script.contains("NONO_SUPERVISOR_FD=42"),
            "launcher should export the supervisor fd only for helper execution"
        );
        assert!(
            script.contains("open-url-helper \"$@\""),
            "launcher should exec the copied helper"
        );
    }

    #[test]
    fn test_clear_close_on_exec_clears_flag() {
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;

        let (a, _b) = UnixStream::pair().expect("socketpair");
        let fd = a.as_raw_fd();

        let before = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(before >= 0, "F_GETFD before failed");
        assert_ne!(before & libc::FD_CLOEXEC, 0, "fd should start CLOEXEC");

        clear_close_on_exec(fd).expect("clear cloexec");

        let after = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(after >= 0, "F_GETFD after failed");
        assert_eq!(after & libc::FD_CLOEXEC, 0, "fd should not be CLOEXEC");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_create_open_shim_installs_helper_in_shim_dir() {
        let exe = std::env::current_exe().expect("current_exe");
        let shim = create_open_shim(&exe, 42).expect("create shim");

        assert!(shim.launcher.exists(), "open shim should exist");

        let script = std::fs::read_to_string(&shim.launcher).expect("read shim");
        assert!(
            script.contains("for arg in \"$@\"; do"),
            "shim should scan all arguments for a URL"
        );
        assert!(
            script.contains("nono-open-url-helper"),
            "shim should reference the copied helper"
        );
        assert!(
            script.contains("NONO_SUPERVISOR_FD=42"),
            "shim should export the supervisor fd only for helper execution"
        );
        assert!(
            script.contains("open-url-helper \"$url_arg\""),
            "shim should exec the copied helper"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_should_install_macos_open_shim_respects_launch_services_flag() {
        struct TestBackend;
        impl ApprovalBackend for TestBackend {
            fn request_capability(
                &self,
                _req: &nono::supervisor::CapabilityRequest,
            ) -> nono::Result<ApprovalDecision> {
                Ok(ApprovalDecision::Denied {
                    reason: "test".to_string(),
                })
            }
            fn backend_name(&self) -> &str {
                "test"
            }
        }

        let backend = TestBackend;
        let config = SupervisorConfig {
            protected_roots: &[],
            approval_backend: &backend,
            session_id: "test",
            attach_initial_client: false,
            detach_sequence: None,
            open_url_origins: &[],
            open_url_allow_localhost: false,
            audit_recorder: None,
            allow_launch_services_active: true,
            #[cfg(target_os = "linux")]
            proxy_port: 0,
            #[cfg(target_os = "linux")]
            proxy_bind_ports: Vec::new(),
        };

        assert!(
            !should_install_macos_open_shim(Some(&config)),
            "launch services sessions should skip the macOS open shim"
        );
        assert!(
            !should_install_macos_open_shim(None),
            "without supervisor config, the helper should not install the macOS open shim"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_open_shim_drop_cleans_up_directory() {
        let exe = std::env::current_exe().expect("current_exe");
        let shim = create_open_shim(&exe, 42).expect("create shim");
        let dir = shim.dir.path().to_path_buf();

        assert!(dir.exists(), "shim dir should exist before drop");
        drop(shim);
        assert!(!dir.exists(), "shim dir should be removed on drop");
    }
}
