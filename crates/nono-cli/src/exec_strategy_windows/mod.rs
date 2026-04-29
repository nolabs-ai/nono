// `dead_code` is allowed at module scope because this module hosts a small
// number of intentionally-unused-on-Windows symbols whose ownership lives
// outside the Phase 16 scope:
//   * `collect_unix_resource_limit_warnings` — Windows shim of the Unix
//     warning collector kept for cross-platform call-site symmetry.
//   * `WindowsSupervisorDenyAllApprovalBackend` — fallback approval backend
//     for SC #4 callers that build a `SupervisorConfig` without an
//     interactive backend.
//   * `set_windows_wfp_test_force_ready` — debug-only WFP readiness toggle
//     pair (the matching reader is wired in `network.rs`).
// These pre-date Phase 16 and should be addressed in a follow-up cleanup.
// The Phase 16 dead helpers in `launch.rs` were removed (16-WR-02); do NOT
// re-introduce broad allow scopes there.
#![allow(dead_code)]

//! Windows execution strategy placeholder.
//!
//! WIN-101 needs the CLI to compile on Windows without pulling in the Unix
//! supervisor and fork/exec machinery. This file intentionally provides a
//! smaller Windows surface that can be expanded in later stories.

#[path = "../exec_strategy/env_sanitization.rs"]
mod env_sanitization;

/// Windows no-op stub of the Unix warning collector. On Windows, resource
/// limits are kernel-enforced by `apply_resource_limits` inside
/// `spawn_windows_child`, so there's nothing to warn about.
///
/// Always returns an empty `Vec`. The signature matches the Unix version in
/// `exec_strategy.rs` so cross-platform callers can invoke
/// `exec_strategy::collect_unix_resource_limit_warnings` without `#[cfg]` gating.
pub(crate) fn collect_unix_resource_limit_warnings(
    _limits: &crate::launch_runtime::ResourceLimits,
    _silent: bool,
) -> Vec<String> {
    Vec::new()
}

/// Windows no-op stub of the Unix warning emitter. On Windows this is a
/// compile-time no-op — resource limits are kernel-enforced in
/// `apply_resource_limits`.
pub(crate) fn warn_unix_resource_limits(
    _limits: &crate::launch_runtime::ResourceLimits,
    _silent: bool,
) {
    // No-op on Windows.
}

use crate::pty_proxy;
use crate::rollback_runtime::{
    finalize_supervised_exit, AuditState, RollbackExitContext, RollbackRuntimeState,
};
use crate::windows_wfp_contract::{
    WfpRuntimeActivationRequest, WfpRuntimeActivationResponse, WFP_RUNTIME_PROTOCOL_VERSION,
};
use nono::supervisor::AuditEntry;
use nono::{ApprovalBackend, CapabilitySet, NonoError, Result, Sandbox};
use rand::RngExt;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(debug_assertions)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::time::SystemTime;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows_sys::Win32::Security::{
    CreateWellKnownSid, DuplicateTokenEx, GetTokenInformation, SecurityImpersonation,
    SetTokenInformation, TokenElevation, TokenIntegrityLevel, TokenPrimary, WinLowLabelSid,
    SECURITY_IMPERSONATION_LEVEL, SECURITY_MAX_SID_SIZE, TOKEN_ADJUST_DEFAULT,
    TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectCpuRateControlInformation,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    TerminateJobObject, JOBOBJECT_CPU_RATE_CONTROL_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_CPU_RATE_CONTROL_ENABLE,
    JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_JOB_MEMORY,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Services::{
    OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO,
    SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_STATUS_PROCESS,
};
use windows_sys::Win32::System::SystemServices::SE_GROUP_INTEGRITY;
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcess,
    InitializeProcThreadAttributeList, OpenProcessToken, ResumeThread, TerminateProcess,
    UpdateProcThreadAttribute, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
    EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, STARTUPINFOEXW, STARTUPINFOW,
};

pub(crate) use env_sanitization::is_dangerous_env_var;
use env_sanitization::should_skip_env_var;

pub(crate) fn to_u16_null_terminated(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Resolve an absolute path to a System32 executable.
///
/// Invoking OS tools (`icacls`, `netsh`, `sc`, etc.) through a relative
/// command name via `Command::new` is a path-hijacking hazard: if an
/// attacker can write to the current working directory or any directory
/// earlier in `PATH`, a malicious executable with the same name is picked
/// up instead of the genuine OS tool. Always invoke system binaries via
/// their full `%SystemRoot%\System32\...` path.
///
/// Fallback chain (matches the existing pattern in this crate):
/// `SystemRoot` env var → `windir` env var → literal `C:\Windows`.
pub(super) fn system32_exe(name: &str) -> PathBuf {
    let system_root = std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("windir"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    system_root.join("System32").join(format!("{name}.exe"))
}

pub fn resolve_program(program: &str) -> Result<PathBuf> {
    which::which(program).map_err(|e| {
        NonoError::CommandExecution(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{}: {}", program, e),
        ))
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThreadingContext {
    #[default]
    Strict,
    KeyringExpected,
    CryptoExpected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExecStrategy {
    Direct,
    #[default]
    Supervised,
}

pub struct ExecConfig<'a> {
    pub command: &'a [String],
    pub resolved_program: &'a Path,
    pub caps: &'a CapabilitySet,
    pub env_vars: Vec<(&'a str, &'a str)>,
    pub cap_file: Option<&'a Path>,
    pub current_dir: &'a Path,
    pub session_sid: Option<String>,
    pub interactive_shell: bool,
    /// Per-session 32-byte hex token authenticating capability requests
    /// from the sandboxed child. `None` disables runtime capability
    /// expansion for this execution (deny-all fallback stays active).
    pub session_token: Option<String>,
    /// Rendezvous file path the capability pipe server binds.
    pub cap_pipe_rendezvous_path: Option<PathBuf>,
}

pub struct SupervisorConfig<'a> {
    pub session_id: &'a str,
    pub requested_features: Vec<&'a str>,
    pub support: nono::WindowsSupervisorSupport,
    /// Owned approval backend that is moved into the capability pipe server
    /// thread and used for every runtime capability request from the
    /// sandboxed child. Must be `Send + Sync` because the background
    /// thread holds it for the lifetime of the supervised session.
    pub approval_backend: std::sync::Arc<dyn ApprovalBackend + Send + Sync>,
    pub interactive_shell: bool,
    /// 32-byte hex session token that the child must echo back on every
    /// `RequestCapability` message. `None` disables the capability pipe
    /// server (the deny-all fallback remains active). Never log.
    pub session_token: Option<&'a str>,
    /// Rendezvous file path at which the capability pipe server binds.
    /// `None` disables the capability pipe server.
    pub cap_pipe_rendezvous_path: Option<&'a Path>,
    /// Per-session restricting SID (`S-1-5-117-<guid>`) supplied to
    /// `CreateRestrictedToken` when the sandboxed child is launched with
    /// `WRITE_RESTRICTED`. When `Some(..)`, the capability pipe's DACL gets
    /// an additional ACE granting `FILE_GENERIC_READ | FILE_GENERIC_WRITE |
    /// SYNCHRONIZE` (object-specific mask `0x0012019F`) to this SID so the
    /// child's second-pass DACL check succeeds on
    /// `CreateFileW(pipe, GENERIC_READ | GENERIC_WRITE)`.
    ///
    /// Mirrors `ExecConfig.session_sid`. `None` means no WRITE_RESTRICTED
    /// child is expected (detached-launch path, legacy callers) and the pipe
    /// uses the byte-identical pre-fix SDDL.
    pub session_sid: Option<String>,
    /// Phase 18 AIPC-01 (Plan 18-03 + Plan 18.1-03): per-handle-type
    /// allowlist resolved by UNIONing the hard-coded supervisor defaults
    /// (D-05) with the loaded profile's `capabilities.aipc` widening
    /// (D-06). Callers that do not load a profile pass
    /// `AipcResolvedAllowlist::default()` — the byte-identical pre-18.1-03
    /// hard-coded default behavior. Callers with a loaded profile pass
    /// `profile.resolve_aipc_allowlist()?`.
    ///
    /// Consumed by `WindowsSupervisorRuntime::initialize` into the
    /// `resolved_aipc_allowlist: Arc<AipcResolvedAllowlist>` field so the
    /// capability pipe server thread honors profile widening at per-kind
    /// mask / role / direction validation time.
    pub aipc_allowlist: crate::profile::AipcResolvedAllowlist,
}

pub struct WindowsSupervisorDenyAllApprovalBackend;

impl ApprovalBackend for WindowsSupervisorDenyAllApprovalBackend {
    fn request_capability(
        &self,
        request: &nono::CapabilityRequest,
    ) -> Result<nono::ApprovalDecision> {
        Ok(nono::ApprovalDecision::Denied {
            reason: format!(
                "Windows live runtime capability expansion is not attached to generic child processes yet for request {}",
                request.request_id
            ),
        })
    }

    fn backend_name(&self) -> &str {
        "windows-preview-deny"
    }
}

#[derive(Debug)]
enum NetworkEnforcementGuard {
    FirewallRules {
        staged_program: PathBuf,
        staged_dir: PathBuf,
        inbound_rule: String,
        outbound_rule: String,
    },
    WfpServiceManaged {
        policy: Box<nono::WindowsNetworkPolicy>,
        probe_config: WfpProbeConfig,
        target_program: PathBuf,
        inbound_rule: String,
        outbound_rule: String,
    },
}

struct PreparedWindowsLaunch {
    // Phase 21: applied-labels guard reverts mandatory-label ACEs on drop.
    // Declared BEFORE _network_enforcement so Rust's reverse-of-declaration
    // drop order reverts labels first, then tears down network enforcement.
    // This matches the Phase 16-02 drop-order discipline (containment_job
    // outliving the supervisor runtime).
    _applied_labels: labels_guard::AppliedLabelsGuard,
    _network_enforcement: Option<NetworkEnforcementGuard>,
    launch_program: PathBuf,
}

impl NetworkEnforcementGuard {
    fn launch_program(&self) -> &Path {
        match self {
            NetworkEnforcementGuard::FirewallRules { staged_program, .. } => {
                staged_program.as_path()
            }
            NetworkEnforcementGuard::WfpServiceManaged { target_program, .. } => {
                target_program.as_path()
            }
        }
    }
}

fn prepare_live_windows_launch(
    config: &ExecConfig<'_>,
    session_id: Option<&str>,
) -> Result<PreparedWindowsLaunch> {
    let fs_policy = Sandbox::windows_filesystem_policy(config.caps);
    Sandbox::validate_windows_launch_paths(
        &fs_policy,
        config.resolved_program,
        config.current_dir,
    )?;
    Sandbox::validate_windows_command_args(
        &fs_policy,
        config.resolved_program,
        &config.command[1..],
        config.current_dir,
    )?;
    tracing::debug!(
        "Windows live-execution backend prepared filesystem policy: {} compiled rule(s), {} unsupported rule(s)",
        fs_policy.rules.len(),
        fs_policy.unsupported.len()
    );

    // Phase 21: snapshot pre-grant label state + apply mode-derived mandatory
    // labels to every rule path (skip-on-any-prior-label per tightened D-02).
    // Guard lifetime = PreparedWindowsLaunch lifetime = supervised session
    // lifetime; Drop reverts applied labels (clears ACEs we added; Skip
    // entries are a drop-time no-op).
    //
    // Note: the CLI path does NOT call nono::apply() (which also label-applies
    // per Plan 21-03) — nono::apply is the library embedding surface; the CLI
    // builds its own fs-policy + label-apply + network-enforcement pipeline.
    // The guard here is the SOLE apply site on the CLI path.
    let applied_labels = labels_guard::AppliedLabelsGuard::snapshot_and_apply(&fs_policy)?;

    let network_enforcement = prepare_network_enforcement(config, session_id)?;
    let launch_program = network_enforcement
        .as_ref()
        .map(NetworkEnforcementGuard::launch_program)
        .unwrap_or(config.resolved_program)
        .to_path_buf();

    Ok(PreparedWindowsLaunch {
        _applied_labels: applied_labels,
        _network_enforcement: network_enforcement,
        launch_program,
    })
}

trait WindowsNetworkBackend {
    fn label(&self) -> &'static str;

    fn install(
        &self,
        policy: &nono::WindowsNetworkPolicy,
        config: &ExecConfig<'_>,
        session_id: Option<&str>,
    ) -> Result<Option<NetworkEnforcementGuard>>;
}

struct FirewallRulesNetworkBackend;
struct WfpNetworkBackend;

const WINDOWS_WFP_PLATFORM_SERVICE: &str = "BFE";
const WINDOWS_WFP_BACKEND_SERVICE: &str = "nono-wfp-service";
const WINDOWS_WFP_BACKEND_DRIVER: &str = "nono-wfp-driver";
const WINDOWS_WFP_BACKEND_BINARY: &str = "nono-wfp-service.exe";
const WINDOWS_WFP_BACKEND_DRIVER_BINARY: &str = "nono-wfp-driver.sys";
const WINDOWS_WFP_BACKEND_SERVICE_ARGS: &[&str] = &["--service-mode"];
const WINDOWS_WFP_RUNTIME_PROBE_ARG: &str = "--probe-runtime-activation";
const WINDOWS_SUPERVISOR_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsServiceState {
    Running,
    Stopped,
    Missing,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WfpProbeStatus {
    Ready,
    BackendBinaryMissing,
    PlatformServiceMissing,
    PlatformServiceStopped,
    BackendServiceMissing,
    BackendServiceStopped,
    BackendDriverBinaryMissing,
    BackendDriverMissing,
    BackendDriverStopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WfpProbeConfig {
    platform_service: &'static str,
    backend_service: &'static str,
    backend_driver: &'static str,
    backend_binary_path: PathBuf,
    backend_driver_binary_path: PathBuf,
    backend_service_args: &'static [&'static str],
}

#[cfg(debug_assertions)]
static WINDOWS_WFP_TEST_FORCE_READY: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, PartialEq, Eq)]
struct WfpRuntimeProbeOutput {
    status_code: Option<i32>,
    response: WfpRuntimeActivationResponse,
    stderr: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WfpRuntimeActivationProbeStatus {
    Ready,
    AcceptedButNotEnforced,
    EnforcedPendingCleanup,
    CleanupSucceeded,
    FilteringProbeSucceeded,
    NotImplemented,
}

#[cfg(debug_assertions)]
pub(crate) fn set_windows_wfp_test_force_ready(force_ready: bool) {
    WINDOWS_WFP_TEST_FORCE_READY.store(force_ready, Ordering::Relaxed);
}

#[cfg(not(debug_assertions))]
pub(crate) fn set_windows_wfp_test_force_ready(_force_ready: bool) {}

fn windows_wfp_test_force_ready() -> bool {
    #[cfg(debug_assertions)]
    {
        WINDOWS_WFP_TEST_FORCE_READY.load(Ordering::Relaxed)
    }
    #[cfg(not(debug_assertions))]
    {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowsWfpReadinessReport {
    pub status_label: &'static str,
    pub details: String,
    pub next_action: Option<String>,
    pub service_status_label: &'static str,
    pub service_details: String,
    pub driver_status_label: &'static str,
    pub driver_details: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowsWfpInstallReport {
    pub status_label: &'static str,
    pub details: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowsWfpDriverInstallReport {
    pub status_label: &'static str,
    pub details: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowsWfpStartReport {
    pub status_label: &'static str,
    pub details: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowsWfpDriverStartReport {
    pub status_label: &'static str,
    pub details: String,
}

#[derive(Debug)]
struct ProcessContainment {
    job: HANDLE,
}

#[derive(Debug)]
struct OwnedHandle(HANDLE);

mod labels_guard;
mod launch;
mod network;
mod restricted_token;
mod supervisor;

use launch::*;
use network::*;
pub(crate) const JOB_OBJECT_QUERY: u32 = 0x0004;
pub(crate) const JOB_OBJECT_TERMINATE: u32 = 0x0008;
pub(crate) use network::{
    install_windows_wfp_driver, install_windows_wfp_service, probe_windows_wfp_readiness,
    start_windows_wfp_driver, start_windows_wfp_service,
};
pub(crate) use restricted_token::generate_session_sid;
use supervisor::*;

pub(crate) fn is_admin_process() -> bool {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let _token_guard = OwnedHandle(token);

        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut size = size_of::<TOKEN_ELEVATION>() as u32;
        if GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as _,
            size,
            &mut size,
        ) == 0
        {
            return false;
        }

        elevation.TokenIsElevated != 0
    }
}

pub(crate) fn probe_job_object_permissions() -> Result<()> {
    let mut bytes = [0u8; 8];
    rand::rng().fill(&mut bytes);
    let suffix: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    let name = format!(
        "Local
ono-setup-probe-{suffix}"
    );
    let name_u16 = to_u16_null_terminated(&name);

    unsafe {
        let handle = CreateJobObjectW(std::ptr::null(), name_u16.as_ptr());
        if handle.is_null() {
            let err = GetLastError();
            return Err(NonoError::Setup(format!(
                "Failed to create probe Job Object `{}`: Windows error {}",
                name, err
            )));
        }
        CloseHandle(handle);
    }
    Ok(())
}

pub(crate) fn probe_integrity_level_support() -> Result<()> {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,
            &mut token,
        ) == 0
        {
            return Err(NonoError::Setup(format!(
                "Failed to open process token for integrity probe: Windows error {}",
                GetLastError()
            )));
        }
        let _token_guard = OwnedHandle(token);

        let mut dup_token: HANDLE = std::ptr::null_mut();
        if DuplicateTokenEx(
            token,
            TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY,
            std::ptr::null(),
            SecurityImpersonation,
            TokenPrimary,
            &mut dup_token,
        ) == 0
        {
            return Err(NonoError::Setup(format!(
                "Failed to duplicate process token for integrity probe: Windows error {}",
                GetLastError()
            )));
        }
        let _dup_token_guard = OwnedHandle(dup_token);

        let mut sid: [u8; SECURITY_MAX_SID_SIZE as usize] = [0; SECURITY_MAX_SID_SIZE as usize];
        let mut sid_size = sid.len() as u32;
        if CreateWellKnownSid(
            WinLowLabelSid,
            std::ptr::null_mut(),
            sid.as_mut_ptr() as _,
            &mut sid_size,
        ) == 0
        {
            return Err(NonoError::Setup(format!(
                "Failed to create Low Integrity SID for probe: Windows error {}",
                GetLastError()
            )));
        }

        let mut tml = TOKEN_MANDATORY_LABEL {
            Label: windows_sys::Win32::Security::SID_AND_ATTRIBUTES {
                Sid: sid.as_mut_ptr() as _,
                Attributes: SE_GROUP_INTEGRITY as u32,
            },
        };

        if SetTokenInformation(
            dup_token,
            TokenIntegrityLevel,
            &mut tml as *mut _ as _,
            std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32,
        ) == 0
        {
            return Err(NonoError::Setup(format!(
                "Failed to set Low Integrity level on probe token: Windows error {}",
                GetLastError()
            )));
        }
    }
    Ok(())
}

pub(crate) fn probe_bfe_service_status() -> Result<()> {
    let bfe_name = to_u16_null_terminated(WINDOWS_WFP_PLATFORM_SERVICE);
    unsafe {
        let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            return Err(NonoError::Setup(format!(
                "Failed to open Service Control Manager for BFE probe: Windows error {}",
                GetLastError()
            )));
        }
        let _scm_guard = OwnedHandle(scm as _);

        let service = OpenServiceW(scm, bfe_name.as_ptr(), SERVICE_QUERY_STATUS);
        if service.is_null() {
            let err = GetLastError();
            return Err(NonoError::Setup(format!(
                "Failed to open BFE service for probe (error {}): Is the Base Filtering Engine installed?",
                err
            )));
        }
        let _service_guard = OwnedHandle(service as _);

        let mut status: SERVICE_STATUS_PROCESS = std::mem::zeroed();
        let mut bytes_needed: u32 = 0;
        if QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            &mut status as *mut _ as _,
            std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut bytes_needed,
        ) == 0
        {
            return Err(NonoError::Setup(format!(
                "Failed to query BFE service status: Windows error {}",
                GetLastError()
            )));
        }

        if status.dwCurrentState != SERVICE_RUNNING {
            return Err(NonoError::Setup(format!(
                "The 'BFE' (Base Filtering Engine) service is not running (Current state: {}). It is required for Windows network filtering.",
                status.dwCurrentState
            )));
        }
    }
    Ok(())
}

pub(crate) fn cleanup_windows_network_enforcement_artifacts() {
    cleanup_stale_network_enforcement_artifacts();
}

pub fn execute_direct(
    config: &ExecConfig<'_>,
    limits: &crate::launch_runtime::ResourceLimits,
    session_id: Option<&str>,
) -> Result<i32> {
    let prepared = prepare_live_windows_launch(config, session_id)?;
    let launch_program = prepared.launch_program.as_path();

    let cmd_args = prepare_runtime_hardened_args(
        launch_program,
        &config.command[1..],
        config.interactive_shell,
    );
    let containment = create_process_containment(session_id)?;

    // Phase 17 (Task 2): spawn_windows_child now returns
    // (WindowsSupervisedChild, Option<DetachedStdioPipes>). The Direct
    // execution path never goes through the detached supervisor — pty=None
    // here means "no PTY", and is_windows_detached_launch() is false outside
    // the inner detached supervisor process — so the second tuple element is
    // always None for execute_direct. Discard it.
    let (mut child, _detached_stdio) = spawn_windows_child(
        config,
        launch_program,
        &containment,
        &cmd_args,
        None,
        limits,
        session_id,
    )?;
    loop {
        if let Some(exit_code) = child.poll_exit_code()? {
            return Ok(exit_code);
        }
        std::thread::sleep(WINDOWS_SUPERVISOR_POLL_INTERVAL);
    }
}

#[allow(clippy::too_many_arguments)]
pub fn execute_supervised(
    config: &ExecConfig<'_>,
    supervisor: Option<&SupervisorConfig<'_>>,
    _trust_interceptor: Option<crate::trust_intercept::TrustInterceptor>,
    _on_fork: Option<&mut dyn FnMut(u32)>,
    pty_pair: Option<pty_proxy::PtyPair>,
    session_id: Option<&str>,
    audit_state: Option<AuditState>,
    rollback_state: Option<RollbackRuntimeState>,
    rollback_status: nono::undo::RollbackStatus,
    audit_recorder: Option<
        &std::sync::Arc<std::sync::Mutex<crate::audit_integrity::AuditRecorder>>,
    >,
    audit_snapshot_state: Option<crate::rollback_runtime::AuditSnapshotState>,
    executable_identity: Option<nono::undo::ExecutableIdentity>,
    audit_signer: Option<&crate::audit_attestation::AuditSigner>,
    proxy_handle: Option<&nono_proxy::server::ProxyHandle>,
    command: &[String],
    started: &str,
    silent: bool,
    rollback_prompt_disabled: bool,
    limits: &crate::launch_runtime::ResourceLimits,
) -> Result<i32> {
    let Some(supervisor) = supervisor else {
        return Err(NonoError::UnsupportedPlatform(
            "Windows supervised execution requires supervisor configuration".to_string(),
        ));
    };

    // Compute the --timeout wall-clock deadline BEFORE any spawn work so a
    // u64::MAX overflow fails fast. None when --timeout is absent.
    let timeout_deadline = supervisor::compute_deadline(limits.timeout, std::time::Instant::now())?;

    // Plan 16-02 Step 5 reorders this block so `containment` is created BEFORE
    // `WindowsSupervisorRuntime::initialize`. The runtime borrows
    // `containment.job` for the `--timeout` expiry path; `ProcessContainment`
    // owns the close-on-drop and must outlive the runtime. Rust drop order is
    // reverse-of-declaration: with `containment` declared first, the runtime
    // drops first (its `Drop` does not touch `containment_job`), then
    // `containment` drops last and calls `CloseHandle` exactly once.
    let prepared = prepare_live_windows_launch(config, session_id)?;
    let launch_program = prepared.launch_program.as_path();

    let cmd_args = prepare_runtime_hardened_args(
        launch_program,
        &config.command[1..],
        config.interactive_shell,
    );
    let containment = create_process_containment(session_id)?;

    let mut runtime = WindowsSupervisorRuntime::initialize(
        supervisor,
        pty_pair,
        session_id,
        timeout_deadline,
        containment.job,
        // Phase 23 D-01: thread the audit recorder Arc into the runtime so
        // the capability-pipe-server thread can append capability_decision
        // events to `<session_dir>/audit-events.ndjson`.
        audit_recorder,
    )?;
    tracing::debug!(
        "Windows supervised approval backend: {}",
        supervisor.approval_backend.as_ref().backend_name()
    );
    let unsupported = supervisor.support.unsupported_feature_labels();
    let unsupported_details = supervisor.support.unsupported_feature_descriptions();
    let supported = supervisor.support.supported_feature_labels();
    if !unsupported.is_empty() {
        return Err(NonoError::UnsupportedPlatform(format!(
            "Windows supervised execution initialized the control channel
             (session: {}, transport: {}), but these supervised features are not available yet: {}.
             Details: {}. Supported Windows supervised features currently: {}.",
            supervisor.session_id,
            runtime.transport_name(),
            unsupported.join(", "),
            unsupported_details.join(" | "),
            if supported.is_empty() {
                "none".to_string()
            } else {
                supported.join(", ")
            }
        )));
    }

    runtime.state = WindowsSupervisorLifecycleState::LaunchingChild;
    tracing::debug!(
        "Windows supervised execution starting event loop (session: {}, transport: {}, features: {})",
        supervisor.session_id,
        runtime.transport_name(),
        if supervisor.requested_features.is_empty() {
            "none".to_string()
        } else {
            supervisor.requested_features.join(", ")
        }
    );

    // Phase 17 (Tasks 2 + 3): spawn_windows_child returns
    // (WindowsSupervisedChild, Option<DetachedStdioPipes>). The second
    // tuple element is the parent-end stdio handles for the Windows
    // detached path; it is None on the PTY (non-detached) path. Hand it to
    // the runtime via attach_detached_stdio BEFORE start_streaming so the
    // pipe-source / pipe-sink bridge threads see the populated field.
    let (mut child, detached_stdio) = spawn_windows_child(
        config,
        launch_program,
        &containment,
        &cmd_args,
        runtime.pty(),
        limits,
        session_id,
    )
    .map_err(|err| runtime.startup_failure(err.to_string()))?;

    runtime.attach_detached_stdio(detached_stdio);
    runtime
        .start_streaming()
        .map_err(|err| runtime.startup_failure(err.to_string()))?;

    // Publish the child's process handle so the capability pipe server
    // thread can broker granted file handles via `DuplicateHandle`.
    runtime.set_child_broker_target(child.process_handle_raw());

    let exit_code = runtime
        .run_child_event_loop(&mut child)
        .map_err(|err| runtime.command_failure(err.to_string()))?;

    let ended = chrono::Local::now().to_rfc3339();
    finalize_supervised_exit(RollbackExitContext {
        audit_state: audit_state.as_ref(),
        rollback_state,
        rollback_status,
        audit_recorder,
        audit_snapshot_state,
        executable_identity,
        audit_signer,
        proxy_handle,
        started,
        ended: &ended,
        command,
        exit_code,
        silent,
        rollback_prompt_disabled,
    })?;

    tracing::debug!(
        "Windows supervised execution finished cleanly (session: {}, transport: {}, exit_code: {})",
        supervisor.session_id,
        runtime.transport_name(),
        exit_code
    );
    Ok(exit_code)
}
