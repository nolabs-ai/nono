//! Windows sandbox implementation.
//!
//! Provides directory read / read-write capability grants, blocked network mode,
//! and port-level WFP filtering (connect, bind, and localhost ports) for the
//! Windows backend. Supervisor activation is handled by `nono-wfp-service` via
//! named-pipe IPC; this module exposes the policy-compilation and support-info
//! surface consumed by the facade in `sandbox/mod.rs`.

use crate::capability::CapabilitySet;
use crate::error::{NonoError, Result};
use crate::sandbox::{
    PreviewRuntimeStatus, SupportInfo, SupportStatus, WindowsFilesystemPolicy,
    WindowsFilesystemRule, WindowsNetworkBackendKind, WindowsNetworkLaunchSupport,
    WindowsNetworkPolicy, WindowsNetworkPolicyMode, WindowsPreviewContext,
    WindowsPreviewEntryPoint, WindowsSupervisorContext, WindowsSupervisorFeatureKind,
    WindowsSupervisorSupport,
};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, LocalFree, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetEffectiveRightsFromAclW,
    GetNamedSecurityInfoW, SetNamedSecurityInfoW, NO_MULTIPLE_TRUSTEE, SDDL_REVISION_1,
    SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    CreateWellKnownSid, DuplicateTokenEx, GetAce, GetSecurityDescriptorSacl, GetSidSubAuthority,
    GetSidSubAuthorityCount, SecurityAnonymous, SetTokenInformation, TokenIntegrityLevel,
    TokenPrimary, WinLowLabelSid, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION,
    LABEL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_IMPERSONATION_LEVEL,
    SECURITY_MAX_SID_SIZE, SYSTEM_MANDATORY_LABEL_ACE, TOKEN_ADJUST_DEFAULT,
    TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
};
use windows_sys::Win32::Storage::FileSystem::WRITE_OWNER;
use windows_sys::Win32::System::SystemServices::{
    SECURITY_MANDATORY_LOW_RID, SE_GROUP_INTEGRITY, SYSTEM_MANDATORY_LABEL_ACE_TYPE,
    SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP, SYSTEM_MANDATORY_LABEL_NO_READ_UP,
    SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const WINDOWS_PREVIEW_SUPPORTED: bool = true;
const WINDOWS_SUPPORTED_DETAILS: &str =
    "Windows sandbox enforcement supports directory and single-file grants in read, \
     write, and read-write modes (enforced via per-path mandatory integrity labels), \
     blocked network mode, port-level network filtering (connect, bind, and localhost ports), \
     and default signal/process/ipc modes. Runtime capability expansion \
     and platform-specific rules are not in the supported subset. \
     `nono shell` is supported on Windows 10 build 17763+ via ConPTY \
     (CreatePseudoConsole); the supervisor stays alive as Job Object owner. \
     `nono wrap` is also supported.";

pub fn apply(caps: &CapabilitySet) -> Result<()> {
    // 1. Filesystem shape validation
    let fs_policy = compile_filesystem_policy(caps);
    if !fs_policy.unsupported.is_empty() {
        return Err(NonoError::UnsupportedPlatform(format!(
            "Windows sandbox does not support: {}",
            fs_policy.unsupported_messages().join(", ")
        )));
    }

    // 1b. Phase 21: apply a SYSTEM_MANDATORY_LABEL_ACE (Low IL RID + mode-derived
    // mask) to each compiled filesystem rule. Fail-closed (I-01) — any label
    // application error aborts `apply()` with `NonoError::LabelApplyFailed`
    // carrying the exact path + Win32 HRESULT + actionable hint. Never silently
    // degrades to a broader grant.
    //
    // Order: apply labels BEFORE the network/signal/ipc checks so a later
    // validation failure (e.g., WFP service absent) does not leave behind
    // partially-labeled files. CAVEAT: if the labels-applied loop returns Err
    // partway through, the files already labeled in this invocation are NOT
    // reverted here — revert-on-error is handled by the RAII guard in
    // `exec_strategy_windows/` (Plan 21-04). This library-level `apply()` is
    // the bare primitive, intentionally stateless; the CLI always wraps the
    // call site in a guard.
    for rule in &fs_policy.rules {
        let mask = label_mask_for_access_mode(rule.access);
        try_set_mandatory_label(&rule.path, mask)?;
    }

    // 2. Network shape validation
    let net_policy = compile_network_policy(caps);
    if !net_policy.unsupported.is_empty() {
        return Err(NonoError::UnsupportedPlatform(format!(
            "Windows sandbox does not support: {}",
            net_policy.unsupported_messages().join(", ")
        )));
    }

    // 3. Remaining field validation against defaults
    if caps.signal_mode() != crate::SignalMode::Isolated {
        return Err(NonoError::UnsupportedPlatform(
            "Windows sandbox does not support non-default signal mode".to_string(),
        ));
    }
    if caps.process_info_mode() != crate::ProcessInfoMode::Isolated {
        return Err(NonoError::UnsupportedPlatform(
            "Windows sandbox does not support non-default process info mode".to_string(),
        ));
    }
    if caps.ipc_mode() != crate::IpcMode::SharedMemoryOnly {
        return Err(NonoError::UnsupportedPlatform(
            "Windows sandbox does not support non-default IPC mode".to_string(),
        ));
    }
    if caps.extensions_enabled() {
        return Err(NonoError::UnsupportedPlatform(
            "Windows sandbox does not support runtime capability expansion".to_string(),
        ));
    }
    if !caps.platform_rules().is_empty() {
        return Err(NonoError::UnsupportedPlatform(
            "Windows sandbox does not support platform-specific rules (Seatbelt-only feature)"
                .to_string(),
        ));
    }

    // seatbelt_debug_deny is macOS-only and has no enforcement claim on Windows;
    // silently accepting it is correct (no overclaim).

    // 4. Validated — CLI layer can proceed with enforcement
    Ok(())
}

#[must_use]
pub fn is_supported() -> bool {
    WINDOWS_PREVIEW_SUPPORTED
}

#[must_use]
pub fn support_info() -> SupportInfo {
    SupportInfo {
        is_supported: WINDOWS_PREVIEW_SUPPORTED,
        status: SupportStatus::Supported,
        platform: "windows",
        details: WINDOWS_SUPPORTED_DETAILS.to_string(),
    }
}

#[must_use]
pub fn preview_runtime_status(
    caps: &CapabilitySet,
    execution_dir: &Path,
    _context: WindowsPreviewContext,
) -> PreviewRuntimeStatus {
    let mut reasons = Vec::new();

    let execution_dir = execution_dir
        .canonicalize()
        .unwrap_or_else(|_| execution_dir.to_path_buf());
    let execution_dir = normalize_windows_path(&execution_dir);

    let fs_policy = compile_filesystem_policy(caps);
    let has_user_intent_fs = fs_policy
        .rules
        .iter()
        .any(|rule| rule.source.is_user_intent())
        || !fs_policy.unsupported.is_empty();

    for label in fs_policy.unsupported_reason_labels() {
        reasons.push(label);
    }

    if has_user_intent_fs
        && fs_policy.has_user_intent_directory_rules()
        && !fs_policy.covers_execution_dir(&execution_dir)
    {
        reasons.push("execution directory outside supported allowlist");
    }
    let network_policy = compile_network_policy(caps);
    if matches!(
        network_policy.mode,
        WindowsNetworkPolicyMode::ProxyOnly { .. }
    ) {
        reasons.push("proxy network restrictions");
    }
    for label in network_policy.unsupported_reason_labels() {
        reasons.push(label);
    }

    if caps.extensions_enabled() {
        reasons.push("runtime capability expansion");
    }

    if !caps.platform_rules().is_empty() {
        reasons.push("platform-specific sandbox rules");
    }

    if caps.signal_mode() != crate::SignalMode::Isolated
        || caps.process_info_mode() != crate::ProcessInfoMode::Isolated
        || caps.ipc_mode() != crate::IpcMode::SharedMemoryOnly
    {
        reasons.push("explicit process or IPC restrictions");
    }

    reasons.sort_unstable();
    reasons.dedup();

    if reasons.is_empty() {
        PreviewRuntimeStatus::AdvisoryOnly
    } else {
        PreviewRuntimeStatus::RequiresEnforcement { reasons }
    }
}

/// Returns Ok if the current Windows build is >= 17763 (ConPTY minimum).
/// Returns Err with a clear message if the build is older.
///
/// Uses `RtlGetVersion` (ntdll) which bypasses the application-compatibility
/// shim that `GetVersionExW` applies on Windows 10+.
fn check_conpty_minimum_build() -> Result<()> {
    use windows_sys::Wdk::System::SystemServices::RtlGetVersion;
    use windows_sys::Win32::System::SystemInformation::OSVERSIONINFOW;

    let mut info: OSVERSIONINFOW = unsafe {
        // SAFETY: OSVERSIONINFOW is a plain C struct; zero-init is the
        // required baseline before calling RtlGetVersion.
        std::mem::zeroed()
    };
    info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOW>() as u32;

    let status = unsafe {
        // SAFETY: `info` is a valid, initialized OSVERSIONINFOW with the
        // size field set.
        RtlGetVersion(&mut info)
    };

    if status != 0 {
        return Err(crate::error::NonoError::UnsupportedPlatform(format!(
            "Could not determine Windows build number (RtlGetVersion returned 0x{:X}). \
             `nono shell` requires Windows 10 build 17763 or later.",
            status
        )));
    }

    const CONPTY_MINIMUM_BUILD: u32 = 17763;
    if info.dwBuildNumber < CONPTY_MINIMUM_BUILD {
        return Err(crate::error::NonoError::UnsupportedPlatform(format!(
            "Windows build {} is too old for `nono shell`. \
             ConPTY (CreatePseudoConsole) requires build {} (Windows 10 October 2018 Update) or later. \
             There is no non-PTY fallback - upgrade Windows to use `nono shell`.",
            info.dwBuildNumber, CONPTY_MINIMUM_BUILD
        )));
    }

    Ok(())
}

pub fn validate_preview_entry_point(
    entry_point: WindowsPreviewEntryPoint,
    caps: &CapabilitySet,
    execution_dir: &Path,
    context: WindowsPreviewContext,
) -> Result<()> {
    match entry_point {
        WindowsPreviewEntryPoint::RunDirect => {
            if let PreviewRuntimeStatus::RequiresEnforcement { reasons } =
                preview_runtime_status(caps, execution_dir, context)
            {
                return Err(NonoError::UnsupportedPlatform(format!(
                    "Windows cannot enforce the requested sandbox controls for this live run ({}). \
Use `nono run --dry-run ...` to validate policy, or rerun without those controls. \
This is an explicit Windows product-surface limitation, not a silent fallback.",
                    reasons.join(", ")
                )));
            }
            Ok(())
        }
        WindowsPreviewEntryPoint::Shell => {
            check_conpty_minimum_build()?;

            if let PreviewRuntimeStatus::RequiresEnforcement { reasons } =
                preview_runtime_status(caps, execution_dir, context)
            {
                return Err(NonoError::UnsupportedPlatform(format!(
                    "Windows cannot enforce the requested sandbox controls for this nono shell run ({}). \
Use `nono shell --dry-run ...` to validate policy, or rerun without those controls.",
                    reasons.join(", ")
                )));
            }
            Ok(())
        }
        WindowsPreviewEntryPoint::Wrap => {
            if let PreviewRuntimeStatus::RequiresEnforcement { reasons } =
                preview_runtime_status(caps, execution_dir, context)
            {
                return Err(NonoError::UnsupportedPlatform(format!(
                    "Windows cannot enforce the requested sandbox controls for this nono wrap run ({}). \
Use `nono wrap --dry-run ...` to validate policy, or rerun without those controls. \
This is an explicit Windows product-surface limitation, not a silent fallback.",
                    reasons.join(", ")
                )));
            }
            Ok(())
        }
    }
}

#[must_use]
pub fn classify_supervisor_support(context: WindowsSupervisorContext) -> WindowsSupervisorSupport {
    let mut supported = Vec::new();
    let mut unsupported = Vec::new();

    if context.rollback_snapshots {
        supported.push(WindowsSupervisorFeatureKind::RollbackSnapshots);
    }
    if context.proxy_filtering {
        unsupported.push(WindowsSupervisorFeatureKind::ProxyFiltering);
    }
    if context.runtime_capability_expansion {
        unsupported.push(WindowsSupervisorFeatureKind::RuntimeCapabilityExpansion);
    }
    if context.runtime_trust_interception {
        unsupported.push(WindowsSupervisorFeatureKind::RuntimeTrustInterception);
    }

    supported.sort_unstable();
    supported.dedup();
    unsupported.sort_unstable();
    unsupported.dedup();

    WindowsSupervisorSupport {
        supported,
        unsupported,
    }
}

#[must_use]
pub fn compile_network_policy(caps: &CapabilitySet) -> WindowsNetworkPolicy {
    let mode = match caps.network_mode() {
        crate::NetworkMode::AllowAll => WindowsNetworkPolicyMode::AllowAll,
        crate::NetworkMode::Blocked => WindowsNetworkPolicyMode::Blocked,
        crate::NetworkMode::ProxyOnly { port, bind_ports } => WindowsNetworkPolicyMode::ProxyOnly {
            port: *port,
            bind_ports: bind_ports.clone(),
        },
    };

    let unsupported = Vec::new();
    let mut tcp_connect_ports = caps.tcp_connect_ports().to_vec();
    tcp_connect_ports.sort_unstable();
    tcp_connect_ports.dedup();
    let mut tcp_bind_ports = caps.tcp_bind_ports().to_vec();
    tcp_bind_ports.sort_unstable();
    tcp_bind_ports.dedup();
    let mut localhost_ports = caps.localhost_ports().to_vec();
    localhost_ports.sort_unstable();
    localhost_ports.dedup();
    let requires_backend = !matches!(mode, WindowsNetworkPolicyMode::AllowAll)
        || !tcp_connect_ports.is_empty()
        || !tcp_bind_ports.is_empty()
        || !localhost_ports.is_empty();
    let preferred_backend = if requires_backend {
        WindowsNetworkBackendKind::Wfp
    } else {
        WindowsNetworkBackendKind::None
    };
    let active_backend = preferred_backend;

    WindowsNetworkPolicy {
        mode,
        tcp_connect_ports,
        tcp_bind_ports,
        localhost_ports,
        unsupported,
        preferred_backend,
        active_backend,
    }
}

#[must_use]
pub fn network_launch_support(
    policy: &WindowsNetworkPolicy,
    resolved_program: &Path,
) -> WindowsNetworkLaunchSupport {
    let _ = (policy, resolved_program);
    WindowsNetworkLaunchSupport::Supported
}

fn normalize_windows_path(path: &Path) -> PathBuf {
    let raw = path.as_os_str().to_string_lossy();

    if let Some(stripped) = raw.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{stripped}"));
    }
    if let Some(stripped) = raw.strip_prefix(r"\\?\") {
        return PathBuf::from(stripped);
    }

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(std::path::MAIN_SEPARATOR.to_string()),
            Component::CurDir => {}
            Component::ParentDir => normalized.push(".."),
            Component::Normal(part) => normalized.push(part),
        }
    }
    normalized
}

pub(crate) fn windows_paths_equal_case_insensitive(left: &Path, right: &Path) -> bool {
    let left = normalize_windows_path(left);
    let right = normalize_windows_path(right);

    let mut left_components = left.components();
    let mut right_components = right.components();

    loop {
        match (left_components.next(), right_components.next()) {
            (None, None) => return true,
            (None, Some(_)) | (Some(_), None) => return false,
            (Some(left_component), Some(right_component)) => {
                let left_component = left_component.as_os_str().to_string_lossy();
                let right_component = right_component.as_os_str().to_string_lossy();
                if !left_component.eq_ignore_ascii_case(&right_component) {
                    return false;
                }
            }
        }
    }
}

pub(crate) fn windows_paths_start_with_case_insensitive(path: &Path, prefix: &Path) -> bool {
    let path = normalize_windows_path(path);
    let prefix = normalize_windows_path(prefix);
    let mut path_components = path.components();
    let mut prefix_components = prefix.components();

    loop {
        match (path_components.next(), prefix_components.next()) {
            (_, None) => return true,
            (None, Some(_)) => return false,
            (Some(path_component), Some(prefix_component)) => {
                let path_component = path_component.as_os_str().to_string_lossy();
                let prefix_component = prefix_component.as_os_str().to_string_lossy();
                if !path_component.eq_ignore_ascii_case(&prefix_component) {
                    return false;
                }
            }
        }
    }
}

fn low_integrity_runtime_prefixes() -> Vec<PathBuf> {
    let mut prefixes = Vec::new();
    let Some(local_appdata) = std::env::var_os("LOCALAPPDATA").map(PathBuf::from) else {
        return prefixes;
    };

    prefixes.push(normalize_windows_path(
        &local_appdata.join("Temp").join("Low"),
    ));

    if let Some(appdata_root) = local_appdata.parent() {
        prefixes.push(normalize_windows_path(&appdata_root.join("LocalLow")));
    }

    prefixes.sort();
    prefixes.dedup();
    prefixes
}

struct OwnedSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for OwnedSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                // SAFETY: The security descriptor was allocated by
                // GetNamedSecurityInfoW and must be released with LocalFree.
                let _ = LocalFree(self.0 as _);
            }
        }
    }
}

/// RAII wrapper around a Win32 `HANDLE` — closes via `CloseHandle` on Drop
/// exactly once.
///
/// Used by [`create_low_integrity_primary_token`] (Phase 31 D-06 lift) and any
/// downstream consumer that needs token handle ownership without manually
/// auditing every error path. The wrapper is `pub` so `nono-shell-broker`
/// (Phase 31 D-05) and `nono-cli` consume the same type.
///
/// Null handles are skipped on Drop (idiomatic Win32: zero handle = no-op).
#[derive(Debug)]
pub struct OwnedHandle(pub HANDLE);

impl OwnedHandle {
    /// Returns the raw `HANDLE` for FFI use without transferring ownership.
    #[must_use]
    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                // SAFETY: This handle is owned by the wrapper and is closed
                // exactly once on drop; null was checked above.
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// Construct a Low Mandatory Integrity Level primary token by duplicating the
/// current process's token and lowering its integrity level via
/// `SetTokenInformation(TokenIntegrityLevel, ..)`.
///
/// Used by `nono-shell-broker.exe` (Phase 31 D-05) to lower its own duplicate
/// token to Low IL before passing it to `CreateProcessAsUserW` for the
/// sandboxed shell child. Also reachable from `nono-cli`'s legacy Direct
/// path (structurally unreachable today; see Phase 31 D-15).
///
/// Library boundary preserved: function is parameterless and policy-free.
///
/// Mechanism MUST stay byte-equivalent to the validated PoC at
/// `.planning/quick/260508-m99-broker-process-poc-minimal-rust-binary-t/poc-broker/src/main.rs:36-103`
/// and to the pre-lift source at
/// `crates/nono-cli/src/exec_strategy_windows/launch.rs:1075-1167` (D-06:
/// single source of truth).
///
/// # Errors
///
/// Returns [`NonoError::SandboxInit`] with a Windows `GetLastError` code if any
/// of `OpenProcessToken`, `DuplicateTokenEx`, `CreateWellKnownSid`, or
/// `SetTokenInformation` fail.
#[must_use = "the returned OwnedHandle owns a Win32 HANDLE and must be retained until CreateProcess[AsUser]W has consumed it"]
pub fn create_low_integrity_primary_token() -> Result<OwnedHandle> {
    let mut current_token: HANDLE = std::ptr::null_mut();
    let opened = unsafe {
        // SAFETY: We pass a valid mutable out-pointer and request access on the
        // current process token only.
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT,
            &mut current_token,
        )
    };
    if opened == 0 {
        return Err(NonoError::SandboxInit(format!(
            "Failed to open Windows process token for low-integrity launch (GetLastError={})",
            unsafe { GetLastError() }
        )));
    }
    let current_token = OwnedHandle(current_token);

    let mut primary_token: HANDLE = std::ptr::null_mut();
    let duplicated = unsafe {
        // SAFETY: We duplicate the current process token into a primary token
        // for child process creation.
        DuplicateTokenEx(
            current_token.raw(),
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,
            std::ptr::null(),
            // Per Win32 docs (DuplicateTokenEx remarks): ImpersonationLevel is
            // ignored when TokenType is TokenPrimary. SecurityAnonymous (0) is the
            // idiomatic choice — empirically equivalent here, and the conventional
            // marker for "primary token, not for impersonation use" (CR-01 hygiene).
            SecurityAnonymous as SECURITY_IMPERSONATION_LEVEL,
            TokenPrimary,
            &mut primary_token,
        )
    };
    if duplicated == 0 {
        return Err(NonoError::SandboxInit(format!(
            "Failed to duplicate Windows process token for low-integrity launch (GetLastError={})",
            unsafe { GetLastError() }
        )));
    }
    let primary_token = OwnedHandle(primary_token);

    let mut sid_buffer = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut sid_size = sid_buffer.len() as u32;
    let created = unsafe {
        // SAFETY: The destination buffer is valid and sized per
        // SECURITY_MAX_SID_SIZE for a well-known SID.
        CreateWellKnownSid(
            WinLowLabelSid,
            std::ptr::null_mut(),
            sid_buffer.as_mut_ptr() as *mut _,
            &mut sid_size,
        )
    };
    if created == 0 {
        return Err(NonoError::SandboxInit(format!(
            "Failed to create Windows low-integrity SID (GetLastError={})",
            unsafe { GetLastError() }
        )));
    }

    let label_size = size_of::<TOKEN_MANDATORY_LABEL>() + sid_size as usize;
    let mut label_buffer = vec![0u8; label_size];
    let label_ptr = label_buffer.as_mut_ptr() as *mut TOKEN_MANDATORY_LABEL;
    let sid_ptr = unsafe {
        // SAFETY: `label_buffer` is sized to hold a TOKEN_MANDATORY_LABEL prefix
        // plus the SID bytes; the offset stays inside the allocation.
        label_buffer
            .as_mut_ptr()
            .add(size_of::<TOKEN_MANDATORY_LABEL>()) as *mut _
    };
    unsafe {
        // SAFETY: `sid_ptr` lives inside `label_buffer`, sized to fit
        // `sid_size` bytes from `sid_buffer`. `label_ptr` aliases the same
        // buffer with the documented Win32 layout.
        std::ptr::copy_nonoverlapping(sid_buffer.as_ptr(), sid_ptr as *mut u8, sid_size as usize);
        (*label_ptr).Label.Sid = sid_ptr;
        (*label_ptr).Label.Attributes = SE_GROUP_INTEGRITY as u32;
    }
    let adjusted = unsafe {
        // SAFETY: `primary_token` is a valid duplicated token; `label_ptr`
        // points to a fully populated TOKEN_MANDATORY_LABEL structure of
        // `label_size` bytes inside `label_buffer`.
        SetTokenInformation(
            primary_token.raw(),
            TokenIntegrityLevel,
            label_ptr as *mut _,
            label_size as u32,
        )
    };
    if adjusted == 0 {
        return Err(NonoError::SandboxInit(format!(
            "Failed to lower Windows child token integrity level (GetLastError={})",
            unsafe { GetLastError() }
        )));
    }

    Ok(primary_token)
}

/// Maps an `AccessMode` to the `SYSTEM_MANDATORY_LABEL_ACE.Mask` bits per
/// CONTEXT.md D-01 mask-encoding table.
///
/// - `Read` → `NO_WRITE_UP | NO_EXECUTE_UP` (Low IL subject can read, not write/execute-up)
/// - `Write` → `NO_READ_UP | NO_EXECUTE_UP` (Low IL subject can write, not read/execute-up)
/// - `ReadWrite` → `NO_EXECUTE_UP` only (Low IL subject can read + write, not execute-up)
///
/// Execute is never granted through a filesystem capability in the nono model —
/// executability is controlled by the profile's command allowlist and the Low
/// IL restricted token's execute rights. Always set `NO_EXECUTE_UP`.
#[must_use]
pub fn label_mask_for_access_mode(mode: crate::AccessMode) -> u32 {
    match mode {
        crate::AccessMode::Read => {
            SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP
        }
        crate::AccessMode::Write => {
            SYSTEM_MANDATORY_LABEL_NO_READ_UP | SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP
        }
        crate::AccessMode::ReadWrite => SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP,
    }
}

/// Applies (or replaces) a `SYSTEM_MANDATORY_LABEL_ACE` at
/// `SECURITY_MANDATORY_LOW_RID` on `path`, with the ACE `Mask` field set to
/// `mask` (typically the return value of `label_mask_for_access_mode`).
///
/// Uses `SetNamedSecurityInfoW(SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, ..)`.
/// Fail-closed: any non-zero return from the FFI surfaces as
/// `NonoError::LabelApplyFailed`.
///
/// The SACL passed to `SetNamedSecurityInfoW` is constructed in-process via
/// `ConvertStringSecurityDescriptorToSecurityDescriptorW` using an SDDL string
/// of the form `"S:(ML;;{mask_hex};;;LW)"` where `LW` is the
/// Low-Integrity-Mandatory-Level alias. This avoids hand-rolling a
/// `SYSTEM_MANDATORY_LABEL_ACE` byte layout.
///
/// # Errors
///
/// Returns `NonoError::LabelApplyFailed` if the SDDL cannot be parsed, the
/// SACL cannot be extracted, or `SetNamedSecurityInfoW` returns non-zero.
pub fn try_set_mandatory_label(path: &Path, mask: u32) -> Result<()> {
    use windows_sys::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_INVALID_FUNCTION, ERROR_NOT_SUPPORTED,
    };

    // WRITE_OWNER pre-flight (260522-v14 fix):
    // `SetNamedSecurityInfoW(LABEL_SECURITY_INFORMATION)` requires the caller to
    // hold `WRITE_OWNER` (0x00080000) on the target. Owner status grants implicit
    // `WRITE_DAC` + `READ_CONTROL` per the NT security model but NOT implicit
    // `WRITE_OWNER`. User-created subdirectories of a drive root (e.g.
    // `C:\poc\temp`) inherit the default `C:\` ACL, which grants `Authenticated
    // Users: Modify` (mask `0x1301BF`) — `WRITE_OWNER` is missing. Probing the
    // effective rights here lets us surface a precise directive error instead of
    // the misleading "writable...NTFS..." catch-all below. Cheapest bail-out
    // (no SDDL parse, no SACL extract, no `SetNamedSecurityInfoW` round-trip)
    // when the user cannot possibly succeed.
    if !path_has_write_owner(path)? {
        return Err(NonoError::LabelApplyFailed {
            path: path.to_path_buf(),
            hresult: ERROR_ACCESS_DENIED,
            hint: format!(
                "The current user lacks WRITE_OWNER (0x00080000) on this path. \
                 Mandatory integrity labels require WRITE_OWNER, which is NOT implicit for path owners. \
                 User-created subdirectories of a drive root (e.g. C:\\poc\\) inherit the default C:\\ ACL, \
                 which grants only `Authenticated Users: Modify` — WRITE_OWNER is missing. \
                 Recommended: run nono from a working directory under your user profile \
                 (e.g. %USERPROFILE%\\nono-poc or %TEMP%\\nono-poc). \
                 Local override: grant FullControl on the current path via \
                 `icacls {} /grant <user>:(OI)(CI)F` (this widens the DACL beyond \
                 default inheritance — explicit user choice, not a default).",
                path.display(),
            ),
        });
    }

    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // Build SDDL: "S:(ML;;<mask-in-hex>;;;LW)" — mandatory-label ACE, Low IL.
    // SDDL is ASCII-only, so encode_utf16 produces the correct wide form.
    let sddl = format!("S:(ML;;0x{mask:X};;;LW)");
    let wide_sddl: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();

    let mut security_descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let ok = unsafe {
        // SAFETY: `wide_sddl` is a valid nul-terminated UTF-16 buffer; the
        // output pointer is a valid mutable out-pointer for the duration of
        // the call. On success, the returned SD must be freed with LocalFree
        // (handled by the OwnedSecurityDescriptor guard below).
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut security_descriptor,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        let hresult = unsafe {
            // SAFETY: GetLastError has no preconditions.
            windows_sys::Win32::Foundation::GetLastError()
        };
        return Err(NonoError::LabelApplyFailed {
            path: path.to_path_buf(),
            hresult,
            hint: format!("Failed to construct mandatory-label SDDL (mask=0x{mask:X})"),
        });
    }
    let _sd_guard = OwnedSecurityDescriptor(security_descriptor);

    // Extract the SACL from the security descriptor.
    let mut sacl: *mut ACL = std::ptr::null_mut();
    let mut sacl_present: i32 = 0;
    let mut sacl_defaulted: i32 = 0;
    let ok = unsafe {
        // SAFETY: `security_descriptor` is a valid SD returned by the
        // conversion above; the output pointers are valid out-pointers.
        GetSecurityDescriptorSacl(
            security_descriptor,
            &mut sacl_present,
            &mut sacl,
            &mut sacl_defaulted,
        )
    };
    if ok == 0 || sacl_present == 0 || sacl.is_null() {
        let hresult = unsafe {
            // SAFETY: GetLastError has no preconditions.
            windows_sys::Win32::Foundation::GetLastError()
        };
        return Err(NonoError::LabelApplyFailed {
            path: path.to_path_buf(),
            hresult,
            hint: "Failed to extract SACL from constructed mandatory-label SD".to_string(),
        });
    }

    let status = unsafe {
        // SAFETY: `wide_path` is a valid nul-terminated UTF-16 buffer; `sacl`
        // points into `security_descriptor` which lives as long as `_sd_guard`.
        // SetNamedSecurityInfoW in windows-sys 0.59 signature:
        //   fn SetNamedSecurityInfoW(
        //     pobjectname: PCWSTR, objecttype: SE_OBJECT_TYPE,
        //     securityinfo: OBJECT_SECURITY_INFORMATION,
        //     psidowner: PSID, psidgroup: PSID,
        //     pdacl: *const ACL, psacl: *const ACL
        //   ) -> WIN32_ERROR
        SetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null(),
            sacl,
        )
    };

    if status == 0 {
        return Ok(());
    }

    // Fail-closed: map common Win32 error codes to actionable hints.
    let hint = match status {
        x if x == ERROR_ACCESS_DENIED
            || x == ERROR_INVALID_FUNCTION
            || x == ERROR_NOT_SUPPORTED =>
        {
            "Ensure the target file is writable by the current user and is on NTFS (not ReFS or a network share).".to_string()
        }
        x if x == ERROR_FILE_NOT_FOUND => {
            "Target path does not exist. Single-file Write / ReadWrite grants must name an existing file; use a directory-scope grant for file creation.".to_string()
        }
        other => {
            format!("Unexpected Win32 error while applying mandatory label (raw=0x{other:08X}); see support triage docs.")
        }
    };
    Err(NonoError::LabelApplyFailed {
        path: path.to_path_buf(),
        hresult: status,
        hint,
    })
}

/// Returns `Ok(true)` if `path`'s NTFS owner SID equals the current process
/// user SID; `Ok(false)` otherwise. Returns `Err(NonoError::LabelApplyFailed)`
/// if the owner cannot be read or the current-user token cannot be queried.
///
/// # Why
///
/// `SetNamedSecurityInfoW(LABEL_SECURITY_INFORMATION)` requires `WRITE_OWNER`
/// on the target. Unprivileged users do not hold `WRITE_OWNER` on system paths
/// like `C:\Windows`, so attempting to label them fails with
/// `ERROR_ACCESS_DENIED` (HRESULT 0x5). The Low-IL integrity model is
/// subtractive — system paths are Medium-IL by default and are already
/// readable by Low-IL subjects through existing OS ACLs, so labeling them
/// was never necessary. This helper lets the label guard skip paths the
/// current user does not own without suppressing fatal errors from the
/// ownership query itself (fail-closed: `Err` propagates).
///
/// # Errors
///
/// * `NonoError::LabelApplyFailed` if `GetNamedSecurityInfoW`,
///   `OpenProcessToken`, `GetTokenInformation`, or the owner-SID extraction
///   fails.
pub fn path_is_owned_by_current_user(path: &Path) -> Result<bool> {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
    use windows_sys::Win32::Security::{
        EqualSid, GetTokenInformation, TokenUser, OWNER_SECURITY_INFORMATION, PSID, TOKEN_QUERY,
        TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // 1. Read the NTFS owner SID for the path.
    let mut owner_sid: PSID = std::ptr::null_mut();
    let mut security_descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let status = unsafe {
        // SAFETY: `wide_path` is a valid nul-terminated UTF-16 buffer; the
        // two out-pointers refer to live local storage for the duration of
        // the call. On success the SD is heap-allocated by the kernel and
        // must be freed with LocalFree (handled by `_sd_guard` below).
        GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner_sid,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut security_descriptor,
        )
    };
    if status != 0 {
        return Err(NonoError::LabelApplyFailed {
            path: path.to_path_buf(),
            hresult: status,
            hint: format!(
                "GetNamedSecurityInfoW(OWNER_SECURITY_INFORMATION) returned 0x{status:08X} while \
                 reading owner SID for {}",
                path.display()
            ),
        });
    }
    let _sd_guard = OwnedSecurityDescriptor(security_descriptor);
    if owner_sid.is_null() {
        return Err(NonoError::LabelApplyFailed {
            path: path.to_path_buf(),
            hresult: 0,
            hint: format!(
                "GetNamedSecurityInfoW returned a null owner SID for {}",
                path.display()
            ),
        });
    }

    // 2. Open the current process token (read-only) to query TokenUser.
    let mut token: HANDLE = std::ptr::null_mut();
    let ok = unsafe {
        // SAFETY: `GetCurrentProcess()` returns a pseudo-handle valid for
        // the lifetime of this process; `&mut token` is a valid out-pointer.
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
    };
    if ok == 0 {
        let hresult = unsafe {
            // SAFETY: GetLastError has no preconditions.
            GetLastError()
        };
        return Err(NonoError::LabelApplyFailed {
            path: path.to_path_buf(),
            hresult,
            hint: format!(
                "OpenProcessToken(TOKEN_QUERY) failed (GetLastError=0x{hresult:08X}) while \
                 resolving current-user SID for ownership check on {}",
                path.display()
            ),
        });
    }
    // SAFETY guard: close the token handle on every exit path.
    struct OwnedTokenHandle(HANDLE);
    impl Drop for OwnedTokenHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    // SAFETY: `self.0` was returned by `OpenProcessToken`
                    // above and has not been closed yet.
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }
    let _token_guard = OwnedTokenHandle(token);

    // 3. Probe TokenUser buffer size (first call returns
    //    ERROR_INSUFFICIENT_BUFFER and fills `required`).
    let mut required: u32 = 0;
    let _ = unsafe {
        // SAFETY: `token` is a valid token handle; passing null + 0 is the
        // documented pattern to ask Windows for the required buffer size.
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut required)
    };
    if required == 0 {
        let hresult = unsafe {
            // SAFETY: GetLastError has no preconditions.
            GetLastError()
        };
        return Err(NonoError::LabelApplyFailed {
            path: path.to_path_buf(),
            hresult,
            hint: format!(
                "GetTokenInformation(TokenUser) size probe returned 0 \
                 (GetLastError=0x{hresult:08X}) for ownership check on {}",
                path.display()
            ),
        });
    }

    // 4. Allocate buffer and fetch TOKEN_USER.
    let mut buffer: Vec<u8> = vec![0u8; required as usize];
    let mut actual: u32 = required;
    let ok = unsafe {
        // SAFETY: `token` is a valid token handle; `buffer` has `required`
        // bytes of live storage; `&mut actual` is a valid out-pointer.
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            required,
            &mut actual,
        )
    };
    if ok == 0 {
        let hresult = unsafe {
            // SAFETY: GetLastError has no preconditions.
            GetLastError()
        };
        return Err(NonoError::LabelApplyFailed {
            path: path.to_path_buf(),
            hresult,
            hint: format!(
                "GetTokenInformation(TokenUser) failed (GetLastError=0x{hresult:08X}) while \
                 resolving current-user SID for ownership check on {}",
                path.display()
            ),
        });
    }

    // 5. Extract the current-user SID from the filled TOKEN_USER and compare
    //    it to the path's owner SID via EqualSid.
    //
    // Buffer layout: TOKEN_USER { User: SID_AND_ATTRIBUTES { Sid: PSID, .. }, .. }.
    // The PSID points INTO the same buffer allocation (it is not a separate
    // heap allocation), so the comparison is safe as long as `buffer` outlives
    // the EqualSid call — which it does (it lives to end of function).
    let token_user = unsafe {
        // SAFETY: GetTokenInformation succeeded above, so the first
        // `required` bytes of `buffer` hold a valid TOKEN_USER.
        &*(buffer.as_ptr() as *const TOKEN_USER)
    };
    let user_sid: PSID = token_user.User.Sid;
    if user_sid.is_null() {
        return Err(NonoError::LabelApplyFailed {
            path: path.to_path_buf(),
            hresult: 0,
            hint: format!(
                "GetTokenInformation(TokenUser) returned a null Sid pointer for ownership check \
                 on {}",
                path.display()
            ),
        });
    }

    let equal = unsafe {
        // SAFETY: both `user_sid` (into `buffer`) and `owner_sid` (into the
        // security descriptor owned by `_sd_guard`) are valid for the
        // duration of this call. EqualSid is a leaf-safe Win32 call that
        // does not retain the pointers.
        EqualSid(user_sid, owner_sid)
    };
    Ok(equal != 0)
}

/// Returns `Ok(true)` if the current-user SID has `WRITE_OWNER` (0x00080000)
/// in its effective rights against `path`'s DACL; `Ok(false)` otherwise.
///
/// # Why
///
/// `SetNamedSecurityInfoW(LABEL_SECURITY_INFORMATION)` requires the caller to
/// hold `WRITE_OWNER` (0x00080000) on the target object. Owner status grants
/// implicit `WRITE_DAC` + `READ_CONTROL` per the NT security model but does
/// NOT imply `WRITE_OWNER` — that bit must come from a DACL ACE. The default
/// `C:\` root ACL inherited by user-created drive-root subdirectories (e.g.
/// `C:\poc\temp`) caps users at `Modify` via `Authenticated Users`, which is
/// missing the `WRITE_OWNER` bit. Probing the effective rights via
/// `GetEffectiveRightsFromAclW` before the label-apply call lets us surface a
/// precise directive error instead of the misleading "writable...NTFS..."
/// catch-all (260522-v14 fix).
///
/// # Errors
///
/// Fail-closed (CLAUDE.md § Security Considerations "Fail Secure"): any FFI
/// failure (DACL read, token open, token-user query, effective-rights query)
/// returns `NonoError::LabelApplyFailed` carrying the underlying Win32 error
/// code. Callers MUST NOT treat this `Err` as "WRITE_OWNER present" — that
/// would be a silent permission widening (T-v14-01).
pub fn path_has_write_owner(path: &Path) -> Result<bool> {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, PSID, TOKEN_USER};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // 1. Read the path's DACL via GetNamedSecurityInfoW(DACL_SECURITY_INFORMATION).
    //    The DACL pointer lives inside the returned security descriptor, which
    //    must be freed with LocalFree (handled by `_sd_guard` below).
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut security_descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let status = unsafe {
        // SAFETY: `wide_path` is a valid nul-terminated UTF-16 buffer; both
        // out-pointers refer to live local storage for the duration of the call.
        // On success, the SD is heap-allocated by the kernel.
        GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut security_descriptor,
        )
    };
    if status != 0 {
        return Err(NonoError::LabelApplyFailed {
            path: path.to_path_buf(),
            hresult: status,
            hint: format!(
                "GetNamedSecurityInfoW(DACL_SECURITY_INFORMATION) returned 0x{status:08X} while \
                 probing WRITE_OWNER for {}",
                path.display()
            ),
        });
    }
    let _sd_guard = OwnedSecurityDescriptor(security_descriptor);
    if dacl.is_null() {
        // A null DACL allows everyone every access — effectively WRITE_OWNER
        // present. Fail-closed conservatively: if the OS reports NULL DACL we
        // still report Ok(true) (matches AccessCheck semantics). This is a
        // rare configuration; the more common edge case is a missing DACL
        // pointer + non-zero status, handled above.
        return Ok(true);
    }

    // 2. Open the current process token (read-only) to query TokenUser.
    let mut token: HANDLE = std::ptr::null_mut();
    let ok = unsafe {
        // SAFETY: `GetCurrentProcess()` returns a pseudo-handle valid for the
        // lifetime of this process; `&mut token` is a valid out-pointer.
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
    };
    if ok == 0 {
        let hresult = unsafe {
            // SAFETY: GetLastError has no preconditions.
            GetLastError()
        };
        return Err(NonoError::LabelApplyFailed {
            path: path.to_path_buf(),
            hresult,
            hint: format!(
                "OpenProcessToken(TOKEN_QUERY) failed (GetLastError=0x{hresult:08X}) while \
                 probing WRITE_OWNER for {}",
                path.display()
            ),
        });
    }
    // SAFETY guard: close the token handle on every exit path.
    struct OwnedTokenHandle(HANDLE);
    impl Drop for OwnedTokenHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    // SAFETY: `self.0` was returned by `OpenProcessToken`
                    // above and has not been closed yet.
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }
    let _token_guard = OwnedTokenHandle(token);

    // 3. Probe TokenUser buffer size (first call returns
    //    ERROR_INSUFFICIENT_BUFFER and fills `required`).
    let mut required: u32 = 0;
    let _ = unsafe {
        // SAFETY: `token` is a valid token handle; passing null + 0 is the
        // documented pattern to ask Windows for the required buffer size.
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut required)
    };
    if required == 0 {
        let hresult = unsafe {
            // SAFETY: GetLastError has no preconditions.
            GetLastError()
        };
        return Err(NonoError::LabelApplyFailed {
            path: path.to_path_buf(),
            hresult,
            hint: format!(
                "GetTokenInformation(TokenUser) size probe returned 0 \
                 (GetLastError=0x{hresult:08X}) while probing WRITE_OWNER for {}",
                path.display()
            ),
        });
    }

    // 4. Allocate buffer and fetch TOKEN_USER.
    let mut buffer: Vec<u8> = vec![0u8; required as usize];
    let mut actual: u32 = required;
    let ok = unsafe {
        // SAFETY: `token` is a valid token handle; `buffer` has `required`
        // bytes of live storage; `&mut actual` is a valid out-pointer.
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            required,
            &mut actual,
        )
    };
    if ok == 0 {
        let hresult = unsafe {
            // SAFETY: GetLastError has no preconditions.
            GetLastError()
        };
        return Err(NonoError::LabelApplyFailed {
            path: path.to_path_buf(),
            hresult,
            hint: format!(
                "GetTokenInformation(TokenUser) failed (GetLastError=0x{hresult:08X}) while \
                 probing WRITE_OWNER for {}",
                path.display()
            ),
        });
    }

    // 5. Extract the current-user SID from the filled TOKEN_USER. The PSID
    //    points INTO the same buffer allocation (it is not a separate heap
    //    allocation), so it stays valid as long as `buffer` lives.
    let token_user = unsafe {
        // SAFETY: GetTokenInformation succeeded above, so the first
        // `required` bytes of `buffer` hold a valid TOKEN_USER.
        &*(buffer.as_ptr() as *const TOKEN_USER)
    };
    let user_sid: PSID = token_user.User.Sid;
    if user_sid.is_null() {
        return Err(NonoError::LabelApplyFailed {
            path: path.to_path_buf(),
            hresult: 0,
            hint: format!(
                "GetTokenInformation(TokenUser) returned a null Sid pointer while probing \
                 WRITE_OWNER for {}",
                path.display()
            ),
        });
    }

    // 6. Build a TRUSTEE_W identifying the current-user SID. windows-sys 0.59
    //    exposes the struct fields directly (no newtype wrappers); we
    //    initialize via a struct literal to avoid the BuildTrusteeWithSidW
    //    FFI hop which does the same thing. `ptstrName` is typed as PWSTR
    //    but per the Win32 docs is reinterpreted as a PSID when TrusteeForm
    //    == TRUSTEE_IS_SID — cast through *mut c_void preserves the bits.
    let trustee = TRUSTEE_W {
        pMultipleTrustee: std::ptr::null_mut(),
        MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_USER,
        ptstrName: user_sid.cast(),
    };

    // 7. Query the effective rights of the trustee against the DACL.
    let mut access_mask: u32 = 0;
    let status = unsafe {
        // SAFETY: `dacl` lives in `security_descriptor` (owned by `_sd_guard`);
        // `trustee` holds a SID pointer into `buffer` (owned by this stack
        // frame); `&mut access_mask` is a valid out-pointer.
        // GetEffectiveRightsFromAclW returns a Win32 error code (0 == success).
        GetEffectiveRightsFromAclW(dacl, &trustee, &mut access_mask)
    };
    if status != 0 {
        return Err(NonoError::LabelApplyFailed {
            path: path.to_path_buf(),
            hresult: status,
            hint: format!(
                "GetEffectiveRightsFromAclW returned 0x{status:08X} while probing WRITE_OWNER \
                 for {}",
                path.display()
            ),
        });
    }

    // WRITE_OWNER is a FILE_ACCESS_RIGHTS constant (= 0x00080000). The mask
    // returned by GetEffectiveRightsFromAclW is a generic access mask, so a
    // bitwise AND against the literal access-right bit is the correct test.
    Ok((access_mask & WRITE_OWNER) != 0)
}

fn low_integrity_label_rid(path: &Path) -> Option<u32> {
    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut sacl: *mut ACL = std::ptr::null_mut();
    let mut security_descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();

    let status = unsafe {
        // SAFETY: `wide_path` is a valid nul-terminated UTF-16 buffer, and
        // the output pointers refer to live local storage for the duration of
        // the call.
        GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sacl,
            &mut security_descriptor,
        )
    };
    if status != 0 {
        return None;
    }
    let _security_descriptor = OwnedSecurityDescriptor(security_descriptor);

    if sacl.is_null() {
        return None;
    }

    let ace_count = unsafe {
        // SAFETY: `sacl` is populated by GetNamedSecurityInfoW on success.
        (*sacl).AceCount
    };

    for index in 0..ace_count {
        let mut ace = std::ptr::null_mut();
        let ok = unsafe {
            // SAFETY: `sacl` is a valid ACL pointer and `ace` is a valid
            // out-pointer for the duration of the call.
            GetAce(sacl, u32::from(index), &mut ace)
        };
        if ok == 0 || ace.is_null() {
            continue;
        }

        let header = unsafe {
            // SAFETY: `ace` points to a valid ACE entry returned by GetAce.
            &*(ace as *const ACE_HEADER)
        };
        if u32::from(header.AceType) != SYSTEM_MANDATORY_LABEL_ACE_TYPE {
            continue;
        }

        let label_ace = unsafe {
            // SAFETY: We already checked the ACE type and can interpret the
            // returned bytes as a SYSTEM_MANDATORY_LABEL_ACE.
            &*(ace as *const SYSTEM_MANDATORY_LABEL_ACE)
        };
        let sid = (&label_ace.SidStart as *const u32).cast_mut().cast();
        let subauthority_count = unsafe {
            // SAFETY: `sid` points to the SID embedded in the label ACE.
            GetSidSubAuthorityCount(sid)
        };
        if subauthority_count.is_null() {
            continue;
        }
        let subauthority_count = unsafe { *subauthority_count };
        if subauthority_count == 0 {
            continue;
        }

        let rid = unsafe {
            // SAFETY: The SID has at least one subauthority, so the final RID
            // pointer is valid for the lifetime of the ACE buffer.
            GetSidSubAuthority(sid, u32::from(subauthority_count) - 1)
        };
        if rid.is_null() {
            continue;
        }

        return Some(unsafe { *rid });
    }

    None
}

/// Reads back the mandatory-label ACE on `path`, returning `Some((rid, mask))`
/// if a label is present. Returns `None` if the path has no SACL, no
/// mandatory-label ACE, or the FFI fails.
///
/// Companion to `try_set_mandatory_label` for verification in tests.
#[must_use]
pub fn low_integrity_label_and_mask(path: &Path) -> Option<(u32, u32)> {
    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut sacl: *mut ACL = std::ptr::null_mut();
    let mut security_descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();

    let status = unsafe {
        // SAFETY: `wide_path` is a valid nul-terminated UTF-16 buffer; the
        // output pointers refer to live local storage for the duration of the
        // call. On success, the SD is freed by OwnedSecurityDescriptor's Drop.
        GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sacl,
            &mut security_descriptor,
        )
    };
    if status != 0 {
        return None;
    }
    let _sd_guard = OwnedSecurityDescriptor(security_descriptor);
    if sacl.is_null() {
        return None;
    }

    let ace_count = unsafe {
        // SAFETY: `sacl` is populated by GetNamedSecurityInfoW on success.
        (*sacl).AceCount
    };
    for index in 0..ace_count {
        let mut ace = std::ptr::null_mut();
        let ok = unsafe {
            // SAFETY: `sacl` is a valid ACL pointer; `ace` is a valid out-pointer.
            GetAce(sacl, u32::from(index), &mut ace)
        };
        if ok == 0 || ace.is_null() {
            continue;
        }
        let header = unsafe {
            // SAFETY: `ace` points to a valid ACE entry returned by GetAce.
            &*(ace as *const ACE_HEADER)
        };
        if u32::from(header.AceType) != SYSTEM_MANDATORY_LABEL_ACE_TYPE {
            continue;
        }
        let label_ace = unsafe {
            // SAFETY: AceType checked above; bytes are a SYSTEM_MANDATORY_LABEL_ACE.
            &*(ace as *const SYSTEM_MANDATORY_LABEL_ACE)
        };
        let mask = label_ace.Mask;
        let sid = (&label_ace.SidStart as *const u32).cast_mut().cast();
        let subauthority_count = unsafe {
            // SAFETY: `sid` points to the SID embedded in the label ACE.
            GetSidSubAuthorityCount(sid)
        };
        if subauthority_count.is_null() {
            continue;
        }
        let subauthority_count = unsafe {
            // SAFETY: subauthority_count was just checked for non-null.
            *subauthority_count
        };
        if subauthority_count == 0 {
            continue;
        }
        let rid = unsafe {
            // SAFETY: SID has at least one subauthority; final RID pointer is valid.
            GetSidSubAuthority(sid, u32::from(subauthority_count) - 1)
        };
        if rid.is_null() {
            continue;
        }
        return Some((
            unsafe {
                // SAFETY: `rid` was just checked for non-null and points into the ACE buffer.
                *rid
            },
            mask,
        ));
    }
    None
}

#[must_use]
pub fn is_low_integrity_compatible_dir(path: &Path) -> bool {
    let canonical = path.canonicalize().ok();
    let normalized = canonical
        .as_ref()
        .map(|path| normalize_windows_path(path))
        .unwrap_or_else(|| normalize_windows_path(path));

    if low_integrity_runtime_prefixes()
        .into_iter()
        .any(|prefix| windows_paths_start_with_case_insensitive(&normalized, &prefix))
    {
        return true;
    }

    canonical
        .as_deref()
        .and_then(low_integrity_label_rid)
        .is_some_and(|rid| rid <= SECURITY_MANDATORY_LOW_RID as u32)
}

#[must_use]
pub fn compile_filesystem_policy(caps: &CapabilitySet) -> WindowsFilesystemPolicy {
    let mut rules = Vec::new();
    let mut unsupported: Vec<crate::sandbox::WindowsUnsupportedIssue> = Vec::new();

    for cap in caps.fs_capabilities() {
        // Phase 21: single-file grants (any mode) and write-only directory grants
        // are now enforced via per-path SYSTEM_MANDATORY_LABEL_ACE (see
        // `try_set_mandatory_label` + `label_mask_for_access_mode`). All three
        // AccessMode variants x both path kinds (file/dir) compile to a
        // WindowsFilesystemRule; no branch emits `unsupported`.
        //
        // The WindowsUnsupportedIssueKind::SingleFileGrant and
        // WriteOnlyDirectoryGrant variants are retained in the enum as reserved
        // shapes for future unsupported cases (D-06 defers enum retirement).
        rules.push(WindowsFilesystemRule {
            path: normalize_windows_path(&cap.resolved),
            access: cap.access,
            is_file: cap.is_file,
            source: cap.source.clone(),
        });
    }

    rules.sort_by(|a, b| a.path.cmp(&b.path));
    rules.dedup_by(|left, right| {
        left.path == right.path
            && left.access == right.access
            && left.is_file == right.is_file
            && left.source == right.source
    });

    unsupported.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.path.cmp(&right.path))
    });
    unsupported.dedup();

    WindowsFilesystemPolicy { rules, unsupported }
}

pub fn validate_launch_paths(
    policy: &WindowsFilesystemPolicy,
    program: &Path,
    current_dir: &Path,
) -> Result<()> {
    if !policy.unsupported.is_empty() {
        return Err(NonoError::UnsupportedPlatform(format!(
            "Windows filesystem enforcement does not support this capability set yet ({}).",
            policy.unsupported_messages().join(", ")
        )));
    }

    if !policy.has_rules() {
        return Ok(());
    }

    let program = program
        .canonicalize()
        .unwrap_or_else(|_| program.to_path_buf());
    let program = normalize_windows_path(&program);

    if !policy.covers_path(&program, crate::AccessMode::Read) {
        return Err(NonoError::UnsupportedPlatform(format!(
            "Windows filesystem policy does not cover the executable path required for launch: {}",
            program.display()
        )));
    }

    let current_dir = current_dir
        .canonicalize()
        .unwrap_or_else(|_| current_dir.to_path_buf());
    let current_dir = normalize_windows_path(&current_dir);
    if policy.has_user_intent_directory_rules() && !policy.covers_execution_dir(&current_dir) {
        return Err(NonoError::UnsupportedPlatform(
            "Windows cannot enforce the requested sandbox controls for this live run (execution directory outside supported allowlist). Use `nono run --dry-run ...` to validate policy, or rerun without those controls. This is an explicit Windows product-surface limitation, not a silent fallback."
                .to_string(),
        ));
    }

    Ok(())
}

fn extract_arg_path_candidate(arg: &str) -> Option<&str> {
    let candidate = if let Some((_, value)) = arg.split_once('=') {
        value
    } else {
        arg
    };

    let trimmed = candidate.trim_matches('"');
    if trimmed.is_empty() {
        return None;
    }

    let path = Path::new(trimmed);
    if path.is_absolute() {
        Some(trimmed)
    } else {
        None
    }
}

fn normalize_candidate_path(candidate: &Path) -> PathBuf {
    candidate
        .canonicalize()
        .map(|path| normalize_windows_path(&path))
        .unwrap_or_else(|_| normalize_windows_path(candidate))
}

fn validate_candidate_path(
    policy: &WindowsFilesystemPolicy,
    candidate: &Path,
    required: crate::AccessMode,
    description: &str,
) -> Result<()> {
    let normalized = normalize_candidate_path(candidate);
    if !policy.covers_path(&normalized, required) {
        return Err(NonoError::UnsupportedPlatform(format!(
            "Windows filesystem policy does not cover the {description} required for launch: {}",
            normalized.display()
        )));
    }
    Ok(())
}

fn validate_absolute_path_args(policy: &WindowsFilesystemPolicy, args: &[String]) -> Result<()> {
    if !policy.is_fully_supported() || !policy.has_rules() {
        return Ok(());
    }

    for arg in args {
        let Some(candidate) = extract_arg_path_candidate(arg) else {
            continue;
        };

        validate_candidate_path(
            policy,
            Path::new(candidate),
            crate::AccessMode::Read,
            "absolute path argument",
        )?;
    }

    Ok(())
}

fn resolve_relative_arg_path(current_dir: &Path, arg: &str) -> Option<PathBuf> {
    let candidate = arg.trim_matches('"');
    if candidate.is_empty() {
        return None;
    }
    if Path::new(candidate).is_absolute() {
        return Some(PathBuf::from(candidate));
    }
    if candidate.contains(['\\', '/']) || current_dir.join(candidate).exists() {
        return Some(current_dir.join(candidate));
    }
    None
}

fn split_powershell_command(command: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;

    for ch in command.chars() {
        match quote {
            Some(q) if ch == q => quote = None,
            Some(_) => current.push(ch),
            None if ch == '\'' || ch == '"' => quote = Some(ch),
            None if ch.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            None => current.push(ch),
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

fn first_named_value<'a>(tokens: &'a [String], names: &[&str]) -> Option<&'a str> {
    tokens.windows(2).find_map(|window| {
        let flag = window[0].to_ascii_lowercase();
        names.contains(&flag.as_str()).then_some(window[1].as_str())
    })
}

fn positional_values(tokens: &[String]) -> Vec<&str> {
    let mut values = Vec::new();
    let mut skip_next = false;

    for token in tokens.iter().skip(1) {
        if skip_next {
            skip_next = false;
            continue;
        }
        if token.starts_with('-') {
            skip_next = true;
            continue;
        }
        values.push(token.as_str());
    }

    values
}

fn validate_powershell_tokens(
    policy: &WindowsFilesystemPolicy,
    tokens: &[String],
    current_dir: &Path,
) -> Result<()> {
    let Some(command) = tokens.first() else {
        return Ok(());
    };

    let command = command.to_ascii_lowercase();
    match command.as_str() {
        "get-content" | "gc" | "cat" | "type" => {
            if let Some(path) = first_named_value(tokens, &["-path", "-literalpath"]) {
                if let Some(candidate) = resolve_relative_arg_path(current_dir, path) {
                    validate_candidate_path(
                        policy,
                        &candidate,
                        crate::AccessMode::Read,
                        "PowerShell file argument",
                    )?;
                }
            } else {
                for value in positional_values(tokens) {
                    if let Some(candidate) = resolve_relative_arg_path(current_dir, value) {
                        validate_candidate_path(
                            policy,
                            &candidate,
                            crate::AccessMode::Read,
                            "PowerShell file argument",
                        )?;
                    }
                }
            }
        }
        "set-content" | "sc" | "add-content" | "ac" | "out-file" => {
            let names = if command == "out-file" {
                &["-filepath"][..]
            } else {
                &["-path", "-literalpath"][..]
            };
            if let Some(path) = first_named_value(tokens, names) {
                if let Some(candidate) = resolve_relative_arg_path(current_dir, path) {
                    validate_candidate_path(
                        policy,
                        &candidate,
                        crate::AccessMode::Write,
                        "PowerShell write target",
                    )?;
                }
            } else if let Some(value) = positional_values(tokens).first() {
                if let Some(candidate) = resolve_relative_arg_path(current_dir, value) {
                    validate_candidate_path(
                        policy,
                        &candidate,
                        crate::AccessMode::Write,
                        "PowerShell write target",
                    )?;
                }
            }
        }
        "copy-item" | "cp" | "copy" | "move-item" | "mv" | "move" => {
            if let Some(path) = first_named_value(tokens, &["-path", "-literalpath"]) {
                if let Some(candidate) = resolve_relative_arg_path(current_dir, path) {
                    validate_candidate_path(
                        policy,
                        &candidate,
                        crate::AccessMode::Read,
                        "PowerShell source path",
                    )?;
                }
            }
            if let Some(dest) = first_named_value(tokens, &["-destination"]) {
                if let Some(candidate) = resolve_relative_arg_path(current_dir, dest) {
                    validate_candidate_path(
                        policy,
                        &candidate,
                        crate::AccessMode::Write,
                        "PowerShell destination path",
                    )?;
                }
            } else {
                let values = positional_values(tokens);
                if let Some(path) = values.first() {
                    if let Some(candidate) = resolve_relative_arg_path(current_dir, path) {
                        validate_candidate_path(
                            policy,
                            &candidate,
                            crate::AccessMode::Read,
                            "PowerShell source path",
                        )?;
                    }
                }
                if let Some(dest) = values.get(1) {
                    if let Some(candidate) = resolve_relative_arg_path(current_dir, dest) {
                        validate_candidate_path(
                            policy,
                            &candidate,
                            crate::AccessMode::Write,
                            "PowerShell destination path",
                        )?;
                    }
                }
            }
        }
        "remove-item" | "ri" | "rm" | "del" | "erase" | "new-item" | "ni" | "rename-item"
        | "rni" => {
            if let Some(path) = first_named_value(tokens, &["-path", "-literalpath"]) {
                if let Some(candidate) = resolve_relative_arg_path(current_dir, path) {
                    validate_candidate_path(
                        policy,
                        &candidate,
                        crate::AccessMode::Write,
                        "PowerShell filesystem mutation path",
                    )?;
                }
            } else {
                for value in positional_values(tokens) {
                    if let Some(candidate) = resolve_relative_arg_path(current_dir, value) {
                        validate_candidate_path(
                            policy,
                            &candidate,
                            crate::AccessMode::Write,
                            "PowerShell filesystem mutation path",
                        )?;
                    }
                }
            }
        }
        _ => {}
    }

    Ok(())
}

fn validate_powershell_args(
    policy: &WindowsFilesystemPolicy,
    args: &[String],
    current_dir: &Path,
) -> Result<()> {
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].to_ascii_lowercase();
        match flag.as_str() {
            "-file" | "-f" => {
                if let Some(path) = args.get(i + 1) {
                    if let Some(candidate) = resolve_relative_arg_path(current_dir, path) {
                        validate_candidate_path(
                            policy,
                            &candidate,
                            crate::AccessMode::Read,
                            "PowerShell script path",
                        )?;
                    }
                }
                i += 2;
            }
            "-command" | "-c" => {
                if let Some(command) = args.get(i + 1) {
                    let tokens = split_powershell_command(command);
                    validate_powershell_tokens(policy, &tokens, current_dir)?;
                }
                i += 2;
            }
            _ => i += 1,
        }
    }

    Ok(())
}

fn validate_cmd_builtin_args(
    policy: &WindowsFilesystemPolicy,
    args: &[String],
    current_dir: &Path,
) -> Result<()> {
    if args.len() < 3 {
        return Ok(());
    }
    let switch = args[0].to_ascii_lowercase();
    if switch != "/c" && switch != "/k" {
        return Ok(());
    }

    let builtin = args[1].to_ascii_lowercase();
    match builtin.as_str() {
        "type" | "more" => {
            for arg in &args[2..] {
                if let Some(candidate) = resolve_relative_arg_path(current_dir, arg) {
                    validate_candidate_path(
                        policy,
                        &candidate,
                        crate::AccessMode::Read,
                        "file argument",
                    )?;
                }
            }
        }
        "copy" | "move" => {
            if let Some(source) = args
                .get(2)
                .and_then(|arg| resolve_relative_arg_path(current_dir, arg))
            {
                validate_candidate_path(
                    policy,
                    &source,
                    crate::AccessMode::Read,
                    "source path argument",
                )?;
            }
            if let Some(dest) = args
                .get(3)
                .and_then(|arg| resolve_relative_arg_path(current_dir, arg))
            {
                validate_candidate_path(
                    policy,
                    &dest,
                    crate::AccessMode::Write,
                    "destination path argument",
                )?;
            }
        }
        "del" | "erase" | "mkdir" | "md" | "rmdir" | "rd" | "ren" | "rename" => {
            for arg in &args[2..] {
                if let Some(candidate) = resolve_relative_arg_path(current_dir, arg) {
                    validate_candidate_path(
                        policy,
                        &candidate,
                        crate::AccessMode::Write,
                        "filesystem mutation argument",
                    )?;
                }
            }
        }
        _ => {}
    }

    Ok(())
}

fn validate_script_host_args(
    policy: &WindowsFilesystemPolicy,
    args: &[String],
    current_dir: &Path,
) -> Result<()> {
    let mut script_index = None;
    for (index, arg) in args.iter().enumerate() {
        if arg.starts_with("//") || arg.starts_with('/') {
            continue;
        }
        script_index = Some(index);
        break;
    }

    let Some(script_index) = script_index else {
        return Ok(());
    };

    if let Some(script_path) = args.get(script_index) {
        if let Some(candidate) = resolve_relative_arg_path(current_dir, script_path) {
            validate_candidate_path(
                policy,
                &candidate,
                crate::AccessMode::Read,
                "Windows Script Host script path",
            )?;
        }
    }

    for arg in &args[script_index + 1..] {
        if let Some(candidate) = resolve_relative_arg_path(current_dir, arg) {
            let required = if candidate.exists() {
                crate::AccessMode::Read
            } else {
                crate::AccessMode::Write
            };
            validate_candidate_path(
                policy,
                &candidate,
                required,
                "Windows Script Host path argument",
            )?;
        }
    }

    Ok(())
}

fn validate_findstr_args(
    policy: &WindowsFilesystemPolicy,
    args: &[String],
    current_dir: &Path,
) -> Result<()> {
    let mut file_args = Vec::new();
    let mut seen_pattern = false;

    for arg in args {
        if arg.starts_with('/') {
            continue;
        }
        if !seen_pattern {
            seen_pattern = true;
            continue;
        }
        file_args.push(arg.as_str());
    }

    for arg in file_args {
        if let Some(candidate) = resolve_relative_arg_path(current_dir, arg) {
            validate_candidate_path(
                policy,
                &candidate,
                crate::AccessMode::Read,
                "findstr file argument",
            )?;
        }
    }

    Ok(())
}

fn validate_fc_args(
    policy: &WindowsFilesystemPolicy,
    args: &[String],
    current_dir: &Path,
) -> Result<()> {
    let mut file_args = Vec::new();

    for arg in args {
        if arg.starts_with('/') {
            continue;
        }
        file_args.push(arg.as_str());
        if file_args.len() == 2 {
            break;
        }
    }

    for arg in file_args {
        if let Some(candidate) = resolve_relative_arg_path(current_dir, arg) {
            validate_candidate_path(
                policy,
                &candidate,
                crate::AccessMode::Read,
                "fc file argument",
            )?;
        }
    }

    Ok(())
}

fn validate_find_args(
    policy: &WindowsFilesystemPolicy,
    args: &[String],
    current_dir: &Path,
) -> Result<()> {
    let mut file_args = Vec::new();
    let mut seen_pattern = false;

    for arg in args {
        if arg.starts_with('/') {
            continue;
        }
        if !seen_pattern {
            seen_pattern = true;
            continue;
        }
        file_args.push(arg.as_str());
    }

    for arg in file_args {
        if let Some(candidate) = resolve_relative_arg_path(current_dir, arg) {
            validate_candidate_path(
                policy,
                &candidate,
                crate::AccessMode::Read,
                "find file argument",
            )?;
        }
    }

    Ok(())
}

fn validate_comp_args(
    policy: &WindowsFilesystemPolicy,
    args: &[String],
    current_dir: &Path,
) -> Result<()> {
    let mut file_args = Vec::new();

    for arg in args {
        if arg.starts_with('/') {
            continue;
        }
        file_args.push(arg.as_str());
        if file_args.len() == 2 {
            break;
        }
    }

    for arg in file_args {
        if let Some(candidate) = resolve_relative_arg_path(current_dir, arg) {
            validate_candidate_path(
                policy,
                &candidate,
                crate::AccessMode::Read,
                "comp file argument",
            )?;
        }
    }

    Ok(())
}

pub fn validate_command_args(
    policy: &WindowsFilesystemPolicy,
    resolved_program: &Path,
    args: &[String],
    current_dir: &Path,
) -> Result<()> {
    validate_absolute_path_args(policy, args)?;

    let program_name = resolved_program
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    match program_name.as_str() {
        "cmd.exe" | "cmd" => validate_cmd_builtin_args(policy, args, current_dir),
        "powershell.exe" | "powershell" | "pwsh.exe" | "pwsh" => {
            validate_powershell_args(policy, args, current_dir)
        }
        "cscript.exe" | "cscript" | "wscript.exe" | "wscript" => {
            validate_script_host_args(policy, args, current_dir)
        }
        "find.exe" | "find" => validate_find_args(policy, args, current_dir),
        "findstr.exe" | "findstr" => validate_findstr_args(policy, args, current_dir),
        "comp.exe" | "comp" => validate_comp_args(policy, args, current_dir),
        "fc.exe" | "fc" => validate_fc_args(policy, args, current_dir),
        "xcopy.exe" | "xcopy" => {
            if let Some(source) = args
                .first()
                .and_then(|arg| resolve_relative_arg_path(current_dir, arg))
            {
                validate_candidate_path(
                    policy,
                    &source,
                    crate::AccessMode::Read,
                    "xcopy source path",
                )?;
            }
            if let Some(dest) = args
                .get(1)
                .and_then(|arg| resolve_relative_arg_path(current_dir, arg))
            {
                validate_candidate_path(
                    policy,
                    &dest,
                    crate::AccessMode::Write,
                    "xcopy destination path",
                )?;
            }
            Ok(())
        }
        "robocopy.exe" | "robocopy" => {
            if let Some(source) = args
                .first()
                .and_then(|arg| resolve_relative_arg_path(current_dir, arg))
            {
                validate_candidate_path(
                    policy,
                    &source,
                    crate::AccessMode::Read,
                    "robocopy source path",
                )?;
            }
            if let Some(dest) = args
                .get(1)
                .and_then(|arg| resolve_relative_arg_path(current_dir, arg))
            {
                validate_candidate_path(
                    policy,
                    &dest,
                    crate::AccessMode::Write,
                    "robocopy destination path",
                )?;
            }
            Ok(())
        }
        "more.com" | "more" => {
            for arg in args {
                if let Some(candidate) = resolve_relative_arg_path(current_dir, arg) {
                    validate_candidate_path(
                        policy,
                        &candidate,
                        crate::AccessMode::Read,
                        "file argument",
                    )?;
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[must_use]
pub fn runtime_state_dir(policy: &WindowsFilesystemPolicy, current_dir: &Path) -> Option<PathBuf> {
    if !policy.unsupported.is_empty() {
        return None;
    }

    let current_dir = current_dir
        .canonicalize()
        .unwrap_or_else(|_| current_dir.to_path_buf());
    let current_dir = normalize_windows_path(&current_dir);

    let user_intent_writable_rule = |rule: &crate::sandbox::WindowsFilesystemRule| {
        rule.source.is_user_intent() && rule.access.contains(crate::AccessMode::Write)
    };

    if policy.rules.iter().any(user_intent_writable_rule)
        && policy.covers_writable_directory_path(&current_dir)
    {
        return Some(current_dir);
    }

    policy
        .rules
        .iter()
        .find(|rule| !rule.is_file && user_intent_writable_rule(rule))
        .map(|rule| rule.path.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccessMode, CapabilitySet, CapabilitySource, FsCapability, IpcMode, NetworkMode};
    use std::process::Command;
    use tempfile::tempdir;

    // Avoid relative-path `Command::new("<tool>")` for OS utilities — path-
    // hijack hazard on Windows. Resolve via `%SystemRoot%\System32\<tool>.exe`
    // with the same fallback chain used elsewhere in the codebase.
    fn system32_exe(name: &str) -> PathBuf {
        let system_root = std::env::var_os("SystemRoot")
            .or_else(|| std::env::var_os("windir"))
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        system_root.join("System32").join(format!("{name}.exe"))
    }

    fn try_create_symlink_file(link: &Path, target: &Path) -> bool {
        match std::os::windows::fs::symlink_file(target, link) {
            Ok(()) => true,
            Err(err) => {
                eprintln!("skipping symlink escape test because symlink creation failed: {err}");
                false
            }
        }
    }

    fn try_create_junction(link: &Path, target: &Path) -> bool {
        let Ok(output) = Command::new(system32_exe("cmd"))
            .args([
                "/c",
                "mklink",
                "/J",
                &link.to_string_lossy(),
                &target.to_string_lossy(),
            ])
            .output()
        else {
            eprintln!("skipping junction escape test because cmd/mklink is unavailable");
            return false;
        };

        if output.status.success() {
            true
        } else {
            eprintln!(
                "skipping junction escape test because mklink /J failed: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            false
        }
    }

    fn try_set_low_integrity_label(path: &Path) -> bool {
        let Ok(output) = Command::new(system32_exe("icacls"))
            .arg(path)
            .args(["/setintegritylevel", "(OI)(CI)L"])
            .output()
        else {
            eprintln!("skipping low-integrity label test because icacls is unavailable");
            return false;
        };

        if output.status.success() {
            true
        } else {
            eprintln!(
                "skipping low-integrity label test because icacls failed: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            false
        }
    }

    #[test]
    fn support_info_reports_supported_status_for_promoted_subset_contract() {
        let info = support_info();
        assert!(is_supported());
        assert!(info.is_supported);
        assert_eq!(info.status, SupportStatus::Supported);
        assert_eq!(info.platform, "windows");
        // details string must be non-empty and not mention "partial"
        assert!(!info.details.is_empty());
        assert!(!info.details.to_ascii_lowercase().contains("partial"));
    }

    #[test]
    fn label_mask_for_access_mode_read_denies_write_and_execute_up() {
        let mask = label_mask_for_access_mode(crate::AccessMode::Read);
        assert_eq!(
            mask,
            SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP,
            "Read mode must deny WRITE_UP and EXECUTE_UP; got 0x{mask:X}"
        );
    }

    #[test]
    fn label_mask_for_access_mode_write_denies_read_and_execute_up() {
        let mask = label_mask_for_access_mode(crate::AccessMode::Write);
        assert_eq!(
            mask,
            SYSTEM_MANDATORY_LABEL_NO_READ_UP | SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP,
            "Write mode must deny READ_UP and EXECUTE_UP; got 0x{mask:X}"
        );
    }

    #[test]
    fn label_mask_for_access_mode_read_write_denies_only_execute_up() {
        let mask = label_mask_for_access_mode(crate::AccessMode::ReadWrite);
        assert_eq!(
            mask, SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP,
            "ReadWrite mode must deny only EXECUTE_UP; got 0x{mask:X}"
        );
    }

    #[test]
    fn apply_accepts_minimal_supported_windows_subset() {
        let dir = tempdir().expect("tempdir");
        let caps = CapabilitySet::new()
            .allow_path(dir.path(), AccessMode::Read)
            .expect("allow path");
        assert!(apply(&caps).is_ok());
    }

    #[test]
    fn apply_accepts_network_blocked_capability_set() {
        let caps = CapabilitySet::new().set_network_mode(NetworkMode::Blocked);
        assert!(apply(&caps).is_ok());
    }

    #[test]
    fn compile_filesystem_policy_emits_rule_for_single_file_read_grant() {
        let dir = tempdir().expect("tempdir");
        let file = dir.path().join("note.txt");
        std::fs::write(&file, "x").expect("write file");
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_file(&file, AccessMode::Read).expect("file cap"));
        let policy = compile_filesystem_policy(&caps);
        assert_eq!(
            policy.unsupported.len(),
            0,
            "single-file read grant must not emit unsupported entry"
        );
        assert_eq!(
            policy.rules.len(),
            1,
            "single-file read grant must emit one rule"
        );
        let rule = &policy.rules[0];
        assert!(rule.is_file, "rule must carry is_file=true");
        assert_eq!(rule.access, AccessMode::Read);
    }

    #[test]
    fn compile_filesystem_policy_emits_rule_for_single_file_write_grant() {
        let dir = tempdir().expect("tempdir");
        let file = dir.path().join("note.txt");
        std::fs::write(&file, "x").expect("write file");
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_file(&file, AccessMode::Write).expect("file cap"));
        let policy = compile_filesystem_policy(&caps);
        assert_eq!(policy.unsupported.len(), 0);
        assert_eq!(policy.rules.len(), 1);
        assert!(policy.rules[0].is_file);
        assert_eq!(policy.rules[0].access, AccessMode::Write);
    }

    #[test]
    fn compile_filesystem_policy_emits_rule_for_single_file_read_write_grant() {
        let dir = tempdir().expect("tempdir");
        let file = dir.path().join("note.txt");
        std::fs::write(&file, "x").expect("write file");
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_file(&file, AccessMode::ReadWrite).expect("file cap"));
        let policy = compile_filesystem_policy(&caps);
        assert_eq!(policy.unsupported.len(), 0);
        assert_eq!(policy.rules.len(), 1);
        assert!(policy.rules[0].is_file);
        assert_eq!(policy.rules[0].access, AccessMode::ReadWrite);
    }

    #[test]
    fn compile_filesystem_policy_emits_rule_for_write_only_directory_grant() {
        let dir = tempdir().expect("tempdir");
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_dir(dir.path(), AccessMode::Write).expect("dir cap"));
        let policy = compile_filesystem_policy(&caps);
        assert_eq!(
            policy.unsupported.len(),
            0,
            "write-only dir grant must not emit unsupported entry"
        );
        assert_eq!(policy.rules.len(), 1);
        assert!(!policy.rules[0].is_file);
        assert_eq!(policy.rules[0].access, AccessMode::Write);
    }

    #[test]
    fn apply_accepts_single_file_grant_and_labels_low_integrity() {
        // Phase 21: single-file grants in all three access modes are now enforced
        // via per-file mandatory-label ACE. This test replaces the pre-phase-21
        // rejection test (apply_rejects_unsupported_single_file_grant).
        let dir = tempdir().expect("tempdir");
        let file = dir.path().join("note.txt");
        std::fs::write(&file, "x").expect("write file");
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_file(&file, AccessMode::Read).expect("file cap"));
        apply(&caps).expect("Phase 21: single-file read grant must be accepted");
        let (rid, mask) = low_integrity_label_and_mask(&file)
            .expect("Phase 21: apply() must leave a mandatory-label ACE on the granted file");
        assert_eq!(
            rid, SECURITY_MANDATORY_LOW_RID as u32,
            "label RID must be SECURITY_MANDATORY_LOW_RID; got 0x{rid:X}"
        );
        assert_eq!(
            mask,
            SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP,
            "Read mode label mask must be NO_WRITE_UP | NO_EXECUTE_UP; got 0x{mask:X}"
        );
    }

    #[test]
    fn apply_accepts_write_only_directory_grant_and_labels_low_integrity() {
        // Phase 21: write-only directory grants are now enforced via directory-scope
        // mandatory-label ACE with the NO_READ_UP mask. This test replaces the
        // pre-phase-21 rejection test (apply_rejects_unsupported_write_only_directory_grant).
        let dir = tempdir().expect("tempdir");
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_dir(dir.path(), AccessMode::Write).expect("dir cap"));
        apply(&caps).expect("Phase 21: write-only directory grant must be accepted");
        let (rid, mask) = low_integrity_label_and_mask(dir.path())
            .expect("Phase 21: apply() must leave a mandatory-label ACE on the granted directory");
        assert_eq!(
            rid, SECURITY_MANDATORY_LOW_RID as u32,
            "label RID must be SECURITY_MANDATORY_LOW_RID; got 0x{rid:X}"
        );
        assert_eq!(
            mask,
            SYSTEM_MANDATORY_LABEL_NO_READ_UP | SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP,
            "Write mode label mask must be NO_READ_UP | NO_EXECUTE_UP; got 0x{mask:X}"
        );
    }

    #[test]
    fn single_file_grant_does_not_label_parent_directory() {
        // Phase 21 Plan 21-05 silent-degradation regression test (CONTEXT.md § specifics).
        // Guards the I-01 fail-closed invariant: single-file grants must NEVER silently
        // degrade into a parent-directory grant. Future refactors that accidentally
        // route single-file grants through a parent-directory label path will fail this
        // test — the parent directory's integrity-label RID must be unchanged across
        // apply(), while the granted file's RID must transition to SECURITY_MANDATORY_LOW_RID.
        let dir = tempdir().expect("tempdir");
        let file = dir.path().join("only-this.txt");
        std::fs::write(&file, "x").expect("write file");
        let parent_label_before = low_integrity_label_rid(dir.path());
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_file(&file, AccessMode::Read).expect("file cap"));
        apply(&caps).expect("apply");
        let parent_label_after = low_integrity_label_rid(dir.path());
        assert_eq!(
            parent_label_before, parent_label_after,
            "single-file grant must not mutate parent directory's label"
        );
        // File itself should now be Low IL.
        assert_eq!(
            low_integrity_label_rid(&file),
            Some(SECURITY_MANDATORY_LOW_RID as u32),
            "granted file must carry Low IL label after apply"
        );
    }

    #[test]
    fn apply_labels_single_file_write_mode_with_correct_mask() {
        // Phase 21 Plan 21-05 per-mode mask integration test for Write mode on a FILE
        // (Read mode on a file is covered by apply_accepts_single_file_grant_and_labels_low_integrity;
        // Write mode on a DIRECTORY is covered by apply_accepts_write_only_directory_grant_and_labels_low_integrity).
        let dir = tempdir().expect("tempdir");
        let file = dir.path().join("note.txt");
        std::fs::write(&file, "x").expect("write file");
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_file(&file, AccessMode::Write).expect("file cap"));
        apply(&caps).expect("Phase 21: single-file write grant must be accepted");
        let (rid, mask) = low_integrity_label_and_mask(&file)
            .expect("Phase 21: apply() must leave a mandatory-label ACE on the granted file");
        assert_eq!(rid, SECURITY_MANDATORY_LOW_RID as u32);
        assert_eq!(
            mask,
            SYSTEM_MANDATORY_LABEL_NO_READ_UP | SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP,
            "Write mode mask must be NO_READ_UP | NO_EXECUTE_UP per D-01; got 0x{mask:X}"
        );
    }

    #[test]
    fn apply_labels_single_file_read_write_mode_with_correct_mask() {
        // Phase 21 Plan 21-05 per-mode mask integration test for ReadWrite mode on a FILE.
        let dir = tempdir().expect("tempdir");
        let file = dir.path().join("note.txt");
        std::fs::write(&file, "x").expect("write file");
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_file(&file, AccessMode::ReadWrite).expect("file cap"));
        apply(&caps).expect("Phase 21: single-file read-write grant must be accepted");
        let (rid, mask) = low_integrity_label_and_mask(&file)
            .expect("Phase 21: apply() must leave a mandatory-label ACE on the granted file");
        assert_eq!(rid, SECURITY_MANDATORY_LOW_RID as u32);
        assert_eq!(
            mask, SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP,
            "ReadWrite mode mask must be NO_EXECUTE_UP only per D-01; got 0x{mask:X}"
        );
    }

    #[test]
    fn compile_filesystem_policy_accepts_git_config_shape() {
        // Phase 21 motivator regression: the `claude-code` profile's `git_config`
        // group grants read access to 5 single files. Pre-phase-21 this tripped
        // 5 x WindowsUnsupportedIssueKind::SingleFileGrant. Post-phase-21 these
        // compile to 5 WindowsFilesystemRule entries, enabling the Phase 18 UAT
        // Path B + Path C to run. Mirrors crates/nono-cli/data/policy.json
        // § git_config (lines 501-512) but anchored at tempdir for test isolation.
        let dir = tempdir().expect("tempdir");
        let files = [
            dir.path().join(".gitconfig"),
            dir.path().join(".gitignore_global"),
            dir.path().join(".config_git_config"),
            dir.path().join(".config_git_ignore"),
            dir.path().join(".config_git_attributes"),
        ];
        for f in &files {
            std::fs::write(f, "x").expect("write file");
        }
        let mut caps = CapabilitySet::new();
        for f in &files {
            caps.add_fs(FsCapability::new_file(f, AccessMode::Read).expect("file cap"));
        }
        let policy = compile_filesystem_policy(&caps);
        assert_eq!(
            policy.unsupported.len(),
            0,
            "git_config-shaped CapabilitySet must not emit any unsupported entries; got: {:?}",
            policy.unsupported
        );
        assert_eq!(
            policy.rules.len(),
            5,
            "git_config-shaped CapabilitySet must emit exactly 5 rules; got {} rules: {:?}",
            policy.rules.len(),
            policy.rules
        );
        for rule in &policy.rules {
            assert!(
                rule.is_file,
                "every git_config rule must carry is_file=true"
            );
            assert_eq!(rule.access, AccessMode::Read);
        }
    }

    #[test]
    fn apply_labels_multiple_single_file_grants_all_succeed() {
        // Phase 21 end-to-end motivator regression: the full `git_config`-shaped apply
        // path, proving all 5 files are labeled Low IL with the Read-mode mask.
        let dir = tempdir().expect("tempdir");
        let files = [
            dir.path().join(".gitconfig"),
            dir.path().join(".gitignore_global"),
            dir.path().join(".config_git_config"),
            dir.path().join(".config_git_ignore"),
            dir.path().join(".config_git_attributes"),
        ];
        for f in &files {
            std::fs::write(f, "x").expect("write file");
        }
        let mut caps = CapabilitySet::new();
        for f in &files {
            caps.add_fs(FsCapability::new_file(f, AccessMode::Read).expect("file cap"));
        }
        apply(&caps).expect("Phase 21: 5 single-file grants must all succeed");
        for f in &files {
            let (rid, mask) = low_integrity_label_and_mask(f).unwrap_or_else(|| {
                panic!("file {} must be Low-IL labeled after apply()", f.display())
            });
            assert_eq!(
                rid,
                SECURITY_MANDATORY_LOW_RID as u32,
                "rid mismatch for {}",
                f.display()
            );
            assert_eq!(
                mask,
                SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP,
                "mask mismatch for {}; got 0x{mask:X}",
                f.display()
            );
        }
    }

    #[test]
    fn apply_accepts_port_level_wfp_caps() {
        // Phase 09 removed the PortConnectAllowlist / PortBindAllowlist /
        // LocalhostPortAllowlist unsupported markers from compile_network_policy().
        // apply() now returns Ok(()) for port-populated capability sets on Windows
        // because the unsupported vec stays empty and the guard at line ~50 passes.
        let mut caps = CapabilitySet::new();
        caps.add_tcp_bind_port(8080);
        caps.add_tcp_connect_port(8443);
        apply(&caps).expect("port-level WFP caps must be accepted on Windows");
    }

    #[test]
    fn apply_rejects_capability_expansion_shape() {
        let caps = CapabilitySet::new().enable_extensions();
        let err = apply(&caps).expect_err("extensions_enabled must be rejected");
        assert!(matches!(err, NonoError::UnsupportedPlatform(_)));
    }

    #[test]
    fn apply_rejects_non_default_ipc_mode() {
        let caps = CapabilitySet::new().set_ipc_mode(IpcMode::Full);
        let err = apply(&caps).expect_err("non-default IPC mode must be rejected");
        assert!(matches!(err, NonoError::UnsupportedPlatform(_)));
    }

    #[test]
    fn apply_error_message_remains_explicit_for_unsupported_subset() {
        // Phase 21: single-file grants are now supported. The original unsupported-
        // subset assertion was repointed from FsCapability::new_file to
        // set_ipc_mode(IpcMode::Full) — a still-unsupported shape that is orthogonal
        // to apply_rejects_capability_expansion_shape (which covers enable_extensions)
        // and apply_rejects_non_default_ipc_mode (which asserts only the error
        // *variant*, not the message content). This test's contribution is the
        // message-quality assertion: the error string must name the specific
        // unsupported feature, not emit a generic stub.
        let caps = CapabilitySet::new().set_ipc_mode(IpcMode::Full);
        let err = apply(&caps).expect_err("non-default IPC mode must be rejected");
        assert!(matches!(err, NonoError::UnsupportedPlatform(_)));
        let msg = err.to_string();
        // Must not be the old generic stub message
        assert!(
            !msg.contains("library-wide `Sandbox::apply()` contract remains partial"),
            "error is still the old stub: {msg}"
        );
        // Must contain a recognizable feature name — "IPC mode" per the
        // Windows apply() branch for non-default IpcMode.
        assert!(
            msg.contains("IPC mode") || msg.contains("ipc mode"),
            "expected named IPC-mode feature in error, got: {msg}"
        );
    }

    #[test]
    fn preview_runtime_status_allows_advisory_only_cwd_read_baseline() {
        let dir = tempdir().expect("tempdir");
        let caps = CapabilitySet::new()
            .allow_path(dir.path(), AccessMode::Read)
            .expect("allow path");

        let status = preview_runtime_status(&caps, dir.path(), WindowsPreviewContext::default());
        assert!(status.is_advisory_only());
    }

    #[test]
    fn preview_runtime_status_allows_blocked_network_mode() {
        let caps = CapabilitySet::new().set_network_mode(NetworkMode::Blocked);

        let status =
            preview_runtime_status(&caps, Path::new("."), WindowsPreviewContext::default());
        assert_eq!(status, PreviewRuntimeStatus::AdvisoryOnly);
    }

    #[test]
    fn compile_network_policy_allow_all_has_no_unsupported_shapes() {
        let policy = compile_network_policy(&CapabilitySet::new());
        assert_eq!(policy.mode, WindowsNetworkPolicyMode::AllowAll);
        assert!(policy.is_fully_supported());
        assert_eq!(policy.preferred_backend, WindowsNetworkBackendKind::None);
        assert_eq!(policy.active_backend, WindowsNetworkBackendKind::None);
    }

    #[test]
    fn compile_network_policy_tracks_blocked_mode() {
        let policy =
            compile_network_policy(&CapabilitySet::new().set_network_mode(NetworkMode::Blocked));
        assert_eq!(policy.mode, WindowsNetworkPolicyMode::Blocked);
        assert!(policy.is_fully_supported());
        assert_eq!(policy.preferred_backend, WindowsNetworkBackendKind::Wfp);
        assert_eq!(policy.active_backend, WindowsNetworkBackendKind::Wfp);
    }

    #[test]
    fn network_launch_support_allows_shell_hosts_for_wfp_backed_mode() {
        let policy =
            compile_network_policy(&CapabilitySet::new().set_network_mode(NetworkMode::Blocked));
        assert_eq!(
            network_launch_support(&policy, Path::new(r"C:\Windows\System32\cmd.exe")),
            WindowsNetworkLaunchSupport::Supported
        );
    }

    #[test]
    fn network_launch_support_allows_standalone_binary_for_blocked_mode() {
        let policy =
            compile_network_policy(&CapabilitySet::new().set_network_mode(NetworkMode::Blocked));
        assert_eq!(
            network_launch_support(&policy, Path::new(r"C:\tools\probe.exe")),
            WindowsNetworkLaunchSupport::Supported
        );
    }

    #[test]
    fn compile_network_policy_carries_port_filters_into_wfp_policy() {
        let mut caps = CapabilitySet::new().set_network_mode(NetworkMode::Blocked);
        caps.add_tcp_connect_port(443);
        caps.add_tcp_bind_port(8080);
        caps.add_localhost_port(3000);

        let policy = compile_network_policy(&caps);
        assert_eq!(policy.mode, WindowsNetworkPolicyMode::Blocked);
        assert!(
            policy.unsupported.is_empty(),
            "port caps should now be fully supported"
        );
        assert!(policy.is_fully_supported());
        assert_eq!(policy.tcp_connect_ports, vec![443]);
        assert_eq!(policy.tcp_bind_ports, vec![8080]);
        assert_eq!(policy.localhost_ports, vec![3000]);
        assert_eq!(policy.preferred_backend, WindowsNetworkBackendKind::Wfp);
        assert_eq!(policy.active_backend, WindowsNetworkBackendKind::Wfp);
    }

    #[test]
    fn compile_network_policy_with_connect_ports_only_is_fully_supported() {
        let mut caps = CapabilitySet::new().set_network_mode(NetworkMode::Blocked);
        caps.add_tcp_connect_port(443);
        let policy = compile_network_policy(&caps);
        assert!(policy.is_fully_supported());
        assert_eq!(policy.tcp_connect_ports, vec![443]);
        assert!(policy.tcp_bind_ports.is_empty());
        assert!(policy.localhost_ports.is_empty());
        assert!(policy.unsupported.is_empty());
    }

    #[test]
    fn compile_network_policy_with_bind_ports_only_is_fully_supported() {
        let mut caps = CapabilitySet::new().set_network_mode(NetworkMode::Blocked);
        caps.add_tcp_bind_port(8080);
        let policy = compile_network_policy(&caps);
        assert!(policy.is_fully_supported());
        assert!(policy.tcp_connect_ports.is_empty());
        assert_eq!(policy.tcp_bind_ports, vec![8080]);
        assert!(policy.localhost_ports.is_empty());
        assert!(policy.unsupported.is_empty());
    }

    #[test]
    fn compile_network_policy_with_localhost_ports_only_is_fully_supported() {
        let mut caps = CapabilitySet::new().set_network_mode(NetworkMode::Blocked);
        caps.add_localhost_port(3000);
        let policy = compile_network_policy(&caps);
        assert!(policy.is_fully_supported());
        assert!(policy.tcp_connect_ports.is_empty());
        assert!(policy.tcp_bind_ports.is_empty());
        assert_eq!(policy.localhost_ports, vec![3000]);
        assert!(policy.unsupported.is_empty());
    }

    #[test]
    fn preview_runtime_status_blocks_extra_filesystem_grants() {
        let dir = tempdir().expect("tempdir");
        let other = tempdir().expect("other tempdir");
        let caps = CapabilitySet::new()
            .allow_path(other.path(), AccessMode::Read)
            .expect("allow path");

        let status = preview_runtime_status(&caps, dir.path(), WindowsPreviewContext::default());
        assert_eq!(
            status,
            PreviewRuntimeStatus::RequiresEnforcement {
                reasons: vec!["execution directory outside supported allowlist"]
            }
        );
    }

    #[test]
    fn preview_runtime_status_allows_supported_directory_allowlist() {
        let dir = tempdir().expect("tempdir");
        let work_dir = dir.path().join("work");
        std::fs::create_dir_all(&work_dir).expect("mkdir work");
        let caps = CapabilitySet::new()
            .allow_path(dir.path(), AccessMode::ReadWrite)
            .expect("allow path");

        let status = preview_runtime_status(&caps, &work_dir, WindowsPreviewContext::default());
        assert!(status.is_advisory_only());
    }

    #[test]
    fn preview_runtime_status_allows_deny_override_when_remaining_policy_is_supported() {
        let status = preview_runtime_status(
            &CapabilitySet::new(),
            Path::new("."),
            WindowsPreviewContext {
                has_deny_override_policy: true,
            },
        );
        assert!(status.is_advisory_only());
    }

    #[test]
    fn validate_preview_entry_point_shell_fails_below_min_build() {
        let result = validate_preview_entry_point(
            WindowsPreviewEntryPoint::Shell,
            &CapabilitySet::new(),
            Path::new("."),
            WindowsPreviewContext::default(),
        );
        assert!(
            result.is_ok(),
            "shell with no enforcement-required caps should succeed on build 17763+: {:?}",
            result
        );
    }

    #[test]
    fn validate_preview_entry_point_allows_wrap_with_empty_caps() {
        validate_preview_entry_point(
            WindowsPreviewEntryPoint::Wrap,
            &CapabilitySet::new(),
            Path::new("."),
            WindowsPreviewContext::default(),
        )
        .expect("wrap with no enforcement-required caps should succeed on Windows");
    }

    #[test]
    fn classify_supervisor_support_tracks_supported_and_unsupported_features() {
        let support = classify_supervisor_support(WindowsSupervisorContext {
            rollback_snapshots: true,
            proxy_filtering: true,
            runtime_capability_expansion: true,
            runtime_trust_interception: false,
        });

        assert_eq!(
            support.supported,
            vec![WindowsSupervisorFeatureKind::RollbackSnapshots]
        );
        assert_eq!(
            support.unsupported,
            vec![
                WindowsSupervisorFeatureKind::ProxyFiltering,
                WindowsSupervisorFeatureKind::RuntimeCapabilityExpansion,
            ]
        );
        assert_eq!(
            support.requested_feature_labels(),
            vec![
                "proxy filtering",
                "rollback snapshots",
                "runtime capability elevation",
            ]
        );
    }

    #[test]
    fn compile_filesystem_policy_keeps_directory_rules() {
        let dir = tempdir().expect("tempdir");
        let caps = CapabilitySet::new()
            .allow_path(dir.path(), AccessMode::ReadWrite)
            .expect("allow path");

        let policy = compile_filesystem_policy(&caps);
        assert!(policy.is_fully_supported());
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(
            policy.rules[0].path,
            normalize_windows_path(&dir.path().canonicalize().expect("canonical"))
        );
        assert_eq!(policy.rules[0].access, AccessMode::ReadWrite);
        assert_eq!(policy.rules[0].source, CapabilitySource::User);
    }

    #[test]
    fn compile_filesystem_policy_classifies_single_file_as_rule() {
        // Phase 21: single-file grants are now enforced via per-file mandatory-label
        // ACE (see try_set_mandatory_label). Pre-phase-21 this test asserted the
        // grant was classified as SingleFileGrant *unsupported*; post-phase-21 the
        // grant MUST be classified as a WindowsFilesystemRule with is_file=true.
        let dir = tempdir().expect("tempdir");
        let file = dir.path().join("note.txt");
        std::fs::write(&file, "hello").expect("write file");
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_file(&file, AccessMode::Read).expect("file cap"));

        let policy = compile_filesystem_policy(&caps);
        assert!(
            policy.is_fully_supported(),
            "Phase 21: single-file grants are fully supported; got: {:?}",
            policy.unsupported
        );
        assert!(
            policy.unsupported.is_empty(),
            "Phase 21: no unsupported entries expected; got: {:?}",
            policy.unsupported
        );
        assert_eq!(
            policy.rules.len(),
            1,
            "single-file grant must emit one rule"
        );
        assert!(
            policy.rules[0].is_file,
            "single-file grant rule must carry is_file=true"
        );
        assert_eq!(policy.rules[0].access, AccessMode::Read);
    }

    #[test]
    fn compile_filesystem_policy_classifies_write_only_directory_as_rule() {
        // Phase 21: write-only directory grants are now enforced via directory-scope
        // mandatory-label ACE with the NO_READ_UP mask. Pre-phase-21 this test
        // asserted the grant was classified as WriteOnlyDirectoryGrant *unsupported*;
        // post-phase-21 the grant MUST be classified as a WindowsFilesystemRule with
        // is_file=false and access=Write.
        let dir = tempdir().expect("tempdir");
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_dir(dir.path(), AccessMode::Write).expect("dir cap"));

        let policy = compile_filesystem_policy(&caps);
        assert!(
            policy.is_fully_supported(),
            "Phase 21: write-only dir grants are fully supported; got: {:?}",
            policy.unsupported
        );
        assert!(
            policy.unsupported.is_empty(),
            "Phase 21: no unsupported entries expected; got: {:?}",
            policy.unsupported
        );
        assert_eq!(
            policy.rules.len(),
            1,
            "write-only dir grant must emit one rule"
        );
        assert!(
            !policy.rules[0].is_file,
            "write-only dir grant rule must carry is_file=false"
        );
        assert_eq!(policy.rules[0].access, AccessMode::Write);
    }

    #[test]
    fn normalize_windows_path_strips_verbatim_prefix() {
        assert_eq!(
            normalize_windows_path(Path::new(r"\\?\C:\Windows\System32\cmd.exe")),
            PathBuf::from(r"C:\Windows\System32\cmd.exe")
        );
    }

    #[test]
    fn normalize_windows_path_strips_unc_verbatim_prefix() {
        assert_eq!(
            normalize_windows_path(Path::new(r"\\?\UNC\server\share\dir\file.txt")),
            PathBuf::from(r"\\server\share\dir\file.txt")
        );
    }

    #[test]
    fn windows_paths_start_with_case_insensitive_matches_drive_case() {
        assert!(windows_paths_start_with_case_insensitive(
            Path::new(r"c:\Users\OMACK\Nono\workspace"),
            Path::new(r"C:\users\omack\nono")
        ));
    }

    #[test]
    fn filesystem_policy_covers_directory_path_case_insensitively() {
        let policy = WindowsFilesystemPolicy {
            rules: vec![WindowsFilesystemRule {
                path: PathBuf::from(r"C:\Users\Omack\Workspace"),
                access: AccessMode::ReadWrite,
                is_file: false,
                source: CapabilitySource::User,
            }],
            unsupported: Vec::new(),
        };

        assert!(policy.covers_path(
            Path::new(r"c:\users\OMACK\workspace\child.txt"),
            AccessMode::Read
        ));
    }

    #[test]
    fn filesystem_policy_covers_directory_path_with_verbatim_prefix_case_insensitively() {
        let policy = WindowsFilesystemPolicy {
            rules: vec![WindowsFilesystemRule {
                path: PathBuf::from(r"C:\Users\Omack\Workspace"),
                access: AccessMode::ReadWrite,
                is_file: false,
                source: CapabilitySource::User,
            }],
            unsupported: Vec::new(),
        };

        assert!(policy.covers_path(
            Path::new(r"\\?\c:\users\omack\workspace\child.txt"),
            AccessMode::Write
        ));
    }

    #[test]
    fn filesystem_policy_covers_single_file_with_verbatim_prefix() {
        let policy = WindowsFilesystemPolicy {
            rules: vec![WindowsFilesystemRule {
                path: PathBuf::from(r"C:\Users\Omack\Workspace\file.txt"),
                access: AccessMode::ReadWrite,
                is_file: true,
                source: CapabilitySource::User,
            }],
            unsupported: Vec::new(),
        };

        assert!(policy.covers_path(
            Path::new(r"\\?\c:\users\omack\workspace\file.txt"),
            AccessMode::Write
        ));
    }

    #[test]
    fn validate_launch_paths_accepts_supported_executable() {
        let dir = tempdir().expect("tempdir");
        let bin_dir = dir.path().join("bin");
        std::fs::create_dir_all(&bin_dir).expect("mkdir bin");
        let program = bin_dir.join("tool.exe");
        std::fs::write(&program, "binary").expect("write program");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_dir(dir.path(), AccessMode::ReadWrite).expect("dir cap"));
        let policy = compile_filesystem_policy(&caps);

        validate_launch_paths(&policy, &program, dir.path()).expect("launch paths should validate");
    }

    #[test]
    fn validate_launch_paths_rejects_executable_outside_policy() {
        let allowed = tempdir().expect("allowed");
        let outside = tempdir().expect("outside");
        let program = outside.path().join("tool.exe");
        std::fs::write(&program, "binary").expect("write program");

        let caps = CapabilitySet::new()
            .allow_path(allowed.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);

        let err = validate_launch_paths(&policy, &program, allowed.path())
            .expect_err("executable outside policy should fail");
        assert!(err.to_string().contains("executable path"));
    }

    #[test]
    fn validate_launch_paths_accepts_single_file_policy_shapes() {
        // Phase 21: single-file grants are now enforced via per-file mandatory-label
        // ACE (see try_set_mandatory_label). Pre-phase-21 this test asserted that
        // validate_launch_paths rejected single-file policies as unsupported;
        // post-phase-21 the policy is fully supported and the launch-path check
        // succeeds as long as the executable path is covered by the rule.
        let dir = tempdir().expect("tempdir");
        let file = dir.path().join("note.txt");
        std::fs::write(&file, "hello").expect("write file");
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_file(&file, AccessMode::Read).expect("file cap"));
        let policy = compile_filesystem_policy(&caps);

        // Single-file grant now a supported WindowsFilesystemRule; the executable
        // path (&file) is covered by the rule, so validate_launch_paths accepts.
        validate_launch_paths(&policy, &file, dir.path())
            .expect("Phase 21: single-file policy covering the executable path must be accepted");
    }

    #[test]
    fn runtime_state_dir_prefers_writable_current_dir_inside_policy() {
        let dir = tempdir().expect("tempdir");
        let work_dir = dir.path().join("work");
        std::fs::create_dir_all(&work_dir).expect("mkdir work");
        let caps = CapabilitySet::new()
            .allow_path(dir.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let expected =
            normalize_windows_path(&work_dir.canonicalize().expect("canonical work dir"));

        assert_eq!(runtime_state_dir(&policy, &work_dir), Some(expected));
    }

    #[test]
    fn runtime_state_dir_returns_none_for_file_only_policy() {
        let dir = tempdir().expect("tempdir");
        let file = dir.path().join("note.txt");
        std::fs::write(&file, "hello").expect("write file");
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_file(&file, AccessMode::Read).expect("file cap"));
        let policy = compile_filesystem_policy(&caps);

        assert_eq!(runtime_state_dir(&policy, dir.path()), None);
    }

    #[test]
    fn preview_runtime_status_allows_advisory_only_for_single_file_policy() {
        // Phase 21: single-file grants are now enforced via per-file mandatory-label
        // ACE at launch time. Pre-phase-21 this test asserted that preview status
        // reported RequiresEnforcement because single-file grants were classified
        // as unsupported. Post-phase-21 a pure single-file policy has no
        // unsupported entries and no user-intent directory rules, so no reasons
        // are collected and the status is AdvisoryOnly (the label application
        // itself happens during Sandbox::apply and is transparent to the preview).
        let dir = tempdir().expect("tempdir");
        let file = dir.path().join("note.txt");
        std::fs::write(&file, "hello").expect("write file");
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_file(&file, AccessMode::Read).expect("file cap"));

        let status = preview_runtime_status(
            &caps,
            Path::new(r"C:\outside-workdir"),
            WindowsPreviewContext::default(),
        );
        assert!(
            matches!(status, PreviewRuntimeStatus::AdvisoryOnly),
            "Phase 21: single-file policy must be advisory-only; got: {status:?}"
        );
    }

    #[test]
    fn preview_runtime_status_allows_advisory_only_for_write_only_directory() {
        // Phase 21: write-only directory grants are now enforced via directory-scope
        // mandatory-label ACE with NO_READ_UP mask. Pre-phase-21 this test asserted
        // RequiresEnforcement because write-only directory grants were unsupported.
        // Post-phase-21 the grant compiles to a WindowsFilesystemRule and — as long
        // as the execution directory is covered by the rule — no enforcement
        // reasons are collected (parity with read-write directory grants).
        let dir = tempdir().expect("tempdir");
        let work_dir = dir.path().join("work");
        std::fs::create_dir_all(&work_dir).expect("mkdir work");
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_dir(dir.path(), AccessMode::Write).expect("dir cap"));

        let status = preview_runtime_status(&caps, &work_dir, WindowsPreviewContext::default());
        assert!(
            matches!(status, PreviewRuntimeStatus::AdvisoryOnly),
            "Phase 21: write-only directory policy covering execution dir must be advisory-only; got: {status:?}"
        );
    }

    #[test]
    fn low_integrity_compatible_dir_matches_localappdata_temp_low() {
        let Some(local) = std::env::var_os("LOCALAPPDATA") else {
            return;
        };
        let candidate = PathBuf::from(local)
            .join("Temp")
            .join("Low")
            .join("nono-test");
        assert!(is_low_integrity_compatible_dir(&candidate));
    }

    #[test]
    fn low_integrity_compatible_dir_matches_locallow() {
        let Some(local) = std::env::var_os("LOCALAPPDATA") else {
            return;
        };
        let Some(appdata_root) = PathBuf::from(local).parent().map(Path::to_path_buf) else {
            return;
        };
        let candidate = appdata_root.join("LocalLow").join("nono-test");
        assert!(is_low_integrity_compatible_dir(&candidate));
    }

    #[test]
    fn low_integrity_compatible_dir_rejects_normal_tempdir() {
        let dir = tempdir().expect("tempdir");
        assert!(!is_low_integrity_compatible_dir(dir.path()));
    }

    #[test]
    fn low_integrity_compatible_dir_matches_dynamically_labeled_directory() {
        let dir = tempdir().expect("tempdir");
        let labeled = dir.path().join("labeled-low");
        std::fs::create_dir_all(&labeled).expect("mkdir");
        if !try_set_low_integrity_label(&labeled) {
            return;
        }

        assert!(is_low_integrity_compatible_dir(&labeled));
    }

    #[test]
    fn validate_command_args_accepts_absolute_path_inside_policy() {
        let dir = tempdir().expect("tempdir");
        let file = dir.path().join("inside.txt");
        std::fs::write(&file, "hello").expect("write file");
        let caps = CapabilitySet::new()
            .allow_path(dir.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![file.to_string_lossy().into_owned()];

        validate_command_args(&policy, Path::new("more.com"), &args, dir.path())
            .expect("path inside policy should validate");
    }

    #[test]
    fn validate_command_args_rejects_absolute_path_outside_policy() {
        let allowed = tempdir().expect("allowed");
        let outside = tempdir().expect("outside");
        let file = outside.path().join("outside.txt");
        std::fs::write(&file, "hello").expect("write file");
        let caps = CapabilitySet::new()
            .allow_path(allowed.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![file.to_string_lossy().into_owned()];

        let err = validate_command_args(&policy, Path::new("more.com"), &args, allowed.path())
            .expect_err("path outside policy should fail validation");
        assert!(err.to_string().contains("absolute path argument"));
    }

    #[test]
    fn validate_command_args_accepts_relative_cmd_type_path_inside_policy() {
        let dir = tempdir().expect("tempdir");
        let workspace = dir.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        let file = workspace.join("inside.txt");
        std::fs::write(&file, "hello").expect("write file");
        let caps = CapabilitySet::new()
            .allow_path(dir.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![
            "/c".to_string(),
            "type".to_string(),
            "inside.txt".to_string(),
        ];

        validate_command_args(&policy, Path::new("cmd.exe"), &args, &workspace)
            .expect("relative type path inside policy should validate");
    }

    #[test]
    fn validate_command_args_rejects_relative_cmd_type_path_outside_policy() {
        let allowed = tempdir().expect("allowed");
        let workspace = allowed.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        let outside = tempdir().expect("outside");
        let file = outside.path().join("outside.txt");
        std::fs::write(&file, "hello").expect("write file");
        let caps = CapabilitySet::new()
            .allow_path(allowed.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![
            "/c".to_string(),
            "type".to_string(),
            file.to_string_lossy().into_owned(),
        ];

        let err = validate_command_args(&policy, Path::new("cmd.exe"), &args, &workspace)
            .expect_err("relative/absolute type path outside policy should fail validation");
        assert!(
            err.to_string().contains("absolute path argument")
                || err.to_string().contains("file argument")
        );
    }

    #[test]
    fn validate_command_args_rejects_relative_parent_escape_outside_policy() {
        let dir = tempdir().expect("tempdir");
        let allowed = dir.path().join("allowed");
        let workspace = allowed.join("workspace");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        std::fs::create_dir_all(&outside).expect("mkdir outside");
        let outside_file = outside.join("outside.txt");
        std::fs::write(&outside_file, "hello").expect("write file");

        let caps = CapabilitySet::new()
            .allow_path(&allowed, AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![
            "/c".to_string(),
            "type".to_string(),
            r"..\..\outside\outside.txt".to_string(),
        ];

        let err = validate_command_args(&policy, Path::new("cmd.exe"), &args, &workspace)
            .expect_err("parent-dir escape should fail validation");
        assert!(err.to_string().contains("file argument"));
    }

    #[test]
    fn validate_command_args_rejects_symlink_escape_inside_policy() {
        let dir = tempdir().expect("tempdir");
        let allowed = dir.path().join("allowed");
        let workspace = allowed.join("workspace");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        std::fs::create_dir_all(&outside).expect("mkdir outside");
        let outside_file = outside.join("secret.txt");
        std::fs::write(&outside_file, "secret").expect("write outside file");
        let link = workspace.join("inside-link.txt");
        if !try_create_symlink_file(&link, &outside_file) {
            return;
        }

        let caps = CapabilitySet::new()
            .allow_path(&allowed, AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![link.to_string_lossy().into_owned()];

        let err = validate_command_args(&policy, Path::new("more.com"), &args, &workspace)
            .expect_err("symlink escape should fail validation");
        assert!(err.to_string().contains("absolute path argument"));
    }

    #[test]
    fn validate_command_args_rejects_junction_escape_inside_policy() {
        let dir = tempdir().expect("tempdir");
        let allowed = dir.path().join("allowed");
        let workspace = allowed.join("workspace");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        std::fs::create_dir_all(&outside).expect("mkdir outside");
        let outside_file = outside.join("secret.txt");
        std::fs::write(&outside_file, "secret").expect("write outside file");
        let junction = workspace.join("outside-link");
        if !try_create_junction(&junction, &outside) {
            return;
        }

        let caps = CapabilitySet::new()
            .allow_path(&allowed, AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![
            "/c".to_string(),
            "type".to_string(),
            r"outside-link\secret.txt".to_string(),
        ];

        let err = validate_command_args(&policy, Path::new("cmd.exe"), &args, &workspace)
            .expect_err("junction escape should fail validation");
        assert!(err.to_string().contains("file argument"));
    }

    #[test]
    fn validate_command_args_accepts_relative_cmd_copy_paths_inside_policy() {
        let dir = tempdir().expect("tempdir");
        let workspace = dir.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        let source = workspace.join("source.txt");
        std::fs::write(&source, "hello").expect("write file");
        let caps = CapabilitySet::new()
            .allow_path(dir.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![
            "/c".to_string(),
            "copy".to_string(),
            "source.txt".to_string(),
            "dest.txt".to_string(),
        ];

        validate_command_args(&policy, Path::new("cmd.exe"), &args, &workspace)
            .expect("relative copy paths inside policy should validate");
    }

    #[test]
    fn validate_command_args_rejects_cmd_copy_destination_outside_policy() {
        let allowed = tempdir().expect("allowed");
        let workspace = allowed.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        let source = workspace.join("source.txt");
        std::fs::write(&source, "hello").expect("write file");
        let outside = tempdir().expect("outside");
        let dest = outside.path().join("dest.txt");
        let caps = CapabilitySet::new()
            .allow_path(allowed.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![
            "/c".to_string(),
            "copy".to_string(),
            "source.txt".to_string(),
            dest.to_string_lossy().into_owned(),
        ];

        let err = validate_command_args(&policy, Path::new("cmd.exe"), &args, &workspace)
            .expect_err("copy destination outside policy should fail validation");
        assert!(
            err.to_string().contains("absolute path argument")
                || err.to_string().contains("destination path argument")
        );
    }

    #[test]
    fn validate_command_args_accepts_powershell_get_content_inside_policy() {
        let dir = tempdir().expect("tempdir");
        let workspace = dir.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        let file = workspace.join("inside.txt");
        std::fs::write(&file, "hello").expect("write file");
        let caps = CapabilitySet::new()
            .allow_path(dir.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec!["-Command".to_string(), "Get-Content inside.txt".to_string()];

        validate_command_args(&policy, Path::new("powershell.exe"), &args, &workspace)
            .expect("PowerShell Get-Content inside policy should validate");
    }

    #[test]
    fn validate_command_args_rejects_powershell_copy_destination_outside_policy() {
        let allowed = tempdir().expect("allowed");
        let workspace = allowed.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        let source = workspace.join("source.txt");
        std::fs::write(&source, "hello").expect("write file");
        let outside = tempdir().expect("outside");
        let dest = outside.path().join("dest.txt");
        let caps = CapabilitySet::new()
            .allow_path(allowed.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![
            "-Command".to_string(),
            format!(
                "Copy-Item source.txt -Destination '{}'",
                dest.to_string_lossy()
            ),
        ];

        let err = validate_command_args(&policy, Path::new("powershell.exe"), &args, &workspace)
            .expect_err("PowerShell copy destination outside policy should fail");
        assert!(
            err.to_string().contains("absolute path argument")
                || err.to_string().contains("PowerShell destination path")
        );
    }

    #[test]
    fn validate_command_args_accepts_xcopy_inside_policy() {
        let dir = tempdir().expect("tempdir");
        let workspace = dir.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        let source = workspace.join("source.txt");
        std::fs::write(&source, "hello").expect("write file");
        let caps = CapabilitySet::new()
            .allow_path(dir.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec!["source.txt".to_string(), "dest.txt".to_string()];

        validate_command_args(&policy, Path::new("xcopy.exe"), &args, &workspace)
            .expect("xcopy inside policy should validate");
    }

    #[test]
    fn validate_command_args_rejects_robocopy_destination_outside_policy() {
        let allowed = tempdir().expect("allowed");
        let workspace = allowed.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        let source = workspace.join("source");
        std::fs::create_dir_all(&source).expect("mkdir source");
        let outside = tempdir().expect("outside");
        let dest = outside.path().join("dest");
        let caps = CapabilitySet::new()
            .allow_path(allowed.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![
            source.to_string_lossy().into_owned(),
            dest.to_string_lossy().into_owned(),
        ];

        let err = validate_command_args(&policy, Path::new("robocopy.exe"), &args, &workspace)
            .expect_err("robocopy destination outside policy should fail");
        assert!(
            err.to_string().contains("absolute path argument")
                || err.to_string().contains("robocopy destination path")
        );
    }

    #[test]
    fn validate_command_args_accepts_cscript_paths_inside_policy() {
        let dir = tempdir().expect("tempdir");
        let workspace = dir.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        let script = workspace.join("copy.vbs");
        std::fs::write(&script, "WScript.Echo \"ok\"").expect("write script");
        let source = workspace.join("source.txt");
        std::fs::write(&source, "hello").expect("write source");
        let caps = CapabilitySet::new()
            .allow_path(dir.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![
            "//NoLogo".to_string(),
            "copy.vbs".to_string(),
            "source.txt".to_string(),
            "dest.txt".to_string(),
        ];

        validate_command_args(&policy, Path::new("cscript.exe"), &args, &workspace)
            .expect("cscript paths inside policy should validate");
    }

    #[test]
    fn validate_command_args_rejects_cscript_destination_outside_policy() {
        let allowed = tempdir().expect("allowed");
        let workspace = allowed.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        let script = workspace.join("copy.vbs");
        std::fs::write(&script, "WScript.Echo \"ok\"").expect("write script");
        let source = workspace.join("source.txt");
        std::fs::write(&source, "hello").expect("write source");
        let outside = tempdir().expect("outside");
        let dest = outside.path().join("dest.txt");
        let caps = CapabilitySet::new()
            .allow_path(allowed.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![
            "//NoLogo".to_string(),
            "copy.vbs".to_string(),
            "source.txt".to_string(),
            dest.to_string_lossy().into_owned(),
        ];

        let err = validate_command_args(&policy, Path::new("cscript.exe"), &args, &workspace)
            .expect_err("cscript destination outside policy should fail");
        assert!(
            err.to_string().contains("absolute path argument")
                || err
                    .to_string()
                    .contains("Windows Script Host path argument")
        );
    }

    #[test]
    fn validate_command_args_accepts_findstr_inside_policy() {
        let dir = tempdir().expect("tempdir");
        let workspace = dir.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        let file = workspace.join("inside.txt");
        std::fs::write(&file, "needle").expect("write file");
        let caps = CapabilitySet::new()
            .allow_path(dir.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![
            "/c:needle".to_string(),
            "needle".to_string(),
            "inside.txt".to_string(),
        ];

        validate_command_args(&policy, Path::new("findstr.exe"), &args, &workspace)
            .expect("findstr file inside policy should validate");
    }

    #[test]
    fn validate_command_args_rejects_fc_file_outside_policy() {
        let allowed = tempdir().expect("allowed");
        let workspace = allowed.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        let file = workspace.join("inside.txt");
        std::fs::write(&file, "same").expect("write file");
        let outside = tempdir().expect("outside");
        let outside_file = outside.path().join("outside.txt");
        std::fs::write(&outside_file, "same").expect("write outside file");
        let caps = CapabilitySet::new()
            .allow_path(allowed.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![
            "inside.txt".to_string(),
            outside_file.to_string_lossy().into_owned(),
        ];

        let err = validate_command_args(&policy, Path::new("fc.exe"), &args, &workspace)
            .expect_err("fc path outside policy should fail");
        assert!(
            err.to_string().contains("absolute path argument")
                || err.to_string().contains("fc file argument")
        );
    }

    #[test]
    fn validate_command_args_accepts_find_inside_policy() {
        let dir = tempdir().expect("tempdir");
        let workspace = dir.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        let file = workspace.join("inside.txt");
        std::fs::write(&file, "needle").expect("write file");
        let caps = CapabilitySet::new()
            .allow_path(dir.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![
            "/n".to_string(),
            "needle".to_string(),
            "inside.txt".to_string(),
        ];

        validate_command_args(&policy, Path::new("find.exe"), &args, &workspace)
            .expect("find file inside policy should validate");
    }

    #[test]
    fn validate_command_args_rejects_comp_file_outside_policy() {
        let allowed = tempdir().expect("allowed");
        let workspace = allowed.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        let file = workspace.join("inside.txt");
        std::fs::write(&file, "same").expect("write file");
        let outside = tempdir().expect("outside");
        let outside_file = outside.path().join("outside.txt");
        std::fs::write(&outside_file, "same").expect("write outside file");
        let caps = CapabilitySet::new()
            .allow_path(allowed.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![
            "inside.txt".to_string(),
            outside_file.to_string_lossy().into_owned(),
        ];

        let err = validate_command_args(&policy, Path::new("comp.exe"), &args, &workspace)
            .expect_err("comp path outside policy should fail");
        assert!(
            err.to_string().contains("absolute path argument")
                || err.to_string().contains("comp file argument")
        );
    }

    #[test]
    fn path_is_owned_by_current_user_returns_true_for_tempfile() {
        // Files we create in a tempdir are owned by the current user.
        let dir = tempdir().expect("tempdir");
        let file = dir.path().join("mine.txt");
        std::fs::write(&file, "x").expect("write file");

        let owned = path_is_owned_by_current_user(&file)
            .expect("owner read must succeed for a user-created tempfile");
        assert!(
            owned,
            "a file just created by the current user must be reported as owned"
        );
    }

    #[test]
    fn path_is_owned_by_current_user_returns_false_for_system_windows_dir() {
        // C:\Windows is owned by TrustedInstaller (or the system) on a clean
        // install and is NEVER owned by an unprivileged interactive user.
        // This test is the whole reason path_is_owned_by_current_user exists:
        // the label guard must skip labeling system paths to avoid
        // ERROR_ACCESS_DENIED from SetNamedSecurityInfoW.
        let system_root = std::env::var_os("SystemRoot")
            .unwrap_or_else(|| std::ffi::OsString::from(r"C:\Windows"));
        let system_root = PathBuf::from(system_root);
        // Only assert the shape; if a developer is somehow running tests as
        // the TrustedInstaller principal the assertion would flip — but in
        // that environment the label guard wouldn't need to skip anyway, so
        // the test would still reflect reality.
        let is_current = path_is_owned_by_current_user(&system_root)
            .expect("owner read must succeed for C:\\Windows (readable by everyone)");
        assert!(
            !is_current,
            "an unprivileged user must not be reported as the owner of {}",
            system_root.display()
        );
    }

    /// 260522-v14 positive case: a directory created by the current user
    /// under `%TEMP%` (which inherits the user-profile tree's explicit
    /// `<user>: FullControl` ACE — that ACE includes WRITE_OWNER /
    /// 0x00080000) must report WRITE_OWNER present. This is the "happy
    /// path" the POC docs steer Windows pilot users toward.
    #[test]
    fn path_has_write_owner_returns_true_for_userprofile_tempdir() {
        let dir = tempdir().expect("tempdir");
        let has_write_owner = path_has_write_owner(dir.path())
            .expect("DACL read + effective-rights query must succeed for a user-created tempdir");
        assert!(
            has_write_owner,
            "tempdir under %TEMP% must report WRITE_OWNER present for the current user (got false for {})",
            dir.path().display()
        );
    }

    /// 260522-v14 negative case: synthesize the `C:\poc\temp` failure mode
    /// in a sandboxed location — create a tempdir, then programmatically
    /// replace its DACL with one that grants the **current user's explicit
    /// SID** `Modify` only (mask `0x1301BF`, missing the `WRITE_OWNER`
    /// bit). Assert that `try_set_mandatory_label` bails out at the new
    /// pre-flight check with the WRITE_OWNER directive hint, BEFORE
    /// attempting `SetNamedSecurityInfoW(LABEL_SECURITY_INFORMATION)`.
    ///
    /// **Why explicit user SID (not `BUILTIN\Administrators` + AU):**
    /// `GetEffectiveRightsFromAclW` walks the trustee's group memberships
    /// from the **full** token (not the UAC-filtered token). If the test
    /// runner is a local admin (typical Windows dev environment), a DACL
    /// granting `BUILTIN\Administrators: FullControl` would return WRITE_
    /// OWNER as present for the user trustee — false positive that lets
    /// the pre-flight pass while the actual label-apply fails under the
    /// filtered token. Using the explicit current-user SID and Modify-only
    /// rights bypasses this group-membership false positive entirely.
    ///
    /// **Cleanup:** `0x1301BF` includes `DELETE` (0x00010000), so tempfile's
    /// Drop can still remove the dir. To allow Drop's recursive cleanup
    /// past the protected DACL we restore inheritance + Authenticated
    /// Users FullControl at end-of-test (best effort).
    ///
    /// The synthesized-DACL approach is preferred over a drive-root
    /// reproduction because it does NOT depend on the test runner's
    /// drive-root permissions or default `C:\` ACL state — it builds the
    /// failure shape from scratch inside a tempdir the test owns.
    #[test]
    fn try_set_mandatory_label_surfaces_directive_when_write_owner_missing() {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
        use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
        use windows_sys::Win32::Security::{
            GetSecurityDescriptorDacl, GetTokenInformation, TokenUser, PSID,
            PROTECTED_DACL_SECURITY_INFORMATION, TOKEN_USER,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        let dir = tempdir().expect("tempdir");
        let path = dir.path().to_path_buf();

        // 1. Resolve the current user SID, then format it as an SDDL-style
        //    string ("S-1-5-21-...") so we can embed it as the ACE trustee.
        let mut token: HANDLE = std::ptr::null_mut();
        let ok = unsafe {
            // SAFETY: GetCurrentProcess() returns a pseudo-handle; `&mut token`
            // is a valid out-pointer.
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
        };
        assert_ne!(ok, 0, "test setup: OpenProcessToken must succeed");

        let mut required: u32 = 0;
        let _ = unsafe {
            // SAFETY: documented null+0 size-probe pattern.
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut required)
        };
        assert!(required > 0, "test setup: TokenUser size probe failed");
        let mut buffer: Vec<u8> = vec![0u8; required as usize];
        let ok = unsafe {
            // SAFETY: `buffer` sized per probe; `&mut required` is a valid out-pointer.
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        };
        assert_ne!(ok, 0, "test setup: GetTokenInformation(TokenUser) must succeed");
        let token_user = unsafe {
            // SAFETY: GetTokenInformation populated `buffer` with TOKEN_USER.
            &*(buffer.as_ptr() as *const TOKEN_USER)
        };
        let user_sid: PSID = token_user.User.Sid;
        assert!(!user_sid.is_null(), "test setup: TokenUser.Sid must not be null");

        let mut sid_string_ptr: *mut u16 = std::ptr::null_mut();
        let ok = unsafe {
            // SAFETY: `user_sid` is a valid SID; out-pointer is valid local storage.
            // Returned PWSTR must be freed with LocalFree.
            ConvertSidToStringSidW(user_sid, &mut sid_string_ptr)
        };
        assert_ne!(ok, 0, "test setup: ConvertSidToStringSidW must succeed");
        assert!(!sid_string_ptr.is_null());
        let user_sid_string: String = unsafe {
            // SAFETY: `sid_string_ptr` was just populated by Convert...W with a
            // nul-terminated UTF-16 string.
            let mut len = 0usize;
            while *sid_string_ptr.add(len) != 0 {
                len += 1;
            }
            let slice = std::slice::from_raw_parts(sid_string_ptr, len);
            String::from_utf16(slice).expect("valid UTF-16 SID string")
        };
        unsafe {
            // SAFETY: `sid_string_ptr` was allocated by ConvertSidToStringSidW.
            let _ = LocalFree(sid_string_ptr as _);
        }
        unsafe {
            // SAFETY: `token` was opened above; closing exactly once.
            let _ = CloseHandle(token);
        }

        // 2. Build SDDL granting the explicit current-user SID Modify only
        //    (mask 0x1301BF). Mask bits enumerated:
        //      0x00000001 FILE_READ_DATA
        //      0x00000002 FILE_WRITE_DATA
        //      0x00000004 FILE_APPEND_DATA
        //      0x00000008 FILE_READ_EA
        //      0x00000010 FILE_WRITE_EA
        //      0x00000020 FILE_EXECUTE
        //      0x00000080 FILE_READ_ATTRIBUTES
        //      0x00000100 FILE_WRITE_ATTRIBUTES
        //      0x00010000 DELETE
        //      0x00020000 READ_CONTROL
        //      0x00100000 SYNCHRONIZE
        //    Total: 0x001301BF (NO WRITE_OWNER, NO WRITE_DAC).
        let sddl = format!(
            "D:PAI(A;OICI;0x1301BF;;;{user_sid_string})"
        );
        let wide_sddl: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();

        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let ok = unsafe {
            // SAFETY: `wide_sddl` is nul-terminated; `&mut sd` is a valid out-pointer.
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide_sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(ok, 0, "test setup: SDDL parse must succeed for {sddl}");
        let _sd_guard = OwnedSecurityDescriptor(sd);

        // Extract the DACL from the synthetic SD.
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut dacl_present: i32 = 0;
        let mut dacl_defaulted: i32 = 0;
        let ok = unsafe {
            // SAFETY: `sd` is valid; out-pointers are valid local storage.
            GetSecurityDescriptorDacl(sd, &mut dacl_present, &mut dacl, &mut dacl_defaulted)
        };
        assert_ne!(ok, 0, "test setup: DACL extract must succeed");
        assert_ne!(
            dacl_present, 0,
            "test setup: DACL must be present in synthetic SD"
        );

        // Apply the restricted DACL with PROTECTED_DACL_SECURITY_INFORMATION so
        // inheritance from the parent tempdir does not restore WRITE_OWNER.
        let wide_path: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let status = unsafe {
            // SAFETY: `wide_path` nul-terminated; `dacl` lives in `sd`.
            SetNamedSecurityInfoW(
                wide_path.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null(),
            )
        };
        assert_eq!(
            status, 0,
            "test setup: SetNamedSecurityInfoW(DACL) must succeed (status=0x{status:08X})"
        );

        // 3. The actual assertion: try_set_mandatory_label must return the new
        //    directive error WITHOUT reaching SetNamedSecurityInfoW(LABEL_).
        let result = try_set_mandatory_label(&path, 0x4);

        // 4. Best-effort cleanup BEFORE re-asserting: restore inheritance so
        //    tempfile::tempdir() Drop can remove the dir. We do this here
        //    (before the asserts) so a failed assertion still leaves the
        //    dir in a deletable state.
        let restore_sddl = "D:AI";
        let wide_restore_sddl: Vec<u16> =
            restore_sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut restore_sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let restore_parse = unsafe {
            // SAFETY: nul-terminated UTF-16 buffer; valid out-pointer.
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide_restore_sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut restore_sd,
                std::ptr::null_mut(),
            )
        };
        if restore_parse != 0 {
            let _restore_guard = OwnedSecurityDescriptor(restore_sd);
            let mut restore_dacl: *mut ACL = std::ptr::null_mut();
            let mut rp: i32 = 0;
            let mut rd: i32 = 0;
            let extract = unsafe {
                // SAFETY: `restore_sd` valid; out-pointers valid.
                GetSecurityDescriptorDacl(restore_sd, &mut rp, &mut restore_dacl, &mut rd)
            };
            if extract != 0 {
                let _ = unsafe {
                    // SAFETY: wide_path nul-terminated; restore_dacl lives in restore_sd.
                    // UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000 — drops the
                    // Protected flag so inheritance resumes.
                    SetNamedSecurityInfoW(
                        wide_path.as_ptr(),
                        SE_FILE_OBJECT,
                        DACL_SECURITY_INFORMATION | 0x2000_0000,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        restore_dacl,
                        std::ptr::null(),
                    )
                };
            }
        }

        // 5. Asserts (after cleanup, so a failure still allows tempdir drop).
        let err = result
            .expect_err("try_set_mandatory_label must fail on a WRITE_OWNER-stripped path");
        let msg = err.to_string();
        assert!(
            matches!(err, NonoError::LabelApplyFailed { .. }),
            "must be LabelApplyFailed variant; got {err:?}"
        );
        assert!(
            msg.contains("WRITE_OWNER"),
            "directive hint must name WRITE_OWNER literally; got: {msg}"
        );
        assert!(
            msg.contains("%USERPROFILE%") || msg.contains("%TEMP%"),
            "directive hint must point user to a profile-tree working dir; got: {msg}"
        );
    }
}

// Phase 31 D-06: library-side guarantor that the lifted function still produces
// a token at Low IL (RID 0x1000). Mirrors the pre-lift assertion that lived in
// nono-cli's `low_integrity_primary_token_sets_low_il`; this version proves the
// new home crate works without going through `nono-cli`.
#[cfg(all(test, target_os = "windows"))]
mod create_low_integrity_primary_token_tests {
    use super::{create_low_integrity_primary_token, OwnedHandle};
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Security::{
        GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TokenIntegrityLevel,
        TOKEN_MANDATORY_LABEL,
    };
    use windows_sys::Win32::System::SystemServices::SECURITY_MANDATORY_LOW_RID;

    /// Phase 31 D-06: library-side guarantor that the lifted function still
    /// produces a token at Low IL (RID 0x1000). Acceptance #3 (write-deny)
    /// depends on this — RESEARCH Assumption A2.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn create_low_integrity_primary_token_returns_low_il_token() {
        let token = create_low_integrity_primary_token().expect(
            "create_low_integrity_primary_token must succeed in a normal user-logon test process",
        );
        assert!(
            !token.0.is_null(),
            "low-integrity primary token handle is non-null"
        );

        // Two-call GetTokenInformation pattern: probe size, then fetch.
        let mut needed: u32 = 0;
        unsafe {
            // SAFETY: Probe call with a null buffer is the documented
            // size-discovery pattern. ERROR_INSUFFICIENT_BUFFER is expected.
            GetTokenInformation(
                token.0,
                TokenIntegrityLevel,
                std::ptr::null_mut(),
                0,
                &mut needed,
            );
        }
        assert!(
            needed >= std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32,
            "TokenIntegrityLevel buffer size should be at least \
             size_of::<TOKEN_MANDATORY_LABEL>(); got {needed}"
        );

        let mut buf = vec![0u8; needed as usize];
        let ok = unsafe {
            // SAFETY: `buf` is sized by the probe call above; `token.0` is a
            // valid HANDLE owned by `token`.
            GetTokenInformation(
                token.0,
                TokenIntegrityLevel,
                buf.as_mut_ptr() as *mut _,
                needed,
                &mut needed,
            )
        };
        assert!(
            ok != 0,
            "GetTokenInformation(TokenIntegrityLevel) must succeed on a duplicated token"
        );

        // SAFETY: GetTokenInformation populated `buf` with a
        // TOKEN_MANDATORY_LABEL prefix; layout is documented in the Win32 SDK.
        let label = unsafe { &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL) };
        // SAFETY: `label.Label.Sid` is a valid SID pointer for the duration of
        // `buf`'s lifetime; `GetSidSubAuthorityCount` returns a valid pointer.
        let count = unsafe { *GetSidSubAuthorityCount(label.Label.Sid) };
        assert!(
            count > 0,
            "integrity-label SID must have at least one sub-authority; got {count}"
        );
        // SAFETY: same SID pointer is still valid; `(count - 1)` is in-range.
        let last = unsafe { *GetSidSubAuthority(label.Label.Sid, (count - 1) as u32) };
        assert_eq!(
            last, SECURITY_MANDATORY_LOW_RID as u32,
            "duplicated token must be at Low integrity (RID 0x1000); got 0x{last:x}"
        );
    }

    /// Phase 31 D-06: validate `OwnedHandle::Drop` does not panic / double-close.
    /// Exercises the lifted RAII wrapper directly.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn owned_handle_drop_is_safe_for_low_il_token() {
        let token = create_low_integrity_primary_token()
            .expect("create_low_integrity_primary_token must succeed");
        assert!(!token.0.is_null());
        // Explicit drop closes the handle exactly once. If `OwnedHandle::Drop`
        // were ill-formed, this would panic, abort, or surface as
        // ERROR_INVALID_HANDLE on a recycled handle value in a later test.
        drop(token);
    }

    /// Phase 31 D-06: confirm `OwnedHandle` Drop is a no-op when the inner
    /// HANDLE is null. This guards Pitfall 5 (double-close) at the
    /// boundary where a null sentinel can flow through.
    #[test]
    fn owned_handle_drop_on_null_is_noop() {
        let null_handle: HANDLE = std::ptr::null_mut();
        let owned = OwnedHandle(null_handle);
        // Must not panic, abort, or call CloseHandle(null).
        drop(owned);
    }
}
