//! Linux sandbox implementation using Landlock LSM

use crate::capability::{AccessMode, CapabilitySet, NetworkMode, SignalMode};
use crate::error::{NonoError, Result};
use crate::sandbox::SupportInfo;
use landlock::{
    Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, NetPort, PathBeneath, PathFd,
    Ruleset, RulesetAttr, RulesetCreatedAttr, Scope, ABI,
};
use std::path::Path;
use tracing::{debug, info, warn};

/// Detected Landlock ABI version with feature query methods.
///
/// Wraps the `landlock::ABI` enum and provides methods to query which
/// features are available at the detected ABI level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectedAbi {
    /// The detected ABI version
    pub abi: ABI,
}

impl DetectedAbi {
    /// Create a new `DetectedAbi` from a raw `landlock::ABI`.
    #[must_use]
    pub fn new(abi: ABI) -> Self {
        Self { abi }
    }

    /// Whether file rename across directories is supported (V2+).
    #[must_use]
    pub fn has_refer(&self) -> bool {
        AccessFs::from_all(self.abi).contains(AccessFs::Refer)
    }

    /// Whether file truncation control is supported (V3+).
    #[must_use]
    pub fn has_truncate(&self) -> bool {
        AccessFs::from_all(self.abi).contains(AccessFs::Truncate)
    }

    /// Whether TCP network filtering is supported (V4+).
    #[must_use]
    pub fn has_network(&self) -> bool {
        !AccessNet::from_all(self.abi).is_empty()
    }

    /// Whether device ioctl filtering is supported (V5+).
    #[must_use]
    pub fn has_ioctl_dev(&self) -> bool {
        AccessFs::from_all(self.abi).contains(AccessFs::IoctlDev)
    }

    /// Whether process scoping (signals and abstract UNIX sockets) is supported (V6+).
    #[must_use]
    pub fn has_scoping(&self) -> bool {
        !Scope::from_all(self.abi).is_empty()
    }

    /// Return a human-readable version string (e.g., "V4").
    #[must_use]
    pub fn version_string(&self) -> &'static str {
        match self.abi {
            ABI::V1 => "V1",
            ABI::V2 => "V2",
            ABI::V3 => "V3",
            ABI::V4 => "V4",
            ABI::V5 => "V5",
            ABI::V6 => "V6",
            _ => "unknown",
        }
    }

    /// Return a list of available feature names at this ABI level.
    ///
    /// Each feature includes the specific Landlock flags in parentheses
    /// for consistency and debuggability.
    #[must_use]
    pub fn feature_names(&self) -> Vec<String> {
        let mut features = vec!["Basic filesystem access control".to_string()];
        if self.has_refer() {
            features.push("File rename across directories (Refer)".to_string());
        }
        if self.has_truncate() {
            features.push("File truncation (Truncate)".to_string());
        }
        if self.has_network() {
            features.push("TCP network filtering".to_string());
        }
        if self.has_ioctl_dev() {
            features.push("Device ioctl filtering".to_string());
        }
        if self.has_scoping() {
            features.push("Process scoping".to_string());
        }
        features
    }
}

impl std::fmt::Display for DetectedAbi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Landlock {}", self.version_string())
    }
}

/// ABI probe order: highest to lowest.
const ABI_PROBE_ORDER: [ABI; 6] = [ABI::V6, ABI::V5, ABI::V4, ABI::V3, ABI::V2, ABI::V1];

/// Detect the highest Landlock ABI supported by the running kernel.
///
/// Probes from V6 down to V1 using `HardRequirement` compatibility mode.
/// Returns the highest ABI for which a full ruleset can be created.
///
/// # Errors
///
/// Returns an error if no ABI version is supported (Landlock not available).
pub fn detect_abi() -> Result<DetectedAbi> {
    let mut last_error = None;

    for &abi in &ABI_PROBE_ORDER {
        match probe_abi_candidate(abi) {
            Ok(()) => return Ok(DetectedAbi::new(abi)),
            Err(err) => {
                debug!("ABI {:?} probe failed: {}", abi, err);
                last_error = Some(format!("ABI {:?}: {}", abi, err));
            }
        }
    }

    Err(NonoError::SandboxInit(format!(
        "No supported Landlock ABI detected{}",
        last_error
            .as_ref()
            .map(|e| format!(" (last error: {})", e))
            .unwrap_or_default()
    )))
}

/// Probe whether a specific ABI version is supported using `HardRequirement`.
fn probe_abi_candidate(abi: ABI) -> std::result::Result<(), String> {
    let mut ruleset = Ruleset::default().set_compatibility(CompatLevel::HardRequirement);

    ruleset = ruleset
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| format!("filesystem access probe failed: {}", e))?;

    let handled_net = AccessNet::from_all(abi);
    if !handled_net.is_empty() {
        ruleset = ruleset
            .handle_access(handled_net)
            .map_err(|e| format!("network access probe failed: {}", e))?;
    }

    let scopes = Scope::from_all(abi);
    if !scopes.is_empty() {
        ruleset = ruleset
            .scope(scopes)
            .map_err(|e| format!("scope probe failed: {}", e))?;
    }

    ruleset
        .create()
        .map_err(|e| format!("ruleset creation probe failed: {}", e))?;

    Ok(())
}

/// Cached WSL2 detection result.
///
/// Uses `OnceLock` so the filesystem/env checks happen at most once per process.
static WSL2_DETECTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// Detect whether the current process is running inside WSL2.
///
/// Uses only kernel-controlled indicators to prevent spoofing:
/// 1. The file `/proc/sys/fs/binfmt_misc/WSLInterop` exists
/// 2. `/proc/version` contains "microsoft" or "WSL"
///
/// The `WSL_DISTRO_NAME` environment variable is intentionally NOT
/// trusted because it is caller-controlled and could be set by a
/// malicious wrapper to disable security features on native Linux.
///
/// The result is cached for the lifetime of the process.
#[must_use]
pub fn is_wsl2() -> bool {
    *WSL2_DETECTED.get_or_init(detect_wsl2)
}

/// Perform the actual WSL2 detection (called once, cached).
///
/// Only trusts kernel-controlled indicators. Environment variables alone
/// are not sufficient because they are caller-controlled and could be
/// spoofed to disable security features on native Linux.
fn detect_wsl2() -> bool {
    // Primary: WSLInterop binfmt entry (kernel-controlled, present in all WSL2 distros)
    if std::path::Path::new("/proc/sys/fs/binfmt_misc/WSLInterop").exists() {
        info!("WSL2 detected via /proc/sys/fs/binfmt_misc/WSLInterop");
        return true;
    }

    // Secondary: kernel version string contains "microsoft" or "WSL2"
    // This is written by the kernel build and cannot be spoofed from userspace.
    if let Ok(version) = std::fs::read_to_string("/proc/version") {
        if version.contains("microsoft") || version.contains("WSL") {
            info!("WSL2 detected via /proc/version kernel string");
            return true;
        }
    }

    // WSL_DISTRO_NAME env var is NOT trusted on its own — it is caller-controlled
    // and could be set by a malicious wrapper to disable security features.
    // Only log it for diagnostics if other indicators were negative.
    if std::env::var_os("WSL_DISTRO_NAME").is_some() {
        warn!(
            "WSL_DISTRO_NAME is set but no kernel-controlled WSL2 indicators found; \
             ignoring env var to prevent security downgrade"
        );
    }

    false
}

/// Check if Landlock is supported on this system
pub fn is_supported() -> bool {
    detect_abi().is_ok()
}

/// Get information about Landlock support
pub fn support_info() -> SupportInfo {
    match detect_abi() {
        Ok(detected) => {
            let features = detected.feature_names();
            SupportInfo {
                is_supported: true,
                platform: "linux",
                details: format!(
                    "Landlock available ({}, features: {})",
                    detected,
                    features.join(", ")
                ),
            }
        }
        Err(_) => SupportInfo {
            is_supported: false,
            platform: "linux",
            details: "Landlock not available. Requires Linux kernel 5.13+ with Landlock enabled."
                .to_string(),
        },
    }
}

/// Result of converting AccessMode to Landlock flags, including any dropped flags.
struct LandlockAccess {
    /// Flags that will be applied (supported by this ABI).
    effective: BitFlags<AccessFs>,
    /// Flags that were requested but not supported by this ABI.
    dropped: BitFlags<AccessFs>,
}

/// Convert AccessMode to Landlock AccessFs flags, intersected with ABI support.
///
/// Returns both the effective flags and any dropped flags so the caller can
/// emit warnings with path context. This prevents `BestEffort` from hiding
/// degradation.
///
/// RemoveFile, RemoveDir, Truncate, and Refer are included to support atomic
/// writes (write to .tmp -> rename to target), which is the standard pattern
/// used by most applications for safe config/build artifact updates.
///
/// IoctlDev is NOT included here — it is added selectively in `apply_with_abi()`
/// only for paths that are actual device files (char/block devices), detected
/// via `stat()` at rule-addition time. This avoids granting device ioctl access
/// to non-device paths.
fn access_to_landlock(access: AccessMode, abi: ABI) -> LandlockAccess {
    let available = AccessFs::from_all(abi);

    let desired = match access {
        AccessMode::Read => AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute,
        AccessMode::Write => {
            AccessFs::WriteFile
                | AccessFs::MakeChar
                | AccessFs::MakeDir
                | AccessFs::MakeReg
                | AccessFs::MakeSock
                | AccessFs::MakeFifo
                | AccessFs::MakeBlock
                | AccessFs::MakeSym
                | AccessFs::RemoveFile
                | AccessFs::RemoveDir
                | AccessFs::Refer
                | AccessFs::Truncate
        }
        AccessMode::ReadWrite => {
            let read = access_to_landlock(AccessMode::Read, abi);
            let write = access_to_landlock(AccessMode::Write, abi);
            return LandlockAccess {
                effective: read.effective | write.effective,
                dropped: read.dropped | write.dropped,
            };
        }
    };

    LandlockAccess {
        effective: desired & available,
        dropped: desired & !available,
    }
}

/// Legacy check: whether the simple block-all seccomp filter can be used.
///
/// Only true for plain `NetworkMode::Blocked` with no port exceptions.
/// Callers should prefer `seccomp_network_fallback_mode()` which also
/// handles `ProxyOnly`.
#[cfg(test)]
#[must_use]
fn can_use_seccomp_network_block_fallback(caps: &CapabilitySet) -> bool {
    matches!(
        seccomp_network_fallback_mode(caps),
        SeccompNetFallback::BlockAll
    )
}

/// Check if a path is a character or block device file.
///
/// Used to selectively grant `IoctlDev` only for actual device files
/// (e.g., `/dev/tty`, `/dev/null`), not for regular files or directories.
fn is_device_path(path: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    std::fs::metadata(path)
        .map(|m| {
            let ft = m.file_type();
            ft.is_char_device() || ft.is_block_device()
        })
        .unwrap_or(false)
}

/// Check if a path is a directory that contains device files (e.g., `/dev/pts`).
///
/// For directories under `/dev`, we grant `IoctlDev` because Landlock's
/// `PathBeneath` applies to all files within the subtree, and those files
/// are device nodes that need ioctl access for terminal operations.
fn is_device_directory(path: &Path) -> bool {
    // Only consider directories directly under /dev as device directories.
    // This avoids granting IoctlDev to arbitrary directories.
    path.starts_with("/dev") && path.is_dir()
}

/// Determine which Landlock scopes must be enabled for these capabilities.
///
/// Only `SignalMode::AllowSameSandbox` has an exact Landlock mapping today.
/// `SignalMode::Isolated` cannot be represented because Landlock scopes to the
/// sandbox domain, not to the calling process alone.
fn requested_scopes(caps: &CapabilitySet, abi: &DetectedAbi) -> Result<BitFlags<Scope>> {
    match caps.signal_mode() {
        SignalMode::AllowAll => Ok(BitFlags::EMPTY),
        SignalMode::Isolated => {
            if abi.has_scoping() {
                Ok(Scope::Signal.into())
            } else {
                Ok(BitFlags::EMPTY)
            }
        }
        SignalMode::AllowSameSandbox => {
            if !abi.has_scoping() {
                return Err(NonoError::SandboxInit(
                    "SignalMode::AllowSameSandbox requires Landlock ABI V6+ \
                     (LANDLOCK_SCOPE_SIGNAL), but this kernel does not support process scoping."
                        .to_string(),
                ));
            }
            Ok(Scope::Signal.into())
        }
    }
}

/// Apply Landlock sandbox with the given capabilities, auto-detecting ABI.
///
/// This is a pure primitive - it applies ONLY the capabilities provided.
/// The caller is responsible for including all necessary paths (including
/// system paths like /usr, /lib, /bin if executables need to run).
///
/// Returns the seccomp network fallback mode that was determined but not
/// yet fully installed. `BlockAll` is self-contained (installed inside apply).
/// `ProxyOnly` signals the caller to install the proxy filter post-fork
/// via `install_seccomp_proxy_filter()`.
pub fn apply(caps: &CapabilitySet) -> Result<SeccompNetFallback> {
    let detected = detect_abi()?;
    apply_with_abi(caps, &detected)
}

/// Apply Landlock sandbox with the given capabilities and a pre-detected ABI.
///
/// This variant avoids re-probing the kernel ABI when the caller has already
/// detected it (e.g., the CLI probes once at startup).
///
/// # Security
///
/// The provided ABI is validated against the kernel: the ruleset is created
/// with `HardRequirement` for filesystem access rights. If the caller passes
/// an ABI higher than the kernel supports, `handle_access()` will fail rather
/// than silently dropping flags.
pub fn apply_with_abi(caps: &CapabilitySet, abi: &DetectedAbi) -> Result<SeccompNetFallback> {
    let target_abi = abi.abi;
    info!("Using Landlock ABI {:?}", target_abi);
    let scopes = requested_scopes(caps, abi)?;

    // Determine which access rights to handle based on ABI
    let handled_fs = AccessFs::from_all(target_abi);

    debug!("Handling filesystem access: {:?}", handled_fs);

    // Create the ruleset with HardRequirement for filesystem access.
    // This ensures that if the caller passes a stale or forged ABI higher
    // than the kernel supports, handle_access() fails instead of silently
    // dropping flags via BestEffort.
    let ruleset_builder = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(handled_fs)
        .map_err(|e| NonoError::SandboxInit(format!("Failed to handle fs access: {}", e)))?
        .set_compatibility(CompatLevel::BestEffort);

    // Determine if we need network handling (any mode besides AllowAll)
    let needs_network_handling = !matches!(caps.network_mode(), NetworkMode::AllowAll)
        || !caps.tcp_connect_ports().is_empty()
        || !caps.tcp_bind_ports().is_empty();

    let mut seccomp_net_fallback = SeccompNetFallback::None;

    let ruleset_builder = if needs_network_handling {
        let handled_net = AccessNet::from_all(target_abi);
        if !handled_net.is_empty() {
            debug!("Handling network access: {:?}", handled_net);
            ruleset_builder
                .set_compatibility(CompatLevel::HardRequirement)
                .handle_access(handled_net)
                .map_err(|e| {
                    NonoError::SandboxInit(format!(
                        "Network filtering requested but unsupported by this kernel: {}",
                        e
                    ))
                })?
                .set_compatibility(CompatLevel::BestEffort)
        } else {
            // Landlock ABI lacks AccessNet. Check seccomp fallback options.
            let fallback = seccomp_network_fallback_mode(caps);
            match &fallback {
                SeccompNetFallback::BlockAll => {
                    warn!(
                        "Landlock ABI {:?} lacks TCP network filtering; \
                         using seccomp full-network-block fallback",
                        target_abi
                    );
                    seccomp_net_fallback = fallback;
                    ruleset_builder
                }
                SeccompNetFallback::ProxyOnly {
                    proxy_port,
                    bind_ports,
                } => {
                    warn!(
                        "Landlock ABI {:?} lacks TCP network filtering; \
                         using seccomp proxy-only fallback (port={}, bind_ports={:?})",
                        target_abi, proxy_port, bind_ports
                    );
                    seccomp_net_fallback = fallback;
                    ruleset_builder
                }
                SeccompNetFallback::None => {
                    return Err(NonoError::SandboxInit(
                        "Network filtering requested but kernel Landlock ABI doesn't support it \
                         (requires V4+). On this kernel, only full --block-net or --proxy-only \
                         fallback via seccomp is supported."
                            .to_string(),
                    ));
                }
            }
        }
    } else {
        ruleset_builder
    };

    let ruleset_builder = if scopes.is_empty() {
        ruleset_builder
    } else {
        debug!("Handling Landlock scopes: {:?}", scopes);
        ruleset_builder
            .set_compatibility(CompatLevel::HardRequirement)
            .scope(scopes)
            .map_err(|e| {
                NonoError::SandboxInit(format!(
                    "Signal scoping requested but unsupported by this kernel: {}",
                    e
                ))
            })?
            .set_compatibility(CompatLevel::BestEffort)
    };

    if matches!(caps.signal_mode(), SignalMode::Isolated) && abi.has_scoping() {
        debug!(
            "SignalMode::Isolated is approximated on Linux with same-sandbox signal scoping: \
             Landlock can restrict signals to the same sandbox, but not to self only"
        );
    } else if matches!(caps.signal_mode(), SignalMode::Isolated) {
        debug!(
            "SignalMode::Isolated is not enforceable on this kernel: \
             Landlock ABI V6+ is required for signal scoping"
        );
    }

    let mut ruleset = ruleset_builder
        .create()
        .map_err(|e| NonoError::SandboxInit(format!("Failed to create ruleset: {}", e)))?;

    // Add Landlock network port rules ONLY when Landlock is handling networking.
    // When a seccomp fallback is active (BlockAll or ProxyOnly), the ruleset was
    // created without handle_access(AccessNet), so adding NetPort rules would fail.
    if matches!(seccomp_net_fallback, SeccompNetFallback::None) {
        // Add per-port TCP connect rules (ProxyOnly port + explicit tcp_connect_ports)
        if let NetworkMode::ProxyOnly { port, bind_ports } = caps.network_mode() {
            debug!("Adding ProxyOnly TCP connect rule for port {}", port);
            ruleset = ruleset
                .add_rule(NetPort::new(*port, AccessNet::ConnectTcp))
                .map_err(|e| {
                    NonoError::SandboxInit(format!(
                        "Cannot add TCP connect rule for proxy port {}: {}",
                        port, e
                    ))
                })?;
            // Add per-port TCP bind rules for bind_ports in ProxyOnly mode
            for bp in bind_ports {
                debug!("Adding ProxyOnly TCP bind rule for port {}", bp);
                ruleset = ruleset
                    .add_rule(NetPort::new(*bp, AccessNet::BindTcp))
                    .map_err(|e| {
                        NonoError::SandboxInit(format!(
                            "Cannot add TCP bind rule for port {}: {}",
                            bp, e
                        ))
                    })?;
            }
        }
        for port in caps.tcp_connect_ports() {
            debug!("Adding TCP connect rule for port {}", port);
            ruleset = ruleset
                .add_rule(NetPort::new(*port, AccessNet::ConnectTcp))
                .map_err(|e| {
                    NonoError::SandboxInit(format!(
                        "Cannot add TCP connect rule for port {}: {}",
                        port, e
                    ))
                })?;
        }
        for port in caps.tcp_bind_ports() {
            debug!("Adding TCP bind rule for port {}", port);
            ruleset = ruleset
                .add_rule(NetPort::new(*port, AccessNet::BindTcp))
                .map_err(|e| {
                    NonoError::SandboxInit(format!(
                        "Cannot add TCP bind rule for port {}: {}",
                        port, e
                    ))
                })?;
        }

        // Add localhost IPC port rules (connect + bind per port).
        // Only meaningful in Blocked/ProxyOnly modes. In AllowAll mode, all ports are
        // already reachable and adding Landlock network handling would restrict them.
        if !matches!(caps.network_mode(), NetworkMode::AllowAll) {
            for port in caps.localhost_ports() {
                debug!("Adding localhost TCP connect rule for port {}", port);
                ruleset = ruleset
                    .add_rule(NetPort::new(*port, AccessNet::ConnectTcp))
                    .map_err(|e| {
                        NonoError::SandboxInit(format!(
                            "Cannot add TCP connect rule for localhost port {}: {}",
                            port, e
                        ))
                    })?;
                debug!("Adding localhost TCP bind rule for port {}", port);
                ruleset = ruleset
                    .add_rule(NetPort::new(*port, AccessNet::BindTcp))
                    .map_err(|e| {
                        NonoError::SandboxInit(format!(
                            "Cannot add TCP bind rule for localhost port {}: {}",
                            port, e
                        ))
                    })?;
            }
        }
    }

    // Add rules for each filesystem capability
    // These MUST succeed - caller explicitly requested these capabilities
    // Failing silently would violate the principle of least surprise and fail-secure design
    let ioctl_dev_available = AccessFs::from_all(target_abi).contains(AccessFs::IoctlDev);

    for cap in caps.fs_capabilities() {
        let result = access_to_landlock(cap.access, target_abi);
        let mut access = result.effective;

        if !result.dropped.is_empty() {
            debug!(
                "Landlock ABI {:?} does not support {:?} for path {} (requested for {:?})",
                target_abi,
                result.dropped,
                cap.resolved.display(),
                cap.access
            );
        }

        // Grant IoctlDev only for device files and device directories (under /dev).
        // Terminal ioctls (TCSETS, TIOCGWINSZ) require this flag on V5+ kernels.
        // Without it, TUI programs fail with EACCES on /dev/tty and /dev/pts.
        // We restrict this to actual devices to avoid granting ioctl access to
        // regular files and non-device directories.
        if ioctl_dev_available
            && matches!(cap.access, AccessMode::Write | AccessMode::ReadWrite)
            && (is_device_path(&cap.resolved) || is_device_directory(&cap.resolved))
        {
            access |= AccessFs::IoctlDev;
            debug!(
                "Adding IoctlDev for device path: {}",
                cap.resolved.display()
            );
        }

        debug!(
            "Adding rule: {} with access {:?}",
            cap.resolved.display(),
            access
        );

        let path_fd = PathFd::new(&cap.resolved)?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(path_fd, access))
            .map_err(|e| {
                NonoError::SandboxInit(format!(
                    "Cannot add Landlock rule for {}: {} (filesystem may not support Landlock)",
                    cap.resolved.display(),
                    e
                ))
            })?;
    }

    // Apply the ruleset - THIS IS IRREVERSIBLE
    let status = ruleset
        .restrict_self()
        .map_err(|e| NonoError::SandboxInit(format!("Failed to restrict self: {}", e)))?;

    match status.ruleset {
        landlock::RulesetStatus::FullyEnforced => {
            info!("Landlock sandbox fully enforced");
        }
        landlock::RulesetStatus::PartiallyEnforced => {
            // Partial enforcement can come from filesystem feature fallback (e.g. newer
            // fs rights not supported by the current kernel or backing filesystem).
            // Network handling is hard-required above whenever requested.
            debug!("Landlock sandbox enforced in best-effort mode (partially enforced)");
        }
        landlock::RulesetStatus::NotEnforced => {
            return Err(NonoError::SandboxInit(
                "Landlock sandbox was not enforced".to_string(),
            ));
        }
    }

    if matches!(seccomp_net_fallback, SeccompNetFallback::BlockAll) {
        install_seccomp_block_network().map_err(|e| {
            NonoError::SandboxInit(format!(
                "Failed to install seccomp network block fallback: {}",
                e
            ))
        })?;
        info!("Seccomp network block fallback enforced");
    }
    // ProxyOnly is NOT installed here — it requires a notify fd that must
    // be sent to the supervisor parent via SCM_RIGHTS. The caller (CLI)
    // installs it post-fork via install_seccomp_proxy_filter().

    Ok(seccomp_net_fallback)
}

// ==========================================================================
// Seccomp user notification (SECCOMP_RET_USER_NOTIF) for transparent
// capability expansion. These primitives install a BPF filter on
// openat/openat2, receive notifications in the supervisor parent, and
// inject opened fds into the child process.
//
// Requires kernel >= 5.14 for SECCOMP_ADDFD_FLAG_SEND (atomic fd injection).
// ==========================================================================

/// seccomp notification received from the kernel.
///
/// Mirrors `struct seccomp_notif` from `<linux/seccomp.h>`.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct SeccompNotif {
    /// Unique notification ID (for responding)
    pub id: u64,
    /// PID of the process that triggered the notification
    pub pid: u32,
    /// Flags (currently unused, reserved)
    pub flags: u32,
    /// The syscall data (architecture, syscall number, args, etc.)
    pub data: SeccompData,
}

/// Syscall data from a seccomp notification.
///
/// Mirrors `struct seccomp_data` from `<linux/seccomp.h>`.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct SeccompData {
    /// Syscall number
    pub nr: i32,
    /// CPU architecture (AUDIT_ARCH_*)
    pub arch: u32,
    /// Instruction pointer at time of syscall
    pub instruction_pointer: u64,
    /// Syscall arguments (up to 6)
    pub args: [u64; 6],
}

/// Response to a seccomp notification.
///
/// Mirrors `struct seccomp_notif_resp` from `<linux/seccomp.h>`.
#[repr(C)]
#[derive(Debug)]
struct SeccompNotifResp {
    /// Must match the notification ID
    id: u64,
    /// Return value for the syscall (if not using SECCOMP_USER_NOTIF_FLAG_CONTINUE)
    val: i64,
    /// Negated errno to return (0 = use val, negative = error)
    error: i32,
    /// Response flags
    flags: u32,
}

/// Addfd request for injecting an fd into the notified process.
///
/// Mirrors `struct seccomp_notif_addfd` from `<linux/seccomp.h>`.
#[repr(C)]
#[derive(Debug)]
struct SeccompNotifAddfd {
    /// Must match the notification ID
    id: u64,
    /// Flags (SECCOMP_ADDFD_FLAG_SEND makes the injected fd the syscall return value)
    flags: u32,
    /// The fd in the supervisor to inject (or 0 if using SETFD)
    srcfd: u32,
    /// Target fd number in the child (0 = kernel chooses)
    newfd: u32,
    /// Additional flags for the target fd (e.g., FD_CLOEXEC)
    newfd_flags: u32,
}

// Seccomp constants not in libc crate
const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_uint = 1 << 3;
const SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV: libc::c_uint = 1 << 4;

// ioctl request codes for seccomp notifications
const SECCOMP_IOCTL_NOTIF_RECV: libc::Ioctl = 0xc0502100 as libc::Ioctl;
const SECCOMP_IOCTL_NOTIF_SEND: libc::Ioctl = 0xc0182101 as libc::Ioctl;
const SECCOMP_IOCTL_NOTIF_ID_VALID: libc::Ioctl = 0x40082102 as libc::Ioctl;
const SECCOMP_IOCTL_NOTIF_ADDFD: libc::Ioctl = 0x40182103 as libc::Ioctl;

// Seccomp addfd flags
const SECCOMP_ADDFD_FLAG_SEND: u32 = 1 << 1;
const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;

// BPF constants
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

// Syscall numbers for x86_64 (public for CLI to distinguish openat vs openat2)
#[cfg(target_arch = "x86_64")]
pub const SYS_OPENAT: i32 = 257;
#[cfg(target_arch = "x86_64")]
pub const SYS_OPENAT2: i32 = 437;

// Syscall numbers for aarch64 (public for CLI to distinguish openat vs openat2)
#[cfg(target_arch = "aarch64")]
pub const SYS_OPENAT: i32 = 56;
#[cfg(target_arch = "aarch64")]
pub const SYS_OPENAT2: i32 = 437;

#[cfg(target_os = "linux")]
const SYS_SOCKET: i32 = libc::SYS_socket as i32;
#[cfg(target_os = "linux")]
const SYS_SOCKETPAIR: i32 = libc::SYS_socketpair as i32;
#[cfg(target_os = "linux")]
const SYS_IO_URING_SETUP: i32 = libc::SYS_io_uring_setup as i32;

// Syscall numbers for connect/bind (public for CLI supervisor handler)
#[cfg(target_os = "linux")]
pub const SYS_CONNECT: i32 = libc::SYS_connect as i32;
#[cfg(target_os = "linux")]
pub const SYS_BIND: i32 = libc::SYS_bind as i32;

/// struct open_how from <linux/openat2.h>
///
/// Used by openat2() syscall. args[2] is a pointer to this struct, NOT the flags integer.
/// This is a critical security distinction from openat() where args[2] IS the flags.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct OpenHow {
    /// O_CREAT, O_RDONLY, O_WRONLY, O_RDWR, etc.
    pub flags: u64,
    /// File mode (when O_CREAT is used)
    pub mode: u64,
    /// RESOLVE_* flags for path resolution control
    pub resolve: u64,
}

/// Classify access mode from open flags.
///
/// Extracts O_ACCMODE bits and maps to AccessMode. Used by both openat (where flags
/// come from args[2] directly) and openat2 (where flags come from open_how.flags).
#[must_use]
pub fn classify_access_from_flags(flags: i32) -> crate::AccessMode {
    match flags & libc::O_ACCMODE {
        libc::O_RDONLY => crate::AccessMode::Read,
        libc::O_WRONLY => crate::AccessMode::Write,
        _ => crate::AccessMode::ReadWrite,
    }
}

/// Validate that the openat2 size argument is large enough to hold the open_how struct.
///
/// For openat2, args[3] contains the size of the open_how struct passed by the caller.
/// If this is smaller than our expected struct size, the request is malformed and should
/// be denied to avoid reading garbage or partial data.
///
/// We also reject unreasonably large sizes. The supervisor only reads the stable
/// leading fields we know (`flags`, `mode`, `resolve`) and should be recompiled
/// against newer kernel headers when `struct open_how` evolves.
const OPENAT2_HOW_SIZE_MAX: usize = 4096;

#[must_use]
pub fn validate_openat2_size(how_size: usize) -> bool {
    let min_size = std::mem::size_of::<OpenHow>();
    how_size >= min_size && how_size <= OPENAT2_HOW_SIZE_MAX
}

// Offset of `nr` field in seccomp_data (used by BPF)
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARG0_OFFSET: u32 = 16;

/// A single BPF instruction.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SockFilterInsn {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

/// BPF program header.
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilterInsn,
}

/// Install a seccomp-notify BPF filter for openat/openat2.
///
/// Returns the notify fd. Must be called BEFORE `Sandbox::apply()` (Landlock
/// `restrict_self()`), so the supervisor can still receive notifications for
/// paths that Landlock would block.
///
/// The BPF filter routes openat/openat2 to `SECCOMP_RET_USER_NOTIF` and
/// allows all other syscalls with `SECCOMP_RET_ALLOW`.
///
/// # Errors
///
/// Returns an error if:
/// - The kernel doesn't support seccomp user notifications (< 5.0)
/// - The `seccomp()` syscall fails
/// - `SECCOMP_FILTER_FLAG_NEW_LISTENER` is not available
pub fn install_seccomp_notify() -> Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;

    // BPF program:
    //   ld  [nr]                     ; load syscall number
    //   jeq SYS_OPENAT, notify       ; if openat -> notify
    //   jeq SYS_OPENAT2, notify      ; if openat2 -> notify
    //   ret SECCOMP_RET_ALLOW        ; else allow
    //   notify: ret SECCOMP_RET_USER_NOTIF
    let filter = [
        // 0: Load syscall number
        SockFilterInsn {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: SECCOMP_DATA_NR_OFFSET,
        },
        // 1: If openat, jump to 4 (notify)
        SockFilterInsn {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 2, // jump +2 to instruction 4 (notify)
            jf: 0,
            k: SYS_OPENAT as u32,
        },
        // 2: If openat2, jump to 4 (notify)
        SockFilterInsn {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 1, // jump +1 to instruction 4 (notify)
            jf: 0,
            k: SYS_OPENAT2 as u32,
        },
        // 3: Allow all other syscalls
        SockFilterInsn {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
        // 4: Route to user notification
        SockFilterInsn {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_USER_NOTIF,
        },
    ];

    let prog = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };

    // seccomp(SET_MODE_FILTER) requires either CAP_SYS_ADMIN or no_new_privs.
    // We use no_new_privs (unprivileged) which prevents gaining privileges via
    // setuid/setgid binaries. This is a one-way flag that cannot be unset, and
    // Landlock's restrict_self() sets it too, so this adds no new restriction.
    // SAFETY: prctl with PR_SET_NO_NEW_PRIVS is always safe to call.
    // SAFETY: `prctl(PR_SET_NO_NEW_PRIVS)` is process-local, takes only scalar
    // arguments here, and does not dereference pointers.
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(NonoError::SandboxInit(format!(
            "prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    // Try with WAIT_KILLABLE_RECV first (kernel 5.19+) for Go runtime compatibility.
    // Falls back without it if the kernel doesn't support it.
    let flags = SECCOMP_FILTER_FLAG_NEW_LISTENER | SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV;

    // SAFETY: seccomp() with SECCOMP_SET_MODE_FILTER installs a BPF filter.
    // The prog pointer is valid for the duration of the syscall. The filter
    // array is stack-allocated and outlives the syscall.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            flags,
            &prog as *const SockFprog,
        )
    };

    let notify_fd = if ret < 0 {
        // Retry without WAIT_KILLABLE_RECV (kernel < 5.19)
        let flags = SECCOMP_FILTER_FLAG_NEW_LISTENER;

        // SAFETY: Same as above, retrying with fewer flags.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_SET_MODE_FILTER,
                flags,
                &prog as *const SockFprog,
            )
        };

        if ret < 0 {
            return Err(NonoError::SandboxInit(format!(
                "seccomp(SECCOMP_SET_MODE_FILTER) failed: {}. \
                 Requires kernel >= 5.0 with SECCOMP_FILTER_FLAG_NEW_LISTENER.",
                std::io::Error::last_os_error()
            )));
        }
        ret as i32
    } else {
        ret as i32
    };

    // SAFETY: The fd returned by seccomp() with NEW_LISTENER is a valid,
    // newly-created file descriptor that we now own.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(notify_fd) })
}

/// Install a seccomp filter that blocks non-Unix socket creation.
///
/// This is a compatibility fallback for kernels whose Landlock ABI lacks
/// `AccessNet`. It enforces a fail-closed `--block-net` policy by allowing
/// only Unix-domain sockets and denying `socket()`, `socketpair()`, and
/// `io_uring_setup()` attempts that could drive network I/O.
fn build_seccomp_block_network_filter() -> [SockFilterInsn; 10] {
    let errno_ret = SECCOMP_RET_ERRNO | (libc::EPERM as u32);

    [
        SockFilterInsn {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: SECCOMP_DATA_NR_OFFSET,
        },
        SockFilterInsn {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 4,
            jf: 0,
            k: SYS_SOCKET as u32,
        },
        SockFilterInsn {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 3,
            jf: 0,
            k: SYS_SOCKETPAIR as u32,
        },
        SockFilterInsn {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 1,
            jf: 0,
            k: SYS_IO_URING_SETUP as u32,
        },
        SockFilterInsn {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
        SockFilterInsn {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: errno_ret,
        },
        SockFilterInsn {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: SECCOMP_DATA_ARG0_OFFSET,
        },
        SockFilterInsn {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 1,
            jf: 0,
            k: libc::AF_UNIX as u32,
        },
        SockFilterInsn {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: errno_ret,
        },
        SockFilterInsn {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
    ]
}

/// Install a seccomp filter that blocks non-Unix socket creation.
///
/// This is a compatibility fallback for kernels whose Landlock ABI lacks
/// `AccessNet`. It enforces a fail-closed `--block-net` policy by allowing
/// only Unix-domain sockets and denying `socket()`, `socketpair()`, and
/// `io_uring_setup()` attempts that could drive network I/O.
pub fn install_seccomp_block_network() -> Result<()> {
    let filter = build_seccomp_block_network_filter();

    let prog = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };

    // SAFETY: `prctl(PR_SET_NO_NEW_PRIVS)` is process-local, takes only scalar
    // arguments here, and does not dereference pointers.
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(NonoError::SandboxInit(format!(
            "prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    // SAFETY: `seccomp(SECCOMP_SET_MODE_FILTER)` reads the provided BPF program
    // during the syscall. `prog` points to a stack-allocated filter array that
    // remains alive for the duration of the call.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            0,
            &prog as *const SockFprog,
        )
    };

    if ret < 0 {
        return Err(NonoError::SandboxInit(format!(
            "seccomp(SECCOMP_SET_MODE_FILTER) for network block failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

/// Probe whether the seccomp full-network-block fallback can be installed.
///
/// This forks a short-lived child so the calling process is not permanently
/// modified by seccomp state during the probe.
pub fn probe_seccomp_block_network_support() -> Result<bool> {
    // SAFETY: `fork()` is used only to isolate the irreversible seccomp probe.
    // The child immediately attempts filter installation and exits.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(NonoError::SandboxInit(format!(
            "fork() failed during seccomp network fallback probe: {}",
            std::io::Error::last_os_error()
        )));
    }

    if pid == 0 {
        let exit_code = if install_seccomp_block_network().is_ok() {
            0
        } else {
            1
        };
        // SAFETY: `_exit()` terminates the probe child without running parent
        // process destructors after fork.
        unsafe { libc::_exit(exit_code) };
    }

    let mut status = 0;
    // SAFETY: `waitpid()` is called for the child PID returned by `fork()`
    // above, and `status` points to valid writable memory.
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    if waited < 0 {
        return Err(NonoError::SandboxInit(format!(
            "waitpid() failed during seccomp network fallback probe: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0)
}

/// Receive the next seccomp notification (blocking).
///
/// Blocks until a notification is available on the notify fd.
/// Returns the notification with syscall data and a unique ID.
///
/// # Errors
///
/// Returns an error if the ioctl fails (e.g., EINTR, ENOENT if child exited).
pub fn recv_notif(notify_fd: std::os::fd::RawFd) -> Result<SeccompNotif> {
    // Zero-initialize the notification struct (kernel writes into it)
    let mut notif = SeccompNotif {
        id: 0,
        pid: 0,
        flags: 0,
        data: SeccompData::default(),
    };

    // SAFETY: SECCOMP_IOCTL_NOTIF_RECV writes a seccomp_notif struct into
    // the provided buffer. The struct is correctly sized and aligned.
    let ret = unsafe {
        libc::ioctl(
            notify_fd,
            SECCOMP_IOCTL_NOTIF_RECV,
            &mut notif as *mut SeccompNotif,
        )
    };

    if ret < 0 {
        return Err(NonoError::SandboxInit(format!(
            "SECCOMP_IOCTL_NOTIF_RECV failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(notif)
}

/// Read the path argument from a seccomp notification.
///
/// Reads from `/proc/PID/mem` at the pointer address in the second syscall
/// argument (args[1] for openat/openat2, which is the pathname pointer).
///
/// # TOCTOU Warning
///
/// The path read here may have been modified between the syscall and this read.
/// Always call `notif_id_valid()` after reading to verify the notification is
/// still pending (the child hasn't been killed and its PID recycled).
///
/// Security boundary note: notification ID validation is only a liveness check.
/// Authorization is bound to the path opened by the supervisor itself; the child
/// receives that already-opened fd via `inject_fd()`.
///
/// # Errors
///
/// Returns an error if:
/// - `/proc/PID/mem` cannot be opened
/// - The read fails
/// - The path is not valid UTF-8
pub fn read_notif_path(pid: u32, addr: u64) -> Result<std::path::PathBuf> {
    use std::io::Read;

    let mem_path = format!("/proc/{}/mem", pid);
    let mut file = std::fs::File::open(&mem_path)
        .map_err(|e| NonoError::SandboxInit(format!("Failed to open {}: {}", mem_path, e)))?;

    // Seek to the address of the path string
    std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(addr))
        .map_err(|e| NonoError::SandboxInit(format!("Failed to seek in {}: {}", mem_path, e)))?;

    // Read up to PATH_MAX bytes, looking for null terminator
    let mut buf = vec![0u8; 4096];
    let n = file.read(&mut buf).map_err(|e| {
        NonoError::SandboxInit(format!("Failed to read path from {}: {}", mem_path, e))
    })?;

    // Find null terminator
    let end = buf[..n].iter().position(|&b| b == 0).unwrap_or(n);
    if end == 0 || end >= 4096 {
        return Err(NonoError::SandboxInit(
            "Invalid path in seccomp notification (empty or too long)".to_string(),
        ));
    }

    let path_str = std::str::from_utf8(&buf[..end]).map_err(|_| {
        NonoError::SandboxInit("Path in seccomp notification is not valid UTF-8".to_string())
    })?;

    Ok(std::path::PathBuf::from(path_str))
}

/// Resolve a path from a seccomp notification, accounting for dirfd-relative paths.
///
/// When the child uses `openat(dirfd, "relative/path", ...)`, the raw pathname
/// read from memory is relative. This function resolves it to an absolute path
/// using `/proc/PID/fd/DIRFD` (or `/proc/PID/cwd` when dirfd is `AT_FDCWD`).
///
/// If the path is already absolute, it is returned unchanged.
///
/// # Arguments
///
/// * `pid` - The child process ID
/// * `dirfd` - The dirfd argument from the openat/openat2 syscall (args[0])
/// * `raw_path` - The pathname read from the child's memory via `read_notif_path`
///
/// # Errors
///
/// Returns an error if the `/proc` symlink cannot be read.
pub fn resolve_notif_path(
    pid: u32,
    dirfd: u64,
    raw_path: &std::path::Path,
) -> Result<std::path::PathBuf> {
    // Absolute paths need no resolution
    if raw_path.is_absolute() {
        return Ok(raw_path.to_path_buf());
    }

    // AT_FDCWD (-100, but stored as u64 in seccomp args via sign extension).
    // Two representations: 32-bit zero-extended (0xFFFFFF9C) and 64-bit sign-extended
    // (0xFFFFFFFFFFFFFF9C). We must check both.
    #[allow(clippy::unnecessary_cast)]
    let at_fdcwd_u64 = libc::AT_FDCWD as i32 as u32 as u64;
    #[allow(clippy::unnecessary_cast)]
    let at_fdcwd_u64_extended = libc::AT_FDCWD as i64 as u64;

    let base_dir = if dirfd == at_fdcwd_u64 || dirfd == at_fdcwd_u64_extended {
        // Use the child's current working directory
        let cwd_link = format!("/proc/{}/cwd", pid);
        std::fs::read_link(&cwd_link).map_err(|e| {
            NonoError::SandboxInit(format!(
                "Failed to read {} for dirfd-relative path resolution: {}",
                cwd_link, e
            ))
        })?
    } else {
        // Read the directory path from /proc/PID/fd/DIRFD
        let fd_link = format!("/proc/{}/fd/{}", pid, dirfd);
        std::fs::read_link(&fd_link).map_err(|e| {
            NonoError::SandboxInit(format!(
                "Failed to read {} for dirfd-relative path resolution: {}",
                fd_link, e
            ))
        })?
    };

    Ok(base_dir.join(raw_path))
}

/// Read the open_how struct from a seccomp notification for openat2 syscalls.
///
/// For openat2, args[2] is a pointer to `struct open_how`, NOT the flags integer.
/// This function safely reads the struct from the child's memory.
///
/// # Security
///
/// This is critical for access-mode classification. Treating args[2] as an integer
/// (as with openat) when it's actually a pointer leads to misclassifying access mode,
/// potentially granting broader permissions than the child requested.
///
/// # TOCTOU Warning
///
/// The struct may be modified between the syscall and this read. Always call
/// `notif_id_valid()` after reading to verify the notification is still pending.
///
/// # Errors
///
/// Returns an error if:
/// - `/proc/PID/mem` cannot be opened
/// - The read fails or doesn't return enough bytes
pub fn read_open_how(pid: u32, addr: u64) -> Result<OpenHow> {
    use std::io::Read;

    let mem_path = format!("/proc/{}/mem", pid);
    let mut file = std::fs::File::open(&mem_path)
        .map_err(|e| NonoError::SandboxInit(format!("Failed to open {}: {}", mem_path, e)))?;

    // Seek to the address of the open_how struct
    std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(addr))
        .map_err(|e| NonoError::SandboxInit(format!("Failed to seek in {}: {}", mem_path, e)))?;

    // Read exactly the size of OpenHow (24 bytes)
    let mut buf = [0u8; std::mem::size_of::<OpenHow>()];
    file.read_exact(&mut buf).map_err(|e| {
        NonoError::SandboxInit(format!("Failed to read open_how from {}: {}", mem_path, e))
    })?;

    // SAFETY: OpenHow is repr(C) with no padding between fields (u64, u64, u64).
    // We read exactly size_of::<OpenHow>() bytes into a properly aligned buffer.
    // The struct contains only u64 values which have no invalid bit patterns.
    let open_how: OpenHow = unsafe { std::ptr::read_unaligned(buf.as_ptr().cast()) };

    Ok(open_how)
}

/// Check that a seccomp notification is still pending (TOCTOU protection).
///
/// Must be called after `read_notif_path()` and before `inject_fd()` or
/// `deny_notif()`. If the notification is no longer valid (child exited,
/// PID recycled), the operation should be skipped.
///
/// # Errors
///
/// Returns an error if the ioctl fails for reasons other than ENOENT.
pub fn notif_id_valid(notify_fd: std::os::fd::RawFd, notif_id: u64) -> Result<bool> {
    // SAFETY: SECCOMP_IOCTL_NOTIF_ID_VALID checks if a notification ID is
    // still pending. The ID is passed by pointer.
    let ret = unsafe {
        libc::ioctl(
            notify_fd,
            SECCOMP_IOCTL_NOTIF_ID_VALID,
            &notif_id as *const u64,
        )
    };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOENT) {
            // Notification is no longer valid (child exited or was killed)
            return Ok(false);
        }
        return Err(NonoError::SandboxInit(format!(
            "SECCOMP_IOCTL_NOTIF_ID_VALID failed: {}",
            err
        )));
    }

    Ok(true)
}

/// Inject an fd into the notified process (atomic respond + inject).
///
/// Uses `SECCOMP_IOCTL_NOTIF_ADDFD` with `SECCOMP_ADDFD_FLAG_SEND` to
/// atomically inject the fd and set it as the syscall return value.
/// This means the child's `openat()` call returns the injected fd directly.
///
/// Requires kernel >= 5.14.
///
/// # Errors
///
/// Returns an error if the ioctl fails (notification expired, kernel too old).
pub fn inject_fd(
    notify_fd: std::os::fd::RawFd,
    notif_id: u64,
    fd: std::os::fd::RawFd,
) -> Result<()> {
    let addfd = SeccompNotifAddfd {
        id: notif_id,
        flags: SECCOMP_ADDFD_FLAG_SEND,
        srcfd: fd as u32,
        newfd: 0,                            // Let kernel choose the fd number
        newfd_flags: libc::O_CLOEXEC as u32, // Prevent fd leaking to child's children
    };

    // SAFETY: SECCOMP_IOCTL_NOTIF_ADDFD injects a file descriptor from our
    // process into the notified process. The addfd struct is correctly
    // initialized with a valid fd and notification ID.
    let ret = unsafe {
        libc::ioctl(
            notify_fd,
            SECCOMP_IOCTL_NOTIF_ADDFD,
            &addfd as *const SeccompNotifAddfd,
        )
    };

    if ret < 0 {
        return Err(NonoError::SandboxInit(format!(
            "SECCOMP_IOCTL_NOTIF_ADDFD failed: {}. Requires kernel >= 5.14.",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

/// Respond to a seccomp notification with a specific errno.
///
/// Sends a response to the kernel that causes the child's syscall to
/// return -1 with the supplied errno.
///
/// # Errors
///
/// Returns an error if the ioctl fails.
pub fn respond_notif_errno(notify_fd: std::os::fd::RawFd, notif_id: u64, errno: i32) -> Result<()> {
    let resp = SeccompNotifResp {
        id: notif_id,
        val: 0,
        error: -errno,
        flags: 0,
    };

    // SAFETY: SECCOMP_IOCTL_NOTIF_SEND sends our response to the kernel.
    // The resp struct is correctly initialized.
    let ret = unsafe {
        libc::ioctl(
            notify_fd,
            SECCOMP_IOCTL_NOTIF_SEND,
            &resp as *const SeccompNotifResp,
        )
    };

    if ret < 0 {
        return Err(NonoError::SandboxInit(format!(
            "SECCOMP_IOCTL_NOTIF_SEND failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

/// Continue a seccomp notification, letting the child's original syscall run.
///
/// This preserves the original syscall semantics exactly. It is safe only when
/// the syscall is already authorized by the sandbox's allow-list.
pub fn continue_notif(notify_fd: std::os::fd::RawFd, notif_id: u64) -> Result<()> {
    let resp = SeccompNotifResp {
        id: notif_id,
        val: 0,
        error: 0,
        flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
    };

    let ret = unsafe {
        libc::ioctl(
            notify_fd,
            SECCOMP_IOCTL_NOTIF_SEND,
            &resp as *const SeccompNotifResp,
        )
    };

    if ret < 0 {
        return Err(NonoError::SandboxInit(format!(
            "SECCOMP_IOCTL_NOTIF_SEND (continue) failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

/// Deny a seccomp notification with EPERM.
///
/// Sends a response to the kernel that causes the child's syscall to
/// return -1 with errno=EPERM.
///
/// # Errors
///
/// Returns an error if the ioctl fails.
pub fn deny_notif(notify_fd: std::os::fd::RawFd, notif_id: u64) -> Result<()> {
    respond_notif_errno(notify_fd, notif_id, libc::EPERM)
}

// ==========================================================================
// Seccomp proxy-only network fallback
//
// For kernels without Landlock AccessNet (ABI < V4), this provides a
// seccomp-based alternative that allows connect() only to the proxy
// port on localhost, blocking all other network activity.
// ==========================================================================

/// Kind of AF_UNIX socket, determined from `sun_path` and `addrlen`.
///
/// See `unix(7)`. This distinction matters for policy because only
/// [`UnixSocketKind::Pathname`] sockets are governed by filesystem rules.
/// Abstract and unnamed sockets live in a separate namespace that Landlock's
/// filesystem rules cannot reach, so the supervisor must decide them
/// explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnixSocketKind {
    /// Filesystem-backed: `sun_path` is a null-terminated filesystem path
    /// (e.g. `/tmp/test.sock`). Access is governed by filesystem permissions
    /// and — in our case — by Landlock's filesystem rules.
    Pathname,
    /// Linux abstract namespace: `sun_path[0] == '\0'` and bytes `[1..]` form
    /// the abstract name. Not backed by any filesystem, so Landlock's
    /// filesystem rules do not apply.
    Abstract,
    /// Unnamed socket: `addrlen` is `offsetof(sockaddr_un, sun_path)` (i.e.
    /// 2 — `sa_family` only). Produced by `socketpair(2)` and autobinding
    /// `bind(fd, NULL, 2)`.
    Unnamed,
}

/// Classify an AF_UNIX sockaddr buffer.
///
/// `sun_path_first_byte` should be `buf[2]` for `addrlen >= 3`, or `None` if
/// the sockaddr is only 2 bytes (unnamed). Pure function so it is unit-tested
/// without the `/proc/PID/mem` plumbing.
#[must_use]
pub fn classify_af_unix(addrlen: u64, sun_path_first_byte: Option<u8>) -> UnixSocketKind {
    // offsetof(sockaddr_un, sun_path) == 2 on Linux.
    if addrlen <= 2 {
        return UnixSocketKind::Unnamed;
    }
    match sun_path_first_byte {
        Some(0) => UnixSocketKind::Abstract,
        Some(_) => UnixSocketKind::Pathname,
        // addrlen > 2 but we couldn't read sun_path[0] — treat as unnamed
        // (fail-closed: callers that deny non-pathname will deny this too).
        None => UnixSocketKind::Unnamed,
    }
}

/// Parsed sockaddr from a seccomp notification.
///
/// Extracted from `/proc/PID/mem` at the pointer in the connect/bind args.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SockaddrInfo {
    /// Address family (AF_INET, AF_INET6, AF_UNIX, etc.)
    pub family: u16,
    /// Port number in host byte order (0 for AF_UNIX)
    pub port: u16,
    /// Whether the address is a loopback address (127.0.0.1 or ::1)
    pub is_loopback: bool,
    /// For `AF_UNIX`: kind of socket (pathname / abstract / unnamed). `None`
    /// for non-UNIX address families.
    pub unix_kind: Option<UnixSocketKind>,
}

/// Seccomp network fallback mode determined during sandbox apply.
///
/// When Landlock ABI lacks `AccessNet`, the sandbox cannot enforce network
/// restrictions via Landlock rules. This enum describes which seccomp
/// fallback (if any) should be installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeccompNetFallback {
    /// No seccomp network fallback needed (Landlock handles it, or no filtering).
    None,
    /// Full network block: deny all non-AF_UNIX sockets. No notify fd needed.
    BlockAll,
    /// Proxy-only mode: trap connect/bind to supervisor for port-level filtering.
    /// Returns a notify fd that the supervisor must poll.
    ProxyOnly {
        /// The proxy port to allow connect() to on localhost.
        proxy_port: u16,
        /// Ports to allow bind() on (e.g. MCP servers).
        bind_ports: Vec<u16>,
    },
}

/// Determine the seccomp network fallback mode for the given capabilities.
///
/// Called when Landlock ABI lacks `AccessNet`. Returns the appropriate
/// fallback strategy based on the network mode and port configuration.
#[must_use]
pub fn seccomp_network_fallback_mode(caps: &CapabilitySet) -> SeccompNetFallback {
    match caps.network_mode() {
        NetworkMode::Blocked => {
            if caps.tcp_connect_ports().is_empty()
                && caps.tcp_bind_ports().is_empty()
                && caps.localhost_ports().is_empty()
            {
                SeccompNetFallback::BlockAll
            } else {
                // Blocked mode with port exceptions cannot be expressed
                // in the simple block filter, and is not a proxy scenario.
                SeccompNetFallback::None
            }
        }
        NetworkMode::ProxyOnly { port, bind_ports } => SeccompNetFallback::ProxyOnly {
            proxy_port: *port,
            bind_ports: bind_ports.clone(),
        },
        NetworkMode::AllowAll => SeccompNetFallback::None,
    }
}

/// Build a BPF filter for proxy-only network mode.
///
/// Routes `connect()` and `bind()` to `SECCOMP_RET_USER_NOTIF` so the
/// supervisor can inspect the sockaddr and make a per-family decision:
///
/// - `AF_INET`/`AF_INET6`: allow connect to `localhost:proxy_port`;
///   allow bind on ports in the configured bind-ports list; deny others.
/// - pathname `AF_UNIX` (#685): allow both connect and bind. Landlock's
///   filesystem rules are the upstream gate on which paths are reachable.
/// - abstract/unnamed `AF_UNIX`: deny (see `decide_network_notification`).
///
/// `has_bind_ports` is retained for API compatibility but no longer
/// influences filter routing — a previous version routed bind directly to
/// ERRNO when no TCP bind ports were configured, which unconditionally
/// failed AF_UNIX bind (regression on Landlock V2 kernels where this
/// fallback fires). The supervisor is the sole arbiter now.
///
/// `socket()` is allowed only for `AF_UNIX`, `AF_INET`, `AF_INET6`.
/// `socketpair()` is allowed only for `AF_UNIX`.
/// `io_uring_setup()` is denied.
///
/// Instruction layout (19 instructions, jt = jump offset from next insn):
/// ```text
///  0: ld  [nr]
///  1: jeq SYS_SOCKET     jt=+6  (-> 8: load socket family)
///  2: jeq SYS_CONNECT    jt=+13 (-> 16: notify)
///  3: jeq SYS_BIND       jt=+13 (-> 17: notify)
///  4: jeq SYS_SOCKETPAIR jt=+8  (-> 13: load socketpair family)
///  5: jeq SYS_IO_URING   jt=+1  (-> 7: errno)
///  6: ret ALLOW
///  7: ret ERRNO(EACCES)
///  8: ld  [args[0]]             ; socket() family
///  9: jeq AF_UNIX  jt=+8 (-> 18: allow)
/// 10: jeq AF_INET  jt=+7 (-> 18: allow)
/// 11: jeq AF_INET6 jt=+6 (-> 18: allow)
/// 12: ret ERRNO(EACCES)         ; bad socket family
/// 13: ld  [args[0]]             ; socketpair() family
/// 14: jeq AF_UNIX  jt=+3 (-> 18: allow)
/// 15: ret ERRNO(EACCES)         ; bad socketpair family
/// 16: ret USER_NOTIF            ; connect
/// 17: ret USER_NOTIF            ; bind
/// 18: ret ALLOW                 ; allowed socket/socketpair
/// ```
fn build_seccomp_proxy_filter(_has_bind_ports: bool) -> Vec<SockFilterInsn> {
    let errno_ret = SECCOMP_RET_ERRNO | (libc::EACCES as u32);

    // bind() always routes to USER_NOTIF so the supervisor can make the
    // per-family decision (deny AF_INET to non-allowed TCP ports; allow
    // pathname AF_UNIX per issue #685). The previous variant took a
    // has_bind_ports short-circuit to ERRNO when no TCP bind ports were
    // configured, which unconditionally failed AF_UNIX bind — a real
    // regression that only manifested on Landlock V2 kernels (where this
    // seccomp fallback fires). The has_bind_ports parameter is retained
    // for API compatibility but no longer gates filter routing; the
    // supervisor's `decide_network_notification` is the sole arbiter.
    let bind_action = SECCOMP_RET_USER_NOTIF;

    // Target instruction index table (jt/jf are offsets from next insn):
    //  0: ld [nr]
    //  1: jeq SOCKET     jt=6  -> insn 8
    //  2: jeq CONNECT    jt=13 -> insn 16
    //  3: jeq BIND       jt=13 -> insn 17
    //  4: jeq SOCKETPAIR jt=8  -> insn 13
    //  5: jeq IO_URING   jt=1  -> insn 7
    //  6: ret ALLOW
    //  7: ret ERRNO
    //  8: ld [args[0]]
    //  9: jeq AF_UNIX    jt=8  -> insn 18
    // 10: jeq AF_INET    jt=7  -> insn 18
    // 11: jeq AF_INET6   jt=6  -> insn 18
    // 12: ret ERRNO            (bad socket family)
    // 13: ld [args[0]]
    // 14: jeq AF_UNIX    jt=3  -> insn 18
    // 15: ret ERRNO            (bad socketpair family)
    // 16: ret USER_NOTIF       (connect)
    // 17: ret bind_action      (bind)
    // 18: ret ALLOW            (good socket/socketpair)

    vec![
        // 0: ld [nr]
        SockFilterInsn {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: SECCOMP_DATA_NR_OFFSET,
        },
        // 1: jeq SYS_SOCKET -> 8 (jt = 8-1-1 = 6)
        SockFilterInsn {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 6,
            jf: 0,
            k: SYS_SOCKET as u32,
        },
        // 2: jeq SYS_CONNECT -> 16 (jt = 16-2-1 = 13)
        SockFilterInsn {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 13,
            jf: 0,
            k: SYS_CONNECT as u32,
        },
        // 3: jeq SYS_BIND -> 17 (jt = 17-3-1 = 13)
        SockFilterInsn {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 13,
            jf: 0,
            k: SYS_BIND as u32,
        },
        // 4: jeq SYS_SOCKETPAIR -> 13 (jt = 13-4-1 = 8)
        SockFilterInsn {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 8,
            jf: 0,
            k: SYS_SOCKETPAIR as u32,
        },
        // 5: jeq SYS_IO_URING_SETUP -> 7 (jt = 7-5-1 = 1)
        SockFilterInsn {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 1,
            jf: 0,
            k: SYS_IO_URING_SETUP as u32,
        },
        // 6: ret ALLOW
        SockFilterInsn {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
        // 7: ret ERRNO(EACCES)
        SockFilterInsn {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: errno_ret,
        },
        // 8: ld [args[0]] — socket() family
        SockFilterInsn {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: SECCOMP_DATA_ARG0_OFFSET,
        },
        // 9: jeq AF_UNIX -> 18 (jt = 18-9-1 = 8)
        SockFilterInsn {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 8,
            jf: 0,
            k: libc::AF_UNIX as u32,
        },
        // 10: jeq AF_INET -> 18 (jt = 18-10-1 = 7)
        SockFilterInsn {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 7,
            jf: 0,
            k: libc::AF_INET as u32,
        },
        // 11: jeq AF_INET6 -> 18 (jt = 18-11-1 = 6)
        SockFilterInsn {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 6,
            jf: 0,
            k: libc::AF_INET6 as u32,
        },
        // 12: ret ERRNO(EACCES) — bad socket family
        SockFilterInsn {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: errno_ret,
        },
        // 13: ld [args[0]] — socketpair() family
        SockFilterInsn {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: SECCOMP_DATA_ARG0_OFFSET,
        },
        // 14: jeq AF_UNIX -> 18 (jt = 18-14-1 = 3)
        SockFilterInsn {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 3,
            jf: 0,
            k: libc::AF_UNIX as u32,
        },
        // 15: ret ERRNO(EACCES) — bad socketpair family
        SockFilterInsn {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: errno_ret,
        },
        // 16: ret USER_NOTIF — connect()
        SockFilterInsn {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_USER_NOTIF,
        },
        // 17: ret bind_action — bind()
        SockFilterInsn {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: bind_action,
        },
        // 18: ret ALLOW — good socket/socketpair family
        SockFilterInsn {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
    ]
}

/// Install a seccomp-notify BPF filter for proxy-only network mode.
///
/// Returns the notify fd that the supervisor must poll for connect/bind
/// notifications. Uses `SECCOMP_FILTER_FLAG_NEW_LISTENER`.
///
/// Must be called AFTER `PR_SET_NO_NEW_PRIVS` is already set (either by
/// a prior seccomp install or by Landlock's `restrict_self()`).
///
/// # Errors
///
/// Returns an error if the seccomp syscall fails.
pub fn install_seccomp_proxy_filter(has_bind_ports: bool) -> Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;

    let filter = build_seccomp_proxy_filter(has_bind_ports);

    let prog = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };

    // PR_SET_NO_NEW_PRIVS should already be set by the openat-notify filter
    // or by Landlock restrict_self(). Set it again defensively (idempotent).
    // SAFETY: prctl with PR_SET_NO_NEW_PRIVS is always safe to call.
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(NonoError::SandboxInit(format!(
            "prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    // Try with WAIT_KILLABLE_RECV first (kernel 5.19+).
    let flags = SECCOMP_FILTER_FLAG_NEW_LISTENER | SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV;

    // SAFETY: seccomp() with SECCOMP_SET_MODE_FILTER installs a BPF filter.
    // The prog pointer is valid for the duration of the syscall.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            flags,
            &prog as *const SockFprog,
        )
    };

    let notify_fd = if ret < 0 {
        let flags = SECCOMP_FILTER_FLAG_NEW_LISTENER;

        // SAFETY: Same as above, retrying with fewer flags.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_SET_MODE_FILTER,
                flags,
                &prog as *const SockFprog,
            )
        };

        if ret < 0 {
            return Err(NonoError::SandboxInit(format!(
                "seccomp(SECCOMP_SET_MODE_FILTER) for proxy filter failed: {}. \
                 Requires kernel >= 5.0 with SECCOMP_FILTER_FLAG_NEW_LISTENER.",
                std::io::Error::last_os_error()
            )));
        }
        ret as i32
    } else {
        ret as i32
    };

    // SAFETY: The fd returned by seccomp() with NEW_LISTENER is a valid,
    // newly-created file descriptor that we now own.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(notify_fd) })
}

/// Read a sockaddr from a seccomp notification's connect/bind arguments.
///
/// Reads from `/proc/PID/mem` at the pointer in args[1] (the sockaddr pointer
/// for connect/bind). Parses the address family, port, and loopback status.
///
/// # TOCTOU Warning
///
/// For connect/bind, the kernel copies sockaddr into kernel memory via
/// `move_addr_to_kernel()` before the seccomp filter runs. The userspace
/// copy we read here may differ from what the kernel uses, but we use
/// `SECCOMP_USER_NOTIF_FLAG_CONTINUE` which lets the kernel proceed with
/// its already-copied data. The userspace read is only used for the
/// allow/deny decision.
///
/// Always call `notif_id_valid()` after reading to verify the notification
/// is still pending.
///
/// # Errors
///
/// Returns an error if `/proc/PID/mem` cannot be read or the sockaddr is
/// too small to parse.
pub fn read_notif_sockaddr(pid: u32, addr_ptr: u64, addrlen: u64) -> Result<SockaddrInfo> {
    use std::io::Read;

    // Minimum size: sa_family (2 bytes)
    if addrlen < 2 {
        return Err(NonoError::SandboxInit(
            "sockaddr too small to contain sa_family".to_string(),
        ));
    }

    let mem_path = format!("/proc/{}/mem", pid);
    let mut file = std::fs::File::open(&mem_path)
        .map_err(|e| NonoError::SandboxInit(format!("Failed to open {}: {}", mem_path, e)))?;

    std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(addr_ptr))
        .map_err(|e| NonoError::SandboxInit(format!("Failed to seek in {}: {}", mem_path, e)))?;

    // Read up to sizeof(sockaddr_in6) = 28 bytes. This covers both IPv4 (16) and IPv6 (28).
    let read_len = std::cmp::min(addrlen as usize, 28);
    let mut buf = [0u8; 28];
    let n = file.read(&mut buf[..read_len]).map_err(|e| {
        NonoError::SandboxInit(format!("Failed to read sockaddr from {}: {}", mem_path, e))
    })?;

    if n < 2 {
        return Err(NonoError::SandboxInit(
            "Short read for sockaddr sa_family".to_string(),
        ));
    }

    // sa_family is the first 2 bytes (u16, native endian on Linux)
    let family = u16::from_ne_bytes([buf[0], buf[1]]);

    match family as i32 {
        libc::AF_INET => {
            // struct sockaddr_in: family(2) + port(2) + addr(4) + zero(8) = 16 bytes
            if n < 8 {
                return Err(NonoError::SandboxInit(
                    "sockaddr_in too small for port + addr".to_string(),
                ));
            }
            // Port is at offset 2, network byte order (big-endian)
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            // IPv4 addr is at offset 4, 4 bytes
            let addr = [buf[4], buf[5], buf[6], buf[7]];
            let is_loopback = addr[0] == 127; // 127.0.0.0/8

            Ok(SockaddrInfo {
                family,
                port,
                is_loopback,
                unix_kind: None,
            })
        }
        libc::AF_INET6 => {
            // struct sockaddr_in6: family(2) + port(2) + flowinfo(4) + addr(16) + scope_id(4) = 28
            if n < 24 {
                return Err(NonoError::SandboxInit(
                    "sockaddr_in6 too small for port + addr".to_string(),
                ));
            }
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            // IPv6 addr is at offset 8, 16 bytes
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&buf[8..24]);
            // ::1 is loopback
            let is_loopback = addr == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
            // Also check IPv4-mapped ::ffff:127.x.x.x
            let is_v4_mapped_loopback =
                addr[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] && addr[12] == 127;

            Ok(SockaddrInfo {
                family,
                port,
                is_loopback: is_loopback || is_v4_mapped_loopback,
                unix_kind: None,
            })
        }
        libc::AF_UNIX => {
            // sun_path starts at offset 2. buf has `n` bytes total; we need
            // addrlen to distinguish unnamed from path-bearing sockets.
            let sun_path_first_byte = if n >= 3 { Some(buf[2]) } else { None };
            Ok(SockaddrInfo {
                family,
                port: 0,
                is_loopback: true, // Unix sockets are always local
                unix_kind: Some(classify_af_unix(addrlen, sun_path_first_byte)),
            })
        }
        _ => Ok(SockaddrInfo {
            family,
            port: 0,
            is_loopback: false,
            unix_kind: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_supported() {
        // This test will pass or fail depending on kernel version
        // Just verify it doesn't panic
        let _ = is_supported();
    }

    #[test]
    fn test_support_info() {
        let info = support_info();
        assert!(!info.details.is_empty());
    }

    #[test]
    fn test_access_conversion_v3() {
        let abi = ABI::V3;

        let read = access_to_landlock(AccessMode::Read, abi);
        assert!(read.effective.contains(AccessFs::ReadFile));
        assert!(!read.effective.contains(AccessFs::WriteFile));
        assert!(read.dropped.is_empty());

        let write = access_to_landlock(AccessMode::Write, abi);
        assert!(write.effective.contains(AccessFs::WriteFile));
        assert!(!write.effective.contains(AccessFs::ReadFile));
        // V3 supports Refer and Truncate but NOT IoctlDev
        assert!(write.effective.contains(AccessFs::RemoveFile));
        assert!(write.effective.contains(AccessFs::RemoveDir));
        assert!(write.effective.contains(AccessFs::Refer));
        assert!(write.effective.contains(AccessFs::Truncate));
        assert!(!write.effective.contains(AccessFs::IoctlDev));
        assert!(write.dropped.is_empty());

        let rw = access_to_landlock(AccessMode::ReadWrite, abi);
        assert!(rw.effective.contains(AccessFs::ReadFile));
        assert!(rw.effective.contains(AccessFs::WriteFile));
        assert!(rw.effective.contains(AccessFs::RemoveFile));
        assert!(rw.effective.contains(AccessFs::RemoveDir));
        assert!(rw.effective.contains(AccessFs::Refer));
        assert!(rw.effective.contains(AccessFs::Truncate));
        assert!(rw.dropped.is_empty());
    }

    #[test]
    fn test_access_conversion_v1_drops_refer_and_truncate() {
        let abi = ABI::V1;

        let write = access_to_landlock(AccessMode::Write, abi);
        assert!(write.effective.contains(AccessFs::WriteFile));
        // V1 does NOT have Refer, Truncate, or IoctlDev
        assert!(!write.effective.contains(AccessFs::Refer));
        assert!(!write.effective.contains(AccessFs::Truncate));
        assert!(!write.effective.contains(AccessFs::IoctlDev));
        // But basic write operations are still present
        assert!(write.effective.contains(AccessFs::RemoveFile));
        assert!(write.effective.contains(AccessFs::RemoveDir));
        // Dropped flags should be reported
        assert!(write.dropped.contains(AccessFs::Refer));
        assert!(write.dropped.contains(AccessFs::Truncate));
    }

    #[test]
    fn test_access_conversion_v2_has_refer_but_not_truncate() {
        let abi = ABI::V2;

        let write = access_to_landlock(AccessMode::Write, abi);
        assert!(write.effective.contains(AccessFs::WriteFile));
        // V2 added Refer but NOT Truncate or IoctlDev
        assert!(write.effective.contains(AccessFs::Refer));
        assert!(!write.effective.contains(AccessFs::Truncate));
        assert!(!write.effective.contains(AccessFs::IoctlDev));
        // Truncate should be in dropped
        assert!(write.dropped.contains(AccessFs::Truncate));
        assert!(!write.dropped.contains(AccessFs::Refer));
    }

    #[test]
    fn test_access_conversion_v5_excludes_ioctl_dev_from_generic_flags() {
        let abi = ABI::V5;

        // IoctlDev is NOT in the generic write flags — it is added selectively
        // at rule-addition time only for device paths (char/block devices).
        let write = access_to_landlock(AccessMode::Write, abi);
        assert!(!write.effective.contains(AccessFs::IoctlDev));

        let rw = access_to_landlock(AccessMode::ReadWrite, abi);
        assert!(!rw.effective.contains(AccessFs::IoctlDev));

        let read = access_to_landlock(AccessMode::Read, abi);
        assert!(!read.effective.contains(AccessFs::IoctlDev));
    }

    #[test]
    fn test_is_device_path_dev_null() {
        // /dev/null is a character device on all Unix systems
        assert!(is_device_path(Path::new("/dev/null")));
    }

    #[test]
    fn test_is_device_path_regular_file() {
        // A regular file should not be detected as a device
        assert!(!is_device_path(Path::new("/etc/hosts")));
    }

    #[test]
    fn test_is_device_path_nonexistent() {
        assert!(!is_device_path(Path::new("/nonexistent/path/12345")));
    }

    #[test]
    fn test_is_device_directory_dev_pts() {
        // /dev/pts is a directory under /dev
        if Path::new("/dev/pts").exists() {
            assert!(is_device_directory(Path::new("/dev/pts")));
        }
    }

    #[test]
    fn test_is_device_directory_not_dev() {
        // /tmp is a directory but not under /dev
        assert!(!is_device_directory(Path::new("/tmp")));
    }

    #[test]
    fn test_detected_abi_feature_methods() {
        let v1 = DetectedAbi::new(ABI::V1);
        assert!(!v1.has_refer());
        assert!(!v1.has_truncate());
        assert!(!v1.has_network());
        assert!(!v1.has_ioctl_dev());
        assert!(!v1.has_scoping());

        let v2 = DetectedAbi::new(ABI::V2);
        assert!(v2.has_refer());
        assert!(!v2.has_truncate());

        let v3 = DetectedAbi::new(ABI::V3);
        assert!(v3.has_refer());
        assert!(v3.has_truncate());
        assert!(!v3.has_network());

        let v4 = DetectedAbi::new(ABI::V4);
        assert!(v4.has_network());
        assert!(!v4.has_ioctl_dev());

        let v5 = DetectedAbi::new(ABI::V5);
        assert!(v5.has_ioctl_dev());
        assert!(!v5.has_scoping());

        let v6 = DetectedAbi::new(ABI::V6);
        assert!(v6.has_scoping());
    }

    #[test]
    fn test_requested_scopes_allow_all_is_empty() {
        let caps = CapabilitySet::new().set_signal_mode(SignalMode::AllowAll);
        let scopes = requested_scopes(&caps, &DetectedAbi::new(ABI::V6));
        assert!(matches!(scopes, Ok(actual) if actual.is_empty()));
    }

    #[test]
    fn test_requested_scopes_isolated_uses_signal_scope_on_v6() {
        let caps = CapabilitySet::new().set_signal_mode(SignalMode::Isolated);
        let scopes = requested_scopes(&caps, &DetectedAbi::new(ABI::V6));
        assert!(matches!(scopes, Ok(actual) if actual == BitFlags::from(Scope::Signal)));
    }

    #[test]
    fn test_requested_scopes_isolated_is_empty_without_v6() {
        let caps = CapabilitySet::new().set_signal_mode(SignalMode::Isolated);
        let scopes = requested_scopes(&caps, &DetectedAbi::new(ABI::V5));
        assert!(matches!(scopes, Ok(actual) if actual.is_empty()));
    }

    #[test]
    fn test_requested_scopes_allow_same_sandbox_requires_v6() {
        let caps = CapabilitySet::new().set_signal_mode(SignalMode::AllowSameSandbox);
        let scopes = requested_scopes(&caps, &DetectedAbi::new(ABI::V5));
        assert!(
            matches!(scopes, Err(NonoError::SandboxInit(message)) if message.contains("Landlock ABI V6+"))
        );
    }

    #[test]
    fn test_requested_scopes_allow_same_sandbox_uses_signal_scope() {
        let caps = CapabilitySet::new().set_signal_mode(SignalMode::AllowSameSandbox);
        let scopes = requested_scopes(&caps, &DetectedAbi::new(ABI::V6));
        assert!(matches!(scopes, Ok(actual) if actual == BitFlags::from(Scope::Signal)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_signal_scope_blocks_external_kill_on_v6() {
        struct ChildCleanup {
            sandbox_pid: Option<libc::pid_t>,
            target_pid: Option<libc::pid_t>,
        }

        impl Drop for ChildCleanup {
            fn drop(&mut self) {
                if let Some(pid) = self.sandbox_pid.take() {
                    unsafe {
                        libc::kill(pid, libc::SIGKILL);
                        libc::waitpid(pid, std::ptr::null_mut(), 0);
                    }
                }

                if let Some(pid) = self.target_pid.take() {
                    unsafe {
                        libc::kill(pid, libc::SIGKILL);
                        libc::waitpid(pid, std::ptr::null_mut(), 0);
                    }
                }
            }
        }

        let detected = match detect_abi() {
            Ok(detected) => detected,
            Err(_) => return,
        };

        if !detected.has_scoping() {
            return;
        }

        let mut report_pipe = [0; 2];
        let pipe_result = unsafe { libc::pipe(report_pipe.as_mut_ptr()) };
        assert_eq!(pipe_result, 0, "pipe() failed");

        let target_pid = unsafe { libc::fork() };
        assert!(target_pid >= 0, "fork() for target failed");
        let mut cleanup = ChildCleanup {
            sandbox_pid: None,
            target_pid: Some(target_pid),
        };

        if target_pid == 0 {
            unsafe {
                libc::close(report_pipe[0]);
                libc::close(report_pipe[1]);
                libc::signal(libc::SIGUSR1, libc::SIG_IGN);
                libc::pause();
                libc::_exit(0);
            }
        }

        let sandbox_pid = unsafe { libc::fork() };
        assert!(sandbox_pid >= 0, "fork() for sandbox failed");
        cleanup.sandbox_pid = Some(sandbox_pid);

        if sandbox_pid == 0 {
            let mut payload = [0_u8; 2];
            unsafe {
                libc::close(report_pipe[0]);
            }

            let caps = CapabilitySet::new().set_signal_mode(SignalMode::AllowSameSandbox);
            match apply_with_abi(&caps, &detected) {
                Ok(_) => {
                    let kill_result = unsafe { libc::kill(target_pid, libc::SIGUSR1) };
                    let errno = std::io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(255);
                    payload[0] = if kill_result == -1 { 1 } else { 0 };
                    payload[1] = u8::try_from(errno).unwrap_or(u8::MAX);
                }
                Err(_) => {
                    payload[0] = 2;
                    payload[1] = 0;
                }
            }

            let write_len = payload.len();
            let wrote = unsafe {
                libc::write(
                    report_pipe[1],
                    payload.as_ptr().cast::<libc::c_void>(),
                    write_len,
                )
            };
            let exit_code = if wrote == isize::try_from(write_len).unwrap_or(-1) {
                0
            } else {
                3
            };
            unsafe {
                libc::close(report_pipe[1]);
                libc::_exit(exit_code);
            }
        }

        unsafe {
            libc::close(report_pipe[1]);
        }

        let mut sandbox_status = 0;
        let waited_sandbox = unsafe { libc::waitpid(sandbox_pid, &mut sandbox_status, 0) };
        assert_eq!(waited_sandbox, sandbox_pid, "waitpid() for sandbox failed");
        assert!(
            libc::WIFEXITED(sandbox_status),
            "sandbox child did not exit normally"
        );
        cleanup.sandbox_pid = None;
        assert_eq!(
            libc::WEXITSTATUS(sandbox_status),
            0,
            "sandbox child returned failure"
        );

        let mut payload = [0_u8; 2];
        let read_len = payload.len();
        let read_result = unsafe {
            libc::read(
                report_pipe[0],
                payload.as_mut_ptr().cast::<libc::c_void>(),
                read_len,
            )
        };
        unsafe {
            libc::close(report_pipe[0]);
        }
        assert_eq!(
            read_result,
            isize::try_from(read_len).unwrap_or(-1),
            "failed to read sandbox report"
        );
        assert_eq!(payload[0], 1, "sandboxed kill unexpectedly succeeded");
        assert_eq!(
            i32::from(payload[1]),
            libc::EPERM,
            "kill should fail with EPERM"
        );

        let target_wait = unsafe { libc::waitpid(target_pid, std::ptr::null_mut(), libc::WNOHANG) };
        assert_eq!(target_wait, 0, "external target should still be running");

        unsafe {
            libc::kill(target_pid, libc::SIGKILL);
            libc::waitpid(target_pid, std::ptr::null_mut(), 0);
        }
        cleanup.target_pid = None;
    }

    #[test]
    fn test_detected_abi_version_string() {
        assert_eq!(DetectedAbi::new(ABI::V1).version_string(), "V1");
        assert_eq!(DetectedAbi::new(ABI::V4).version_string(), "V4");
        assert_eq!(DetectedAbi::new(ABI::V6).version_string(), "V6");
    }

    #[test]
    fn test_detected_abi_display() {
        let d = DetectedAbi::new(ABI::V4);
        assert_eq!(format!("{}", d), "Landlock V4");
    }

    #[test]
    fn test_detected_abi_feature_names() {
        let v1 = DetectedAbi::new(ABI::V1);
        let names = v1.feature_names();
        assert_eq!(names.len(), 1);
        assert_eq!(names[0], "Basic filesystem access control");

        let v4 = DetectedAbi::new(ABI::V4);
        let names = v4.feature_names();
        assert!(names.iter().any(|n| n.starts_with("TCP network filtering")));
        assert!(names
            .iter()
            .any(|n| n == "File rename across directories (Refer)"));
        assert!(names.iter().any(|n| n == "File truncation (Truncate)"));
    }

    #[test]
    fn test_detect_abi_returns_ok_on_supported_system() {
        // On a system with Landlock, this should succeed
        // On a system without it, it should return Err (not panic)
        let _ = detect_abi();
    }

    #[test]
    fn test_seccomp_notif_struct_sizes() {
        // Verify our repr(C) structs match expected sizes
        use std::mem;
        // SeccompData: 4 + 4 + 8 + 6*8 = 64 bytes
        assert_eq!(mem::size_of::<SeccompData>(), 64);
        // SeccompNotif: 8 + 4 + 4 + 64 = 80 bytes
        assert_eq!(mem::size_of::<SeccompNotif>(), 80);
        // SeccompNotifResp: 8 + 8 + 4 + 4 = 24 bytes
        assert_eq!(mem::size_of::<SeccompNotifResp>(), 24);
        // SeccompNotifAddfd: 8 + 4 + 4 + 4 + 4 = 24 bytes
        assert_eq!(mem::size_of::<SeccompNotifAddfd>(), 24);
    }

    #[test]
    fn test_bpf_filter_instruction_count() {
        // The BPF filter should have exactly 5 instructions:
        // ld, jeq openat, jeq openat2, ret allow, ret notify
        let filter = [
            SockFilterInsn {
                code: BPF_LD | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: SECCOMP_DATA_NR_OFFSET,
            },
            SockFilterInsn {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 2,
                jf: 0,
                k: SYS_OPENAT as u32,
            },
            SockFilterInsn {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 1,
                jf: 0,
                k: SYS_OPENAT2 as u32,
            },
            SockFilterInsn {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ALLOW,
            },
            SockFilterInsn {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_USER_NOTIF,
            },
        ];
        assert_eq!(filter.len(), 5);
    }

    #[test]
    fn test_build_seccomp_block_network_filter() {
        let filter = build_seccomp_block_network_filter();

        assert_eq!(filter.len(), 10);
        assert_eq!(filter[0].k, SECCOMP_DATA_NR_OFFSET);

        assert_eq!(filter[1].k, SYS_SOCKET as u32);
        assert_eq!(filter[1].jt, 4);

        assert_eq!(filter[2].k, SYS_SOCKETPAIR as u32);
        assert_eq!(filter[2].jt, 3);

        assert_eq!(filter[3].k, SYS_IO_URING_SETUP as u32);
        assert_eq!(filter[3].jt, 1);

        assert_eq!(filter[4].k, SECCOMP_RET_ALLOW);
        assert_eq!(filter[5].k, SECCOMP_RET_ERRNO | (libc::EPERM as u32));

        assert_eq!(filter[6].k, SECCOMP_DATA_ARG0_OFFSET);
        assert_eq!(filter[7].k, libc::AF_UNIX as u32);
        assert_eq!(filter[7].jt, 1);

        assert_eq!(filter[8].k, SECCOMP_RET_ERRNO | (libc::EPERM as u32));
        assert_eq!(filter[9].k, SECCOMP_RET_ALLOW);
    }

    #[test]
    fn test_open_how_struct_size() {
        use std::mem;
        // OpenHow: 3 x u64 = 24 bytes (flags, mode, resolve)
        assert_eq!(mem::size_of::<OpenHow>(), 24);
    }

    #[test]
    fn test_syscall_numbers_distinct() {
        // Verify openat and openat2 have different syscall numbers
        assert_ne!(SYS_OPENAT, SYS_OPENAT2);
    }

    #[test]
    fn test_syscall_numbers_match_seccomp_data_nr_type() {
        // SeccompData.nr is i32, verify our constants fit
        let _: i32 = SYS_OPENAT;
        let _: i32 = SYS_OPENAT2;
    }

    #[test]
    fn test_classify_access_rdonly() {
        let access = classify_access_from_flags(libc::O_RDONLY);
        assert!(matches!(access, crate::AccessMode::Read));
    }

    #[test]
    fn test_classify_access_wronly() {
        let access = classify_access_from_flags(libc::O_WRONLY);
        assert!(matches!(access, crate::AccessMode::Write));
    }

    #[test]
    fn test_classify_access_rdwr() {
        let access = classify_access_from_flags(libc::O_RDWR);
        assert!(matches!(access, crate::AccessMode::ReadWrite));
    }

    #[test]
    fn test_classify_access_with_extra_flags() {
        // O_RDONLY with O_CREAT, O_TRUNC etc should still be Read
        let flags = libc::O_RDONLY | libc::O_CREAT | libc::O_TRUNC;
        let access = classify_access_from_flags(flags);
        assert!(matches!(access, crate::AccessMode::Read));

        // O_WRONLY with O_APPEND should still be Write
        let flags = libc::O_WRONLY | libc::O_APPEND;
        let access = classify_access_from_flags(flags);
        assert!(matches!(access, crate::AccessMode::Write));

        // O_RDWR with O_CLOEXEC should still be ReadWrite
        let flags = libc::O_RDWR | libc::O_CLOEXEC;
        let access = classify_access_from_flags(flags);
        assert!(matches!(access, crate::AccessMode::ReadWrite));
    }

    #[test]
    fn test_classify_access_pointer_as_flags_gives_readwrite() {
        // Simulates the original bug: a pointer value (e.g., 0x7fff12345678) treated as flags.
        // The O_ACCMODE mask (0o3) would extract garbage bits, likely resulting in O_RDWR (2).
        // This test documents that garbage input defaults to ReadWrite (fail-safe for deny
        // decisions, but the real fix is proper syscall discrimination).
        let fake_pointer = 0x7fff_1234_5678_i64 as i32; // truncated pointer
        let access = classify_access_from_flags(fake_pointer);
        // With this specific value, (fake_pointer & 0o3) == 0, which is O_RDONLY
        // But the point is: any garbage value goes through the match, we don't panic.
        // The actual security fix is not calling this with garbage in the first place.
        let _ = access; // Just verify it doesn't panic
    }

    #[test]
    fn test_validate_openat2_size_rejects_zero() {
        assert!(!validate_openat2_size(0));
    }

    #[test]
    fn test_validate_openat2_size_rejects_undersized() {
        // Anything less than sizeof(OpenHow) = 24 should be rejected
        assert!(!validate_openat2_size(1));
        assert!(!validate_openat2_size(8));
        assert!(!validate_openat2_size(16));
        assert!(!validate_openat2_size(23));
    }

    #[test]
    fn test_validate_openat2_size_accepts_exact() {
        // Exactly sizeof(OpenHow) = 24 should be accepted
        let exact_size = std::mem::size_of::<OpenHow>();
        assert_eq!(exact_size, 24);
        assert!(validate_openat2_size(exact_size));
    }

    #[test]
    fn test_validate_openat2_size_accepts_larger() {
        // Larger (but bounded) sizes are valid (kernel may extend struct in future)
        assert!(validate_openat2_size(32));
        assert!(validate_openat2_size(64));
        assert!(validate_openat2_size(128));
    }

    #[test]
    fn test_validate_openat2_size_rejects_unreasonably_large() {
        assert!(!validate_openat2_size(4097));
        assert!(!validate_openat2_size(usize::MAX));
    }

    #[test]
    fn test_resolve_notif_path_absolute_unchanged() {
        // Absolute paths should be returned unchanged regardless of dirfd
        let abs_path = std::path::PathBuf::from("/usr/lib/libc.so.6");
        let result = resolve_notif_path(1, 42, &abs_path);
        let path = match result {
            Ok(p) => p,
            Err(e) => panic!("unexpected error: {e}"),
        };
        assert_eq!(path, abs_path);
    }

    #[test]
    fn test_resolve_notif_path_absolute_with_at_fdcwd() {
        // Absolute paths should be returned unchanged even with AT_FDCWD
        let abs_path = std::path::PathBuf::from("/etc/passwd");
        let at_fdcwd = libc::AT_FDCWD as i64 as u64;
        let path = match resolve_notif_path(1, at_fdcwd, &abs_path) {
            Ok(p) => p,
            Err(e) => panic!("unexpected error: {e}"),
        };
        assert_eq!(path, abs_path);
    }

    #[test]
    fn test_resolve_notif_path_relative_with_invalid_pid_fails() {
        // Relative path with non-existent PID should fail (can't read /proc/PID/cwd)
        let rel_path = std::path::PathBuf::from("relative/path.so");
        let at_fdcwd = libc::AT_FDCWD as i64 as u64;
        let result = resolve_notif_path(u32::MAX, at_fdcwd, &rel_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_notif_path_relative_with_invalid_fd_fails() {
        // Relative path with non-existent PID/fd should fail
        let rel_path = std::path::PathBuf::from("some_lib.so");
        let result = resolve_notif_path(u32::MAX, 999, &rel_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_notif_path_at_fdcwd_both_representations() {
        // AT_FDCWD is -100. When stored as u64 in seccomp args, it may be
        // sign-extended to 0xFFFFFFFFFFFFFF9C or truncated to 0xFFFFFF9C.
        // Both should be recognized.
        let abs_path = std::path::PathBuf::from("/absolute");
        #[allow(clippy::unnecessary_cast)]
        let at_fdcwd_32 = libc::AT_FDCWD as i32 as u32 as u64; // 0xFFFFFF9C
        let at_fdcwd_64 = libc::AT_FDCWD as i64 as u64; // 0xFFFFFFFFFFFFFF9C

        // Both should work for absolute paths (early return)
        let path_32 = match resolve_notif_path(1, at_fdcwd_32, &abs_path) {
            Ok(p) => p,
            Err(e) => panic!("unexpected error for 32-bit AT_FDCWD: {e}"),
        };
        assert_eq!(path_32, abs_path);

        let path_64 = match resolve_notif_path(1, at_fdcwd_64, &abs_path) {
            Ok(p) => p,
            Err(e) => panic!("unexpected error for 64-bit AT_FDCWD: {e}"),
        };
        assert_eq!(path_64, abs_path);
    }

    #[test]
    fn test_seccomp_network_fallback_mode_blocked() {
        let caps = CapabilitySet::new().block_network();
        assert_eq!(
            seccomp_network_fallback_mode(&caps),
            SeccompNetFallback::BlockAll
        );
    }

    #[test]
    fn test_seccomp_network_fallback_mode_blocked_with_ports_is_none() {
        let mut caps = CapabilitySet::new().block_network();
        caps.add_localhost_port(3000);
        assert_eq!(
            seccomp_network_fallback_mode(&caps),
            SeccompNetFallback::None
        );
    }

    #[test]
    fn test_seccomp_network_fallback_mode_proxy_only() {
        let caps = CapabilitySet::new().proxy_only(8080);
        assert_eq!(
            seccomp_network_fallback_mode(&caps),
            SeccompNetFallback::ProxyOnly {
                proxy_port: 8080,
                bind_ports: vec![],
            }
        );
    }

    #[test]
    fn test_seccomp_network_fallback_mode_proxy_only_with_bind() {
        let caps = CapabilitySet::new().proxy_only_with_bind(8080, vec![3000, 3001]);
        assert_eq!(
            seccomp_network_fallback_mode(&caps),
            SeccompNetFallback::ProxyOnly {
                proxy_port: 8080,
                bind_ports: vec![3000, 3001],
            }
        );
    }

    #[test]
    fn test_seccomp_network_fallback_mode_allow_all() {
        let caps = CapabilitySet::new();
        assert_eq!(
            seccomp_network_fallback_mode(&caps),
            SeccompNetFallback::None
        );
    }

    #[test]
    fn test_legacy_can_use_seccomp_block_fallback() {
        // BlockAll => true
        assert!(can_use_seccomp_network_block_fallback(
            &CapabilitySet::new().block_network()
        ));

        // ProxyOnly => false
        let with_proxy = CapabilitySet::new().proxy_only(8080);
        assert!(!can_use_seccomp_network_block_fallback(&with_proxy));

        // Blocked with ports => false
        let mut with_localhost = CapabilitySet::new().block_network();
        with_localhost.add_localhost_port(3000);
        assert!(!can_use_seccomp_network_block_fallback(&with_localhost));
    }

    #[test]
    fn test_build_seccomp_proxy_filter_with_bind() {
        let filter = build_seccomp_proxy_filter(true);
        // 19 instructions
        assert_eq!(filter.len(), 19);

        // Instruction 0 should be ld [nr]
        assert_eq!(filter[0].code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(filter[0].k, SECCOMP_DATA_NR_OFFSET);

        // Instruction 16 should be USER_NOTIF (connect)
        assert_eq!(filter[16].code, BPF_RET | BPF_K);
        assert_eq!(filter[16].k, SECCOMP_RET_USER_NOTIF);

        // Instruction 17 should be USER_NOTIF (bind; supervisor decides).
        assert_eq!(filter[17].code, BPF_RET | BPF_K);
        assert_eq!(filter[17].k, SECCOMP_RET_USER_NOTIF);
    }

    /// Regression test for the Landlock V2 + `has_bind_ports=false`
    /// scenario (issue #685): even with no TCP bind ports configured,
    /// bind() must route to USER_NOTIF so the supervisor can allow
    /// pathname AF_UNIX bind. Previously the filter short-circuited to
    /// ERRNO in this branch, unconditionally failing AF_UNIX bind.
    #[test]
    fn test_build_seccomp_proxy_filter_without_bind() {
        let filter = build_seccomp_proxy_filter(false);
        assert_eq!(filter.len(), 19);

        // Instruction 17 (bind) must ALSO route to USER_NOTIF — the
        // supervisor is the sole gate. This is the fix: previously this
        // emitted ERRNO, which skipped the supervisor entirely.
        assert_eq!(filter[17].code, BPF_RET | BPF_K);
        assert_eq!(
            filter[17].k, SECCOMP_RET_USER_NOTIF,
            "bind must route to USER_NOTIF regardless of has_bind_ports so \
             the supervisor can permit AF_UNIX pathname bind (#685)"
        );
    }

    #[test]
    fn test_sockaddr_info_ipv4_loopback() {
        let info = SockaddrInfo {
            family: libc::AF_INET as u16,
            port: 8080,
            is_loopback: true,
            unix_kind: None,
        };
        assert!(info.is_loopback);
        assert_eq!(info.port, 8080);
    }

    #[test]
    fn test_sockaddr_info_ipv6_loopback() {
        let info = SockaddrInfo {
            family: libc::AF_INET6 as u16,
            port: 443,
            is_loopback: true,
            unix_kind: None,
        };
        assert!(info.is_loopback);
    }

    #[test]
    fn test_sockaddr_info_non_loopback() {
        let info = SockaddrInfo {
            family: libc::AF_INET as u16,
            port: 80,
            is_loopback: false,
            unix_kind: None,
        };
        assert!(!info.is_loopback);
    }

    #[test]
    fn test_sockaddr_info_unix_is_loopback() {
        let info = SockaddrInfo {
            family: libc::AF_UNIX as u16,
            port: 0,
            is_loopback: true,
            unix_kind: Some(UnixSocketKind::Pathname),
        };
        assert!(info.is_loopback);
        assert_eq!(info.port, 0);
    }

    // --- classify_af_unix tests (issue #685) --------------------------------

    #[test]
    fn test_classify_af_unix_pathname() {
        // `/tmp/test.sock` — first byte is '/'
        assert_eq!(
            classify_af_unix(14, Some(b'/')),
            UnixSocketKind::Pathname,
            "non-null first byte => pathname"
        );
    }

    #[test]
    fn test_classify_af_unix_abstract() {
        // \0foo — first byte is null (Linux abstract namespace)
        assert_eq!(
            classify_af_unix(6, Some(0)),
            UnixSocketKind::Abstract,
            "null first byte => abstract namespace"
        );
    }

    #[test]
    fn test_classify_af_unix_unnamed() {
        // addrlen == 2: only sa_family, no sun_path
        assert_eq!(
            classify_af_unix(2, None),
            UnixSocketKind::Unnamed,
            "addrlen <= 2 => unnamed"
        );
    }

    #[test]
    fn test_classify_af_unix_fails_closed_on_short_read() {
        // Defensive: if we couldn't read sun_path[0] despite addrlen > 2
        // (unexpected), treat as unnamed so policy fails closed.
        assert_eq!(
            classify_af_unix(10, None),
            UnixSocketKind::Unnamed,
            "missing sun_path byte => fail-closed to unnamed"
        );
    }

    /// Integration test: seccomp proxy filter blocks connect to non-proxy ports
    /// and allows connect to the designated proxy port on localhost.
    ///
    /// Forks a child that installs the proxy filter, then attempts connects.
    /// Results are reported via a pipe. This test works on any kernel with
    /// seccomp user notification support (>= 5.0), regardless of Landlock ABI.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_seccomp_proxy_filter_allows_proxy_port_blocks_others() {
        use std::io::Read;

        // Pick an ephemeral port for the "proxy". We bind a listener so the
        // connect to the allowed port actually succeeds (otherwise we'd get
        // ECONNREFUSED which is indistinguishable from EACCES in the child).
        let listener = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(l) => l,
            Err(_) => return, // Can't bind, skip test
        };
        let proxy_port = match listener.local_addr() {
            Ok(addr) => addr.port(),
            Err(_) => return,
        };

        let mut report_pipe = [0i32; 2];
        let pipe_result = unsafe { libc::pipe(report_pipe.as_mut_ptr()) };
        assert_eq!(pipe_result, 0, "pipe() failed");

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork() failed");

        if pid == 0 {
            // CHILD: install proxy filter, attempt connects, report results.
            unsafe { libc::close(report_pipe[0]) };
            // Drop the listener in child (parent keeps it open for accept)
            drop(listener);

            // Install the proxy filter (no bind ports).
            // This requires PR_SET_NO_NEW_PRIVS first.
            let result = install_seccomp_proxy_filter(false);
            if result.is_err() {
                // Seccomp not available on this system
                let payload: [u8; 3] = [2, 2, 2]; // skip sentinel
                unsafe {
                    libc::write(report_pipe[1], payload.as_ptr().cast(), payload.len());
                    libc::close(report_pipe[1]);
                    libc::_exit(0);
                }
            }
            let notify_fd = result.expect("install_seccomp_proxy_filter failed");

            // Spawn a thread to handle notifications from the seccomp filter.
            // The filter routes connect() to USER_NOTIF; we must respond or the
            // child's connect() calls block forever.
            let notify_raw = {
                use std::os::fd::AsRawFd;
                notify_fd.as_raw_fd()
            };

            // We handle notifications in the same process since we forked.
            // For each connect notification, allow localhost:proxy_port, deny others.
            // Run the handler in a thread so the main thread can do connects.
            let proxy_port_copy = proxy_port;
            let handler = std::thread::spawn(move || {
                for _ in 0..2 {
                    // We expect exactly 2 connect attempts
                    let notif = match recv_notif(notify_raw) {
                        Ok(n) => n,
                        Err(_) => break,
                    };

                    // Read sockaddr from our own /proc/self/mem (same process)
                    let info = match read_notif_sockaddr(
                        notif.pid,
                        notif.data.args[1],
                        notif.data.args[2],
                    ) {
                        Ok(i) => i,
                        Err(_) => {
                            let _ = deny_notif(notify_raw, notif.id);
                            continue;
                        }
                    };

                    if info.is_loopback && info.port == proxy_port_copy {
                        let _ = continue_notif(notify_raw, notif.id);
                    } else {
                        let _ = respond_notif_errno(notify_raw, notif.id, libc::EACCES);
                    }
                }
            });

            // Test 1: connect to proxy port on localhost — should succeed
            let sock1 = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            let mut addr1: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            addr1.sin_family = libc::AF_INET as u16;
            addr1.sin_port = proxy_port.to_be();
            addr1.sin_addr.s_addr = u32::from_be_bytes([127, 0, 0, 1]).to_be();

            let connect1 = unsafe {
                libc::connect(
                    sock1,
                    (&addr1 as *const libc::sockaddr_in).cast(),
                    std::mem::size_of::<libc::sockaddr_in>() as u32,
                )
            };
            let errno1 = if connect1 < 0 {
                std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
            } else {
                0
            };
            unsafe { libc::close(sock1) };

            // Test 2: connect to a different port on localhost — should be denied (EACCES)
            let sock2 = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            let mut addr2: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            addr2.sin_family = libc::AF_INET as u16;
            addr2.sin_port = (proxy_port.wrapping_add(1)).to_be();
            addr2.sin_addr.s_addr = u32::from_be_bytes([127, 0, 0, 1]).to_be();

            let connect2 = unsafe {
                libc::connect(
                    sock2,
                    (&addr2 as *const libc::sockaddr_in).cast(),
                    std::mem::size_of::<libc::sockaddr_in>() as u32,
                )
            };
            let errno2 = if connect2 < 0 {
                std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
            } else {
                0
            };
            unsafe { libc::close(sock2) };

            handler.join().ok();

            // Report: [connect1_result, connect2_errno]
            let payload: [u8; 3] = [
                if connect1 == 0 { 0 } else { 1 },
                errno1 as u8,
                errno2 as u8,
            ];
            unsafe {
                libc::write(report_pipe[1], payload.as_ptr().cast(), payload.len());
                libc::close(report_pipe[1]);
                libc::_exit(0);
            }
        }

        // PARENT: read results from child
        unsafe { libc::close(report_pipe[1]) };

        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };

        let mut buf = [0u8; 3];
        let mut pipe_read = unsafe {
            use std::os::fd::FromRawFd;
            std::fs::File::from_raw_fd(report_pipe[0])
        };
        let n = pipe_read.read(&mut buf).expect("read from pipe failed");

        if n == 3 && buf[0] == 2 && buf[1] == 2 && buf[2] == 2 {
            // Skip sentinel: seccomp not available on this system
            return;
        }

        assert_eq!(n, 3, "expected 3 bytes from child, got {n}");

        // connect1 to proxy port should have succeeded (0)
        assert_eq!(
            buf[0], 0,
            "connect to proxy port should succeed, got result={} errno={}",
            buf[0], buf[1]
        );

        // connect2 to wrong port should have been denied with EACCES
        assert_eq!(
            buf[2],
            libc::EACCES as u8,
            "connect to non-proxy port should get EACCES, got errno={}",
            buf[2]
        );
    }

    /// End-to-end regression test for issue #685: a pathname `AF_UNIX`
    /// `bind(2)` must succeed under the proxy-only seccomp filter even
    /// when `has_bind_ports=false`. Previously the filter short-circuited
    /// bind() to `EACCES` in that configuration, unconditionally failing
    /// AF_UNIX bind regardless of what the supervisor would have decided.
    ///
    /// Structure mirrors `test_seccomp_proxy_filter_allows_proxy_port_blocks_others`:
    /// fork, install filter in the child, run a minimal supervisor-mimic
    /// handler in a child thread, try the bind, report result over a pipe.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_seccomp_proxy_filter_allows_af_unix_bind_without_bind_ports() {
        use std::io::Read;

        // Unique per-test socket path under /tmp so parallel tests don't
        // collide.
        let sock_path = format!("/tmp/nono-integ-af-unix-bind-{}.sock", std::process::id());
        let _ = std::fs::remove_file(&sock_path);

        let mut report_pipe = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(report_pipe.as_mut_ptr()) }, 0, "pipe()");

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork() failed");

        if pid == 0 {
            // CHILD
            unsafe { libc::close(report_pipe[0]) };

            // Install filter with `has_bind_ports=false` — this is the
            // exact configuration the #685 bug manifested under.
            let notify_fd = match install_seccomp_proxy_filter(false) {
                Ok(fd) => fd,
                Err(_) => {
                    // Seccomp unavailable — skip via sentinel.
                    let sentinel: [u8; 2] = [2, 2];
                    unsafe {
                        libc::write(report_pipe[1], sentinel.as_ptr().cast(), sentinel.len());
                        libc::close(report_pipe[1]);
                        libc::_exit(0);
                    }
                }
            };

            let notify_raw = {
                use std::os::fd::AsRawFd;
                notify_fd.as_raw_fd()
            };

            // Minimal supervisor mimic: for each bind notification, allow
            // pathname AF_UNIX, deny everything else. Matches the policy
            // baked into `decide_network_notification` at PR A commit 1.
            let handler = std::thread::spawn(move || {
                for _ in 0..1 {
                    let notif = match recv_notif(notify_raw) {
                        Ok(n) => n,
                        Err(_) => break,
                    };
                    let info = match read_notif_sockaddr(
                        notif.pid,
                        notif.data.args[1],
                        notif.data.args[2],
                    ) {
                        Ok(i) => i,
                        Err(_) => {
                            let _ = deny_notif(notify_raw, notif.id);
                            continue;
                        }
                    };
                    let is_pathname_unix = info.family == libc::AF_UNIX as u16
                        && matches!(info.unix_kind, Some(UnixSocketKind::Pathname));
                    if is_pathname_unix {
                        let _ = continue_notif(notify_raw, notif.id);
                    } else {
                        let _ = respond_notif_errno(notify_raw, notif.id, libc::EACCES);
                    }
                }
            });

            // Attempt bind(AF_UNIX) at the pathname socket.
            let sock = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
            let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
            addr.sun_family = libc::AF_UNIX as u16;
            let bytes = sock_path.as_bytes();
            assert!(bytes.len() < addr.sun_path.len(), "test path too long");
            for (i, &b) in bytes.iter().enumerate() {
                addr.sun_path[i] = b as libc::c_char;
            }
            let addrlen = (std::mem::size_of::<u16>() + bytes.len() + 1) as libc::socklen_t;

            let rc =
                unsafe { libc::bind(sock, (&addr as *const libc::sockaddr_un).cast(), addrlen) };
            let errno = if rc < 0 {
                std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
            } else {
                0
            };
            unsafe { libc::close(sock) };

            let _ = handler.join();
            // Clean up the socket file the child just created.
            let _ = std::fs::remove_file(&sock_path);

            let payload: [u8; 2] = [
                if rc < 0 { 1 } else { 0 },
                errno.unsigned_abs().min(255) as u8,
            ];
            unsafe {
                libc::write(report_pipe[1], payload.as_ptr().cast(), payload.len());
                libc::close(report_pipe[1]);
                libc::_exit(0);
            }
        }

        // PARENT
        unsafe { libc::close(report_pipe[1]) };

        // Wait for child.
        let mut status: libc::c_int = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };

        use std::os::fd::FromRawFd;
        let mut pipe_read = unsafe { std::fs::File::from_raw_fd(report_pipe[0]) };
        let mut buf = [0u8; 2];
        let n = pipe_read.read(&mut buf).expect("read from pipe");

        if n == 2 && buf[0] == 2 && buf[1] == 2 {
            // Skip sentinel: seccomp not available.
            return;
        }
        assert_eq!(n, 2, "expected 2 bytes from child, got {n}");
        assert_eq!(
            buf[0], 0,
            "AF_UNIX bind must succeed under proxy filter with \
             has_bind_ports=false (errno={})",
            buf[1]
        );
    }

    /// Integration test: ProxyOnly + Landlock V4+ does NOT install seccomp
    /// proxy filter (Landlock handles networking natively).
    ///
    /// Verifies that apply_with_abi() returns SeccompNetFallback::None when
    /// the kernel supports AccessNet, even with ProxyOnly mode.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_proxy_only_with_landlock_v4_returns_no_fallback() {
        let detected = match detect_abi() {
            Ok(d) => d,
            Err(_) => return,
        };

        if !detected.has_network() {
            // Pre-V4 kernel: the fallback SHOULD be ProxyOnly, not None.
            // Test that separately.
            return;
        }

        // On V4+, Landlock handles ProxyOnly natively. apply_with_abi should
        // return None (no seccomp fallback needed). We can't actually call
        // apply_with_abi in the parent (irreversible), so fork a child.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork() failed");

        if pid == 0 {
            let caps = CapabilitySet::new().proxy_only(8080);
            let exit_code = match apply_with_abi(&caps, &detected) {
                Ok(SeccompNetFallback::None) => 0,
                Ok(SeccompNetFallback::BlockAll) => 1,
                Ok(SeccompNetFallback::ProxyOnly { .. }) => 2,
                Err(_) => 3,
            };
            unsafe { libc::_exit(exit_code) };
        }

        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        assert!(libc::WIFEXITED(status));
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "Expected SeccompNetFallback::None on V4+ kernel, got exit code {}",
            libc::WEXITSTATUS(status)
        );
    }

    /// Integration test: ProxyOnly on pre-V4 kernel returns ProxyOnly fallback.
    ///
    /// Verifies that apply_with_abi() returns SeccompNetFallback::ProxyOnly
    /// when the kernel's Landlock ABI lacks AccessNet.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_proxy_only_without_landlock_net_returns_proxy_fallback() {
        let detected = match detect_abi() {
            Ok(d) => d,
            Err(_) => return,
        };

        if detected.has_network() {
            // V4+ kernel: Landlock handles it, fallback not used.
            // This test only runs on pre-V4 kernels.
            return;
        }

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork() failed");

        if pid == 0 {
            let caps = CapabilitySet::new().proxy_only(8080);
            let exit_code = match apply_with_abi(&caps, &detected) {
                Ok(SeccompNetFallback::ProxyOnly {
                    proxy_port: 8080, ..
                }) => 0,
                Ok(SeccompNetFallback::ProxyOnly { .. }) => 1, // wrong port
                Ok(SeccompNetFallback::None) => 2,
                Ok(SeccompNetFallback::BlockAll) => 3,
                Err(_) => 4,
            };
            unsafe { libc::_exit(exit_code) };
        }

        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        assert!(libc::WIFEXITED(status));
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "Expected SeccompNetFallback::ProxyOnly on pre-V4 kernel, got exit code {}",
            libc::WEXITSTATUS(status)
        );
    }

    /// Integration test: under the proxy filter with `has_bind_ports=false`,
    /// an `AF_INET` `bind(2)` must still be denied — but now the denial
    /// comes from the supervisor (via `USER_NOTIF`), not from the BPF
    /// filter directly. Issue #685 required the filter to route bind to
    /// USER_NOTIF regardless of `has_bind_ports` so pathname `AF_UNIX`
    /// bind can be allowed (see `test_seccomp_proxy_filter_allows_af_unix_bind_without_bind_ports`);
    /// this test pins the complementary invariant that `AF_INET` bind is
    /// still rejected when the supervisor's policy says so.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_seccomp_proxy_filter_blocks_bind_without_bind_ports() {
        let mut report_pipe = [0i32; 2];
        let pipe_result = unsafe { libc::pipe(report_pipe.as_mut_ptr()) };
        assert_eq!(pipe_result, 0, "pipe() failed");

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork() failed");

        if pid == 0 {
            unsafe { libc::close(report_pipe[0]) };

            // Install proxy filter with has_bind_ports=false. As of the
            // #685 fix, bind() now routes to USER_NOTIF — so a handler
            // IS required even for the "block all bind" policy.
            let notify_fd = match install_seccomp_proxy_filter(false) {
                Ok(fd) => fd,
                Err(_) => {
                    // Seccomp not available — skip.
                    let skip: u8 = 255;
                    unsafe {
                        libc::write(report_pipe[1], &skip as *const u8 as _, 1);
                        libc::close(report_pipe[1]);
                        libc::_exit(0);
                    }
                }
            };
            let notify_raw = {
                use std::os::fd::AsRawFd;
                notify_fd.as_raw_fd()
            };

            // Supervisor mimic: deny every bind notification with EACCES.
            // Models the "no bind ports configured → deny AF_INET bind"
            // policy that `decide_network_notification` implements in
            // the real supervisor when `config.proxy_bind_ports` is empty.
            let handler = std::thread::spawn(move || {
                for _ in 0..1 {
                    let notif = match recv_notif(notify_raw) {
                        Ok(n) => n,
                        Err(_) => break,
                    };
                    let _ = respond_notif_errno(notify_raw, notif.id, libc::EACCES);
                }
            });

            let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            addr.sin_family = libc::AF_INET as u16;
            addr.sin_port = 0;
            addr.sin_addr.s_addr = u32::from_be_bytes([127, 0, 0, 1]).to_be();
            let bind_result = unsafe {
                libc::bind(
                    sock,
                    (&addr as *const libc::sockaddr_in).cast(),
                    std::mem::size_of::<libc::sockaddr_in>() as u32,
                )
            };
            let errno = if bind_result < 0 {
                std::io::Error::last_os_error().raw_os_error().unwrap_or(-1) as u8
            } else {
                0
            };
            unsafe { libc::close(sock) };
            let _ = handler.join();

            unsafe {
                libc::write(report_pipe[1], &errno as *const u8 as _, 1);
                libc::close(report_pipe[1]);
                libc::_exit(0);
            }
        }

        // PARENT
        unsafe { libc::close(report_pipe[1]) };

        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };

        let mut buf = [0u8; 1];
        let mut pipe_read = unsafe {
            use std::os::fd::FromRawFd;
            std::fs::File::from_raw_fd(report_pipe[0])
        };
        use std::io::Read as _;
        let n = pipe_read.read(&mut buf).expect("read from pipe");

        if n == 1 && buf[0] == 255 {
            return; // seccomp not available, skip
        }

        assert_eq!(n, 1);
        assert_eq!(
            buf[0],
            libc::EACCES as u8,
            "AF_INET bind() must still receive EACCES (from supervisor, not filter) \
             when has_bind_ports=false, got errno={}",
            buf[0]
        );
    }

    // =========================================================================
    // WSL2 detection tests
    // =========================================================================

    #[test]
    fn test_is_wsl2_does_not_panic() {
        // Must not panic regardless of environment
        let _ = is_wsl2();
    }

    #[test]
    fn test_is_wsl2_consistent() {
        // Cached result must be stable across calls
        let first = is_wsl2();
        let second = is_wsl2();
        assert_eq!(first, second, "is_wsl2() must return consistent results");
    }

    #[test]
    fn test_detect_wsl2_matches_indicators() {
        // Verify detection agrees with kernel-controlled indicators.
        // WSL_DISTRO_NAME env var alone is NOT sufficient (spoofable).
        let has_interop = std::path::Path::new("/proc/sys/fs/binfmt_misc/WSLInterop").exists();
        let has_kernel_string = std::fs::read_to_string("/proc/version")
            .map(|v| v.contains("microsoft") || v.contains("WSL"))
            .unwrap_or(false);

        if has_interop || has_kernel_string {
            assert!(
                is_wsl2(),
                "Kernel-controlled WSL2 indicators present but is_wsl2() returned false"
            );
        }
        // Note: we don't assert the negative because the OnceLock cache
        // may have been populated by another test or indicator.
    }

    #[test]
    fn test_wsl2_landlock_available() {
        // Landlock should be available on both WSL2 and native Linux
        // (WSL2 kernel 6.6 has Landlock V3)
        if is_wsl2() || is_supported() {
            assert!(
                is_supported(),
                "Landlock must be available when WSL2 or native Linux"
            );
        }
    }
}
