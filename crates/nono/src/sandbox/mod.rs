//! OS-level sandbox implementation
//!
//! This module provides the core sandboxing functionality using platform-specific
//! mechanisms:
//! - Linux: Landlock LSM
//! - macOS: Seatbelt sandbox

use crate::capability::CapabilitySet;
use crate::error::Result;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

// Re-export macOS extension functions for supervisor use
#[cfg(target_os = "macos")]
pub use macos::{extension_consume, extension_issue_file, extension_release};

// Re-export Linux Landlock ABI detection and scope policy reporting
#[cfg(target_os = "linux")]
pub use linux::{
    DetectedAbi, LandlockScopePolicy, detect_abi, landlock_scope_policy, restrict_execute,
};

// Re-export Linux WSL2 detection
#[cfg(target_os = "linux")]
pub use linux::is_wsl2;

// Re-export Linux seccomp-notify primitives for supervisor use
#[cfg(target_os = "linux")]
pub use linux::{
    OpenHow, SYS_BIND, SYS_CONNECT, SYS_OPENAT, SYS_OPENAT2, SYS_SENDMMSG, SYS_SENDMSG, SYS_SENDTO,
    SeccompData, SeccompNetFallback, SeccompNotif, SockaddrInfo, UnixSocketKind,
    classify_access_from_flags, classify_af_unix, continue_notif, deny_notif, inject_fd,
    install_seccomp_af_unix_filter, install_seccomp_notify, install_seccomp_proxy_filter,
    notif_id_valid, probe_seccomp_block_network_support, read_mmsghdr_dests, read_msghdr_dest,
    read_notif_path, read_notif_sockaddr, read_open_how, recv_notif, resolve_notif_path,
    respond_notif_errno, validate_openat2_size,
};

/// Information about sandbox support on this platform
#[derive(Debug, Clone)]
pub struct SupportInfo {
    /// Whether sandboxing is supported
    pub is_supported: bool,
    /// Platform name
    pub platform: &'static str,
    /// Detailed support information
    pub details: String,
}

/// Main sandbox API
///
/// This struct provides static methods for applying sandboxing restrictions.
/// Once applied, restrictions cannot be removed or expanded.
///
/// # Example
///
/// ```no_run
/// use nono::{CapabilitySet, AccessMode, Sandbox};
///
/// let caps = CapabilitySet::new()
///     .allow_path("/usr", AccessMode::Read)?
///     .allow_path("/project", AccessMode::ReadWrite)?
///     .block_network();
///
/// // Check if sandbox is supported
/// if Sandbox::is_supported() {
///     Sandbox::apply_auto(&caps)?;
/// }
/// # Ok::<(), nono::NonoError>(())
/// ```
pub struct Sandbox;

impl Sandbox {
    /// Detect the Landlock ABI version supported by the running kernel.
    ///
    /// This is only available on Linux. Returns a `DetectedAbi` that can
    /// be passed to `apply_with_abi()` to avoid re-probing.
    ///
    /// # Errors
    ///
    /// Returns an error if Landlock is not available.
    #[cfg(target_os = "linux")]
    #[must_use = "ABI detection result should be checked"]
    pub fn detect_abi() -> Result<DetectedAbi> {
        linux::detect_abi()
    }

    /// Apply sandboxing with automatic Landlock → seccomp fallback (Linux).
    ///
    /// Uses Landlock where possible; falls back to seccomp when the kernel
    /// ABI lacks network support (< V4). This is the default behaviour.
    /// `BlockAll` is installed inline; `ProxyOnly` must be installed
    /// post-fork via `install_seccomp_proxy_filter()`.
    #[cfg(target_os = "linux")]
    #[must_use = "sandbox application result should be checked"]
    pub fn apply_auto(caps: &CapabilitySet) -> Result<linux::SeccompNetFallback> {
        linux::apply_auto(caps)
    }

    /// Apply sandboxing with automatic fallback and a pre-detected ABI (Linux).
    #[cfg(target_os = "linux")]
    #[must_use = "sandbox application result should be checked"]
    pub fn apply_auto_with_abi(
        caps: &CapabilitySet,
        abi: &DetectedAbi,
    ) -> Result<linux::SeccompNetFallback> {
        linux::apply_auto_with_abi(caps, abi)
    }

    /// Apply Landlock-only sandboxing (Linux).
    ///
    /// Returns an error if network restrictions cannot be satisfied via
    /// Landlock alone (kernel ABI < V4). Use `apply_auto` for fallback.
    #[cfg(target_os = "linux")]
    pub fn apply_landlock(caps: &CapabilitySet) -> Result<()> {
        linux::apply_landlock(caps)
    }

    /// Apply Landlock-only sandboxing with a pre-detected ABI (Linux).
    #[cfg(target_os = "linux")]
    pub fn apply_landlock_with_abi(caps: &CapabilitySet, abi: &DetectedAbi) -> Result<()> {
        linux::apply_landlock_with_abi(caps, abi)
    }

    /// Declare that sandboxing is managed externally (Linux).
    ///
    /// No-op: nono installs no Landlock or seccomp rules. The caller asserts
    /// that enforcement is handled at the infrastructure level.
    #[cfg(target_os = "linux")]
    pub fn apply_external() -> Result<()> {
        linux::apply_external()
    }

    /// Apply the sandbox with the given capabilities (macOS).
    #[cfg(target_os = "macos")]
    #[must_use = "sandbox application result should be checked"]
    pub fn apply_auto(caps: &CapabilitySet) -> Result<()> {
        macos::apply(caps)
    }

    /// Stack a second Landlock layer that restricts execute to the given paths (Linux only).
    ///
    /// Must be called after `apply()`. See [`linux::restrict_execute`] for semantics.
    ///
    /// # Errors
    ///
    /// Returns an error if the restriction cannot be applied.
    #[cfg(target_os = "linux")]
    pub fn restrict_execute(paths: &[impl AsRef<std::path::Path>]) -> Result<()> {
        linux::restrict_execute(paths)
    }

    /// Check if sandboxing is supported on this platform
    #[must_use]
    pub fn is_supported() -> bool {
        #[cfg(target_os = "linux")]
        {
            linux::is_supported()
        }

        #[cfg(target_os = "macos")]
        {
            macos::is_supported()
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            false
        }
    }

    /// Get detailed information about sandbox support on this platform
    #[must_use]
    pub fn support_info() -> SupportInfo {
        #[cfg(target_os = "linux")]
        {
            linux::support_info()
        }

        #[cfg(target_os = "macos")]
        {
            macos::support_info()
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            SupportInfo {
                is_supported: false,
                platform: std::env::consts::OS,
                details: format!("Platform '{}' is not supported", std::env::consts::OS),
            }
        }
    }
}
