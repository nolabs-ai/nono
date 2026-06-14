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
pub use linux::{DetectedAbi, LandlockScopePolicy, detect_abi, landlock_scope_policy};

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
///     Sandbox::apply(&caps)?;
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

    /// Apply the sandbox with the given capabilities.
    ///
    /// This function applies OS-level restrictions that **cannot be undone**.
    /// After calling this, the current process (and all children) will
    /// only be able to access resources granted by the capabilities.
    ///
    /// On Linux, returns the seccomp network fallback mode. `BlockAll` is
    /// already enforced. `ProxyOnly` signals the caller to install the
    /// proxy filter post-fork via `install_seccomp_proxy_filter()`.
    /// On macOS, always returns `()` (no seccomp fallback concept).
    ///
    /// # Errors
    ///
    /// Returns an error if sandbox initialization fails.
    #[cfg(target_os = "linux")]
    #[must_use = "sandbox application result should be checked"]
    pub fn apply(caps: &CapabilitySet) -> Result<linux::SeccompNetFallback> {
        linux::apply(caps)
    }

    /// Apply the sandbox with the given capabilities (macOS).
    #[cfg(target_os = "macos")]
    #[must_use = "sandbox application result should be checked"]
    pub fn apply(caps: &CapabilitySet) -> Result<()> {
        macos::apply(caps)
    }

    /// Apply the sandbox with the given capabilities (unsupported platforms).
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[must_use = "sandbox application result should be checked"]
    pub fn apply(caps: &CapabilitySet) -> Result<()> {
        let _ = caps;
        #[cfg(target_arch = "wasm32")]
        {
            Err(crate::error::NonoError::UnsupportedPlatform(
                "WASM: Browser sandboxing requires different approach (CSP, iframe sandbox)".into(),
            ))
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            Err(crate::error::NonoError::UnsupportedPlatform(
                std::env::consts::OS.to_string(),
            ))
        }
    }

    /// Apply the sandbox with a pre-detected Landlock ABI (Linux only).
    ///
    /// Avoids re-probing the kernel when the caller has already detected
    /// the ABI (e.g., probed once at startup).
    ///
    /// Returns the seccomp network fallback mode (see `apply()` docs).
    ///
    /// # Errors
    ///
    /// Returns an error if sandbox initialization fails.
    #[cfg(target_os = "linux")]
    #[must_use = "sandbox application result should be checked"]
    pub fn apply_with_abi(
        caps: &CapabilitySet,
        abi: &DetectedAbi,
    ) -> Result<linux::SeccompNetFallback> {
        linux::apply_with_abi(caps, abi)
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
