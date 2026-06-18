//! C-compatible types for the nono FFI layer.
//!
//! All types here use `#[repr(C)]` for stable ABI layout.

use std::os::raw::c_char;

/// Access mode for filesystem capabilities.
///
/// Constants: `NONO_ACCESS_MODE_READ` (0), `NONO_ACCESS_MODE_WRITE` (1),
/// `NONO_ACCESS_MODE_READ_WRITE` (2).
///
/// Represented as `u32` at the FFI boundary to prevent undefined behavior
/// from invalid enum discriminants. Validated on entry to each FFI function.
pub const NONO_ACCESS_MODE_READ: u32 = 0;
pub const NONO_ACCESS_MODE_WRITE: u32 = 1;
pub const NONO_ACCESS_MODE_READ_WRITE: u32 = 2;
/// Sentinel value returned on error (NULL pointer, out-of-bounds index).
pub const NONO_ACCESS_MODE_INVALID: u32 = u32::MAX;

/// Validate a raw access mode value from C and convert to `nono::AccessMode`.
///
/// Returns `None` for invalid values.
pub fn validate_access_mode(raw: u32) -> Option<nono::AccessMode> {
    match raw {
        NONO_ACCESS_MODE_READ => Some(nono::AccessMode::Read),
        NONO_ACCESS_MODE_WRITE => Some(nono::AccessMode::Write),
        NONO_ACCESS_MODE_READ_WRITE => Some(nono::AccessMode::ReadWrite),
        _ => None,
    }
}

/// Convert a `nono::AccessMode` to its FFI constant value.
#[must_use]
pub fn access_mode_to_raw(mode: nono::AccessMode) -> u32 {
    match mode {
        nono::AccessMode::Read => NONO_ACCESS_MODE_READ,
        nono::AccessMode::Write => NONO_ACCESS_MODE_WRITE,
        nono::AccessMode::ReadWrite => NONO_ACCESS_MODE_READ_WRITE,
    }
}

/// Tag for capability source discriminant.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonoCapabilitySourceTag {
    /// Added directly by the user via CLI flags
    User = 0,
    /// Resolved from a named policy group
    Group = 1,
    /// System-level path
    System = 2,
    /// Added from a profile's filesystem section
    Profile = 3,
}

/// Status of a query result.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonoQueryStatus {
    Allowed = 0,
    Denied = 1,
}

/// Reason code for a query result.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonoQueryReason {
    /// Path is covered by a granted capability
    GrantedPath = 0,
    /// Network access is not blocked
    NetworkAllowed = 1,
    /// Path not covered by any capability
    PathNotGranted = 2,
    /// Path covered but with insufficient access level
    InsufficientAccess = 3,
    /// Network access is blocked
    NetworkBlocked = 4,
}

/// Result of a permission query.
///
/// String fields are nullable. Non-NULL string fields are caller-owned
/// and must be freed with `nono_string_free()`.
#[repr(C)]
pub struct NonoQueryResult {
    /// Whether the operation is allowed or denied.
    pub status: NonoQueryStatus,
    /// The specific reason.
    pub reason: NonoQueryReason,
    /// For `GrantedPath`: the path that grants access. NULL otherwise.
    pub granted_path: *mut c_char,
    /// For `GrantedPath`: the access mode string. NULL otherwise.
    pub access: *mut c_char,
    /// For `InsufficientAccess`: the granted access mode. NULL otherwise.
    pub granted: *mut c_char,
    /// For `InsufficientAccess`: the requested access mode. NULL otherwise.
    pub requested: *mut c_char,
}

/// Platform support information.
///
/// Returned by `nono_sandbox_support_info()`.
/// Caller must free string fields with `nono_string_free()`.
#[repr(C)]
pub struct NonoSupportInfo {
    /// Whether sandboxing is supported on this platform.
    pub is_supported: bool,
    /// Platform name. Caller must free with `nono_string_free()`.
    pub platform: *mut c_char,
    /// Detailed support information. Caller must free with `nono_string_free()`.
    pub details: *mut c_char,
}

/// Network mode for sandbox capabilities.
///
/// Constants: `NONO_NETWORK_MODE_BLOCKED` (0), `NONO_NETWORK_MODE_ALLOW_ALL` (1),
/// `NONO_NETWORK_MODE_PROXY_ONLY` (2).
pub const NONO_NETWORK_MODE_BLOCKED: u32 = 0;
pub const NONO_NETWORK_MODE_ALLOW_ALL: u32 = 1;
pub const NONO_NETWORK_MODE_PROXY_ONLY: u32 = 2;

/// Validate a raw network mode value from C and convert to `nono::NetworkMode`.
///
/// For `ProxyOnly`, the port must be set separately via the dedicated setter.
/// This function creates `ProxyOnly { port: 0 }` as a placeholder.
pub fn validate_network_mode(raw: u32) -> Option<nono::NetworkMode> {
    match raw {
        NONO_NETWORK_MODE_BLOCKED => Some(nono::NetworkMode::Blocked),
        NONO_NETWORK_MODE_ALLOW_ALL => Some(nono::NetworkMode::AllowAll),
        NONO_NETWORK_MODE_PROXY_ONLY => Some(nono::NetworkMode::ProxyOnly {
            port: 0,
            bind_ports: vec![],
        }),
        _ => None,
    }
}

/// Convert a `nono::NetworkMode` to its FFI constant value.
#[must_use]
pub fn network_mode_to_raw(mode: &nono::NetworkMode) -> u32 {
    match mode {
        nono::NetworkMode::Blocked => NONO_NETWORK_MODE_BLOCKED,
        nono::NetworkMode::AllowAll => NONO_NETWORK_MODE_ALLOW_ALL,
        nono::NetworkMode::ProxyOnly { .. } => NONO_NETWORK_MODE_PROXY_ONLY,
    }
}

/// Error codes returned by nono FFI functions.
///
/// Zero means success. Negative values indicate error categories.
/// Call `nono_last_error()` for the detailed error message.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonoErrorCode {
    /// Operation succeeded.
    Ok = 0,
    /// Path does not exist.
    ErrPathNotFound = -1,
    /// Expected a directory but got a file.
    ErrExpectedDirectory = -2,
    /// Expected a file but got a directory.
    ErrExpectedFile = -3,
    /// Path canonicalization failed.
    ErrPathCanonicalization = -4,
    /// No capabilities specified.
    ErrNoCapabilities = -5,
    /// Sandbox initialization failed.
    ErrSandboxInit = -6,
    /// Platform not supported.
    ErrUnsupportedPlatform = -7,
    /// Command is blocked.
    ErrBlockedCommand = -8,
    /// Configuration parse error.
    ErrConfigParse = -9,
    /// Profile parse error.
    ErrProfileParse = -10,
    /// I/O error.
    ErrIo = -11,
    /// Invalid argument (NULL pointer, invalid UTF-8).
    ErrInvalidArg = -12,
    /// Trust/attestation verification error.
    ErrTrustVerification = -13,
    /// Unknown or uncategorized error.
    ErrUnknown = -99,
}

/// Diagnostic code for sandbox and setup errors.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonoDiagnosticCode {
    SandboxDeniedPath = 0,
    SandboxDeniedNetwork = 1,
    SandboxDeniedUnixSocket = 2,
    CommandNotFound = 3,
    CommandFailedLikelySandbox = 4,
    CommandFailedApplication = 5,
    CredentialNotFound = 6,
    CredentialUnavailable = 7,
    UnsupportedPlatformFeature = 8,
    RollbackBudgetExceeded = 9,
    CwdAccessRequired = 10,
    ConfigurationError = 11,
    TrustVerificationFailed = 12,
    IoError = 13,
    Cancelled = 14,
    Other = 99,
}

impl From<nono::NonoDiagnosticCode> for NonoDiagnosticCode {
    fn from(code: nono::NonoDiagnosticCode) -> Self {
        match code {
            nono::NonoDiagnosticCode::SandboxDeniedPath => Self::SandboxDeniedPath,
            nono::NonoDiagnosticCode::SandboxDeniedNetwork => Self::SandboxDeniedNetwork,
            nono::NonoDiagnosticCode::SandboxDeniedUnixSocket => Self::SandboxDeniedUnixSocket,
            nono::NonoDiagnosticCode::CommandNotFound => Self::CommandNotFound,
            nono::NonoDiagnosticCode::CommandFailedLikelySandbox => {
                Self::CommandFailedLikelySandbox
            }
            nono::NonoDiagnosticCode::CommandFailedApplication => Self::CommandFailedApplication,
            nono::NonoDiagnosticCode::CredentialNotFound => Self::CredentialNotFound,
            nono::NonoDiagnosticCode::CredentialUnavailable => Self::CredentialUnavailable,
            nono::NonoDiagnosticCode::UnsupportedPlatformFeature => {
                Self::UnsupportedPlatformFeature
            }
            nono::NonoDiagnosticCode::RollbackBudgetExceeded => Self::RollbackBudgetExceeded,
            nono::NonoDiagnosticCode::CwdAccessRequired => Self::CwdAccessRequired,
            nono::NonoDiagnosticCode::ConfigurationError => Self::ConfigurationError,
            nono::NonoDiagnosticCode::TrustVerificationFailed => Self::TrustVerificationFailed,
            nono::NonoDiagnosticCode::IoError => Self::IoError,
            nono::NonoDiagnosticCode::Cancelled => Self::Cancelled,
            nono::NonoDiagnosticCode::Other => Self::Other,
            _ => Self::Other,
        }
    }
}
