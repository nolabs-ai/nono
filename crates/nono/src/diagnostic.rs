//! Structured sandbox diagnostic records.
//!
//! This module holds the structured, policy-free facts that the sandbox and
//! its supervisors produce when access is denied: denial records, IPC denial
//! records, OS-native sandbox violations, and the platform mapping from a
//! Seatbelt operation name to an [`AccessMode`].
//!
//! All user-facing diagnostic rendering (footer text, CLI flag suggestions,
//! `nono why`/`nono learn` guidance, policy explanations, and stderr
//! heuristics) lives in the `nono-cli` crate. The core library stays a pure
//! sandbox primitive and only exposes these records as a stable API for
//! clients that want to render or inspect denials themselves.

use crate::capability::AccessMode;
use std::path::PathBuf;

/// Why a path access was denied during a supervised session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenialReason {
    /// Path is blocked by sandbox policy before approval is consulted
    PolicyBlocked,
    /// Path matches a capability but the requested access mode is not granted
    InsufficientAccess,
    /// User declined the interactive approval prompt
    UserDenied,
    /// Request was rate limited (too many requests)
    RateLimited,
    /// Approval backend returned an error
    BackendError,
    /// Pathname Unix socket was denied by IPC mediation
    UnixSocketDenied,
}

/// Record of a denied access attempt during a supervised session.
#[derive(Debug, Clone)]
pub struct DenialRecord {
    /// The path that was denied
    pub path: PathBuf,
    /// Access mode requested
    pub access: AccessMode,
    /// Why it was denied
    pub reason: DenialReason,
}

/// Record of a denied IPC attempt during a supervised session.
#[derive(Debug, Clone)]
pub struct IpcDenialRecord {
    /// IPC resource that was denied, e.g. `/run/user/1000/bus` or `unix:<abstract>`.
    pub target: String,
    /// Operation attempted, e.g. `connect` or `bind`.
    pub operation: String,
    /// Why it was denied.
    pub reason: String,
    /// Suggested CLI flag when this denial can be fixed by an explicit grant.
    pub suggested_flag: Option<String>,
}

/// Best-effort sandbox violation recovered from OS-native logging.
///
/// On macOS, Seatbelt does not stream deny events back to the supervisor like
/// Linux seccomp-notify does, so diagnostics can supplement denials with
/// unified-log records recovered from sandboxd.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxViolation {
    /// Denied operation, such as `file-read-data` or `mach-lookup`.
    pub operation: String,
    /// Optional path or resource associated with the violation.
    pub target: Option<String>,
}

/// Map a Seatbelt operation name to an `AccessMode`.
///
/// Returns `None` for non-filesystem operations (e.g. `mach-lookup`,
/// `signal`, `process-exec`) that cannot be expressed as path grants.
#[must_use]
pub fn seatbelt_operation_to_access(operation: &str) -> Option<AccessMode> {
    match operation {
        "file-read-data" | "file-read-metadata" | "file-read-xattr" => Some(AccessMode::Read),
        "file-write-data" | "file-write-create" | "file-write-unlink" | "file-write-flags"
        | "file-write-mode" | "file-write-owner" | "file-write-times" | "file-write-xattr" => {
            Some(AccessMode::Write)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seatbelt_read_operations_map_to_read() {
        assert_eq!(
            seatbelt_operation_to_access("file-read-data"),
            Some(AccessMode::Read)
        );
        assert_eq!(
            seatbelt_operation_to_access("file-read-metadata"),
            Some(AccessMode::Read)
        );
    }

    #[test]
    fn seatbelt_write_operations_map_to_write() {
        assert_eq!(
            seatbelt_operation_to_access("file-write-data"),
            Some(AccessMode::Write)
        );
        assert_eq!(
            seatbelt_operation_to_access("file-write-create"),
            Some(AccessMode::Write)
        );
    }

    #[test]
    fn seatbelt_non_filesystem_operations_map_to_none() {
        assert_eq!(seatbelt_operation_to_access("mach-lookup"), None);
        assert_eq!(seatbelt_operation_to_access("signal"), None);
        assert_eq!(seatbelt_operation_to_access("network-outbound"), None);
    }
}
