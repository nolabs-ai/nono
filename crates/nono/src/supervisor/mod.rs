//! Supervisor IPC for runtime capability expansion
//!
//! This module provides the types, socket helpers, and validation logic for
//! supervisor-child IPC. The supervisor is an unsandboxed parent process that
//! can grant additional capabilities to the sandboxed child at runtime.
//!
//! # Architecture
//!
//! ```text
//! Child (sandboxed) --[Unix socket]--> Supervisor (unsandboxed) --[ApprovalBackend]--> decision source
//! ```
//!
//! The child sends [`CapabilityRequest`]s over a [`SupervisorSocket`]. The
//! supervisor delegates to an [`ApprovalBackend`] for the decision. If granted,
//! the supervisor opens the path and passes the fd back via `SCM_RIGHTS`.
//!
//! # Components
//!
//! - **Types** ([`types`]): IPC message types (`CapabilityRequest`, `ApprovalDecision`, `AuditEntry`)
//! - **Socket** ([`socket`]): Unix domain socket with length-prefixed framing and fd-passing
//! - **ApprovalBackend** (this module): Trait for pluggable approval decisions
//!
//! # Security
//!
//! - All messages are length-prefixed with a 64 KiB cap to prevent memory exhaustion
//! - Peer authentication via `SO_PEERCRED` (Linux) / `LOCAL_PEERPID` (macOS)
//! - Path comparison uses [`Path::starts_with()`], never string operations

pub mod socket;
pub mod types;

pub use socket::{SupervisorListener, SupervisorSocket};
pub use types::{
    ApprovalDecision, AuditEntry, CapabilityRequest, CredentialFrontend, CredentialItemClass,
    CredentialOperation, CredentialProvider, CredentialRequest, CredentialResponse, SecretBytes,
    SupervisorMessage, SupervisorResponse, UrlOpenRequest,
};

use crate::error::Result;

/// Trait for pluggable approval backends.
///
/// Implementors decide whether to grant or deny a [`CapabilityRequest`].
///
/// # Built-in implementations (in nono-cli)
///
/// - `TerminalApproval` — interactive terminal prompt (default)
/// - `WebhookApproval` — POST to external system, block until callback
/// - `PolicyApproval` — auto-approve based on path patterns
///
/// # Implementing in language bindings
///
/// - **Python**: Implement as a protocol class, PyO3 dispatches to Rust
/// - **TypeScript**: Implement as a JS class/callback, napi-rs dispatches to Rust
/// - **C**: Register a callback function pointer via `nono_set_approval_callback()`
///
/// # Example
///
/// ```rust
/// use nono::supervisor::{ApprovalBackend, ApprovalDecision, CapabilityRequest};
/// use nono::Result;
///
/// struct AutoDeny;
///
/// impl ApprovalBackend for AutoDeny {
///     fn request_capability(
///         &self,
///         _request: &CapabilityRequest,
///     ) -> Result<ApprovalDecision> {
///         Ok(ApprovalDecision::Denied {
///             reason: "auto-deny policy".to_string(),
///         })
///     }
///
///     fn backend_name(&self) -> &str {
///         "auto-deny"
///     }
/// }
/// ```
pub trait ApprovalBackend: Send + Sync {
    /// Decide whether to grant or deny a capability request.
    ///
    /// This may block (e.g., waiting for user input or a webhook response).
    /// The supervisor should set a read timeout on the socket to prevent
    /// indefinite blocking.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend encounters a communication failure
    /// or internal error. The supervisor should treat errors as denials.
    fn request_capability(&self, request: &CapabilityRequest) -> Result<ApprovalDecision>;

    /// Human-readable name for this backend (used in audit logs).
    fn backend_name(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::AccessMode;

    struct TestDenyBackend;

    impl ApprovalBackend for TestDenyBackend {
        fn request_capability(&self, _request: &CapabilityRequest) -> Result<ApprovalDecision> {
            Ok(ApprovalDecision::Denied {
                reason: "test deny".to_string(),
            })
        }

        fn backend_name(&self) -> &str {
            "test-deny"
        }
    }

    struct TestGrantBackend;

    impl ApprovalBackend for TestGrantBackend {
        fn request_capability(&self, _request: &CapabilityRequest) -> Result<ApprovalDecision> {
            Ok(ApprovalDecision::Granted)
        }

        fn backend_name(&self) -> &str {
            "test-grant"
        }
    }

    fn make_request() -> CapabilityRequest {
        CapabilityRequest {
            request_id: "test-001".to_string(),
            path: "/tmp/test".into(),
            access: AccessMode::Read,
            reason: Some("unit test".to_string()),
            child_pid: 1234,
            session_id: "sess-001".to_string(),
        }
    }

    #[test]
    fn test_deny_backend() {
        let backend = TestDenyBackend;
        let request = make_request();
        let decision = backend.request_capability(&request).expect("decision");
        assert!(decision.is_denied());
        assert_eq!(backend.backend_name(), "test-deny");
    }

    #[test]
    fn test_grant_backend() {
        let backend = TestGrantBackend;
        let request = make_request();
        let decision = backend.request_capability(&request).expect("decision");
        assert!(decision.is_granted());
        assert_eq!(backend.backend_name(), "test-grant");
    }

    #[test]
    fn test_approval_decision_methods() {
        let granted = ApprovalDecision::Granted;
        assert!(granted.is_granted());
        assert!(!granted.is_denied());

        let denied = ApprovalDecision::Denied {
            reason: "no".to_string(),
        };
        assert!(!denied.is_granted());
        assert!(denied.is_denied());

        let timeout = ApprovalDecision::Timeout;
        assert!(!timeout.is_granted());
        assert!(!timeout.is_denied());
    }
}
