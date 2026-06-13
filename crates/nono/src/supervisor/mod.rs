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
    ApprovalDecision, ApprovalRequest, AuditEntry, CapabilityRequest, SupervisorMessage,
    SupervisorResponse, UrlOpenRequest,
};

use crate::error::Result;

/// Trait for pluggable approval backends.
///
/// Implementors decide whether to grant or deny an [`ApprovalRequest`], which
/// covers filesystem capability expansion, network access, and Tool Sandbox  command
/// launch (the `Approve` intercept action).
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
/// use nono::supervisor::{ApprovalBackend, ApprovalDecision, ApprovalRequest};
/// use nono::Result;
///
/// struct AutoDeny;
///
/// impl ApprovalBackend for AutoDeny {
///     fn request_approval(
///         &self,
///         _request: &ApprovalRequest,
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
    /// Decide whether to grant or deny an approval request.
    ///
    /// The request may be a filesystem capability expansion, a network access
    /// request, or an Tool Sandbox  command-launch request. This may block (e.g.,
    /// waiting for user input or a webhook response). The supervisor should
    /// apply a timeout and treat expiry as a denial.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend encounters a communication failure
    /// or internal error. The supervisor treats errors as denials.
    fn request_approval(&self, request: &ApprovalRequest) -> Result<ApprovalDecision>;

    /// Human-readable name for this backend (used in audit logs).
    fn backend_name(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::AccessMode;

    struct TestDenyBackend;

    impl ApprovalBackend for TestDenyBackend {
        fn request_approval(&self, _request: &ApprovalRequest) -> Result<ApprovalDecision> {
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
        fn request_approval(&self, _request: &ApprovalRequest) -> Result<ApprovalDecision> {
            Ok(ApprovalDecision::Granted)
        }

        fn backend_name(&self) -> &str {
            "test-grant"
        }
    }

    fn make_capability_request() -> ApprovalRequest {
        ApprovalRequest::Capability {
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
        let request = make_capability_request();
        let decision = backend.request_approval(&request).expect("decision");
        assert!(decision.is_denied());
        assert_eq!(backend.backend_name(), "test-deny");
    }

    #[test]
    fn test_grant_backend() {
        let backend = TestGrantBackend;
        let request = make_capability_request();
        let decision = backend.request_approval(&request).expect("decision");
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

    #[test]
    fn test_approval_request_accessors() {
        let cap = make_capability_request();
        assert_eq!(cap.request_id(), "test-001");
        assert_eq!(cap.session_id(), "sess-001");

        let net = ApprovalRequest::Network {
            request_id: "net-001".to_string(),
            host: "example.com".to_string(),
            port: 443,
            protocol: "tcp".to_string(),
            resolved_ips: vec![],
            reason: None,
            child_pid: 42,
            session_id: "sess-002".to_string(),
        };
        assert_eq!(net.request_id(), "net-001");
        assert_eq!(net.session_id(), "sess-002");

        let endpoint = ApprovalRequest::Endpoint {
            request_id: "endpoint-001".to_string(),
            route_id: "internal-api".to_string(),
            upstream: "https://api.internal.example".to_string(),
            method: "POST".to_string(),
            path: "/v1/tasks/1/comments".to_string(),
            rule_label: "endpoint_policy.approve[POST /v1/tasks/*/comments]".to_string(),
            reason: None,
            child_pid: 42,
            session_id: "sess-004".to_string(),
        };
        assert_eq!(endpoint.request_id(), "endpoint-001");
        assert_eq!(endpoint.session_id(), "sess-004");

        let cmd = ApprovalRequest::Command {
            request_id: "cmd-001".to_string(),
            command: "git".to_string(),
            args: vec!["git".to_string(), "push".to_string()],
            caller: "session".to_string(),
            intercept_rule: "push".to_string(),
            reason: None,
            child_pid: 99,
            session_id: "sess-003".to_string(),
        };
        assert_eq!(cmd.request_id(), "cmd-001");
        assert_eq!(cmd.session_id(), "sess-003");
    }

    #[test]
    fn test_capability_request_into_approval_request() {
        let cap_req = CapabilityRequest {
            request_id: "r1".to_string(),
            path: "/tmp/foo".into(),
            access: AccessMode::ReadWrite,
            reason: Some("test".to_string()),
            child_pid: 7,
            session_id: "s1".to_string(),
        };
        let approval: ApprovalRequest = cap_req.into();
        assert_eq!(approval.request_id(), "r1");
        assert_eq!(approval.session_id(), "s1");
        assert!(matches!(approval, ApprovalRequest::Capability { .. }));
    }
}
