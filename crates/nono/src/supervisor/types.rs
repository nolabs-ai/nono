//! Supervisor IPC types for capability expansion
//!
//! These types define the protocol between a sandboxed child process and its
//! unsandboxed supervisor parent. The child sends [`CapabilityRequest`]s over
//! a Unix socket, and the supervisor responds with [`ApprovalDecision`]s.

use crate::capability::AccessMode;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::SystemTime;

/// A request from the sandboxed child for additional filesystem access.
///
/// Sent over the supervisor Unix socket when the child needs access to a path
/// not covered by its initial sandbox policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityRequest {
    /// Unique identifier for this request (for replay protection and audit)
    pub request_id: String,
    /// The filesystem path being requested
    pub path: PathBuf,
    /// The access mode requested (read, write, or read+write)
    pub access: AccessMode,
    /// Human-readable reason for the request (provided by the agent)
    pub reason: Option<String>,
    /// PID of the requesting child process
    pub child_pid: u32,
    /// Session identifier for correlating requests within a single run
    pub session_id: String,
}

/// The supervisor's response to a [`CapabilityRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApprovalDecision {
    /// Access was granted. The supervisor will pass an fd via `SCM_RIGHTS`.
    Granted,
    /// Access was denied with a reason.
    Denied {
        /// Why the request was denied
        reason: String,
    },
    /// The approval request timed out without a decision.
    Timeout,
}

impl ApprovalDecision {
    /// Returns true if access was granted.
    #[must_use]
    pub fn is_granted(&self) -> bool {
        matches!(self, ApprovalDecision::Granted)
    }

    /// Returns true if access was denied.
    #[must_use]
    pub fn is_denied(&self) -> bool {
        matches!(self, ApprovalDecision::Denied { .. })
    }
}

/// A structured audit record for every approval decision.
///
/// Every capability request produces an audit entry regardless of outcome.
/// These entries support fleet-level monitoring and compliance reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// When the decision was made
    pub timestamp: SystemTime,
    /// The original request
    pub request: CapabilityRequest,
    /// The decision that was reached
    pub decision: ApprovalDecision,
    /// Which approval backend handled the request
    pub backend: String,
    /// How long the decision took (milliseconds)
    pub duration_ms: u64,
}

/// A request from the sandboxed child to open a URL in the user's browser.
///
/// Sent over the supervisor Unix socket when the child needs to launch a
/// browser (e.g., for OAuth2 login). The unsandboxed supervisor validates
/// the URL against the profile's allowed origins and opens it outside the
/// sandbox, where the browser can access its own config files freely.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlOpenRequest {
    /// Unique identifier for this request (for replay protection and audit)
    pub request_id: String,
    /// The URL to open in the user's browser
    pub url: String,
    /// PID of the requesting child process
    pub child_pid: u32,
    /// Session identifier for correlating requests within a single run
    pub session_id: String,
}

/// IPC message envelope sent from child to supervisor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SupervisorMessage {
    /// A capability expansion request (explicit, from SDK clients)
    Request(CapabilityRequest),
    /// A request to open a URL in the user's browser (e.g., OAuth2 login)
    OpenUrl(UrlOpenRequest),
    /// A request to approve network access to a blocked host
    NetworkApproval(NetworkApprovalRequest),
}

/// IPC message envelope sent from supervisor to child.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SupervisorResponse {
    /// Response to a capability request
    Decision {
        /// The request_id this responds to
        request_id: String,
        /// The approval decision
        decision: ApprovalDecision,
    },
    /// Response to a URL open request
    UrlOpened {
        /// The request_id this responds to
        request_id: String,
        /// Whether the URL was opened successfully
        success: bool,
        /// Error message if the open failed
        error: Option<String>,
    },
    /// Response to a network approval request
    NetworkDecision {
        /// The request_id this responds to
        request_id: String,
        /// The network approval decision
        decision: NetworkApprovalDecision,
    },
}

/// Scope of a network approval — affects whether the host is persisted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ApprovalScope {
    /// Approved for a single request only; next request to the same host will prompt again.
    Once,
    /// Approved for this sandbox session only (in-memory)
    Session,
    /// Approved and persisted to config for future sessions
    Persistent,
}

/// A request to approve network access to a host that is not on the allowlist.
///
/// Sent when the proxy intercepts a request to a blocked host and
/// interactive approval is enabled (`--network-approval ask`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkApprovalRequest {
    /// Unique identifier for this request
    pub request_id: String,
    /// The hostname being requested
    pub host: String,
    /// The port being requested (if known)
    pub port: Option<u16>,
    /// Human-readable reason for the request
    pub reason: Option<String>,
    /// PID of the requesting child process
    pub child_pid: u32,
    /// Session identifier for correlating requests within a single run
    pub session_id: String,
}

/// The supervisor's response to a [`NetworkApprovalRequest`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NetworkApprovalDecision {
    /// Access was granted with the given scope.
    Granted(ApprovalScope),
    /// Access was denied with a reason.
    Denied {
        /// Why the request was denied
        reason: String,
    },
    /// The approval request timed out without a decision.
    Timeout,
}

impl NetworkApprovalDecision {
    /// Returns true if access was granted (in any scope).
    #[must_use]
    pub fn is_granted(&self) -> bool {
        matches!(self, NetworkApprovalDecision::Granted(_))
    }

    /// Returns true if access was denied.
    #[must_use]
    pub fn is_denied(&self) -> bool {
        matches!(self, NetworkApprovalDecision::Denied { .. })
    }
}
