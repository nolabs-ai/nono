//! Supervisor IPC types for capability expansion
//!
//! These types define the protocol between a sandboxed child process and its
//! unsandboxed supervisor parent. The child sends [`CapabilityRequest`]s over
//! a Unix socket, and the supervisor responds with [`ApprovalDecision`]s.
//!
//! [`ApprovalRequest`] is the generalised form consumed by [`crate::supervisor::ApprovalBackend`].
//! It covers file capability, network, and Tool Sandbox  command-launch requests.

use crate::capability::AccessMode;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::SystemTime;

/// A request from the sandboxed child for additional filesystem access.
///
/// This is the IPC wire type sent over the supervisor Unix socket. The
/// supervisor converts it to [`ApprovalRequest::Capability`] before calling
/// the approval backend.
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

/// A generalised approval request covering all request types handled by
/// [`crate::supervisor::ApprovalBackend`].
///
/// The supervisor IPC wire type [`CapabilityRequest`] maps to the
/// [`ApprovalRequest::Capability`] variant. Tool Sandbox  command launch uses the
/// [`ApprovalRequest::Command`] variant, built directly in the Tool Sandbox  shim
/// handler without going over the IPC socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "capability_type", rename_all = "snake_case")]
pub enum ApprovalRequest {
    /// A filesystem capability expansion request (from `nono grant` IPC).
    Capability {
        /// Unique identifier for this request (for replay protection and audit)
        request_id: String,
        /// The filesystem path being requested
        path: PathBuf,
        /// The access mode requested (read, write, or read+write)
        access: AccessMode,
        /// Human-readable reason for the request (provided by the agent)
        reason: Option<String>,
        /// PID of the requesting child process
        child_pid: u32,
        /// Session identifier for correlating requests within a single run
        session_id: String,
    },
    /// A network-level capability approval request.
    Network {
        /// Unique identifier for this request
        request_id: String,
        /// The hostname or IP being connected to
        host: String,
        /// The TCP/UDP port being connected to
        port: u16,
        /// Protocol: `"tcp"` or `"udp"`
        protocol: String,
        /// Resolved IP addresses for the host (may be empty)
        resolved_ips: Vec<String>,
        /// Human-readable reason for the request
        reason: Option<String>,
        /// PID of the requesting child process
        child_pid: u32,
        /// Session identifier
        session_id: String,
    },
    /// An L7 endpoint approval request from the network proxy.
    Endpoint {
        /// Unique identifier for this request
        request_id: String,
        /// Stable configured route identifier, e.g. `"github-api"`
        route_id: String,
        /// Upstream URL for the route, without credentials
        upstream: String,
        /// HTTP method being requested
        method: String,
        /// Request path being requested
        path: String,
        /// The endpoint policy rule/default that triggered approval
        rule_label: String,
        /// Human-readable reason
        reason: Option<String>,
        /// PID of the requesting child process, if known
        child_pid: u32,
        /// Session identifier
        session_id: String,
    },
    /// An Tool Sandbox  command-launch approval request (from the `Approve` intercept action).
    Command {
        /// Unique identifier for this request
        request_id: String,
        /// The command name (e.g. `"git"`)
        command: String,
        /// Full argument list including argv[0]
        args: Vec<String>,
        /// Tool Sandbox  caller identity (e.g. `"session"` or a chained command name)
        caller: String,
        /// The intercept rule pattern that triggered this approval
        intercept_rule: String,
        /// Human-readable reason (may be empty)
        reason: Option<String>,
        /// PID of the shim process that sent the request
        child_pid: u32,
        /// Session identifier
        session_id: String,
    },
}

impl ApprovalRequest {
    /// The request_id for this request (all variants carry one).
    #[must_use]
    pub fn request_id(&self) -> &str {
        match self {
            ApprovalRequest::Capability { request_id, .. }
            | ApprovalRequest::Network { request_id, .. }
            | ApprovalRequest::Endpoint { request_id, .. }
            | ApprovalRequest::Command { request_id, .. } => request_id,
        }
    }

    /// The session_id for this request (all variants carry one).
    #[must_use]
    pub fn session_id(&self) -> &str {
        match self {
            ApprovalRequest::Capability { session_id, .. }
            | ApprovalRequest::Network { session_id, .. }
            | ApprovalRequest::Endpoint { session_id, .. }
            | ApprovalRequest::Command { session_id, .. } => session_id,
        }
    }
}

impl From<CapabilityRequest> for ApprovalRequest {
    fn from(r: CapabilityRequest) -> Self {
        ApprovalRequest::Capability {
            request_id: r.request_id,
            path: r.path,
            access: r.access,
            reason: r.reason,
            child_pid: r.child_pid,
            session_id: r.session_id,
        }
    }
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
/// The `request` field covers all request types via [`ApprovalRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// When the decision was made
    pub timestamp: SystemTime,
    /// The original request (file, network, or command)
    pub request: ApprovalRequest,
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
}
