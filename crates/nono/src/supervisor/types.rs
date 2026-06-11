//! Supervisor IPC types for capability expansion
//!
//! These types define the protocol between a sandboxed child process and its
//! unsandboxed supervisor parent. The child sends [`CapabilityRequest`]s over
//! a Unix socket, and the supervisor responds with [`ApprovalDecision`]s.

use crate::capability::AccessMode;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::SystemTime;
use zeroize::Zeroizing;

/// Secret bytes carried over supervisor IPC.
///
/// The wrapper zeroizes the allocation when dropped. It does not protect
/// serialized copies in kernel/socket buffers or provider-owned allocations.
pub type SecretBytes = Zeroizing<Vec<u8>>;

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
    /// Unique identifier for correlating the request with its response and audit entries.
    pub request_id: String,
    /// The URL to open in the user's browser
    pub url: String,
    /// PID of the requesting child process
    pub child_pid: u32,
    /// Session identifier for correlating requests within a single run
    pub session_id: String,
}

/// Frontend that observed a credential operation inside the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialFrontend {
    /// Native Security.framework API interposition.
    SecurityFramework,
    /// `/usr/bin/security` compatible command shim.
    SecurityCli,
}

/// Credential provider handled by the supervisor broker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialProvider {
    /// macOS Keychain.
    MacosKeychain,
}

/// Credential item class in the provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialItemClass {
    /// Generic password item.
    GenericPassword,
    /// Internet password item.
    InternetPassword,
}

/// Credential operation requested by the sandboxed child.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialOperation {
    Read,
    Create,
    Update,
    Upsert,
    Delete,
    Status,
}

/// A normalized credential request from an opaque frontend.
///
/// Secret values are optional because most operations do not carry secret
/// material. When present, callers must treat `secret` as sensitive data and
/// must not log it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRequest {
    /// Unique identifier for correlating the request with its response and audit entries.
    pub request_id: String,
    /// Frontend that converted the native operation into this request.
    pub frontend: CredentialFrontend,
    /// Provider that should handle the operation.
    pub provider: CredentialProvider,
    /// Operation being requested.
    pub operation: CredentialOperation,
    /// Item class being requested.
    pub item_class: CredentialItemClass,
    /// Generic-password service name, when present.
    pub service: Option<String>,
    /// Account name, when present.
    pub account: Option<String>,
    /// Human-readable label, when present.
    pub label: Option<String>,
    /// Internet-password server, when present.
    pub server: Option<String>,
    /// Internet-password protocol, when present.
    pub protocol: Option<String>,
    /// Internet-password path, when present.
    pub path: Option<String>,
    /// Keychain access group, when present.
    pub access_group: Option<String>,
    /// Secret bytes for create/update/upsert operations.
    pub secret: Option<SecretBytes>,
    /// Whether the caller requested secret material in the response.
    pub return_secret: bool,
    /// PID of the requesting child process.
    pub child_pid: u32,
    /// Session identifier for correlating requests within a single run.
    pub session_id: String,
}

/// The supervisor's response to a [`CredentialRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CredentialResponse {
    /// Operation succeeded. `secret` is populated only for successful read
    /// operations that requested secret material.
    Ok {
        request_id: String,
        secret: Option<SecretBytes>,
    },
    /// Operation was denied by policy.
    Denied { request_id: String, reason: String },
    /// Operation is not supported by the current frontend or broker.
    Unsupported { request_id: String, reason: String },
    /// Operation failed after policy allowed it.
    Error { request_id: String, reason: String },
}

/// IPC message envelope sent from child to supervisor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SupervisorMessage {
    /// A capability expansion request (explicit, from SDK clients)
    Request(CapabilityRequest),
    /// A request to open a URL in the user's browser (e.g., OAuth2 login)
    OpenUrl(UrlOpenRequest),
    /// A credential operation request from an opaque frontend.
    Credential(CredentialRequest),
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
    /// Response to a credential operation request.
    Credential(CredentialResponse),
}
