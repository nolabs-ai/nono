//! Structured context attached to session diagnostics.

use super::records::DenialReason;
use serde::{Deserialize, Serialize};

/// Origin and structured context for a session diagnostic entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NonoDiagnosticDetail {
    /// Path denial recorded by the supervised session.
    SupervisedDenial { reason: DenialReason },
    /// Unix socket denial recorded by IPC mediation.
    IpcDenial {
        operation: String,
        target: String,
        ipc_reason: String,
    },
    /// macOS Seatbelt violation that is not expressible as a path grant.
    SeatbeltViolation {
        operation: String,
        target: Option<String>,
    },
    /// From stderr parsing in `nono-cli`.
    StderrObservation {
        observation_kind: StderrObservationKind,
    },
}

/// Kind of stderr-derived observation encoded as a structured diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StderrObservationKind {
    LikelySandboxPath,
    MissingPath,
    ApplicationFailure,
    ProtectedFileWrite,
    NetworkBlocked,
}
