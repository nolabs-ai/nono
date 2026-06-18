//! Stable diagnostic codes and remediation types.

use crate::capability::AccessMode;
use crate::diagnostic::NonoDiagnosticDetail;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Severity of a structured diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NonoDiagnosticSeverity {
    Info,
    Warning,
    Error,
}

/// Stable diagnostic code suitable for Rust, C FFI, and language bindings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NonoDiagnosticCode {
    SandboxDeniedPath,
    SandboxDeniedNetwork,
    SandboxDeniedUnixSocket,
    CommandNotFound,
    CommandFailedLikelySandbox,
    CommandFailedApplication,
    CredentialNotFound,
    CredentialUnavailable,
    UnsupportedPlatformFeature,
    RollbackBudgetExceeded,
    CwdAccessRequired,
    ConfigurationError,
    TrustVerificationFailed,
    IoError,
    Cancelled,
    Other,
}

/// Remediation action; clients render this as flags or other UI text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NonoRemediation {
    GrantPath {
        path: PathBuf,
        access: AccessMode,
        is_file: bool,
    },
    GrantUnixSocket {
        path: PathBuf,
        bind: bool,
    },
    GrantNetwork,
    RunDiscovery,
    CheckPolicy,
    AuthenticateCredentialProvider {
        provider: String,
    },
    AdjustRollbackBudget {
        current_bytes: Option<u64>,
        limit_bytes: Option<u64>,
    },
    AllowCwd,
    DisableRollback,
}

/// Map structured remediation to the legacy CLI flag string shape.
///
/// Kept for backwards compatibility with code that read
/// [`crate::IpcDenialRecord::suggested_flag`]. New code should use
/// [`NonoRemediation`] and render flags in the CLI/bindings layer.
#[deprecated(
    since = "0.64.0",
    note = "Use `NonoRemediation` instead. Legacy flag strings will be removed in 1.0.0."
)]
#[must_use]
pub fn suggested_flag_for_remediation(rem: &NonoRemediation) -> Option<String> {
    match rem {
        NonoRemediation::GrantPath {
            path,
            access,
            is_file,
        } => {
            let (flag, target) = suggested_flag_parts(path, *access, *is_file);
            Some(format!("{flag} {}", target.display()))
        }
        NonoRemediation::GrantUnixSocket { path, bind } => {
            let flag = if *bind {
                "--allow-unix-socket-bind"
            } else {
                "--allow-unix-socket"
            };
            Some(format!("{flag} {}", path.display()))
        }
        NonoRemediation::AllowCwd => Some("--allow-cwd".to_string()),
        NonoRemediation::DisableRollback => Some("--no-rollback".to_string()),
        NonoRemediation::GrantNetwork => Some("--allow-net".to_string()),
        NonoRemediation::RunDiscovery
        | NonoRemediation::CheckPolicy
        | NonoRemediation::AuthenticateCredentialProvider { .. }
        | NonoRemediation::AdjustRollbackBudget { .. } => None,
    }
}

fn suggested_flag_parts(
    path: &Path,
    requested: AccessMode,
    is_file: bool,
) -> (&'static str, PathBuf) {
    if is_file {
        let flag = match requested {
            AccessMode::Read => "--read-file",
            AccessMode::Write => "--write-file",
            AccessMode::ReadWrite => "--allow-file",
        };
        return (flag, path.to_path_buf());
    }

    let flag = match requested {
        AccessMode::Read => "--read",
        AccessMode::Write => "--write",
        AccessMode::ReadWrite => "--allow",
    };
    (flag, path.to_path_buf())
}

/// One structured diagnostic entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonoDiagnostic {
    pub code: NonoDiagnosticCode,
    pub severity: NonoDiagnosticSeverity,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<NonoRemediation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access: Option<AccessMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<NonoDiagnosticDetail>,
}

impl NonoDiagnostic {
    #[must_use]
    pub fn new(
        code: NonoDiagnosticCode,
        severity: NonoDiagnosticSeverity,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            severity,
            message: message.into(),
            hint: None,
            remediation: None,
            path: None,
            access: None,
            detail: None,
        }
    }

    #[must_use]
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    #[must_use]
    pub fn with_remediation(mut self, remediation: NonoRemediation) -> Self {
        self.remediation = Some(remediation);
        self
    }

    #[must_use]
    pub fn with_path_access(mut self, path: PathBuf, access: AccessMode) -> Self {
        self.path = Some(path);
        self.access = Some(access);
        self
    }

    #[must_use]
    pub fn with_detail(mut self, detail: NonoDiagnosticDetail) -> Self {
        self.detail = Some(detail);
        self
    }
}
