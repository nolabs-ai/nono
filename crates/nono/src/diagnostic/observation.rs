//! Stderr observation inputs converted to [`NonoDiagnostic`] records.
//!
//! Parsing heuristics live in `nono-cli`; this module defines the record shape.

use crate::capability::AccessMode;
use crate::diagnostic::{
    NonoDiagnostic, NonoDiagnosticCode, NonoDiagnosticDetail, NonoDiagnosticSeverity,
    NonoRemediation, StderrObservationKind,
};
use std::path::PathBuf;

/// Input for stderr-derived session diagnostics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionObservationInput {
    /// Paths inferred from stderr that likely hit sandbox restrictions.
    pub likely_sandbox_paths: Vec<(PathBuf, AccessMode)>,
    /// Paths reported missing by the command output.
    pub missing_paths: Vec<PathBuf>,
    /// Application-level failure text unrelated to sandbox permissions.
    pub application_failure: Option<String>,
    /// Protected instruction file referenced in stderr.
    pub blocked_protected_file: Option<String>,
    /// Stderr suggests a network operation was blocked.
    pub network_blocked_hint: bool,
}

impl SessionObservationInput {
    /// Build structured diagnostics from observation inputs.
    #[must_use]
    pub fn into_diagnostics(self) -> Vec<NonoDiagnostic> {
        let mut diagnostics = Vec::new();

        if let Some(file) = self.blocked_protected_file {
            diagnostics.push(diagnostic_protected_file_write(file));
        }

        for path in self.missing_paths {
            diagnostics.push(diagnostic_missing_path(path));
        }

        if let Some(message) = self.application_failure {
            diagnostics.push(diagnostic_application_failure(message));
        }

        if self.network_blocked_hint {
            diagnostics.push(diagnostic_network_blocked());
        }

        for (path, access) in self.likely_sandbox_paths {
            let remediation = grant_path_remediation(path.clone(), access);
            diagnostics.push(diagnostic_likely_sandbox_path(path, access, remediation));
        }

        diagnostics
    }
}

/// Discovery and policy-check hints for footers with no logged path denials.
#[must_use]
pub fn follow_up_diagnostics() -> Vec<NonoDiagnostic> {
    vec![
        NonoDiagnostic::new(
            NonoDiagnosticCode::CommandFailedLikelySandbox,
            NonoDiagnosticSeverity::Info,
            "discover additional paths required by the command",
        )
        .with_remediation(NonoRemediation::RunDiscovery),
        NonoDiagnostic::new(
            NonoDiagnosticCode::CommandFailedApplication,
            NonoDiagnosticSeverity::Info,
            "inspect sandbox policy for a specific path",
        )
        .with_remediation(NonoRemediation::CheckPolicy),
    ]
}

#[must_use]
pub fn diagnostic_likely_sandbox_path(
    path: PathBuf,
    access: AccessMode,
    remediation: NonoRemediation,
) -> NonoDiagnostic {
    NonoDiagnostic::new(
        NonoDiagnosticCode::CommandFailedLikelySandbox,
        NonoDiagnosticSeverity::Warning,
        format!(
            "command output suggests {} ({access}) may be sandbox-related",
            path.display()
        ),
    )
    .with_path_access(path, access)
    .with_remediation(remediation)
    .with_detail(NonoDiagnosticDetail::StderrObservation {
        observation_kind: StderrObservationKind::LikelySandboxPath,
    })
}

#[must_use]
pub fn diagnostic_missing_path(path: PathBuf) -> NonoDiagnostic {
    NonoDiagnostic::new(
        NonoDiagnosticCode::CommandFailedApplication,
        NonoDiagnosticSeverity::Warning,
        format!("command reported missing path {}", path.display()),
    )
    .with_path_access(path.clone(), AccessMode::Read)
    .with_detail(NonoDiagnosticDetail::StderrObservation {
        observation_kind: StderrObservationKind::MissingPath,
    })
}

#[must_use]
pub fn diagnostic_application_failure(message: String) -> NonoDiagnostic {
    NonoDiagnostic::new(
        NonoDiagnosticCode::CommandFailedApplication,
        NonoDiagnosticSeverity::Warning,
        format!("command reported application error: {message}"),
    )
    .with_detail(NonoDiagnosticDetail::StderrObservation {
        observation_kind: StderrObservationKind::ApplicationFailure,
    })
}

#[must_use]
pub fn diagnostic_protected_file_write(file: String) -> NonoDiagnostic {
    NonoDiagnostic::new(
        NonoDiagnosticCode::TrustVerificationFailed,
        NonoDiagnosticSeverity::Warning,
        format!("Write to '{file}' blocked: file is a signed instruction file."),
    )
    .with_detail(NonoDiagnosticDetail::StderrObservation {
        observation_kind: StderrObservationKind::ProtectedFileWrite,
    })
}

#[must_use]
pub fn diagnostic_network_blocked() -> NonoDiagnostic {
    NonoDiagnostic::new(
        NonoDiagnosticCode::SandboxDeniedNetwork,
        NonoDiagnosticSeverity::Warning,
        "command output contains a network error; if a required host is unreachable, check whether network access is blocked",
    )
    .with_detail(NonoDiagnosticDetail::StderrObservation {
        observation_kind: StderrObservationKind::NetworkBlocked,
    })
}

#[must_use]
fn grant_path_remediation(path: PathBuf, access: AccessMode) -> NonoRemediation {
    NonoRemediation::GrantPath {
        is_file: grant_path_is_file(&path),
        path,
        access,
    }
}

#[must_use]
fn grant_path_is_file(path: &std::path::Path) -> bool {
    if path.is_file() {
        return true;
    }
    if path.is_dir() {
        return false;
    }
    path.file_name().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn observation_input_builds_likely_sandbox_diagnostic() {
        let input = SessionObservationInput {
            likely_sandbox_paths: vec![(PathBuf::from("/tmp/x"), AccessMode::Read)],
            ..SessionObservationInput::default()
        };
        let diagnostics = input.into_diagnostics();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].code,
            NonoDiagnosticCode::CommandFailedLikelySandbox
        );
    }

    #[test]
    fn network_hint_emits_sandbox_denied_network() {
        let input = SessionObservationInput {
            network_blocked_hint: true,
            ..SessionObservationInput::default()
        };
        let diagnostics = input.into_diagnostics();
        assert!(
            diagnostics
                .iter()
                .any(|d| d.code == NonoDiagnosticCode::SandboxDeniedNetwork)
        );
    }
}
