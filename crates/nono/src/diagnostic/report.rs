//! Session diagnostic reports for library and binding clients.

use crate::capability::AccessMode;
use crate::diagnostic::{
    DenialReason, DenialRecord, IpcDenialRecord, NonoDiagnostic, NonoDiagnosticCode,
    NonoDiagnosticDetail, NonoDiagnosticSeverity, NonoRemediation, SandboxViolation,
    seatbelt_operation_to_access,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Structured report of sandbox-related diagnostics for a supervised session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionDiagnosticReport {
    pub exit_code: i32,
    pub denials: Vec<DenialRecord>,
    pub ipc_denials: Vec<IpcDenialRecord>,
    pub violations: Vec<SandboxViolation>,
    pub diagnostics: Vec<NonoDiagnostic>,
}

impl SessionDiagnosticReport {
    /// Build a report from runtime denial records and optional OS violations.
    #[must_use]
    pub fn from_session(
        exit_code: i32,
        denials: Vec<DenialRecord>,
        ipc_denials: Vec<IpcDenialRecord>,
        violations: Vec<SandboxViolation>,
    ) -> Self {
        Self::from_merged_session(exit_code, denials, ipc_denials, violations)
    }

    /// Merge filesystem violations into denials, then build diagnostics.
    ///
    /// Filesystem Seatbelt violations become path denials. Other violations
    /// become separate diagnostic entries.
    #[must_use]
    pub fn from_merged_session(
        exit_code: i32,
        denials: Vec<DenialRecord>,
        ipc_denials: Vec<IpcDenialRecord>,
        violations: Vec<SandboxViolation>,
    ) -> Self {
        let (violation_denials, non_fs_violations) = violations_to_denials(&violations);
        let mut merged_denials = denials;
        merged_denials.extend(violation_denials);
        let deduped = dedupe_denials(&merged_denials);

        let mut diagnostics = Vec::new();
        for denial in &deduped {
            if denial.reason == DenialReason::UnixSocketDenied && !ipc_denials.is_empty() {
                continue;
            }
            diagnostics.push(diagnostic_from_denial(denial));
        }
        for ipc in &ipc_denials {
            diagnostics.push(diagnostic_from_ipc_denial(ipc));
        }
        for violation in &non_fs_violations {
            diagnostics.push(diagnostic_from_non_fs_violation(violation));
        }

        Self {
            exit_code,
            denials: deduped,
            ipc_denials,
            violations,
            diagnostics,
        }
    }

    /// Serialize this report to JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if JSON serialization fails.
    pub fn to_json(&self) -> crate::Result<String> {
        serde_json::to_string(self).map_err(|e| {
            crate::NonoError::ConfigParse(format!("session diagnostic JSON error: {e}"))
        })
    }

    /// Wrap session report JSON with an optional proxy diagnostics array.
    ///
    /// `proxy_diagnostics_json` must be a JSON array when present (the shape emitted by
    /// `nono_proxy::ProxyHandle::diagnostics_json()`).
    ///
    /// # Errors
    ///
    /// Returns an error if either JSON blob is malformed.
    pub fn merge_with_proxy_json(
        session_json: &str,
        proxy_diagnostics_json: Option<&str>,
    ) -> crate::Result<String> {
        let session_value: serde_json::Value = serde_json::from_str(session_json).map_err(|e| {
            crate::NonoError::ConfigParse(format!("parse session diagnostic JSON: {e}"))
        })?;
        let output = if let Some(proxy_text) = proxy_diagnostics_json.filter(|s| !s.is_empty()) {
            let proxy_value: serde_json::Value = serde_json::from_str(proxy_text).map_err(|e| {
                crate::NonoError::ConfigParse(format!("parse proxy diagnostics JSON: {e}"))
            })?;
            serde_json::json!({
                "session": session_value,
                "proxy": proxy_value,
            })
        } else {
            serde_json::json!({ "session": session_value })
        };
        serde_json::to_string_pretty(&output).map_err(|e| {
            crate::NonoError::ConfigParse(format!("format merged diagnostic JSON: {e}"))
        })
    }
}

/// Deduplicate denials by path, merging access modes.
#[must_use]
pub fn dedupe_denials(denials: &[DenialRecord]) -> Vec<DenialRecord> {
    let mut by_path = BTreeMap::<PathBuf, (AccessMode, DenialReason)>::new();

    for denial in denials {
        by_path
            .entry(denial.path.clone())
            .and_modify(|(access, reason)| {
                *access = merge_access_modes(*access, denial.access);
                *reason = stricter_reason(reason.clone(), denial.reason.clone());
            })
            .or_insert_with(|| (denial.access, denial.reason.clone()));
    }

    by_path
        .into_iter()
        .map(|(path, (access, reason))| DenialRecord {
            path,
            access,
            reason,
        })
        .collect()
}

#[must_use]
fn violations_to_denials(
    violations: &[SandboxViolation],
) -> (Vec<DenialRecord>, Vec<SandboxViolation>) {
    let mut denials = Vec::new();
    let mut non_fs = Vec::new();
    let mut seen = BTreeMap::<PathBuf, AccessMode>::new();

    for violation in violations {
        if let (Some(access), Some(target)) = (
            seatbelt_operation_to_access(&violation.operation),
            &violation.target,
        ) {
            let path = PathBuf::from(target);
            seen.entry(path)
                .and_modify(|existing| *existing = merge_access_modes(*existing, access))
                .or_insert(access);
        } else {
            non_fs.push(violation.clone());
        }
    }

    for (path, access) in seen {
        denials.push(DenialRecord {
            path,
            access,
            reason: DenialReason::PolicyBlocked,
        });
    }

    (denials, non_fs)
}

/// Filesystem violations converted into path denials for session merging.
#[must_use]
pub fn filesystem_denials_from_violations(violations: &[SandboxViolation]) -> Vec<DenialRecord> {
    violations_to_denials(violations).0
}

#[must_use]
fn merge_access_modes(existing: AccessMode, new: AccessMode) -> AccessMode {
    if existing == new {
        existing
    } else {
        AccessMode::ReadWrite
    }
}

#[must_use]
fn stricter_reason(a: DenialReason, b: DenialReason) -> DenialReason {
    fn rank(r: &DenialReason) -> u8 {
        match r {
            DenialReason::PolicyBlocked => 5,
            DenialReason::UnixSocketDenied => 5,
            DenialReason::InsufficientAccess => 4,
            DenialReason::UserDenied => 3,
            DenialReason::RateLimited => 2,
            DenialReason::BackendError => 1,
        }
    }
    if rank(&a) >= rank(&b) { a } else { b }
}

#[must_use]
fn diagnostic_from_denial(denial: &DenialRecord) -> NonoDiagnostic {
    let code = match denial.reason {
        DenialReason::UnixSocketDenied => NonoDiagnosticCode::SandboxDeniedUnixSocket,
        DenialReason::PolicyBlocked => NonoDiagnosticCode::SandboxDeniedPath,
        _ => NonoDiagnosticCode::SandboxDeniedPath,
    };
    let message = format!(
        "access to {} ({}) denied: {:?}",
        denial.path.display(),
        denial.access,
        denial.reason
    );
    let mut diagnostic = NonoDiagnostic::new(code, NonoDiagnosticSeverity::Warning, message)
        .with_path_access(denial.path.clone(), denial.access)
        .with_detail(NonoDiagnosticDetail::SupervisedDenial {
            reason: denial.reason.clone(),
        });
    match denial.reason {
        DenialReason::UnixSocketDenied => {
            diagnostic = diagnostic.with_remediation(NonoRemediation::GrantUnixSocket {
                path: denial.path.clone(),
                bind: denial.access.contains(AccessMode::Write),
            });
        }
        DenialReason::InsufficientAccess
        | DenialReason::PolicyBlocked
        | DenialReason::UserDenied
        | DenialReason::RateLimited => {
            diagnostic = diagnostic
                .with_remediation(grant_path_remediation(denial.path.clone(), denial.access));
        }
        DenialReason::BackendError => {}
    }
    diagnostic
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
fn grant_path_is_file(path: &Path) -> bool {
    if path.is_file() {
        return true;
    }
    if path.is_dir() {
        return false;
    }
    path.file_name().is_some()
}

#[must_use]
fn diagnostic_from_ipc_denial(ipc: &IpcDenialRecord) -> NonoDiagnostic {
    let mut diagnostic = NonoDiagnostic::new(
        NonoDiagnosticCode::SandboxDeniedUnixSocket,
        NonoDiagnosticSeverity::Warning,
        format!("{} {} denied: {}", ipc.operation, ipc.target, ipc.reason),
    )
    .with_detail(NonoDiagnosticDetail::IpcDenial {
        operation: ipc.operation.clone(),
        target: ipc.target.clone(),
        ipc_reason: ipc.reason.clone(),
    });
    if let Some(remediation) = ipc.remediation.clone() {
        if let NonoRemediation::GrantUnixSocket { ref path, .. } = remediation {
            diagnostic = diagnostic.with_path_access(path.clone(), AccessMode::Read);
        }
        diagnostic = diagnostic.with_remediation(remediation);
    }
    diagnostic
}

#[must_use]
fn diagnostic_from_non_fs_violation(violation: &SandboxViolation) -> NonoDiagnostic {
    let target = violation.target.as_deref().unwrap_or("<unknown>");
    NonoDiagnostic::new(
        NonoDiagnosticCode::UnsupportedPlatformFeature,
        NonoDiagnosticSeverity::Warning,
        format!(
            "sandbox blocked system service: {} ({target})",
            violation.operation
        ),
    )
    .with_detail(NonoDiagnosticDetail::SeatbeltViolation {
        operation: violation.operation.clone(),
        target: violation.target.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn session_report_builds_diagnostics_from_denials() {
        let denials = vec![DenialRecord {
            path: PathBuf::from("/tmp/secret"),
            access: AccessMode::Read,
            reason: DenialReason::PolicyBlocked,
        }];
        let report = SessionDiagnosticReport::from_session(1, denials, vec![], vec![]);
        assert_eq!(report.diagnostics.len(), 1);
        assert_eq!(
            report.diagnostics[0].code,
            NonoDiagnosticCode::SandboxDeniedPath
        );
        assert!(matches!(
            report.diagnostics[0].remediation,
            Some(NonoRemediation::GrantPath { .. })
        ));
        assert!(matches!(
            report.diagnostics[0].detail,
            Some(NonoDiagnosticDetail::SupervisedDenial { .. })
        ));
    }

    #[test]
    fn insufficient_access_includes_grant_path_remediation() {
        let denials = vec![DenialRecord {
            path: PathBuf::from("/project/src"),
            access: AccessMode::Write,
            reason: DenialReason::InsufficientAccess,
        }];
        let report = SessionDiagnosticReport::from_session(1, denials, vec![], vec![]);
        assert!(matches!(
            report.diagnostics[0].remediation,
            Some(NonoRemediation::GrantPath { .. })
        ));
    }

    #[test]
    fn unix_socket_path_denial_includes_grant_remediation() {
        let denials = vec![DenialRecord {
            path: PathBuf::from("/run/user/1000/bus"),
            access: AccessMode::Read,
            reason: DenialReason::UnixSocketDenied,
        }];
        let report = SessionDiagnosticReport::from_session(1, denials, vec![], vec![]);
        assert_eq!(report.diagnostics.len(), 1);
        assert!(matches!(
            report.diagnostics[0].remediation,
            Some(NonoRemediation::GrantUnixSocket { bind: false, .. })
        ));
    }

    #[test]
    fn unix_socket_path_denial_skipped_when_ipc_denials_present() {
        let denials = vec![DenialRecord {
            path: PathBuf::from("/run/user/1000/bus"),
            access: AccessMode::Read,
            reason: DenialReason::UnixSocketDenied,
        }];
        let ipc_denials = vec![IpcDenialRecord::new(
            "/run/user/1000/bus".to_string(),
            "connect".to_string(),
            "no matching unix_socket capability".to_string(),
            Some(NonoRemediation::GrantUnixSocket {
                path: PathBuf::from("/run/user/1000/bus"),
                bind: false,
            }),
        )];
        let report = SessionDiagnosticReport::from_session(1, denials, ipc_denials, vec![]);
        assert_eq!(report.diagnostics.len(), 1);
        assert!(matches!(
            report.diagnostics[0].detail,
            Some(NonoDiagnosticDetail::IpcDenial { .. })
        ));
    }

    #[test]
    fn non_fs_violation_becomes_system_service_diagnostic() {
        let violations = vec![SandboxViolation {
            operation: "mach-lookup".to_string(),
            target: Some("com.apple.secd".to_string()),
        }];
        let report = SessionDiagnosticReport::from_session(1, vec![], vec![], violations);
        assert_eq!(report.diagnostics.len(), 1);
        assert_eq!(
            report.diagnostics[0].code,
            NonoDiagnosticCode::UnsupportedPlatformFeature
        );
    }

    #[test]
    fn violation_includes_grant_path_remediation() {
        let violations = vec![SandboxViolation {
            operation: "file-read-data".to_string(),
            target: Some("/Users/me/Desktop/secret.txt".to_string()),
        }];
        let report = SessionDiagnosticReport::from_session(1, vec![], vec![], violations);
        assert!(matches!(
            report.diagnostics[0].remediation,
            Some(NonoRemediation::GrantPath { is_file: true, .. })
        ));
    }

    #[test]
    fn session_report_json_roundtrip() {
        let report = SessionDiagnosticReport::from_session(2, vec![], vec![], vec![]);
        let json = report.to_json().expect("json");
        assert!(json.contains("\"exit_code\":2"));
    }

    #[test]
    fn merge_with_proxy_json_wraps_session_and_proxy_arrays() {
        let session = SessionDiagnosticReport::from_session(1, vec![], vec![], vec![]);
        let session_json = session.to_json().expect("session json");
        let proxy_json = r#"[{"code":"credential_not_found","severity":"warning","route_prefix":"openai","message":"missing"}]"#;
        let merged =
            SessionDiagnosticReport::merge_with_proxy_json(&session_json, Some(proxy_json))
                .expect("merged");
        assert!(merged.contains("\"session\""));
        assert!(merged.contains("\"proxy\""));
        assert!(merged.contains("credential_not_found"));
    }

    #[test]
    fn dedupe_denials_merges_access_modes() {
        let denials = vec![
            DenialRecord {
                path: PathBuf::from("/tmp/a"),
                access: AccessMode::Read,
                reason: DenialReason::UserDenied,
            },
            DenialRecord {
                path: PathBuf::from("/tmp/a"),
                access: AccessMode::Write,
                reason: DenialReason::InsufficientAccess,
            },
        ];
        let deduped = dedupe_denials(&denials);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].access, AccessMode::ReadWrite);
    }
}
