pub(crate) use nono::audit::{AuditRecorder, verify_audit_log};

#[cfg(test)]
pub(crate) use nono::audit::{AUDIT_EVENTS_FILENAME, AUDIT_HASH_ALGORITHM, AuditEventRecord};

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use nono::AccessMode;
    use nono::supervisor::{ApprovalDecision, AuditEntry, CapabilityRequest, UrlOpenRequest};
    use nono::undo::{NetworkAuditDecision, NetworkAuditEvent, NetworkAuditMode};
    use std::path::PathBuf;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn recorder_produces_integrity_summary() {
        let dir = tempfile::tempdir().unwrap();
        let mut recorder = AuditRecorder::new(dir.path().to_path_buf()).unwrap();
        recorder
            .record_session_started("2026-04-21T00:00:00Z".to_string(), vec!["pwd".to_string()])
            .unwrap();
        recorder
            .record_session_ended("2026-04-21T00:00:01Z".to_string(), 0)
            .unwrap();

        let summary = recorder.finalize().unwrap();
        assert_eq!(summary.event_count, 2);
        assert_eq!(summary.hash_algorithm, AUDIT_HASH_ALGORITHM);
    }

    #[test]
    fn recorder_tracks_event_count_without_needing_integrity_output() {
        let dir = tempfile::tempdir().unwrap();
        let mut recorder = AuditRecorder::new(dir.path().to_path_buf()).unwrap();
        recorder
            .record_session_started("2026-04-21T00:00:00Z".to_string(), vec!["pwd".to_string()])
            .unwrap();

        assert_eq!(recorder.event_count(), 1);
    }

    #[test]
    fn record_session_started_scrubs_command_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let mut recorder = AuditRecorder::new(dir.path().to_path_buf()).unwrap();
        recorder
            .record_session_started(
                "2026-04-21T00:00:00Z".to_string(),
                vec![
                    "curl".to_string(),
                    "--password".to_string(),
                    "real-password".to_string(),
                    "-H".to_string(),
                    "Authorization: Bearer real-token".to_string(),
                    "https://example.com/api?token=query-secret".to_string(),
                ],
            )
            .unwrap();

        let contents = std::fs::read_to_string(dir.path().join(AUDIT_EVENTS_FILENAME)).unwrap();

        assert!(contents.contains("[REDACTED]"));
        assert!(!contents.contains("real-password"));
        assert!(!contents.contains("real-token"));
        assert!(!contents.contains("query-secret"));
    }

    #[test]
    fn record_session_started_uses_configured_redaction_policy() {
        let dir = tempfile::tempdir().unwrap();
        let mut redactions = nono::ScrubPolicy::secure_default();
        redactions.add_flag("--private-token");
        redactions.remove_query_key("state");
        let mut recorder =
            AuditRecorder::new_with_policy(dir.path().to_path_buf(), redactions).unwrap();
        recorder
            .record_session_started(
                "2026-04-21T00:00:00Z".to_string(),
                vec![
                    "curl".to_string(),
                    "--private-token=private-secret".to_string(),
                    "https://example.com/callback?state=visible&token=hidden".to_string(),
                ],
            )
            .unwrap();

        let contents = std::fs::read_to_string(dir.path().join(AUDIT_EVENTS_FILENAME)).unwrap();

        assert!(contents.contains("--private-token=[REDACTED]"));
        assert!(contents.contains("state=visible"));
        assert!(contents.contains("\"added_flags\":[\"--private-token\"]"));
        assert!(contents.contains("\"removed_query_keys\":[\"state\"]"));
        assert!(!contents.contains("private-secret"));
        assert!(!contents.contains("token=hidden"));
    }

    #[test]
    fn verifier_round_trips_all_current_audit_event_payload_variants() {
        let dir = tempfile::tempdir().unwrap();
        let mut recorder = AuditRecorder::new(dir.path().to_path_buf()).unwrap();
        recorder
            .record_session_started(
                "2026-04-21T00:00:00Z".to_string(),
                vec!["claude".to_string(), "--debug".to_string()],
            )
            .unwrap();
        recorder
            .record_capability_decision(AuditEntry {
                timestamp: UNIX_EPOCH + Duration::from_secs(5),
                request: CapabilityRequest {
                    request_id: "req-1".to_string(),
                    path: PathBuf::from("/tmp/example"),
                    access: AccessMode::ReadWrite,
                    reason: Some("need scratch space".to_string()),
                    child_pid: 42,
                    session_id: "sess-1".to_string(),
                },
                decision: ApprovalDecision::Denied {
                    reason: "outside policy".to_string(),
                },
                backend: "terminal".to_string(),
                duration_ms: 12,
            })
            .unwrap();
        recorder
            .record_open_url(
                UrlOpenRequest {
                    request_id: "open-1".to_string(),
                    url: "https://example.com/callback".to_string(),
                    child_pid: 42,
                    session_id: "sess-1".to_string(),
                },
                false,
                Some("blocked".to_string()),
            )
            .unwrap();
        recorder
            .record_network_event(NetworkAuditEvent {
                timestamp_unix_ms: 123,
                mode: NetworkAuditMode::Reverse,
                decision: NetworkAuditDecision::Deny,
                route_id: None,
                auth_mechanism: None,
                auth_outcome: None,
                managed_credential_active: None,
                injection_mode: None,
                denial_category: None,
                target: "api.example.com".to_string(),
                port: Some(443),
                method: Some("POST".to_string()),
                path: Some("/v1/chat".to_string()),
                status: Some(403),
                reason: Some("policy".to_string()),
            })
            .unwrap();
        recorder
            .record_session_ended("2026-04-21T00:00:01Z".to_string(), 7)
            .unwrap();

        let summary = recorder.finalize().unwrap();
        let verified = verify_audit_log(dir.path(), Some(&summary)).unwrap();
        assert_eq!(verified.event_count, 5);
        assert_eq!(verified.merkle_scheme, "alpha");
        assert!(verified.records_verified);
    }

    #[test]
    fn verifier_rejects_alpha_records_missing_event_json() {
        let dir = tempfile::tempdir().unwrap();
        let mut recorder = AuditRecorder::new(dir.path().to_path_buf()).unwrap();
        recorder
            .record_session_started("2026-04-21T00:00:00Z".to_string(), vec!["pwd".to_string()])
            .unwrap();
        recorder
            .record_session_ended("2026-04-21T00:00:01Z".to_string(), 0)
            .unwrap();

        let path = dir.path().join(AUDIT_EVENTS_FILENAME);
        let contents = std::fs::read_to_string(&path).unwrap();
        let rewritten = contents
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                let mut record: AuditEventRecord = serde_json::from_str(line).unwrap();
                record.event_json = None;
                serde_json::to_string(&record).unwrap()
            })
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&path, format!("{rewritten}\n")).unwrap();

        let summary = recorder.finalize().unwrap();
        let err = match verify_audit_log(dir.path(), Some(&summary)) {
            Ok(_) => panic!("alpha verification should reject records missing event_json"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("missing canonical event_json bytes")
        );
    }
}
