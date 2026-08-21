use crate::audit_integrity::{
    AUDIT_EVENTS_FILENAME, AuditEventPayload, AuditEventRecord, CommandPolicyAuditEvent,
    CommandPolicySummaryBuilder,
};
use crate::tool_sandbox::command_policy_decision::CommandPolicyDecision;
use nono::supervisor::AuditEntry;
use nono::undo::CommandPolicySummary;
use nono::{NonoError, Result};
use serde::Serialize;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

#[derive(Clone, Serialize)]
pub(crate) struct CommandPolicyAuditRecord {
    pub(crate) sequence: u64,
    pub(crate) leaf_hash: String,
    pub(crate) chain_hash: String,
    #[serde(flatten)]
    pub(crate) event: CommandPolicyAuditEvent,
}

/// Visit every record in a session's audit event log.
///
/// Returns whether a trailing record was skipped because it did not parse.
/// `tolerate_partial_tail` is for readers of a log whose writer may not have
/// finished its final record: only the final line can be such a record, so a
/// parse failure anywhere earlier stays an error.
///
/// Reading stops at the length the log had when it was opened, so the parse
/// walks a fixed snapshot without holding the whole log in memory. Deciding
/// "is this the last line?" against the live file instead would race a
/// concurrent writer: a record completed after a torn read but before the
/// check would turn the tolerated tail into a hard error.
fn for_each_event_record(
    path: &Path,
    tolerate_partial_tail: bool,
    mut visit: impl FnMut(AuditEventRecord),
) -> Result<bool> {
    fn read_error(path: &Path, e: std::io::Error) -> NonoError {
        NonoError::Snapshot(format!(
            "Failed to read audit event log {}: {e}",
            path.display()
        ))
    }

    let file = File::open(path).map_err(|e| read_error(path, e))?;
    let snapshot_len = file.metadata().map_err(|e| read_error(path, e))?.len();
    let mut lines = BufReader::new(file.take(snapshot_len))
        .lines()
        .enumerate()
        .peekable();
    while let Some((index, line)) = lines.next() {
        let line = line.map_err(|e| read_error(path, e))?;
        if line.trim().is_empty() {
            continue;
        }
        let record: AuditEventRecord = match serde_json::from_str(&line) {
            Ok(record) => record,
            Err(_) if tolerate_partial_tail && lines.peek().is_none() => return Ok(true),
            Err(e) => {
                return Err(NonoError::Snapshot(format!(
                    "Failed to parse audit event record {} line {}: {e}",
                    path.display(),
                    index.saturating_add(1)
                )));
            }
        };
        visit(record);
    }
    Ok(false)
}

pub(crate) fn load_command_policy_events(
    session_dir: &Path,
) -> Result<Vec<CommandPolicyAuditRecord>> {
    let path = session_dir.join(AUDIT_EVENTS_FILENAME);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut events = Vec::new();
    for_each_event_record(&path, false, |record| {
        if let AuditEventPayload::CommandPolicy { event } = record.event {
            events.push(CommandPolicyAuditRecord {
                sequence: record.sequence,
                leaf_hash: record.leaf_hash.to_string(),
                chain_hash: record.chain_hash.to_string(),
                event: *event,
            });
        }
    })?;
    Ok(events)
}

/// Recompute a session's mediated-command rollup from its audit event log.
///
/// For callers reaching a session whose stored rollup is unavailable: the
/// session is still running, or it died before finalizing `session.json`.
/// Folds the same events in the same order as the recorder, so the result
/// equals the summary the session would have committed.
///
/// Returns whether the log ended in a partial record. Either kind of writer —
/// still appending, or killed mid-write — can legitimately leave its final
/// record half-written, so a torn tail is reported through the flag rather
/// than as an error; damage anywhere earlier stays an error. A session that
/// finalized has an authoritative, digest-covered rollup in its metadata, and
/// readers must use that instead of refolding the log.
pub(crate) fn recompute_command_policy_summary(
    session_dir: &Path,
) -> Result<(Option<CommandPolicySummary>, bool)> {
    let path = session_dir.join(AUDIT_EVENTS_FILENAME);
    if !path.exists() {
        return Ok((None, false));
    }
    let mut builder = CommandPolicySummaryBuilder::new();
    let partial_tail = for_each_event_record(&path, true, |record| match record.event {
        AuditEventPayload::CommandPolicy { event } => {
            let outcome = CommandPolicyDecision::classify(&event.decision);
            builder.observe(&event, outcome);
        }
        AuditEventPayload::SandboxRuntime { event } if event.tool_sandbox_active => {
            builder.observe_mediation_active();
        }
        _ => {}
    })?;
    Ok((builder.finish(), partial_tail))
}

pub(crate) fn command_policy_events_json(session_dir: &Path) -> Result<Vec<serde_json::Value>> {
    let mut values = Vec::new();
    for record in load_command_policy_events(session_dir)? {
        let mut value = serde_json::to_value(record).map_err(|e| {
            NonoError::Snapshot(format!(
                "Failed to serialize command policy audit event: {e}"
            ))
        })?;
        let Some(object) = value.as_object_mut() else {
            return Err(NonoError::Snapshot(
                "Command policy audit event did not serialize as an object".to_string(),
            ));
        };
        object.insert(
            "event_type".to_string(),
            serde_json::Value::String("command_policy".to_string()),
        );
        values.push(value);
    }
    Ok(values)
}

pub(crate) fn load_capability_decisions(session_dir: &Path) -> Result<Vec<AuditEntry>> {
    let path = session_dir.join(AUDIT_EVENTS_FILENAME);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut events = Vec::new();
    for_each_event_record(&path, false, |record| {
        if let AuditEventPayload::CapabilityDecision { entry } = record.event {
            events.push(entry);
        }
    })?;
    Ok(events)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::audit_integrity::{AuditRecorder, SandboxRuntimeAuditEvent};
    use nono::undo::CommandPolicyOutcome;
    use std::fs::OpenOptions;
    use std::io::Write;

    fn command_policy_event(
        command: &str,
        decision: CommandPolicyDecision,
    ) -> CommandPolicyAuditEvent {
        CommandPolicyAuditEvent {
            timestamp: "2026-08-13T00:00:00Z".to_string(),
            session_id: Some("20260813-120000-4242".to_string()),
            invocation_id: None,
            command: command.to_string(),
            caller: "session".to_string(),
            caller_kind: Some("session".to_string()),
            caller_command: None,
            caller_pid: Some(41),
            shim_pid: Some(42),
            session_root_pid: Some(41),
            decision: decision.as_str().to_string(),
            reason: None,
            stdio_mode: "direct_fds".to_string(),
            argv_hash: "argv-hash".to_string(),
            env_name_hash: "env-hash".to_string(),
            cwd_hash: "cwd-hash".to_string(),
            argv_display: vec![command.to_string()],
            env_names_display: Vec::new(),
            env_display: Vec::new(),
            cwd_display: "/work".to_string(),
            exit_code: None,
            stdio: None,
        }
    }

    fn mediating_recorder(session_dir: &Path) -> AuditRecorder {
        let mut recorder = AuditRecorder::new(session_dir.to_path_buf()).unwrap();
        recorder
            .record_session_started(
                "2026-08-13T00:00:00Z".to_string(),
                vec!["claude".to_string()],
            )
            .unwrap();
        recorder
            .record_sandbox_runtime_event(SandboxRuntimeAuditEvent {
                timestamp: "2026-08-13T00:00:00Z".to_string(),
                platform: "linux".to_string(),
                landlock_abi: Some("v5".to_string()),
                landlock_execute_enforced: Some(true),
                tool_sandbox_active: true,
            })
            .unwrap();
        recorder
    }

    #[test]
    fn recomputed_summary_matches_the_one_the_recorder_would_commit() {
        let dir = tempfile::tempdir().unwrap();
        let mut recorder = mediating_recorder(dir.path());
        for decision in [
            CommandPolicyDecision::InvocationAllowed,
            CommandPolicyDecision::Allowed,
            CommandPolicyDecision::Denied,
        ] {
            recorder
                .record_command_policy_event(
                    command_policy_event("gh", decision),
                    decision.outcome(),
                )
                .unwrap();
        }
        recorder
            .record_command_policy_event(
                command_policy_event("git", CommandPolicyDecision::Allowed),
                CommandPolicyOutcome::Allowed,
            )
            .unwrap();

        let (recomputed, partial_tail) = recompute_command_policy_summary(dir.path()).unwrap();

        assert_eq!(recomputed, recorder.command_policy_summary());
        assert!(!partial_tail);
    }

    #[test]
    fn configured_mediation_is_recomputed_before_any_invocation() {
        let dir = tempfile::tempdir().unwrap();
        let _recorder = mediating_recorder(dir.path());

        let (recomputed, _) = recompute_command_policy_summary(dir.path()).unwrap();

        let summary = recomputed.expect("an active-mediation session always has a summary");
        assert!(summary.mediation_active);
        assert_eq!(summary.event_count, 0);
        assert!(summary.commands.is_empty());
    }

    #[test]
    fn a_session_without_mediation_has_no_summary() {
        let dir = tempfile::tempdir().unwrap();
        let mut recorder = AuditRecorder::new(dir.path().to_path_buf()).unwrap();
        recorder
            .record_session_started("2026-08-13T00:00:00Z".to_string(), vec!["pwd".to_string()])
            .unwrap();

        assert_eq!(
            recompute_command_policy_summary(dir.path()).unwrap(),
            (None, false)
        );
    }

    #[test]
    fn a_session_with_no_event_log_has_no_summary() {
        let dir = tempfile::tempdir().unwrap();

        assert_eq!(
            recompute_command_policy_summary(dir.path()).unwrap(),
            (None, false)
        );
    }

    #[test]
    fn a_half_written_final_record_is_reported_not_counted() {
        let dir = tempfile::tempdir().unwrap();
        let mut recorder = mediating_recorder(dir.path());
        recorder
            .record_command_policy_event(
                command_policy_event("gh", CommandPolicyDecision::Allowed),
                CommandPolicyOutcome::Allowed,
            )
            .unwrap();
        let mut log = OpenOptions::new()
            .append(true)
            .open(dir.path().join(AUDIT_EVENTS_FILENAME))
            .unwrap();
        log.write_all(br#"{"sequence":3,"prev_chain":"#).unwrap();
        log.flush().unwrap();

        let (recomputed, partial_tail) = recompute_command_policy_summary(dir.path()).unwrap();

        assert!(partial_tail);
        assert_eq!(recomputed, recorder.command_policy_summary());
    }

    /// Damage anywhere but the tail cannot be a record in flight, so a rollup
    /// over it would quietly drop decisions the operator asked to see.
    #[test]
    fn damage_before_the_final_record_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let mut recorder = mediating_recorder(dir.path());
        for decision in [
            CommandPolicyDecision::Allowed,
            CommandPolicyDecision::Denied,
        ] {
            recorder
                .record_command_policy_event(
                    command_policy_event("gh", decision),
                    decision.outcome(),
                )
                .unwrap();
        }
        let path = dir.path().join(AUDIT_EVENTS_FILENAME);
        let contents = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<&str> = contents.lines().collect();
        lines[1] = r#"{"sequence":1,"#;
        std::fs::write(&path, lines.join("\n")).unwrap();

        assert!(recompute_command_policy_summary(dir.path()).is_err());
    }

    #[test]
    fn strict_readers_reject_a_half_written_final_record() {
        let dir = tempfile::tempdir().unwrap();
        let mut recorder = mediating_recorder(dir.path());
        recorder
            .record_command_policy_event(
                command_policy_event("gh", CommandPolicyDecision::Allowed),
                CommandPolicyOutcome::Allowed,
            )
            .unwrap();
        let mut log = OpenOptions::new()
            .append(true)
            .open(dir.path().join(AUDIT_EVENTS_FILENAME))
            .unwrap();
        log.write_all(br#"{"sequence":3,"prev_chain":"#).unwrap();
        log.flush().unwrap();

        assert!(load_command_policy_events(dir.path()).is_err());
    }
}
