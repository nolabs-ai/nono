use crate::audit_integrity::{
    AUDIT_EVENTS_FILENAME, AuditEventPayload, AuditEventRecord, CommandPolicyAuditEvent,
};
use nono::supervisor::AuditEntry;
use nono::{NonoError, Result};
use serde::Serialize;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[derive(Clone, Serialize)]
pub(crate) struct CommandPolicyAuditRecord {
    pub(crate) sequence: u64,
    pub(crate) leaf_hash: String,
    pub(crate) chain_hash: String,
    #[serde(flatten)]
    pub(crate) event: CommandPolicyAuditEvent,
}

pub(crate) fn load_command_policy_events(
    session_dir: &Path,
) -> Result<Vec<CommandPolicyAuditRecord>> {
    let path = session_dir.join(AUDIT_EVENTS_FILENAME);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = File::open(&path).map_err(|e| {
        NonoError::Snapshot(format!(
            "Failed to open audit event log {}: {e}",
            path.display()
        ))
    })?;
    let reader = BufReader::new(file);
    let mut events = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| {
            NonoError::Snapshot(format!(
                "Failed to read audit event log {}: {e}",
                path.display()
            ))
        })?;
        if line.trim().is_empty() {
            continue;
        }
        let record: AuditEventRecord = serde_json::from_str(&line).map_err(|e| {
            NonoError::Snapshot(format!(
                "Failed to parse audit event record {} line {}: {e}",
                path.display(),
                index.saturating_add(1)
            ))
        })?;
        if let AuditEventPayload::CommandPolicy { event } = record.event {
            events.push(CommandPolicyAuditRecord {
                sequence: record.sequence,
                leaf_hash: record.leaf_hash.to_string(),
                chain_hash: record.chain_hash.to_string(),
                event: *event,
            });
        }
    }
    Ok(events)
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
    let file = File::open(&path).map_err(|e| {
        NonoError::Snapshot(format!(
            "Failed to open audit event log {}: {e}",
            path.display()
        ))
    })?;
    let reader = BufReader::new(file);
    let mut events = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| {
            NonoError::Snapshot(format!(
                "Failed to read audit event log {}: {e}",
                path.display()
            ))
        })?;
        if line.trim().is_empty() {
            continue;
        }
        let record: AuditEventRecord = serde_json::from_str(&line).map_err(|e| {
            NonoError::Snapshot(format!(
                "Failed to parse audit event record {} line {}: {e}",
                path.display(),
                index.saturating_add(1)
            ))
        })?;
        if let AuditEventPayload::CapabilityDecision { entry } = record.event {
            events.push(entry);
        }
    }
    Ok(events)
}
