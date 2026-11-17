//! The audit log records terminal recording writes (NEP-0010 §4, §5).
//!
//! These are extension events: the `nono` library hash-links them like any
//! other record and verifies the chain without interpreting them, and this
//! module defines, writes and parses them. On disk each is
//! `{"type": <name>, ...fields}`, the same layout as the library's own
//! events, so the platform and other readers see ordinary audit records.
//!
//! Readers parse a record's `event_json`, the bytes its leaf hash covers,
//! never a separately stored copy.

use crate::audit_integrity::{AuditEventRecord, AuditRecorder};
use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};

/// Directory, inside an audit session directory, holding terminal chunks.
pub(crate) const TERMINAL_RECORDING_DIRNAME: &str = "terminal";

/// File name of terminal recording chunk `index` inside
/// [`TERMINAL_RECORDING_DIRNAME`].
///
/// The name is derived from the index only, so a log record can never point
/// a verifier at an arbitrary path.
#[must_use]
pub(crate) fn terminal_chunk_file_name(index: u64) -> String {
    format!("chunk-{index:08}.cast.zst")
}

/// A closed terminal recording chunk (NEP-0010 §4).
///
/// Ranges are half-open: `[start, end)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TerminalChunkEvent {
    /// Chunk index, starting at 0, contiguous within a session.
    pub(crate) index: u64,
    /// First capture `seq` in the chunk.
    pub(crate) seq_start: u64,
    /// One past the last capture `seq` in the chunk.
    pub(crate) seq_end: u64,
    /// Offset of the first event from session start, in microseconds.
    pub(crate) start_offset_us: u64,
    /// Offset of the last event from session start, in microseconds.
    pub(crate) end_offset_us: u64,
    /// First audit record sequence number written during the chunk window.
    pub(crate) audit_seq_start: u64,
    /// One past the last audit record sequence number written during the
    /// chunk window (this chunk's own record is not included).
    pub(crate) audit_seq_end: u64,
    /// Uncompressed chunk size in bytes.
    pub(crate) raw_bytes: u64,
    /// Stored (compressed) chunk size in bytes.
    pub(crate) stored_bytes: u64,
    /// SHA-256 of the stored chunk file, lowercase hex.
    pub(crate) sha256: String,
    /// Number of credential values replaced in this chunk.
    pub(crate) credential_redactions: u64,
    /// Number of input events whose content was not captured.
    pub(crate) suppressed_inputs: u64,
}

/// Capture events a sink could not keep (NEP-0010 §5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RecordingLostEvent {
    /// Sink that lost the events.
    pub(crate) sink: String,
    /// First lost capture `seq`.
    pub(crate) seq_start: u64,
    /// One past the last lost capture `seq`.
    pub(crate) seq_end: u64,
    /// Why the events were lost.
    pub(crate) reason: String,
}

/// Recording stopped at its configured size limit (NEP-0010 §4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TerminalRecordingTruncatedEvent {
    /// First capture `seq` not recorded.
    pub(crate) seq: u64,
    /// Configured limit in uncompressed bytes.
    pub(crate) max_bytes: u64,
    /// Uncompressed bytes recorded before the limit.
    pub(crate) recorded_bytes: u64,
}

const TERMINAL_CHUNK: &str = "terminal_chunk";
const RECORDING_LOST: &str = "recording_lost";
const TERMINAL_RECORDING_TRUNCATED: &str = "terminal_recording_truncated";

#[derive(Serialize)]
struct ChunkFields<'a> {
    chunk: &'a TerminalChunkEvent,
}

#[derive(Serialize)]
struct EventFields<'a, T: Serialize> {
    event: &'a T,
}

/// Record a closed terminal recording chunk.
pub(crate) fn record_terminal_chunk(
    recorder: &mut AuditRecorder,
    chunk: &TerminalChunkEvent,
) -> Result<()> {
    recorder.record_extension_event(TERMINAL_CHUNK, &ChunkFields { chunk })
}

/// Record capture events a sink could not keep.
pub(crate) fn record_recording_lost(
    recorder: &mut AuditRecorder,
    event: &RecordingLostEvent,
) -> Result<()> {
    recorder.record_extension_event(RECORDING_LOST, &EventFields { event })
}

/// Record that terminal recording stopped at its size limit.
pub(crate) fn record_terminal_recording_truncated(
    recorder: &mut AuditRecorder,
    event: &TerminalRecordingTruncatedEvent,
) -> Result<()> {
    recorder.record_extension_event(TERMINAL_RECORDING_TRUNCATED, &EventFields { event })
}

/// A terminal recording record read from the audit log.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum RecordingAuditEvent {
    TerminalChunk {
        chunk: TerminalChunkEvent,
    },
    RecordingLost {
        event: RecordingLostEvent,
    },
    TerminalRecordingTruncated {
        event: TerminalRecordingTruncatedEvent,
    },
}

/// The terminal recording event in `record`, if it is one.
///
/// Library events are not recording events. A record whose type names a
/// recording event but whose fields do not parse is an error, never skipped,
/// so a damaged or forged record cannot silently drop a chunk.
pub(crate) fn parse_recording_event(
    record: &AuditEventRecord,
) -> Result<Option<RecordingAuditEvent>> {
    if !record.event.is_unrecognized() {
        return Ok(None);
    }
    let Some(json) = record.event_json.as_deref() else {
        return Ok(None);
    };
    let value: serde_json::Value = serde_json::from_str(json).map_err(|e| {
        NonoError::Snapshot(format!(
            "audit record {} is not valid JSON: {e}",
            record.sequence
        ))
    })?;
    let is_recording_event = matches!(
        value.get("type").and_then(serde_json::Value::as_str),
        Some(TERMINAL_CHUNK | RECORDING_LOST | TERMINAL_RECORDING_TRUNCATED)
    );
    if !is_recording_event {
        return Ok(None);
    }
    serde_json::from_value(value).map(Some).map_err(|e| {
        NonoError::Snapshot(format!(
            "audit record {} is a malformed terminal recording event: {e}",
            record.sequence
        ))
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::audit_integrity::AUDIT_EVENTS_FILENAME;

    fn sample_chunk() -> TerminalChunkEvent {
        TerminalChunkEvent {
            index: 2,
            seq_start: 40,
            seq_end: 75,
            start_offset_us: 20_000_000,
            end_offset_us: 29_500_000,
            audit_seq_start: 6,
            audit_seq_end: 9,
            raw_bytes: 4096,
            stored_bytes: 812,
            sha256: "5d41402abc4b2a76b9719d911017c592aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            credential_redactions: 1,
            suppressed_inputs: 2,
        }
    }

    fn records(dir: &std::path::Path) -> Vec<AuditEventRecord> {
        std::fs::read_to_string(dir.join(AUDIT_EVENTS_FILENAME))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    /// The exact bytes and leaf hashes these events had when the library
    /// defined them. Moving them must not change a single byte, or logs and
    /// the platform would see different records.
    #[test]
    fn recording_events_keep_their_exact_bytes_and_leaf_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let mut recorder = AuditRecorder::new(dir.path().to_path_buf()).unwrap();
        record_terminal_chunk(&mut recorder, &sample_chunk()).unwrap();
        record_recording_lost(
            &mut recorder,
            &RecordingLostEvent {
                sink: "recording".to_string(),
                seq_start: 75,
                seq_end: 90,
                reason: "queue_full".to_string(),
            },
        )
        .unwrap();
        record_terminal_recording_truncated(
            &mut recorder,
            &TerminalRecordingTruncatedEvent {
                seq: 90,
                max_bytes: 268_435_456,
                recorded_bytes: 268_435_000,
            },
        )
        .unwrap();
        let expected = [
            (
                r#"{"type":"terminal_chunk","chunk":{"index":2,"seq_start":40,"seq_end":75,"start_offset_us":20000000,"end_offset_us":29500000,"audit_seq_start":6,"audit_seq_end":9,"raw_bytes":4096,"stored_bytes":812,"sha256":"5d41402abc4b2a76b9719d911017c592aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","credential_redactions":1,"suppressed_inputs":2}}"#,
                "58a3c2bb093ef3faf394eb0939ad58ce44fd870717c8f6765abf87390a3a26c6",
            ),
            (
                r#"{"type":"recording_lost","event":{"sink":"recording","seq_start":75,"seq_end":90,"reason":"queue_full"}}"#,
                "83698e8df2e8ac376e3e368467b98f5d53bd2cbaa2191793a3b0f02516320c90",
            ),
            (
                r#"{"type":"terminal_recording_truncated","event":{"seq":90,"max_bytes":268435456,"recorded_bytes":268435000}}"#,
                "1871ac463e4cb49eb5094470648627f84959b932ecacc65108519cd5423eeacf",
            ),
        ];
        let written = records(dir.path());
        assert_eq!(written.len(), expected.len());
        for (record, (json, leaf)) in written.iter().zip(expected) {
            assert_eq!(record.event_json.as_deref(), Some(json));
            assert_eq!(record.leaf_hash.to_string(), leaf);
        }
    }

    #[test]
    fn recording_events_verify_and_parse_back() {
        let dir = tempfile::tempdir().unwrap();
        let mut recorder = AuditRecorder::new(dir.path().to_path_buf()).unwrap();
        recorder
            .record_session_started("2026-04-21T00:00:00Z".to_string(), vec!["pwd".to_string()])
            .unwrap();
        record_terminal_chunk(&mut recorder, &sample_chunk()).unwrap();
        recorder
            .record_session_ended("2026-04-21T00:00:01Z".to_string(), 0)
            .unwrap();
        let summary = recorder.finalize().unwrap();
        let verified = nono::audit::verify_audit_log(dir.path(), Some(&summary)).unwrap();
        assert!(verified.records_verified);

        let parsed: Vec<_> = records(dir.path())
            .iter()
            .map(|record| parse_recording_event(record).unwrap())
            .collect();
        assert_eq!(
            parsed,
            vec![
                None,
                Some(RecordingAuditEvent::TerminalChunk {
                    chunk: sample_chunk()
                }),
                None
            ]
        );
    }

    #[test]
    fn a_malformed_recording_record_is_an_error_not_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let mut recorder = AuditRecorder::new(dir.path().to_path_buf()).unwrap();
        recorder
            .record_extension_event(
                TERMINAL_CHUNK,
                &serde_json::json!({ "chunk": { "index": 1 } }),
            )
            .unwrap();
        let record = &records(dir.path())[0];
        assert!(parse_recording_event(record).is_err());
    }

    #[test]
    fn other_extension_types_are_not_recording_events() {
        let dir = tempfile::tempdir().unwrap();
        let mut recorder = AuditRecorder::new(dir.path().to_path_buf()).unwrap();
        recorder
            .record_extension_event("something_else", &serde_json::json!({ "x": 1 }))
            .unwrap();
        assert_eq!(
            parse_recording_event(&records(dir.path())[0]).unwrap(),
            None
        );
    }

    #[test]
    fn chunk_file_names_depend_only_on_index() {
        assert_eq!(terminal_chunk_file_name(0), "chunk-00000000.cast.zst");
        assert_eq!(terminal_chunk_file_name(12), "chunk-00000012.cast.zst");
        assert_eq!(
            terminal_chunk_file_name(u64::MAX),
            "chunk-18446744073709551615.cast.zst"
        );
    }
}
