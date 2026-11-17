//! Reading and checking a stored session recording (NEP-0010 §4).
//!
//! The audit log is the index: `terminal_chunk` records name each chunk by
//! index, with the hash and size of its stored form and the capture `seq`
//! range it holds. This module checks the stored chunks against those
//! records and decodes them back into asciicast events for `nono replay`
//! and `nono transcript`.
//!
//! Chunk files are only ever located by index through
//! [`terminal_chunk_file_name`], never by a path taken from the log, and
//! every chunk is hash-checked before it is decompressed. Decompression is
//! bounded by the recorded raw size.

use super::audit_events::{
    RecordingAuditEvent, RecordingLostEvent, TerminalChunkEvent, parse_recording_event,
    terminal_chunk_file_name,
};
use super::writer::{hex_digest, recording_dir};
use nono::{NonoError, Result};
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::Path;

/// Largest chunk this reader will decompress. The writer closes chunks at
/// 1 MiB by default; the margin allows the default to grow.
const MAX_CHUNK_RAW_BYTES: u64 = 64 * 1024 * 1024;

/// What `nono audit verify` and `nono inspect` report about a recording.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub(crate) struct RecordingReport {
    /// The audit log references a recording.
    pub(crate) present: bool,
    pub(crate) chunks: u64,
    /// Indexes whose chunk file is missing.
    pub(crate) missing: Vec<u64>,
    /// Indexes whose stored bytes do not match the audit record.
    pub(crate) mismatched: Vec<u64>,
    /// Chunk indexes are not 0, 1, 2, ... in log order.
    pub(crate) index_gaps: bool,
    /// `seq` ranges between chunks not explained by `recording_lost`.
    pub(crate) unexplained_gaps: Vec<(u64, u64)>,
    /// Events lost and recorded as lost.
    pub(crate) lost_events: u64,
    /// The recording stopped at its size limit.
    pub(crate) truncated: bool,
    /// Files in the recording directory that no chunk record names.
    pub(crate) unreferenced_files: Vec<String>,
    pub(crate) raw_bytes: u64,
    pub(crate) stored_bytes: u64,
    pub(crate) credential_redactions: u64,
    pub(crate) suppressed_inputs: u64,
    /// The audit log ended in a partial record (the session is still
    /// being written).
    pub(crate) partial_log: bool,
}

impl RecordingReport {
    /// Every referenced chunk exists and matches, and the capture sequence
    /// is contiguous apart from recorded losses.
    pub(crate) fn verified(&self) -> bool {
        self.missing.is_empty()
            && self.mismatched.is_empty()
            && !self.index_gaps
            && self.unexplained_gaps.is_empty()
    }
}

/// The recording's audit records, in log order.
struct RecordingIndex {
    chunks: Vec<TerminalChunkEvent>,
    lost: Vec<RecordingLostEvent>,
    truncated: bool,
    partial_log: bool,
}

fn read_index(session_dir: &Path) -> Result<RecordingIndex> {
    let path = session_dir.join(crate::audit_integrity::AUDIT_EVENTS_FILENAME);
    let mut index = RecordingIndex {
        chunks: Vec::new(),
        lost: Vec::new(),
        truncated: false,
        partial_log: false,
    };
    if !path.exists() {
        return Ok(index);
    }
    // The first malformed recording record; reading stops being trusted there.
    let mut malformed: Option<NonoError> = None;
    index.partial_log = crate::audit_event_reader::for_each_event_record(&path, true, |record| {
        if malformed.is_some() {
            return;
        }
        match parse_recording_event(&record) {
            Ok(Some(RecordingAuditEvent::TerminalChunk { chunk })) => index.chunks.push(chunk),
            Ok(Some(RecordingAuditEvent::RecordingLost { event })) => index.lost.push(event),
            Ok(Some(RecordingAuditEvent::TerminalRecordingTruncated { .. })) => {
                index.truncated = true;
            }
            Ok(None) => {}
            Err(e) => malformed = Some(e),
        }
    })?;
    match malformed {
        Some(e) => Err(e),
        None => Ok(index),
    }
}

/// Check the stored recording against the audit log.
pub(crate) fn verify(session_dir: &Path) -> Result<RecordingReport> {
    let index = read_index(session_dir)?;
    let mut report = RecordingReport {
        present: !index.chunks.is_empty() || !index.lost.is_empty() || index.truncated,
        chunks: index.chunks.len() as u64,
        truncated: index.truncated,
        partial_log: index.partial_log,
        ..RecordingReport::default()
    };
    if !report.present {
        return Ok(report);
    }
    let dir = recording_dir(session_dir);
    let mut referenced = BTreeSet::new();
    for (position, chunk) in index.chunks.iter().enumerate() {
        if chunk.index != position as u64 {
            report.index_gaps = true;
        }
        let name = terminal_chunk_file_name(chunk.index);
        referenced.insert(name.clone());
        report.raw_bytes = report.raw_bytes.saturating_add(chunk.raw_bytes);
        report.stored_bytes = report.stored_bytes.saturating_add(chunk.stored_bytes);
        report.credential_redactions = report
            .credential_redactions
            .saturating_add(chunk.credential_redactions);
        report.suppressed_inputs = report
            .suppressed_inputs
            .saturating_add(chunk.suppressed_inputs);
        match std::fs::read(dir.join(&name)) {
            Ok(stored) => {
                if !stored_matches(&stored, chunk) {
                    report.mismatched.push(chunk.index);
                }
            }
            Err(_) => report.missing.push(chunk.index),
        }
    }
    report.lost_events = index
        .lost
        .iter()
        .map(|lost| lost.seq_end.saturating_sub(lost.seq_start))
        .fold(0u64, u64::saturating_add);
    report.unexplained_gaps = unexplained_gaps(&index.chunks, &index.lost);
    if let Ok(entries) = std::fs::read_dir(&dir) {
        let mut extra: Vec<String> = entries
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| !referenced.contains(name))
            .collect();
        extra.sort();
        report.unreferenced_files = extra;
    }
    Ok(report)
}

fn stored_matches(stored: &[u8], chunk: &TerminalChunkEvent) -> bool {
    stored.len() as u64 == chunk.stored_bytes && hex_digest(stored) == chunk.sha256
}

/// `seq` ranges between consecutive chunks (and before the first) that no
/// `recording_lost` record covers.
fn unexplained_gaps(chunks: &[TerminalChunkEvent], lost: &[RecordingLostEvent]) -> Vec<(u64, u64)> {
    let mut ranges: Vec<(u64, u64)> = lost
        .iter()
        .filter(|l| l.seq_end > l.seq_start)
        .map(|l| (l.seq_start, l.seq_end))
        .collect();
    ranges.sort_unstable();
    let covered = |start: u64, end: u64| {
        let mut cursor = start;
        for &(lo, hi) in &ranges {
            if lo <= cursor && hi > cursor {
                cursor = hi;
            }
            if cursor >= end {
                return true;
            }
        }
        cursor >= end
    };
    let mut gaps = Vec::new();
    let mut expected = 0u64;
    for chunk in chunks {
        if chunk.seq_start > expected && !covered(expected, chunk.seq_start) {
            gaps.push((expected, chunk.seq_start));
        }
        if chunk.seq_start < expected || chunk.seq_end < chunk.seq_start {
            // Overlapping or inverted ranges cannot come from the writer.
            gaps.push((chunk.seq_start, chunk.seq_end));
        }
        expected = expected.max(chunk.seq_end);
    }
    gaps
}

/// One decoded asciicast event.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum CastEvent {
    Output { time: f64, data: String },
    Input { time: f64, data: String },
    Resize { time: f64, cols: u16, rows: u16 },
    Marker { time: f64, label: String },
}

impl CastEvent {
    pub(crate) fn time(&self) -> f64 {
        match self {
            Self::Output { time, .. }
            | Self::Input { time, .. }
            | Self::Resize { time, .. }
            | Self::Marker { time, .. } => *time,
        }
    }
}

/// A recording decoded from its verified chunks.
#[derive(Clone, Debug)]
pub(crate) struct Recording {
    pub(crate) header: serde_json::Value,
    pub(crate) cols: u16,
    pub(crate) rows: u16,
    pub(crate) events: Vec<CastEvent>,
    pub(crate) report: RecordingReport,
}

/// Load a recording for replay or transcript. Refuses a recording that
/// fails verification, so nothing is shown from altered chunks.
pub(crate) fn load(session_dir: &Path) -> Result<Recording> {
    let report = verify(session_dir)?;
    if !report.present || report.chunks == 0 {
        return Err(NonoError::Snapshot(
            "this session has no terminal recording".to_string(),
        ));
    }
    if !report.verified() {
        return Err(NonoError::Snapshot(
            "the terminal recording does not match the audit log; \
             run `nono audit verify` for details"
                .to_string(),
        ));
    }
    let index = read_index(session_dir)?;
    let dir = recording_dir(session_dir);
    let mut text = String::new();
    for chunk in &index.chunks {
        let stored =
            std::fs::read(dir.join(terminal_chunk_file_name(chunk.index))).map_err(|e| {
                NonoError::Snapshot(format!("failed to read chunk {}: {e}", chunk.index))
            })?;
        // Re-check: the file may have changed since `verify` read it.
        if !stored_matches(&stored, chunk) {
            return Err(NonoError::Snapshot(format!(
                "terminal recording chunk {} changed while it was read",
                chunk.index
            )));
        }
        if chunk.raw_bytes > MAX_CHUNK_RAW_BYTES {
            return Err(NonoError::Snapshot(format!(
                "terminal recording chunk {} is too large to read",
                chunk.index
            )));
        }
        let raw = zstd::bulk::decompress(&stored, chunk.raw_bytes as usize).map_err(|e| {
            NonoError::Snapshot(format!("failed to decompress chunk {}: {e}", chunk.index))
        })?;
        if raw.len() as u64 != chunk.raw_bytes {
            return Err(NonoError::Snapshot(format!(
                "terminal recording chunk {} has the wrong size",
                chunk.index
            )));
        }
        text.push_str(&String::from_utf8_lossy(&raw));
    }
    let mut lines = text.lines();
    let header: serde_json::Value = lines
        .next()
        .and_then(|line| serde_json::from_str(line).ok())
        .ok_or_else(|| NonoError::Snapshot("terminal recording has no header".to_string()))?;
    let dimension = |key: &str, default: u16| {
        header[key]
            .as_u64()
            .and_then(|v| u16::try_from(v).ok())
            .filter(|v| *v > 0)
            .unwrap_or(default)
    };
    let (cols, rows) = (dimension("width", 80), dimension("height", 24));
    let events = lines.filter_map(parse_event).collect();
    Ok(Recording {
        header,
        cols,
        rows,
        events,
        report,
    })
}

fn parse_event(line: &str) -> Option<CastEvent> {
    let (time, code, data): (f64, String, String) = serde_json::from_str(line).ok()?;
    if !time.is_finite() || time < 0.0 {
        return None;
    }
    match code.as_str() {
        "o" => Some(CastEvent::Output { time, data }),
        "i" => Some(CastEvent::Input { time, data }),
        "r" => {
            let (cols, rows) = data.split_once('x')?;
            Some(CastEvent::Resize {
                time,
                cols: cols.parse().ok().filter(|c| *c > 0)?,
                rows: rows.parse().ok().filter(|r| *r > 0)?,
            })
        }
        "m" => Some(CastEvent::Marker { time, label: data }),
        _ => None,
    }
}

/// Split a `nono:<event>:<json>` marker label.
pub(crate) fn parse_marker(label: &str) -> Option<(&str, serde_json::Value)> {
    let rest = label.strip_prefix("nono:")?;
    let (name, body) = rest.split_once(':')?;
    Some((name, serde_json::from_str(body).ok()?))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn chunk(index: u64, seq_start: u64, seq_end: u64) -> TerminalChunkEvent {
        TerminalChunkEvent {
            index,
            seq_start,
            seq_end,
            start_offset_us: 0,
            end_offset_us: 0,
            audit_seq_start: 0,
            audit_seq_end: 0,
            raw_bytes: 0,
            stored_bytes: 0,
            sha256: String::new(),
            credential_redactions: 0,
            suppressed_inputs: 0,
        }
    }

    fn lost(seq_start: u64, seq_end: u64) -> RecordingLostEvent {
        RecordingLostEvent {
            sink: "recording".to_string(),
            seq_start,
            seq_end,
            reason: "queue_full".to_string(),
        }
    }

    #[test]
    fn contiguous_chunks_have_no_gaps() {
        assert!(unexplained_gaps(&[chunk(0, 0, 5), chunk(1, 5, 9)], &[]).is_empty());
    }

    #[test]
    fn gaps_must_be_covered_by_recorded_losses() {
        let chunks = [chunk(0, 0, 5), chunk(1, 8, 9), chunk(2, 12, 13)];
        assert_eq!(
            unexplained_gaps(&chunks, &[lost(5, 8)]),
            vec![(9, 12)],
            "the first gap is explained, the second is not"
        );
        assert!(unexplained_gaps(&chunks, &[lost(5, 7), lost(7, 8), lost(9, 12)]).is_empty());
        assert_eq!(
            unexplained_gaps(&[chunk(0, 3, 4)], &[]),
            vec![(0, 3)],
            "a missing start is a gap"
        );
    }

    #[test]
    fn overlapping_ranges_are_reported() {
        assert_eq!(
            unexplained_gaps(&[chunk(0, 0, 5), chunk(1, 3, 6)], &[]),
            vec![(3, 6)]
        );
    }

    #[test]
    fn parses_asciicast_events_and_rejects_junk() {
        assert_eq!(
            parse_event(r#"[1.5,"o","hi"]"#),
            Some(CastEvent::Output {
                time: 1.5,
                data: "hi".to_string()
            })
        );
        assert_eq!(
            parse_event(r#"[2,"r","100x40"]"#),
            Some(CastEvent::Resize {
                time: 2.0,
                cols: 100,
                rows: 40
            })
        );
        assert_eq!(parse_event(r#"[2,"r","0x40"]"#), None);
        assert_eq!(parse_event(r#"[-1,"o","x"]"#), None);
        assert_eq!(parse_event(r#"[1,"z","x"]"#), None);
        assert_eq!(parse_event("not json"), None);
        let (name, body) = parse_marker(r#"nono:lifecycle:{"event":"started"}"#).unwrap();
        assert_eq!(name, "lifecycle");
        assert_eq!(body["event"], "started");
    }
}
