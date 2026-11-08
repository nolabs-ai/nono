//! The recording writer: asciicast v2 encoding, zstd chunks, and the sinks
//! that react to closed chunks (NEP-0010 §4, §5).
//!
//! Runs on its own thread so capture never waits on disk or the audit lock.
//! Chunk 0 starts with the asciicast header; later chunks hold event lines
//! only. Each chunk is one zstd frame, so concatenating the chunk files in
//! index order gives a single zstd stream that decompresses to one complete
//! asciicast v2 file.

use super::events::{CaptureEvent, ProtectedEvent, SessionEnd};
use crate::audit_integrity::AuditRecorder;
use nono::audit::{
    RecordingLostEvent, TERMINAL_RECORDING_DIRNAME, TerminalChunkEvent,
    TerminalRecordingTruncatedEvent, terminal_chunk_file_name,
};
use nono::{NonoError, Result};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// zstd level: fast, and terminal output compresses well at any level.
const ZSTD_LEVEL: i32 = 3;

/// Messages from the capture front end to the writer.
pub(crate) enum WriterMsg {
    Event(ProtectedEvent),
    /// Events the front end dropped before they reached the writer.
    Lost {
        seq_start: u64,
        seq_end: u64,
        reason: &'static str,
    },
    /// Close the open chunk now (suspend).
    CloseChunk,
    /// Session end: close the open chunk and stop.
    End(SessionEnd),
}

/// Per-message overhead counted against the queue's byte budget.
const MESSAGE_OVERHEAD: usize = 64;

impl WriterMsg {
    /// Bytes this message counts against the queue budget.
    pub(crate) fn budget_size(&self) -> usize {
        let payload = match self {
            Self::Event(event) => match &event.event {
                CaptureEvent::Output { bytes, .. } | CaptureEvent::Input { bytes, .. } => {
                    bytes.len()
                }
                _ => 0,
            },
            _ => 0,
        };
        payload.saturating_add(MESSAGE_OVERHEAD)
    }
}

/// Information about one closed chunk, handed to downstream sinks.
pub(crate) struct ChunkInfo {
    pub(crate) event: TerminalChunkEvent,
    /// The chunk's protected asciicast lines, uncompressed.
    pub(crate) raw: Vec<u8>,
}

/// A destination that reacts to closed chunks (NEP-0010 §5).
///
/// The local recording itself is the writer; sinks downstream of it receive
/// each protected event, each closed chunk, and the session end.
pub(crate) trait Sink: Send {
    fn name(&self) -> &str;
    fn required(&self) -> bool;
    /// Start any worker the sink needs. Runs on the recorder thread, after
    /// the supervisor has forked.
    fn activate(&mut self) -> Result<()> {
        Ok(())
    }
    fn write(&mut self, event: &ProtectedEvent) -> Result<()>;
    fn chunk_closed(&mut self, chunk: &ChunkInfo) -> Result<()>;
    fn close(&mut self, end: &SessionEnd) -> Result<()>;
}

/// Shared handle on the session's audit recorder.
pub(crate) type SharedAuditRecorder = Arc<Mutex<AuditRecorder>>;

fn with_recorder<T>(
    recorder: &SharedAuditRecorder,
    f: impl FnOnce(&mut AuditRecorder) -> Result<T>,
) -> Result<T> {
    let mut guard = recorder
        .lock()
        .map_err(|_| NonoError::Snapshot("Audit recorder lock poisoned".to_string()))?;
    f(&mut guard)
}

/// Writes `terminal_chunk` events into the hash-chained audit log.
pub(crate) struct AuditLinkSink {
    recorder: SharedAuditRecorder,
    required: bool,
}

impl AuditLinkSink {
    pub(crate) fn new(recorder: SharedAuditRecorder, required: bool) -> Self {
        Self { recorder, required }
    }
}

impl Sink for AuditLinkSink {
    fn name(&self) -> &str {
        "audit_link"
    }
    fn required(&self) -> bool {
        self.required
    }
    fn write(&mut self, _event: &ProtectedEvent) -> Result<()> {
        Ok(())
    }
    fn chunk_closed(&mut self, chunk: &ChunkInfo) -> Result<()> {
        with_recorder(&self.recorder, |r| {
            r.record_terminal_chunk(chunk.event.clone())
        })
    }
    fn close(&mut self, _end: &SessionEnd) -> Result<()> {
        Ok(())
    }
}

/// Writer settings.
pub(crate) struct WriterConfig {
    /// `<audit session dir>/terminal`.
    pub(crate) dir: PathBuf,
    /// asciicast v2 header line (JSON object, no newline).
    pub(crate) header: String,
    pub(crate) max_bytes: u64,
    pub(crate) chunk_max_bytes: usize,
    pub(crate) chunk_max_duration: Duration,
    pub(crate) required: bool,
    pub(crate) audit: SharedAuditRecorder,
}

/// What the writer reports when it stops.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct WriterSummary {
    pub(crate) chunks: u64,
    pub(crate) raw_bytes: u64,
    pub(crate) stored_bytes: u64,
    pub(crate) redactions: u64,
    pub(crate) suppressed_inputs: u64,
    pub(crate) lost_events: u64,
    pub(crate) truncated: bool,
}

/// Slot the writer fills when a required destination fails; the front end
/// polls it and stops the session.
pub(crate) type FatalSlot = Arc<Mutex<Option<String>>>;

pub(crate) fn set_fatal(slot: &FatalSlot, reason: String) {
    let mut guard = slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if guard.is_none() {
        *guard = Some(reason);
    }
}

/// The chunk being built.
struct OpenChunk {
    buf: Vec<u8>,
    opened_at: Instant,
    seq_start: u64,
    seq_end: u64,
    start_offset_us: u64,
    end_offset_us: u64,
    audit_seq_start: u64,
    redactions: u64,
    suppressed_inputs: u64,
}

/// Per-stream UTF-8 carry: asciicast data is text, so an incomplete trailing
/// sequence waits for the next read; invalid bytes become U+FFFD.
#[derive(Default)]
struct Utf8Carry {
    pending: Vec<u8>,
}

impl Utf8Carry {
    fn decode(&mut self, bytes: &[u8]) -> String {
        let mut data = std::mem::take(&mut self.pending);
        data.extend_from_slice(bytes);
        let mut out = String::with_capacity(data.len());
        let mut rest = data.as_slice();
        loop {
            match std::str::from_utf8(rest) {
                Ok(valid) => {
                    out.push_str(valid);
                    break;
                }
                Err(e) => {
                    let (valid, after) = rest.split_at(e.valid_up_to());
                    out.push_str(&String::from_utf8_lossy(valid));
                    match e.error_len() {
                        Some(bad) => {
                            out.push('\u{FFFD}');
                            rest = after.get(bad..).unwrap_or_default();
                        }
                        None => {
                            self.pending = after.to_vec();
                            break;
                        }
                    }
                }
            }
        }
        out
    }

    fn finish(&mut self) -> String {
        let rest = std::mem::take(&mut self.pending);
        String::from_utf8_lossy(&rest).into_owned()
    }
}

pub(crate) struct Writer {
    config: WriterConfig,
    sinks: Vec<Box<dyn Sink>>,
    fatal: FatalSlot,
    next_index: u64,
    open: Option<OpenChunk>,
    total_raw: u64,
    truncated: bool,
    header_written: bool,
    carries: [Utf8Carry; 4],
    summary: WriterSummary,
}

impl Writer {
    pub(crate) fn new(
        config: WriterConfig,
        sinks: Vec<Box<dyn Sink>>,
        fatal: FatalSlot,
    ) -> Result<Self> {
        create_private_dir(&config.dir)?;
        Ok(Self {
            config,
            sinks,
            fatal,
            next_index: 0,
            open: None,
            total_raw: 0,
            truncated: false,
            header_written: false,
            carries: Default::default(),
            summary: WriterSummary::default(),
        })
    }

    /// Run until `End` or the channel closes.
    pub(crate) fn run(
        mut self,
        rx: Receiver<WriterMsg>,
        queued: Arc<AtomicUsize>,
    ) -> WriterSummary {
        for sink in &mut self.sinks {
            if let Err(e) = sink.activate() {
                tracing::warn!("terminal capture sink {} failed to start: {e}", sink.name());
                if sink.required() {
                    set_fatal(&self.fatal, format!("{} sink failed", sink.name()));
                }
            }
        }
        loop {
            let msg = match self.open.as_ref() {
                Some(chunk) => {
                    let deadline = chunk.opened_at + self.config.chunk_max_duration;
                    let wait = deadline.saturating_duration_since(Instant::now());
                    match rx.recv_timeout(wait) {
                        Ok(msg) => Some(msg),
                        Err(RecvTimeoutError::Timeout) => {
                            self.close_chunk();
                            continue;
                        }
                        Err(RecvTimeoutError::Disconnected) => None,
                    }
                }
                None => rx.recv().ok(),
            };
            if let Some(msg) = msg.as_ref() {
                queued.fetch_sub(msg.budget_size(), Ordering::AcqRel);
            }
            match msg {
                Some(WriterMsg::Event(event)) => self.handle_event(event),
                Some(WriterMsg::Lost {
                    seq_start,
                    seq_end,
                    reason,
                }) => self.record_lost("recording", seq_start, seq_end, reason),
                Some(WriterMsg::CloseChunk) => self.close_chunk(),
                Some(WriterMsg::End(end)) => {
                    self.finish(&end);
                    break;
                }
                None => {
                    // Front end vanished without an end marker; keep what we have.
                    self.flush_carries();
                    self.close_chunk();
                    break;
                }
            }
        }
        self.summary
    }

    fn handle_event(&mut self, event: ProtectedEvent) {
        if self.truncated {
            return;
        }
        for sink in &mut self.sinks {
            if let Err(e) = sink.write(&event) {
                tracing::warn!("terminal capture sink {} failed: {e}", sink.name());
                if sink.required() {
                    set_fatal(&self.fatal, format!("{} sink failed", sink.name()));
                }
            }
        }
        let line = self.encode(&event);
        self.append_line(&event, line);
    }

    fn encode(&mut self, event: &ProtectedEvent) -> Option<String> {
        let time = event.offset_us as f64 / 1_000_000.0;
        let (code, data) = match &event.event {
            CaptureEvent::Output { stream, bytes } => {
                let text = self.carries[stream.index()].decode(bytes);
                if text.is_empty() {
                    return None;
                }
                ("o", text)
            }
            CaptureEvent::Input { bytes, .. } => {
                let text = self.carries[3].decode(bytes);
                if text.is_empty() {
                    return None;
                }
                ("i", text)
            }
            CaptureEvent::Resize { cols, rows } => ("r", format!("{cols}x{rows}")),
            other => ("m", other.marker_label()),
        };
        let line = serde_json::to_string(&(time, code, data)).ok()?;
        Some(line)
    }

    fn append_line(&mut self, event: &ProtectedEvent, line: Option<String>) {
        let line_len = line.as_ref().map_or(0, |l| l.len().saturating_add(1));
        let header_len = if self.header_written {
            0
        } else {
            self.config.header.len().saturating_add(1)
        };
        let projected = self
            .total_raw
            .saturating_add(line_len as u64)
            .saturating_add(header_len as u64);
        if projected > self.config.max_bytes {
            self.truncate(event.seq);
            return;
        }

        if self.open.is_none() {
            let audit_seq_start =
                with_recorder(&self.config.audit, |r| Ok(r.next_sequence())).unwrap_or(0);
            let mut buf = Vec::with_capacity(self.config.chunk_max_bytes.min(64 * 1024));
            if !self.header_written {
                buf.extend_from_slice(self.config.header.as_bytes());
                buf.push(b'\n');
                self.total_raw = self.total_raw.saturating_add(header_len as u64);
                self.header_written = true;
            }
            self.open = Some(OpenChunk {
                buf,
                opened_at: Instant::now(),
                seq_start: event.seq,
                seq_end: event.seq,
                start_offset_us: event.offset_us,
                end_offset_us: event.offset_us,
                audit_seq_start,
                redactions: 0,
                suppressed_inputs: 0,
            });
        }
        let Some(chunk) = self.open.as_mut() else {
            return;
        };
        if let Some(line) = line {
            chunk.buf.extend_from_slice(line.as_bytes());
            chunk.buf.push(b'\n');
            self.total_raw = self.total_raw.saturating_add(line_len as u64);
        }
        chunk.seq_end = event.seq.saturating_add(1);
        chunk.end_offset_us = event.offset_us;
        chunk.redactions = chunk.redactions.saturating_add(event.redactions);
        if matches!(event.event, CaptureEvent::InputSuppressed { .. }) {
            chunk.suppressed_inputs = chunk.suppressed_inputs.saturating_add(1);
        }
        if chunk.buf.len() >= self.config.chunk_max_bytes {
            self.close_chunk();
        }
    }

    fn truncate(&mut self, seq: u64) {
        self.close_chunk();
        self.truncated = true;
        self.summary.truncated = true;
        let event = TerminalRecordingTruncatedEvent {
            seq,
            max_bytes: self.config.max_bytes,
            recorded_bytes: self.total_raw,
        };
        if let Err(e) = with_recorder(&self.config.audit, |r| {
            r.record_terminal_recording_truncated(event)
        }) {
            tracing::warn!("failed to record terminal recording truncation: {e}");
        }
        if self.config.required {
            set_fatal(
                &self.fatal,
                "terminal recording reached its size limit".to_string(),
            );
        }
    }

    fn close_chunk(&mut self) {
        let Some(chunk) = self.open.take() else {
            return;
        };
        let index = self.next_index;
        let (seq_start, seq_end) = (chunk.seq_start, chunk.seq_end);
        match self.store_chunk(index, chunk) {
            Ok(info) => {
                self.next_index = self.next_index.saturating_add(1);
                self.summary.chunks = self.summary.chunks.saturating_add(1);
                self.summary.raw_bytes =
                    self.summary.raw_bytes.saturating_add(info.event.raw_bytes);
                self.summary.stored_bytes = self
                    .summary
                    .stored_bytes
                    .saturating_add(info.event.stored_bytes);
                self.summary.redactions = self
                    .summary
                    .redactions
                    .saturating_add(info.event.credential_redactions);
                self.summary.suppressed_inputs = self
                    .summary
                    .suppressed_inputs
                    .saturating_add(info.event.suppressed_inputs);
                for sink in &mut self.sinks {
                    if let Err(e) = sink.chunk_closed(&info) {
                        tracing::warn!("terminal capture sink {} failed: {e}", sink.name());
                        if sink.required() {
                            set_fatal(&self.fatal, format!("{} sink failed", sink.name()));
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("failed to store terminal recording chunk {index}: {e}");
                self.record_lost("recording", seq_start, seq_end, "write_failed");
                if self.config.required {
                    set_fatal(
                        &self.fatal,
                        "terminal recording could not be written".to_string(),
                    );
                }
            }
        }
    }

    fn store_chunk(&self, index: u64, chunk: OpenChunk) -> Result<ChunkInfo> {
        let compressed = zstd::bulk::compress(&chunk.buf, ZSTD_LEVEL)
            .map_err(|e| NonoError::Snapshot(format!("failed to compress terminal chunk: {e}")))?;
        let path = self.config.dir.join(terminal_chunk_file_name(index));
        write_private_file(&path, &compressed)?;
        let sha256 = hex_digest(&compressed);
        let audit_seq_end = with_recorder(&self.config.audit, |r| Ok(r.next_sequence()))?;
        Ok(ChunkInfo {
            event: TerminalChunkEvent {
                index,
                seq_start: chunk.seq_start,
                seq_end: chunk.seq_end,
                start_offset_us: chunk.start_offset_us,
                end_offset_us: chunk.end_offset_us,
                audit_seq_start: chunk.audit_seq_start,
                audit_seq_end,
                raw_bytes: chunk.buf.len() as u64,
                stored_bytes: compressed.len() as u64,
                sha256,
                credential_redactions: chunk.redactions,
                suppressed_inputs: chunk.suppressed_inputs,
            },
            raw: chunk.buf,
        })
    }

    fn record_lost(&mut self, sink: &str, seq_start: u64, seq_end: u64, reason: &str) {
        self.summary.lost_events = self
            .summary
            .lost_events
            .saturating_add(seq_end.saturating_sub(seq_start));
        let event = RecordingLostEvent {
            sink: sink.to_string(),
            seq_start,
            seq_end,
            reason: reason.to_string(),
        };
        if let Err(e) = with_recorder(&self.config.audit, |r| r.record_recording_lost(event)) {
            tracing::warn!("failed to record terminal recording loss: {e}");
            if self.config.required {
                set_fatal(
                    &self.fatal,
                    "terminal recording loss could not be recorded".to_string(),
                );
            }
        }
    }

    /// Emit incomplete trailing UTF-8 lossily into the open chunk, so bytes
    /// held for decoding are not silently dropped at session end.
    fn flush_carries(&mut self) {
        let Some(chunk) = self.open.as_mut() else {
            return;
        };
        let time = chunk.end_offset_us as f64 / 1_000_000.0;
        for (index, carry) in self.carries.iter_mut().enumerate() {
            let text = carry.finish();
            if text.is_empty() {
                continue;
            }
            let code = if index == 3 { "i" } else { "o" };
            if let Ok(line) = serde_json::to_string(&(time, code, text)) {
                chunk.buf.extend_from_slice(line.as_bytes());
                chunk.buf.push(b'\n');
                self.total_raw = self.total_raw.saturating_add(line.len() as u64 + 1);
            }
        }
    }

    fn finish(&mut self, end: &SessionEnd) {
        self.flush_carries();
        self.close_chunk();
        for sink in &mut self.sinks {
            if let Err(e) = sink.close(end) {
                tracing::warn!("terminal capture sink {} failed to close: {e}", sink.name());
                if sink.required() {
                    set_fatal(&self.fatal, format!("{} sink failed", sink.name()));
                }
            }
        }
    }
}

pub(super) fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn create_private_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).map_err(|e| {
        NonoError::Snapshot(format!(
            "failed to create terminal recording directory {}: {e}",
            dir.display()
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| {
            NonoError::Snapshot(format!(
                "failed to restrict terminal recording directory {}: {e}",
                dir.display()
            ))
        })?;
    }
    Ok(())
}

/// Write a new chunk file. `create_new` refuses to follow or replace an
/// existing entry, so a pre-placed file or symlink fails the write.
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| NonoError::Snapshot(format!("failed to create {}: {e}", path.display())))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| NonoError::Snapshot(format!("failed to write {}: {e}", path.display())))
}

/// Location of a session's terminal recording.
pub(crate) fn recording_dir(audit_session_dir: &Path) -> PathBuf {
    audit_session_dir.join(TERMINAL_RECORDING_DIRNAME)
}
