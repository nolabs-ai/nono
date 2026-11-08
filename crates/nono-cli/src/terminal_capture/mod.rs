//! Session terminal capture (NEP-0010).
//!
//! The capture front end runs on the supervisor's poll thread. It assigns
//! each event a contiguous `seq` and a monotonic offset, applies the fixed
//! protections (§3) inline, and hands protected events to the writer thread
//! through a bounded queue. Capture never waits: when the queue is full the
//! events are counted as lost and a `recording_lost` record covers the gap,
//! or, when recording is required, the session is stopped.
//!
//! Capture is passive. Nothing here changes the bytes the agent or the user
//! receives; the protections apply only to what is recorded.

pub(crate) mod commands;
pub(crate) mod delivery;
pub(crate) mod events;
pub(crate) mod file_sink;
pub(crate) mod recording;
pub(crate) mod redact;
pub(crate) mod replay;
pub(crate) mod settings;
pub(crate) mod transcript;
pub(crate) mod writer;

pub(crate) use settings::RecordingSettings;

use events::{
    CaptureEvent, INPUT_STREAM, Lifecycle, NotificationKind, OutputStream, ProtectedEvent,
    SessionEnd,
};
use nono::{NonoError, Result};
use nono_proxy::SecretRegistry;
use redact::Redactor;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use writer::{
    AuditLinkSink, FatalSlot, SharedAuditRecorder, Sink, Writer, WriterConfig, WriterMsg,
    WriterSummary, recording_dir, set_fatal,
};

/// Default chunk duration limit (§4).
pub(crate) const DEFAULT_CHUNK_MAX_DURATION: Duration = Duration::from_secs(10);
/// Default chunk size limit, uncompressed (§4).
pub(crate) const DEFAULT_CHUNK_MAX_BYTES: usize = 1024 * 1024;
/// Exit status when a required recording failed (`EX_IOERR`), so a pipeline
/// sees the failure even if the agent itself succeeded.
pub(crate) const RECORDING_FAILED_EXIT_CODE: i32 = 74;
/// Default recording size limit, uncompressed (§7).
pub(crate) const DEFAULT_MAX_BYTES: u64 = 256 * 1024 * 1024;

/// Queue limits between the poll thread and the writer.
const QUEUE_MESSAGES: usize = 4096;
const QUEUE_BYTES: usize = 32 * 1024 * 1024;

/// Output silence after which the foreground process is sampled.
const FOREGROUND_QUIET: Duration = Duration::from_millis(300);

/// Whether input content is captured (§7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InputCapture {
    On,
    Off,
}

impl InputCapture {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::On => "on",
            Self::Off => "off",
        }
    }
}

/// Settings for one session's capture.
pub(crate) struct CaptureConfig {
    pub(crate) session_id: String,
    pub(crate) audit_session_id: String,
    pub(crate) audit_session_dir: PathBuf,
    pub(crate) pty: bool,
    pub(crate) input: InputCapture,
    pub(crate) required: bool,
    pub(crate) max_bytes: u64,
    pub(crate) chunk_max_bytes: usize,
    pub(crate) chunk_max_duration: Duration,
    pub(crate) initial_size: Option<(u16, u16)>,
}

impl CaptureConfig {
    fn header(&self) -> String {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let (cols, rows) = self.initial_size.unwrap_or((80, 24));
        serde_json::json!({
            "version": 2,
            "width": cols,
            "height": rows,
            "timestamp": timestamp,
            "nono": {
                "format": "nono-session-recording-v1",
                "session_id": self.session_id,
                "audit_session_id": self.audit_session_id,
                "pty": self.pty,
                "capture": {
                    "input": self.input.as_str(),
                    "required": self.required,
                    "max_bytes": self.max_bytes,
                },
            },
        })
        .to_string()
    }
}

/// What the supervisor knows when it starts a session's capture.
pub(crate) struct SessionCaptureContext<'a> {
    pub(crate) settings: &'a RecordingSettings,
    pub(crate) session_id: &'a str,
    /// Audit session id and directory; recording lives in protected audit
    /// state, so it needs the audit log.
    pub(crate) audit: Option<(&'a str, &'a std::path::Path, &'a SharedAuditRecorder)>,
    /// Initial window size when the session has a PTY; `None` without one.
    pub(crate) pty_size: Option<Option<(u16, u16)>>,
    pub(crate) registry: &'a SecretRegistry,
}

/// Start capture for a supervised session, before the child is forked.
///
/// A required recording that cannot start is an error, so the agent never
/// runs unrecorded. An optional one that cannot start is reported on stderr
/// and the session runs without it.
pub(crate) fn start_for_session(ctx: SessionCaptureContext<'_>) -> Result<Option<TerminalCapture>> {
    let required = ctx.settings.required;
    let fail = |reason: String| -> Result<Option<TerminalCapture>> {
        if required {
            Err(NonoError::SandboxInit(format!(
                "required session recording cannot start: {reason}"
            )))
        } else {
            eprintln!("[nono] Warning: session recording is off for this session: {reason}");
            Ok(None)
        }
    };
    let Some((audit_session_id, audit_session_dir, audit)) = ctx.audit else {
        return fail("the audit log is disabled".to_string());
    };
    let Some(initial_size) = ctx.pty_size else {
        return fail("the session has no terminal".to_string());
    };
    let input = ctx.settings.input.unwrap_or(InputCapture::On);
    let mut sinks: Vec<Box<dyn Sink>> = Vec::new();
    let mut files = Vec::new();
    for path in &ctx.settings.files {
        match file_sink::FileSink::create(path, required, ctx.session_id, audit_session_id) {
            Ok(sink) => {
                sinks.push(Box::new(sink));
                files.push(path.clone());
            }
            Err(e) if required => return fail(e.to_string()),
            Err(e) => eprintln!(
                "[nono] Warning: session recording will not be copied to {}: {e}",
                path.display()
            ),
        }
    }
    let mut delivering = false;
    if let Some(delivery) = ctx.settings.delivery.as_ref() {
        let started = delivery::platform_receiver()
            .and_then(|receiver| delivery::PlatformTransport::new(receiver, audit_session_id))
            .map(|transport| {
                delivery::DeliverySink::new(
                    Box::new(transport),
                    recording_dir(audit_session_dir),
                    delivery.clone(),
                )
            });
        match started {
            Ok(sink) => {
                sinks.push(Box::new(sink));
                delivering = true;
            }
            Err(e) if delivery.required => {
                return Err(NonoError::SandboxInit(format!(
                    "required recording delivery cannot start: {e}"
                )));
            }
            Err(e) => eprintln!(
                "[nono] Warning: the recording will not be delivered to the platform: {e}"
            ),
        }
    }
    let config = CaptureConfig {
        session_id: ctx.session_id.to_string(),
        audit_session_id: audit_session_id.to_string(),
        audit_session_dir: audit_session_dir.to_path_buf(),
        pty: true,
        input,
        required,
        max_bytes: ctx.settings.max_bytes,
        chunk_max_bytes: DEFAULT_CHUNK_MAX_BYTES,
        chunk_max_duration: DEFAULT_CHUNK_MAX_DURATION,
        initial_size,
    };
    match TerminalCapture::start(config, ctx.registry.clone(), audit.clone(), sinks) {
        Ok(mut capture) => {
            capture.files = files;
            capture.delivering = delivering;
            // §7: always shown, whatever the profile or `--silent` say.
            eprintln!("{}", recording_notice(input, delivering));
            Ok(Some(capture))
        }
        Err(e) => fail(e.to_string()),
    }
}

/// Recording needs the supervisor. Without one (`nono wrap`), a required
/// recording is an error and an optional one is reported and skipped.
pub(crate) fn check_unsupervised(settings: Option<&RecordingSettings>) -> Result<()> {
    match settings {
        Some(settings) if settings.required => Err(NonoError::SandboxInit(
            "required session recording cannot start: this command runs without a supervisor; \
             use `nono run` instead"
                .to_string(),
        )),
        Some(_) => {
            eprintln!(
                "[nono] Warning: session recording is off for this session: \
                 it runs without a supervisor"
            );
            Ok(())
        }
        None => Ok(()),
    }
}

/// The recording notice for a session published as recorded, for launchers
/// and attaching clients that are not the supervisor's terminal.
pub(crate) fn session_notice(record: &crate::session::SessionRecord) -> Option<String> {
    record.recording.as_ref().map(|recording| {
        recording_notice(
            if recording.input {
                InputCapture::On
            } else {
                InputCapture::Off
            },
            recording.delivered,
        )
    })
}

/// The one-line notice printed when a recorded session starts (§7).
pub(crate) fn recording_notice(input: InputCapture, delivered: bool) -> String {
    let what = match input {
        InputCapture::On => "terminal output and input are",
        InputCapture::Off => "terminal output is",
    };
    let where_ = if delivered {
        "saved with its audit log and sent to the platform"
    } else {
        "saved with its audit log"
    };
    let input_note = match input {
        InputCapture::On => "",
        InputCapture::Off => " (input is not)",
    };
    format!("[nono] This session is being recorded: {what} {where_}{input_note}.")
}

/// What a finished capture reports.
#[derive(Clone, Debug, Default)]
pub(crate) struct CaptureSummary {
    pub(crate) writer: WriterSummary,
    pub(crate) events: u64,
    pub(crate) unmatched_credentials: Vec<String>,
    /// Set when a required destination failed.
    pub(crate) fatal: Option<String>,
}

/// The capture front end owned by the PTY proxy or the pipe relay.
pub(crate) struct TerminalCapture {
    start: Instant,
    next_seq: u64,
    redactor: Redactor,
    input: InputCapture,
    required: bool,
    tx: Option<SyncSender<WriterMsg>>,
    queued_bytes: Arc<AtomicUsize>,
    lost: Option<(u64, u64)>,
    fatal: FatalSlot,
    writer: Option<JoinHandle<WriterSummary>>,
    /// The writer before `activate` starts its thread.
    pending_writer: Option<(Writer, Receiver<WriterMsg>)>,
    last_mode: Option<(bool, bool)>,
    last_foreground: Option<i32>,
    last_size: Option<(u16, u16)>,
    last_input_client: Option<String>,
    last_output_at: Option<Instant>,
    foreground_sampled: bool,
    /// `file` sink destinations that were opened.
    files: Vec<PathBuf>,
    /// Chunks are uploaded to the platform.
    delivering: bool,
}

impl TerminalCapture {
    /// Prepare capture: create the recording directory and the writer, and
    /// record the `started` lifecycle event. No thread is started, so this
    /// may run before the supervisor forks; [`activate`](Self::activate)
    /// starts the recorder afterwards, in the parent. Events recorded in
    /// between wait in the queue.
    pub(crate) fn start(
        config: CaptureConfig,
        registry: SecretRegistry,
        audit: SharedAuditRecorder,
        extra_sinks: Vec<Box<dyn Sink>>,
    ) -> Result<Self> {
        let redactor = Redactor::new(registry, 3)?;
        let fatal: FatalSlot = Arc::new(Mutex::new(None));
        let mut sinks: Vec<Box<dyn Sink>> =
            vec![Box::new(AuditLinkSink::new(audit.clone(), config.required))];
        sinks.extend(extra_sinks);
        let writer = Writer::new(
            WriterConfig {
                dir: recording_dir(&config.audit_session_dir),
                header: config.header(),
                max_bytes: config.max_bytes,
                chunk_max_bytes: config.chunk_max_bytes,
                chunk_max_duration: config.chunk_max_duration,
                required: config.required,
                audit,
            },
            sinks,
            fatal.clone(),
        )?;
        let (tx, rx) = sync_channel(QUEUE_MESSAGES);
        let queued_bytes = Arc::new(AtomicUsize::new(0));

        let mut capture = Self {
            start: Instant::now(),
            next_seq: 0,
            redactor,
            input: config.input,
            required: config.required,
            tx: Some(tx),
            queued_bytes,
            lost: None,
            fatal,
            writer: None,
            pending_writer: Some((writer, rx)),
            last_mode: None,
            last_foreground: None,
            last_size: config.initial_size,
            last_input_client: None,
            last_output_at: None,
            foreground_sampled: true,
            files: Vec::new(),
            delivering: false,
        };
        capture.emit(CaptureEvent::Lifecycle(Lifecycle::Started), 0);
        if let Some((cols, rows)) = config.initial_size {
            capture.emit(CaptureEvent::Resize { cols, rows }, 0);
        }
        let unmatched: Vec<String> = capture.redactor.unmatched_names().iter().cloned().collect();
        if !unmatched.is_empty() {
            capture.emit(CaptureEvent::Coverage { unmatched }, 0);
        }
        Ok(capture)
    }

    /// Start the recorder thread, and through it the sinks' workers. Called
    /// in the supervisor after the fork, which needs a single-threaded
    /// process; calling it again does nothing.
    pub(crate) fn activate(&mut self) -> Result<()> {
        let Some((writer, rx)) = self.pending_writer.take() else {
            return Ok(());
        };
        let queued = self.queued_bytes.clone();
        let handle = std::thread::Builder::new()
            .name("nono-terminal-recorder".to_string())
            .spawn(move || writer.run(rx, queued))
            .map_err(|e| {
                NonoError::Snapshot(format!("failed to start terminal recorder thread: {e}"))
            })?;
        self.writer = Some(handle);
        Ok(())
    }

    fn offset_us(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_micros()).unwrap_or(u64::MAX)
    }

    fn emit(&mut self, event: CaptureEvent, redactions: u64) {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        let protected = ProtectedEvent {
            seq,
            offset_us: self.offset_us(),
            event,
            redactions,
        };

        if let Some((start, end)) = self.lost.take()
            && !self.send(WriterMsg::Lost {
                seq_start: start,
                seq_end: end,
                reason: "queue_full",
            })
        {
            self.lost = Some((start, end));
        }
        let sent = self.lost.is_none() && self.send(WriterMsg::Event(protected));
        if !sent {
            self.lost = Some(match self.lost {
                Some((start, _)) => (start, seq.saturating_add(1)),
                None => (seq, seq.saturating_add(1)),
            });
            if self.required {
                set_fatal(&self.fatal, "terminal recording fell behind".to_string());
            }
        }
    }

    fn send(&mut self, msg: WriterMsg) -> bool {
        let Some(tx) = self.tx.as_ref() else {
            return false;
        };
        let size = msg.budget_size();
        let queued = self.queued_bytes.load(Ordering::Acquire);
        if queued.saturating_add(size) > QUEUE_BYTES {
            return false;
        }
        self.queued_bytes.fetch_add(size, Ordering::AcqRel);
        match tx.try_send(msg) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.queued_bytes.fetch_sub(size, Ordering::AcqRel);
                false
            }
        }
    }

    /// Rebuild the credential matcher if new values were registered.
    fn refresh_redactor(&mut self) {
        match self.redactor.refresh() {
            Ok(Some(unmatched)) => {
                let unmatched: Vec<String> = unmatched.into_iter().collect();
                self.emit(CaptureEvent::Coverage { unmatched }, 0);
            }
            Ok(None) => {}
            Err(e) => {
                // The previous matcher stays in place; it still covers every
                // value known before this registration.
                tracing::warn!("terminal capture: {e}");
                if self.required {
                    set_fatal(
                        &self.fatal,
                        "credential matcher could not be rebuilt".to_string(),
                    );
                }
            }
        }
    }

    /// Record agent output.
    pub(crate) fn output(&mut self, stream: OutputStream, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.refresh_redactor();
        let protected = self.redactor.process(stream.index(), bytes);
        self.last_output_at = Some(Instant::now());
        self.foreground_sampled = false;
        if !protected.bytes.is_empty() {
            self.emit(
                CaptureEvent::Output {
                    stream,
                    bytes: protected.bytes,
                },
                protected.redactions,
            );
        }
    }

    /// Record the terminal mode read before an input batch.
    pub(crate) fn observe_mode(&mut self, icanon: bool, echo: bool) {
        if self.last_mode == Some((icanon, echo)) {
            return;
        }
        self.last_mode = Some((icanon, echo));
        self.emit(CaptureEvent::Mode { icanon, echo }, 0);
    }

    /// Whether the terminal is in password mode: canonical input with echo
    /// off, as `getpass(3)`, `sudo`, `su` and `ssh` use (§3.2).
    pub(crate) fn password_mode(&self) -> bool {
        matches!(self.last_mode, Some((true, false)))
    }

    /// Record input sent to the agent by `client`.
    /// Whether input content is captured.
    pub(crate) fn input_mode(&self) -> InputCapture {
        self.input
    }

    /// Whether this recording is required.
    pub(crate) fn is_required(&self) -> bool {
        self.required
    }

    /// `file` sink destinations in use.
    pub(crate) fn files(&self) -> &[PathBuf] {
        &self.files
    }

    /// Whether chunks are uploaded to the platform.
    pub(crate) fn delivering(&self) -> bool {
        self.delivering
    }

    pub(crate) fn input(&mut self, client: &str, bytes: &[u8]) {
        let bytes = strip_focus_reports(bytes);
        if bytes.is_empty() {
            return;
        }
        if self.last_input_client.as_deref() != Some(client) {
            self.last_input_client = Some(client.to_string());
            self.emit(
                CaptureEvent::InputClient {
                    client: client.to_string(),
                },
                0,
            );
        }
        let reason = if self.password_mode() {
            Some("password_mode")
        } else if self.input == InputCapture::Off {
            Some("input_off")
        } else {
            None
        };
        if let Some(reason) = reason {
            // Input typed before the window opened can no longer continue
            // a match: end that stream, then record only that input
            // happened: no content, no length.
            self.end_stream(INPUT_STREAM);
            self.emit(
                CaptureEvent::InputSuppressed {
                    client: client.to_string(),
                    reason,
                },
                0,
            );
            return;
        }
        self.refresh_redactor();
        let protected = self.redactor.process(INPUT_STREAM, &bytes);
        if !protected.bytes.is_empty() {
            self.emit(
                CaptureEvent::Input {
                    client: client.to_string(),
                    bytes: protected.bytes,
                },
                protected.redactions,
            );
        }
    }

    /// Record a window size, if it changed.
    pub(crate) fn resize(&mut self, cols: u16, rows: u16) {
        if cols == 0 || rows == 0 || self.last_size == Some((cols, rows)) {
            return;
        }
        self.last_size = Some((cols, rows));
        self.emit(CaptureEvent::Resize { cols, rows }, 0);
    }

    /// Record the foreground process group, if it changed.
    pub(crate) fn foreground(&mut self, pgid: i32, exe: Option<String>) {
        self.foreground_sampled = true;
        // No foreground group yet (the child has not taken the terminal):
        // record nothing rather than a group that does not exist.
        if pgid <= 0 || self.last_foreground == Some(pgid) {
            return;
        }
        self.last_foreground = Some(pgid);
        self.emit(CaptureEvent::Foreground { pgid, exe }, 0);
    }

    /// Whether output has paused long enough to sample the foreground.
    pub(crate) fn wants_foreground_sample(&self) -> bool {
        !self.foreground_sampled
            && self
                .last_output_at
                .is_some_and(|t| t.elapsed() >= FOREGROUND_QUIET)
    }

    pub(crate) fn notification(&mut self, kind: NotificationKind) {
        self.emit(CaptureEvent::Notification { kind }, 0);
    }

    pub(crate) fn lifecycle(&mut self, event: Lifecycle) {
        if matches!(event, Lifecycle::Suspended) {
            // A suspend closes the open chunk (§4). Bytes held back as a
            // possible credential stay held, so the match can still
            // complete when the session resumes.
            self.emit(CaptureEvent::Lifecycle(event), 0);
            let _ = self.send(WriterMsg::CloseChunk);
            return;
        }
        self.emit(CaptureEvent::Lifecycle(event), 0);
    }

    /// End `stream`: no more bytes can continue a match, so release what is
    /// held back (see [`Redactor::end_stream`]).
    fn end_stream(&mut self, stream: usize) {
        if !self.redactor.has_pending(stream) {
            return;
        }
        let protected = self.redactor.end_stream(stream);
        if protected.bytes.is_empty() {
            return;
        }
        let event = if stream == INPUT_STREAM {
            CaptureEvent::Input {
                client: self
                    .last_input_client
                    .clone()
                    .unwrap_or_else(|| "local".to_string()),
                bytes: protected.bytes,
            }
        } else {
            CaptureEvent::Output {
                stream: if stream == OutputStream::Stderr.index() {
                    OutputStream::Stderr
                } else {
                    OutputStream::Pty
                },
                bytes: protected.bytes,
            }
        };
        self.emit(event, protected.redactions);
    }

    /// Periodic check from the poll loop: report a fatal failure of a
    /// required destination.
    ///
    /// Held-back bytes are never released on a timer: releasing a partial
    /// match would let the rest of the credential, arriving later, through
    /// unmatched. At most the longest pattern's length less one byte is held
    /// per stream, and it is recorded with the next bytes or at session end.
    pub(crate) fn tick(&mut self) -> Option<String> {
        self.fatal_reason()
    }

    /// Reason a required destination failed, if one did.
    pub(crate) fn fatal_reason(&self) -> Option<String> {
        self.fatal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Record the session end, close the last chunk, and stop the writer.
    ///
    /// Must run before the audit log records `session_ended`, so every
    /// `terminal_chunk` record precedes it.
    pub(crate) fn finish(mut self, status: String) -> CaptureSummary {
        // Normally started after the fork; a session that ended before then
        // still closes its recording.
        if let Err(e) = self.activate() {
            tracing::warn!("{e}");
        }
        for stream in 0..3 {
            self.end_stream(stream);
        }
        self.emit(
            CaptureEvent::Lifecycle(Lifecycle::Exited {
                status: status.clone(),
            }),
            0,
        );
        if let Some((start, end)) = self.lost.take() {
            // Blocking here is fine: the session is over.
            if let Some(tx) = self.tx.as_ref() {
                let _ = tx.send(WriterMsg::Lost {
                    seq_start: start,
                    seq_end: end,
                    reason: "queue_full",
                });
            }
        }
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(WriterMsg::End(SessionEnd { status }));
        }
        let writer = match self.writer.take().map(JoinHandle::join) {
            Some(Ok(summary)) => summary,
            Some(Err(_)) | None => {
                tracing::warn!("terminal recorder thread failed");
                if self.required {
                    set_fatal(&self.fatal, "terminal recorder thread failed".to_string());
                }
                WriterSummary::default()
            }
        };
        CaptureSummary {
            writer,
            events: self.next_seq,
            unmatched_credentials: self.redactor.unmatched_names().iter().cloned().collect(),
            fatal: self.fatal_reason(),
        }
    }
}

impl Drop for TerminalCapture {
    fn drop(&mut self) {
        // Without `finish`, closing the channel lets the writer close its
        // open chunk and exit. A writer never started has nothing open.
        self.pending_writer.take();
        self.tx.take();
        if let Some(handle) = self.writer.take() {
            let _ = handle.join();
        }
    }
}

/// Focus reports (`ESC [ I`, `ESC [ O`) are terminal chatter, not input.
fn strip_focus_reports(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b
            && bytes.get(i + 1) == Some(&b'[')
            && matches!(bytes.get(i + 2), Some(b'I') | Some(b'O'))
        {
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::audit_integrity::{AUDIT_EVENTS_FILENAME, AuditEventPayload, AuditRecorder};
    use nono::audit::{TerminalChunkEvent, terminal_chunk_file_name, verify_audit_log};
    use sha2::{Digest, Sha256};

    const SECRET: &str = "ghp_abcdefghijklmnop0123456789";

    struct Harness {
        dir: tempfile::TempDir,
        audit: SharedAuditRecorder,
        registry: SecretRegistry,
    }

    impl Harness {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let mut recorder = AuditRecorder::new(dir.path().to_path_buf()).unwrap();
            recorder
                .record_session_started(
                    "2026-11-05T00:00:00Z".to_string(),
                    vec!["agent".to_string()],
                )
                .unwrap();
            let registry = SecretRegistry::new();
            registry.register("GITHUB_TOKEN", SECRET);
            Self {
                dir,
                audit: Arc::new(Mutex::new(recorder)),
                registry,
            }
        }

        fn config(&self) -> CaptureConfig {
            CaptureConfig {
                session_id: "abcd1234abcd1234".to_string(),
                audit_session_id: "20261105-000000-42".to_string(),
                audit_session_dir: self.dir.path().to_path_buf(),
                pty: true,
                input: InputCapture::On,
                required: false,
                max_bytes: DEFAULT_MAX_BYTES,
                chunk_max_bytes: DEFAULT_CHUNK_MAX_BYTES,
                chunk_max_duration: DEFAULT_CHUNK_MAX_DURATION,
                initial_size: Some((80, 24)),
            }
        }

        fn start(&self, config: CaptureConfig) -> TerminalCapture {
            let mut capture = TerminalCapture::start(
                config,
                self.registry.clone(),
                self.audit.clone(),
                Vec::new(),
            )
            .unwrap();
            capture.activate().unwrap();
            capture
        }

        fn chunk_events(&self) -> Vec<TerminalChunkEvent> {
            let text =
                std::fs::read_to_string(self.dir.path().join(AUDIT_EVENTS_FILENAME)).unwrap();
            text.lines()
                .filter_map(|line| {
                    let record: crate::audit_integrity::AuditEventRecord =
                        serde_json::from_str(line).unwrap();
                    match record.event {
                        AuditEventPayload::TerminalChunk { chunk } => Some(*chunk),
                        _ => None,
                    }
                })
                .collect()
        }

        fn audit_types(&self) -> Vec<String> {
            let text =
                std::fs::read_to_string(self.dir.path().join(AUDIT_EVENTS_FILENAME)).unwrap();
            text.lines()
                .map(|line| {
                    let v: serde_json::Value = serde_json::from_str(line).unwrap();
                    v["event"]["type"].as_str().unwrap().to_string()
                })
                .collect()
        }

        /// Decompress every chunk in order into one asciicast document.
        fn recording(&self) -> String {
            let mut out = Vec::new();
            for chunk in self.chunk_events() {
                let path =
                    recording_dir(self.dir.path()).join(terminal_chunk_file_name(chunk.index));
                let stored = std::fs::read(&path).unwrap();
                let digest: String = Sha256::digest(&stored)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                assert_eq!(digest, chunk.sha256, "chunk {} hash", chunk.index);
                assert_eq!(stored.len() as u64, chunk.stored_bytes);
                let raw = zstd::stream::decode_all(stored.as_slice()).unwrap();
                assert_eq!(raw.len() as u64, chunk.raw_bytes);
                out.extend(raw);
            }
            String::from_utf8(out).unwrap()
        }
    }

    fn lines(recording: &str) -> Vec<serde_json::Value> {
        recording
            .lines()
            .skip(1)
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn data_of(lines: &[serde_json::Value], code: &str) -> String {
        lines
            .iter()
            .filter(|l| l[1] == code)
            .map(|l| l[2].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn records_output_input_and_metadata_as_asciicast() {
        let h = Harness::new();
        let mut capture = h.start(h.config());
        capture.output(OutputStream::Pty, b"hello \xe2\x9c");
        capture.output(OutputStream::Pty, b"\x93 world\r\n");
        capture.observe_mode(false, false);
        capture.input("local", b"ls\r");
        capture.resize(120, 40);
        capture.notification(NotificationKind::Bell);
        capture.foreground(4242, Some("/usr/bin/vim".to_string()));
        let summary = capture.finish("exited:0".to_string());
        assert!(summary.fatal.is_none());

        let recording = h.recording();
        let header: serde_json::Value =
            serde_json::from_str(recording.lines().next().unwrap()).unwrap();
        assert_eq!(header["version"], 2);
        assert_eq!(header["nono"]["pty"], true);
        assert_eq!(header["nono"]["audit_session_id"], "20261105-000000-42");

        let lines = lines(&recording);
        assert_eq!(data_of(&lines, "o"), "hello ✓ world\r\n");
        assert_eq!(data_of(&lines, "i"), "ls\r");
        assert!(lines.iter().any(|l| l[1] == "r" && l[2] == "120x40"));
        let markers = data_of(&lines, "m");
        for expected in [
            "nono:lifecycle:{\"event\":\"started\"}",
            "nono:mode:{\"icanon\":false,\"echo\":false}",
            "nono:input_client:{\"client\":\"local\"}",
            "nono:notification:{\"kind\":\"bell\"}",
            "nono:foreground:{\"pgid\":4242,\"exe\":\"/usr/bin/vim\"}",
            "nono:lifecycle:{\"event\":\"exited\",\"status\":\"exited:0\"}",
        ] {
            assert!(
                markers.contains(expected),
                "missing {expected} in {markers}"
            );
        }
        // Times are monotonic.
        let times: Vec<f64> = lines.iter().map(|l| l[0].as_f64().unwrap()).collect();
        assert!(times.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn chunk_events_link_into_a_verifiable_audit_log() {
        let h = Harness::new();
        let mut capture = h.start(h.config());
        capture.output(OutputStream::Pty, b"one");
        let summary = capture.finish("exited:0".to_string());

        let chunks = h.chunk_events();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].index, 0);
        assert_eq!(chunks[0].seq_start, 0);
        assert_eq!(chunks[0].seq_end, summary.events);
        // session_started was record 0 and was written before the chunk opened.
        assert_eq!(chunks[0].audit_seq_start, 1);
        assert_eq!(chunks[0].audit_seq_end, 1);

        let recorder = h.audit.lock().unwrap();
        let integrity = recorder.finalize().unwrap();
        let verified = verify_audit_log(h.dir.path(), Some(&integrity)).unwrap();
        assert!(verified.records_verified);
    }

    #[test]
    fn known_credentials_never_reach_the_recording_or_audit_log() {
        let h = Harness::new();
        let mut capture = h.start(h.config());
        let (a, b) = SECRET.split_at(12);
        capture.output(OutputStream::Pty, format!("token: {a}").as_bytes());
        capture.output(OutputStream::Pty, format!("{b}\r\n").as_bytes());
        capture.observe_mode(false, true);
        capture.input("local", format!("export T={SECRET}\r").as_bytes());
        let summary = capture.finish("exited:0".to_string());

        let recording = h.recording();
        assert!(!recording.contains(SECRET));
        assert!(!recording.contains(a) || !recording.contains(b));
        assert!(recording.contains("[redacted:credential:GITHUB_TOKEN]"));
        assert_eq!(summary.writer.redactions, 2);
        assert_eq!(h.chunk_events()[0].credential_redactions, 2);
        let audit = std::fs::read_to_string(h.dir.path().join(AUDIT_EVENTS_FILENAME)).unwrap();
        assert!(!audit.contains(SECRET));
    }

    #[test]
    fn credentials_registered_mid_session_are_removed() {
        let h = Harness::new();
        let mut capture = h.start(h.config());
        h.registry
            .register("REFRESHED", "oauth-access-token-xyz-0987654321");
        capture.output(
            OutputStream::Pty,
            b"got oauth-access-token-xyz-0987654321 ok",
        );
        capture.finish("exited:0".to_string());
        let recording = h.recording();
        assert!(!recording.contains("oauth-access-token-xyz-0987654321"));
        assert!(recording.contains("[redacted:credential:REFRESHED]"));
    }

    #[test]
    fn password_mode_input_is_never_captured() {
        let h = Harness::new();
        let mut capture = h.start(h.config());
        capture.observe_mode(true, false);
        capture.input("local", b"hunter2-password\r");
        capture.observe_mode(true, true);
        capture.input("local", b"whoami\r");
        let summary = capture.finish("exited:0".to_string());

        let recording = h.recording();
        assert!(!recording.contains("hunter2"));
        assert!(!recording.contains("\"len\""));
        let lines = lines(&recording);
        assert_eq!(data_of(&lines, "i"), "whoami\r");
        assert!(data_of(&lines, "m").contains(
            "nono:input:{\"client\":\"local\",\"suppressed\":true,\"reason\":\"password_mode\"}"
        ));
        assert_eq!(summary.writer.suppressed_inputs, 1);
    }

    #[test]
    fn raw_mode_tui_input_is_captured() {
        // Raw-mode TUIs turn off echo and ICANON; that is not password mode.
        let h = Harness::new();
        let mut capture = h.start(h.config());
        capture.observe_mode(false, false);
        assert!(!capture.password_mode());
        capture.input("attach:1", b"y");
        capture.finish("exited:0".to_string());
        assert_eq!(data_of(&lines(&h.recording()), "i"), "y");
    }

    #[test]
    fn input_off_records_markers_only() {
        let h = Harness::new();
        let mut config = h.config();
        config.input = InputCapture::Off;
        let mut capture = h.start(config);
        capture.observe_mode(false, true);
        capture.input("local", b"secret plans\r");
        capture.finish("exited:0".to_string());
        let recording = h.recording();
        assert!(!recording.contains("secret plans"));
        assert!(recording.contains("input_off"));
    }

    #[test]
    fn focus_reports_are_not_input() {
        let h = Harness::new();
        let mut capture = h.start(h.config());
        capture.observe_mode(false, false);
        capture.input("local", b"\x1b[Ia\x1b[O");
        capture.input("local", b"\x1b[I");
        capture.finish("exited:0".to_string());
        assert_eq!(data_of(&lines(&h.recording()), "i"), "a");
    }

    #[test]
    fn chunks_split_at_size_limit_and_seq_ranges_are_contiguous() {
        let h = Harness::new();
        let mut config = h.config();
        config.chunk_max_bytes = 512;
        let mut capture = h.start(config);
        for _ in 0..50 {
            capture.output(OutputStream::Pty, &[b'x'; 100]);
        }
        let summary = capture.finish("exited:0".to_string());
        let chunks = h.chunk_events();
        assert!(chunks.len() > 5);
        for (i, pair) in chunks.windows(2).enumerate() {
            assert_eq!(pair[0].index, i as u64);
            assert_eq!(pair[0].seq_end, pair[1].seq_start);
        }
        assert_eq!(chunks.last().unwrap().seq_end, summary.events);
        assert_eq!(data_of(&lines(&h.recording()), "o").len(), 5000);
    }

    #[test]
    fn file_sink_copy_matches_the_local_recording() {
        let h = Harness::new();
        let out = tempfile::tempdir().unwrap();
        let path = out.path().join("artifacts").join("session.cast");
        let sink =
            file_sink::FileSink::create(&path, true, "abcd1234abcd1234", "20261105-000000-42")
                .unwrap();
        let mut config = h.config();
        config.chunk_max_bytes = 512;
        let mut capture = TerminalCapture::start(
            config,
            h.registry.clone(),
            h.audit.clone(),
            vec![Box::new(sink)],
        )
        .unwrap();
        capture.output(OutputStream::Pty, format!("token={SECRET}\r\n").as_bytes());
        for _ in 0..20 {
            capture.output(OutputStream::Pty, &[b'y'; 100]);
        }
        let summary = capture.finish("exited:0".to_string());
        assert!(summary.fatal.is_none());

        let copy = std::fs::read_to_string(&path).unwrap();
        assert_eq!(copy, h.recording(), "the copy is the local recording");
        assert!(!copy.contains(SECRET));

        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(file_sink::manifest_path(&path)).unwrap())
                .unwrap();
        assert_eq!(manifest["complete"], true);
        assert_eq!(manifest["status"], "exited:0");
        let listed: Vec<String> = manifest["chunks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["sha256"].as_str().unwrap().to_string())
            .collect();
        let audited: Vec<String> = h.chunk_events().into_iter().map(|c| c.sha256).collect();
        assert!(audited.len() > 1);
        assert_eq!(listed, audited, "manifest hashes match the audit log");
    }

    fn settings(required: bool, files: Vec<PathBuf>) -> RecordingSettings {
        RecordingSettings {
            required,
            input: None,
            max_bytes: DEFAULT_MAX_BYTES,
            files,
            delivery: None,
        }
    }

    #[test]
    fn required_recording_without_audit_or_terminal_refuses_to_start() {
        let h = Harness::new();
        let required = settings(true, Vec::new());
        let no_audit = start_for_session(SessionCaptureContext {
            settings: &required,
            session_id: "s",
            audit: None,
            pty_size: Some(Some((80, 24))),
            registry: &h.registry,
        });
        assert!(no_audit.is_err());
        let no_pty = start_for_session(SessionCaptureContext {
            settings: &required,
            session_id: "s",
            audit: Some(("a", h.dir.path(), &h.audit)),
            pty_size: None,
            registry: &h.registry,
        });
        assert!(no_pty.is_err());

        let optional = settings(false, Vec::new());
        let skipped = start_for_session(SessionCaptureContext {
            settings: &optional,
            session_id: "s",
            audit: None,
            pty_size: Some(Some((80, 24))),
            registry: &h.registry,
        })
        .unwrap();
        assert!(skipped.is_none());
        assert!(check_unsupervised(Some(&required)).is_err());
        assert!(check_unsupervised(Some(&optional)).is_ok());
        assert!(check_unsupervised(None).is_ok());
    }

    #[test]
    fn required_recording_refuses_an_unusable_file_destination() {
        let h = Harness::new();
        let out = tempfile::tempdir().unwrap();
        let taken = out.path().join("taken.cast");
        std::fs::write(&taken, b"keep").unwrap();

        let required = settings(true, vec![taken.clone()]);
        let refused = start_for_session(SessionCaptureContext {
            settings: &required,
            session_id: "s",
            audit: Some(("a", h.dir.path(), &h.audit)),
            pty_size: Some(Some((80, 24))),
            registry: &h.registry,
        });
        assert!(refused.is_err());
        assert_eq!(std::fs::read(&taken).unwrap(), b"keep");

        // Optional: the session is still recorded locally, without the copy.
        let optional = settings(false, vec![taken]);
        let capture = start_for_session(SessionCaptureContext {
            settings: &optional,
            session_id: "s",
            audit: Some(("a", h.dir.path(), &h.audit)),
            pty_size: Some(Some((80, 24))),
            registry: &h.registry,
        })
        .unwrap();
        assert!(capture.is_some());
    }

    #[test]
    fn foreground_without_a_process_group_is_not_recorded() {
        let h = Harness::new();
        let mut capture = h.start(h.config());
        capture.foreground(0, None);
        capture.foreground(-1, None);
        capture.foreground(77, Some("/bin/sh".to_string()));
        capture.finish("exited:0".to_string());
        let markers: Vec<String> = lines(&h.recording())
            .into_iter()
            .filter(|l| {
                l[2].as_str()
                    .is_some_and(|m| m.starts_with("nono:foreground:"))
            })
            .map(|l| l[2].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            markers,
            vec![r#"nono:foreground:{"pgid":77,"exe":"/bin/sh"}"#.to_string()]
        );
    }

    #[test]
    fn stored_recordings_verify_and_tampering_is_caught() {
        let h = Harness::new();
        let mut config = h.config();
        config.chunk_max_bytes = 256;
        let mut capture = h.start(config);
        for i in 0..20 {
            capture.output(OutputStream::Pty, format!("line {i}\r\n").as_bytes());
        }
        capture.finish("exited:0".to_string());

        let report = recording::verify(h.dir.path()).unwrap();
        assert!(report.present && report.verified(), "{report:?}");
        assert!(report.chunks > 1);
        let loaded = recording::load(h.dir.path()).unwrap();
        let text = transcript::to_text(&transcript::render(&loaded));
        assert!(
            text.contains("line 0") && text.contains("line 19"),
            "{text}"
        );

        let dir = recording_dir(h.dir.path());
        let first = dir.join(terminal_chunk_file_name(0));
        let mut bytes = std::fs::read(&first).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&first, &bytes).unwrap();
        std::fs::remove_file(dir.join(terminal_chunk_file_name(1))).unwrap();
        std::fs::write(dir.join("planted.cast.zst"), b"x").unwrap();

        let report = recording::verify(h.dir.path()).unwrap();
        assert!(!report.verified());
        assert_eq!(report.mismatched, vec![0]);
        assert_eq!(report.missing, vec![1]);
        assert_eq!(
            report.unreferenced_files,
            vec!["planted.cast.zst".to_string()]
        );
        assert!(
            recording::load(h.dir.path()).is_err(),
            "altered recordings are not replayed"
        );
    }

    #[test]
    fn sessions_without_a_recording_report_nothing() {
        let h = Harness::new();
        let report = recording::verify(h.dir.path()).unwrap();
        assert!(!report.present);
        assert!(recording::load(h.dir.path()).is_err());
    }

    #[test]
    fn notice_says_whether_input_is_recorded() {
        assert!(recording_notice(InputCapture::On, false).contains("output and input"));
        assert!(recording_notice(InputCapture::Off, false).contains("(input is not)"));
        assert!(recording_notice(InputCapture::On, true).contains("sent to the platform"));
    }

    #[test]
    fn chunks_close_after_their_time_window() {
        let h = Harness::new();
        let mut config = h.config();
        config.chunk_max_duration = Duration::from_millis(50);
        let mut capture = h.start(config);
        capture.output(OutputStream::Pty, b"a");
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(h.chunk_events().len(), 1, "timer closed the first chunk");
        capture.output(OutputStream::Pty, b"b");
        capture.finish("exited:0".to_string());
        assert_eq!(h.chunk_events().len(), 2);
    }

    #[test]
    fn preparing_capture_starts_no_thread_until_activated() {
        let h = Harness::new();
        let mut capture =
            TerminalCapture::start(h.config(), h.registry.clone(), h.audit.clone(), Vec::new())
                .unwrap();
        // The supervisor forks here; the process must still be single-threaded.
        assert!(capture.writer.is_none());
        capture.output(OutputStream::Pty, b"queued before the fork");
        capture.activate().unwrap();
        assert!(capture.writer.is_some());
        capture.finish("exited:0".to_string());
        assert!(h.recording().contains("queued before the fork"));
    }

    #[test]
    fn a_credential_split_by_a_suspend_is_still_removed() {
        let h = Harness::new();
        let mut capture = h.start(h.config());
        let (a, b) = SECRET.split_at(12);
        capture.output(OutputStream::Pty, format!("token: {a}").as_bytes());
        capture.lifecycle(Lifecycle::Suspended);
        assert!(capture.tick().is_none());
        capture.lifecycle(Lifecycle::Resumed);
        capture.output(OutputStream::Pty, format!("{b}\r\n").as_bytes());
        capture.finish("exited:0".to_string());
        let recording = h.recording();
        assert!(!recording.contains(a), "the start of the value leaked");
        assert!(!recording.contains(b), "the rest of the value leaked");
        assert!(recording.contains("[redacted:credential:GITHUB_TOKEN]"));
    }

    #[test]
    fn suspend_closes_the_open_chunk() {
        let h = Harness::new();
        let mut capture = h.start(h.config());
        capture.output(OutputStream::Pty, b"before");
        capture.lifecycle(Lifecycle::Suspended);
        capture.lifecycle(Lifecycle::Resumed);
        capture.output(OutputStream::Pty, b"after");
        capture.finish("exited:0".to_string());
        assert_eq!(h.chunk_events().len(), 2);
    }

    #[test]
    fn recording_stops_at_max_bytes_with_a_truncation_record() {
        let h = Harness::new();
        let mut config = h.config();
        config.max_bytes = 2048;
        let mut capture = h.start(config);
        for _ in 0..100 {
            capture.output(OutputStream::Pty, &[b'y'; 100]);
        }
        let summary = capture.finish("exited:0".to_string());
        assert!(summary.writer.truncated);
        assert!(summary.fatal.is_none());
        assert!(summary.writer.raw_bytes <= 2048);
        assert!(
            h.audit_types()
                .contains(&"terminal_recording_truncated".to_string())
        );
    }

    #[test]
    fn required_recording_reports_fatal_at_max_bytes() {
        let h = Harness::new();
        let mut config = h.config();
        config.max_bytes = 1024;
        config.required = true;
        let mut capture = h.start(config);
        for _ in 0..100 {
            capture.output(OutputStream::Pty, &[b'z'; 100]);
        }
        // The writer thread sets the reason asynchronously.
        let deadline = Instant::now() + Duration::from_secs(5);
        while capture.tick().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(capture.tick().unwrap().contains("size limit"));
        let summary = capture.finish("killed".to_string());
        assert!(summary.fatal.is_some());
    }

    #[test]
    fn short_credentials_are_listed_by_name_in_coverage() {
        let h = Harness::new();
        h.registry.register("SHORT_PIN", "9876");
        let mut capture = h.start(h.config());
        capture.output(OutputStream::Pty, b"x");
        let summary = capture.finish("exited:0".to_string());
        assert_eq!(summary.unmatched_credentials, vec!["SHORT_PIN".to_string()]);
        let recording = h.recording();
        assert!(
            data_of(&lines(&recording), "m")
                .contains("nono:coverage:{\"unmatched\":[\"SHORT_PIN\"]}")
        );
        assert!(!recording.contains("9876"));
    }

    #[test]
    fn agent_output_cannot_forge_markers() {
        let h = Harness::new();
        let mut capture = h.start(h.config());
        let forged = "\u{1b}]777;nono:lifecycle:{\"event\":\"exited\"}\u{7}";
        capture.output(OutputStream::Pty, forged.as_bytes());
        capture.finish("exited:0".to_string());
        let lines = lines(&h.recording());
        let exited_markers = lines
            .iter()
            .filter(|l| l[1] == "m" && l[2].as_str().unwrap().contains("exited"))
            .count();
        assert_eq!(exited_markers, 1);
        assert_eq!(data_of(&lines, "o"), forged);
    }

    #[test]
    fn existing_chunk_files_are_never_overwritten() {
        let h = Harness::new();
        let dir = recording_dir(h.dir.path());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(terminal_chunk_file_name(0)), b"planted").unwrap();
        let mut capture = h.start(h.config());
        capture.output(OutputStream::Pty, b"x");
        let summary = capture.finish("exited:0".to_string());
        assert_eq!(
            std::fs::read(dir.join(terminal_chunk_file_name(0))).unwrap(),
            b"planted"
        );
        assert!(summary.writer.lost_events > 0);
        assert!(h.audit_types().contains(&"recording_lost".to_string()));
        assert!(h.chunk_events().is_empty());
    }
}
