//! The `delivery` sink (NEP-0010 §6.1): upload each closed chunk to the
//! platform this host is enrolled with.
//!
//! Capture never waits on delivery. The sink only queues the closed chunk's
//! description; an uploader thread reads the stored chunk from the session's
//! protected recording directory, signs the request with the enrolled device
//! key, and posts it. The local chunks stay the authoritative copy and the
//! upload buffer: a transient failure is retried with backoff, and session
//! end waits up to the flush timeout for what is still queued.
//!
//! The platform treats uploaded chunks as provisional until the session's
//! audit log reaches it and its `terminal_chunk` events match the bytes.
//! Request bodies are never logged.

use super::audit_events::{TerminalChunkEvent, terminal_chunk_file_name};
use super::events::{ProtectedEvent, SessionEnd};
use super::settings::DeliverySettings;
use super::writer::{ChunkInfo, Sink, hex_digest};
use crate::platform_client::{self, PlatformState};
use aws_lc_rs::signature::EcdsaKeyPair;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use nono::{NonoError, Result};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, TryRecvError, channel};
use std::time::{Duration, Instant};

/// Upload route, relative to the platform URL.
pub(crate) const RECORDING_CHUNK_UPLOAD_PATH: &str = "/api/v1/audit/recordings/chunks";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const RESPONSE_LIMIT_BYTES: u64 = 64 * 1024;
const BACKOFF_START: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Who receives the chunks and how to authenticate to them.
pub(crate) struct PlatformReceiver {
    pub(crate) state: PlatformState,
    pub(crate) key: EcdsaKeyPair,
}

/// What the uploader achieved by session end.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DeliveryOutcome {
    pub(crate) delivered: u64,
    /// Refused by the receiver; retrying would not help.
    pub(crate) rejected: u64,
    /// Still queued when the flush timeout ran out.
    pub(crate) undelivered: u64,
}

enum Job {
    Chunk(TerminalChunkEvent),
    /// No more chunks: finish delivering the queue, then report.
    End,
    /// The flush timeout ran out: report now and stop.
    Cancel,
}

/// Result of one upload attempt.
pub(crate) enum Attempt {
    Delivered,
    /// Retry later: network trouble, overload or a server error.
    Transient(String),
    /// The receiver refused this chunk.
    Rejected(String),
}

/// Sends one chunk; replaced in tests.
pub(crate) trait Transport: Send {
    fn send(&mut self, chunk: &TerminalChunkEvent, stored: &[u8]) -> Attempt;
}

pub(crate) struct PlatformTransport {
    receiver: PlatformReceiver,
    audit_session_id: String,
    endpoint: String,
    request_path: String,
}

impl PlatformTransport {
    pub(crate) fn new(receiver: PlatformReceiver, audit_session_id: &str) -> Result<Self> {
        let endpoint = platform_client::endpoint_url(
            &receiver.state.platform_url,
            RECORDING_CHUNK_UPLOAD_PATH,
        )?;
        let request_path = url::Url::parse(&endpoint)
            .map_err(|e| NonoError::ConfigParse(format!("invalid recording endpoint: {e}")))?
            .path()
            .to_string();
        Ok(Self {
            receiver,
            audit_session_id: audit_session_id.to_string(),
            endpoint,
            request_path,
        })
    }

    fn body(&self, chunk: &TerminalChunkEvent, stored: &[u8]) -> Result<Vec<u8>> {
        serde_json::to_vec(&serde_json::json!({
            "tenant_id": self.receiver.state.tenant_id,
            "session_id": self.audit_session_id,
            "shipper_id": self.receiver.state.subject_id,
            "chunk": chunk,
            "data_base64": STANDARD.encode(stored),
        }))
        .map_err(|e| NonoError::Snapshot(format!("failed to encode recording upload: {e}")))
    }
}

impl Transport for PlatformTransport {
    fn send(&mut self, chunk: &TerminalChunkEvent, stored: &[u8]) -> Attempt {
        let body = match self.body(chunk, stored) {
            Ok(body) => body,
            Err(e) => return Attempt::Rejected(e.to_string()),
        };
        let state = &self.receiver.state;
        let signed = match platform_client::sign_request_v1_with_key(
            state,
            &self.receiver.key,
            "POST",
            &self.request_path,
            uuid::Uuid::new_v4(),
            &body,
        ) {
            Ok(signed) => signed,
            Err(e) => return Attempt::Rejected(e.to_string()),
        };
        let response = platform_client::http_agent(REQUEST_TIMEOUT)
            .post(&self.endpoint)
            .config()
            .http_status_as_error(false)
            .build()
            .header("Content-Type", "application/json")
            .header(
                "X-Nono-Protocol-Version",
                platform_client::REQUEST_PROTOCOL_V1,
            )
            .header("X-Nono-Subject-Id", &state.subject_id)
            .header("X-Nono-Timestamp", &signed.timestamp)
            .header("X-Nono-Request-Id", &signed.request_id)
            .header("X-Nono-Content-SHA256", &signed.body_digest)
            .header("X-Nono-Signature", &signed.signature)
            .send(&body[..]);
        let mut response = match response {
            Ok(response) => response,
            Err(e) => return Attempt::Transient(format!("request failed: {e}")),
        };
        let status = response.status().as_u16();
        let message = response
            .body_mut()
            .with_config()
            .limit(RESPONSE_LIMIT_BYTES)
            .read_to_string()
            .unwrap_or_default();
        classify(status, chunk.index, &message)
    }
}

/// Decide what an HTTP answer means for one chunk.
fn classify(status: u16, index: u64, body: &str) -> Attempt {
    match status {
        200..=299 => {
            let receipt: Option<serde_json::Value> = serde_json::from_str(body).ok();
            if receipt
                .as_ref()
                .and_then(|r| r["index"].as_u64())
                .is_some_and(|i| i == index)
            {
                Attempt::Delivered
            } else {
                Attempt::Rejected("the receiver returned a mismatched receipt".to_string())
            }
        }
        408 | 425 | 429 | 500..=599 => Attempt::Transient(format!("HTTP {status}")),
        _ => Attempt::Rejected(format!(
            "HTTP {status}: {}",
            body.chars()
                .filter(|c| !c.is_control())
                .take(200)
                .collect::<String>()
        )),
    }
}

/// The uploader's loop: deliver queued chunks in order until told to end
/// and the queue is empty, or until cancelled.
fn run_uploader(
    mut transport: Box<dyn Transport>,
    dir: PathBuf,
    jobs: Receiver<Job>,
    done: Sender<DeliveryOutcome>,
) {
    let mut queue: VecDeque<TerminalChunkEvent> = VecDeque::new();
    let mut outcome = DeliveryOutcome::default();
    let mut ending = false;
    let mut backoff = BACKOFF_START;
    let mut retry_at: Option<Instant> = None;
    loop {
        if queue.is_empty() && ending {
            let _ = done.send(outcome);
            return;
        }
        // Block for work when there is nothing to send, wait for new jobs
        // or the retry time while backing off, and otherwise just collect
        // whatever has arrived. The sender stays connected until `close`
        // has its answer or cancels, so these waits do not spin.
        let now = Instant::now();
        let next = if queue.is_empty() {
            jobs.recv().map_err(|_| RecvTimeoutError::Disconnected)
        } else {
            match retry_at {
                Some(at) if at > now => jobs.recv_timeout(at - now),
                _ => jobs.try_recv().map_err(|e| match e {
                    TryRecvError::Empty => RecvTimeoutError::Timeout,
                    TryRecvError::Disconnected => RecvTimeoutError::Disconnected,
                }),
            }
        };
        match next {
            Ok(Job::Chunk(chunk)) => {
                queue.push_back(chunk);
                continue;
            }
            Ok(Job::End) => {
                ending = true;
                continue;
            }
            // Cancelled, or the sink is gone: stop without further attempts.
            Ok(Job::Cancel) | Err(RecvTimeoutError::Disconnected) => {
                outcome.undelivered = u64::try_from(queue.len()).unwrap_or(u64::MAX);
                let _ = done.send(outcome);
                return;
            }
            Err(RecvTimeoutError::Timeout) => {}
        }
        if retry_at.is_some_and(|at| Instant::now() < at) {
            continue;
        }
        retry_at = None;
        let Some(chunk) = queue.front().cloned() else {
            continue;
        };
        let attempt = match std::fs::read(dir.join(terminal_chunk_file_name(chunk.index))) {
            Ok(stored) if hex_digest(&stored) == chunk.sha256 => transport.send(&chunk, &stored),
            Ok(_) => Attempt::Rejected("the stored chunk no longer matches its record".to_string()),
            Err(e) => Attempt::Rejected(format!("the stored chunk cannot be read: {e}")),
        };
        match attempt {
            Attempt::Delivered => {
                queue.pop_front();
                outcome.delivered = outcome.delivered.saturating_add(1);
                backoff = BACKOFF_START;
            }
            Attempt::Rejected(reason) => {
                tracing::warn!(
                    "recording chunk {} was not delivered: {reason}",
                    chunk.index
                );
                queue.pop_front();
                outcome.rejected = outcome.rejected.saturating_add(1);
            }
            Attempt::Transient(reason) => {
                tracing::debug!(
                    "recording chunk {} delivery will be retried: {reason}",
                    chunk.index
                );
                retry_at = Some(Instant::now() + backoff);
                backoff = (backoff * 2).min(BACKOFF_MAX);
            }
        }
    }
}

/// The uploader's inputs, kept until [`Sink::activate`] starts it.
struct PendingUploader {
    transport: Box<dyn Transport>,
    recording_dir: PathBuf,
    jobs: Receiver<Job>,
    done: Sender<DeliveryOutcome>,
}

pub(crate) struct DeliverySink {
    jobs: Option<Sender<Job>>,
    done: Receiver<DeliveryOutcome>,
    uploader: Option<PendingUploader>,
    queued: u64,
    settings: DeliverySettings,
}

impl DeliverySink {
    /// Prepare delivery. The uploader thread starts in `activate`, after the
    /// supervisor has forked; chunks closed before then wait in the queue.
    pub(crate) fn new(
        transport: Box<dyn Transport>,
        recording_dir: PathBuf,
        settings: DeliverySettings,
    ) -> Self {
        let (jobs, job_rx) = channel();
        let (done_tx, done) = channel();
        Self {
            jobs: Some(jobs),
            done,
            uploader: Some(PendingUploader {
                transport,
                recording_dir,
                jobs: job_rx,
                done: done_tx,
            }),
            queued: 0,
            settings,
        }
    }
}

impl Sink for DeliverySink {
    fn name(&self) -> &str {
        "delivery"
    }

    fn required(&self) -> bool {
        self.settings.required
    }

    fn activate(&mut self) -> Result<()> {
        let Some(pending) = self.uploader.take() else {
            return Ok(());
        };
        std::thread::Builder::new()
            .name("nono-recording-delivery".to_string())
            .spawn(move || {
                run_uploader(
                    pending.transport,
                    pending.recording_dir,
                    pending.jobs,
                    pending.done,
                )
            })
            .map_err(|e| NonoError::Snapshot(format!("failed to start recording delivery: {e}")))?;
        Ok(())
    }

    fn write(&mut self, _event: &ProtectedEvent) -> Result<()> {
        Ok(())
    }

    fn chunk_closed(&mut self, chunk: &ChunkInfo) -> Result<()> {
        let sent = self
            .jobs
            .as_ref()
            .is_some_and(|jobs| jobs.send(Job::Chunk(chunk.event.clone())).is_ok());
        if !sent {
            return Err(NonoError::Snapshot(
                "recording delivery stopped unexpectedly".to_string(),
            ));
        }
        self.queued = self.queued.saturating_add(1);
        Ok(())
    }

    fn close(&mut self, _end: &SessionEnd) -> Result<()> {
        // The sender stays open until the uploader answers or is cancelled,
        // so its waits keep working while it finishes.
        let jobs = self.jobs.take();
        let ended = jobs
            .as_ref()
            .is_some_and(|jobs| jobs.send(Job::End).is_ok());
        let answer = if ended {
            self.done.recv_timeout(self.settings.flush_timeout).ok()
        } else {
            None
        };
        let outcome = match answer {
            Some(outcome) => outcome,
            // Out of time, or the uploader is gone: cancel it, and count
            // whatever was not confirmed as undelivered.
            None => {
                if let Some(jobs) = jobs.as_ref() {
                    let _ = jobs.send(Job::Cancel);
                }
                DeliveryOutcome {
                    delivered: 0,
                    rejected: 0,
                    undelivered: self.queued,
                }
            }
        };
        drop(jobs);
        let missing = outcome.rejected.saturating_add(outcome.undelivered);
        if missing == 0 {
            tracing::info!(
                "recording delivery: {} chunk(s) delivered",
                outcome.delivered
            );
            return Ok(());
        }
        let message = format!(
            "{missing} of {} recording chunk(s) were not delivered to the platform",
            self.queued
        );
        if self.settings.required {
            Err(NonoError::Snapshot(message))
        } else {
            eprintln!("[nono] Warning: {message}; they remain in the local recording.");
            Ok(())
        }
    }
}

/// Load the enrolled platform identity for delivery.
pub(crate) fn platform_receiver() -> Result<PlatformReceiver> {
    let state = platform_client::load_state()?.ok_or_else(|| {
        NonoError::ConfigParse(
            "this host is not enrolled with a platform (see `nono platform enroll`)".to_string(),
        )
    })?;
    let key = platform_client::load_signing_key(&state)?;
    Ok(PlatformReceiver { state, key })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn event(index: u64, stored: &[u8]) -> TerminalChunkEvent {
        TerminalChunkEvent {
            index,
            seq_start: index,
            seq_end: index + 1,
            start_offset_us: 0,
            end_offset_us: 1,
            audit_seq_start: 0,
            audit_seq_end: 0,
            raw_bytes: 1,
            stored_bytes: stored.len() as u64,
            sha256: hex_digest(stored),
            credential_redactions: 0,
            suppressed_inputs: 0,
        }
    }

    /// Answers from a script; records what was sent.
    struct Scripted {
        answers: VecDeque<&'static str>,
        sent: Arc<Mutex<Vec<u64>>>,
    }

    impl Transport for Scripted {
        fn send(&mut self, chunk: &TerminalChunkEvent, _stored: &[u8]) -> Attempt {
            self.sent.lock().unwrap().push(chunk.index);
            match self.answers.pop_front().unwrap_or("ok") {
                "ok" => Attempt::Delivered,
                "retry" => Attempt::Transient("busy".to_string()),
                _ => Attempt::Rejected("no".to_string()),
            }
        }
    }

    fn chunk_info(dir: &std::path::Path, index: u64) -> ChunkInfo {
        let stored = format!("stored chunk {index}").into_bytes();
        std::fs::write(dir.join(terminal_chunk_file_name(index)), &stored).unwrap();
        ChunkInfo {
            event: event(index, &stored),
            raw: Vec::new(),
        }
    }

    fn start_sink(
        dir: &std::path::Path,
        answers: &[&'static str],
        required: bool,
        flush: Duration,
    ) -> (DeliverySink, Arc<Mutex<Vec<u64>>>) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let transport = Scripted {
            answers: answers.iter().copied().collect(),
            sent: sent.clone(),
        };
        let mut sink = DeliverySink::new(
            Box::new(transport),
            dir.to_path_buf(),
            DeliverySettings {
                required,
                flush_timeout: flush,
            },
        );
        sink.activate().unwrap();
        (sink, sent)
    }

    fn end() -> SessionEnd {
        SessionEnd {
            status: "exited:0".to_string(),
        }
    }

    #[test]
    fn chunks_are_delivered_in_order_and_retried() {
        let dir = tempfile::tempdir().unwrap();
        let (mut sink, sent) = start_sink(
            dir.path(),
            &["ok", "retry", "ok", "ok"],
            true,
            Duration::from_secs(10),
        );
        for index in 0..3 {
            sink.chunk_closed(&chunk_info(dir.path(), index)).unwrap();
        }
        sink.close(&end()).unwrap();
        assert_eq!(*sent.lock().unwrap(), vec![0, 1, 1, 2]);
    }

    #[test]
    fn required_delivery_fails_when_chunks_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (mut sink, _) = start_sink(dir.path(), &["ok", "no"], true, Duration::from_secs(10));
        sink.chunk_closed(&chunk_info(dir.path(), 0)).unwrap();
        sink.chunk_closed(&chunk_info(dir.path(), 1)).unwrap();
        assert!(sink.close(&end()).is_err());

        let (mut optional, _) = start_sink(dir.path(), &["no"], false, Duration::from_secs(10));
        optional.chunk_closed(&chunk_info(dir.path(), 2)).unwrap();
        assert!(optional.close(&end()).is_ok());
    }

    #[test]
    fn session_end_waits_only_for_the_flush_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let (mut sink, _) =
            start_sink(dir.path(), &["retry"; 50], true, Duration::from_millis(300));
        sink.chunk_closed(&chunk_info(dir.path(), 0)).unwrap();
        let started = Instant::now();
        assert!(sink.close(&end()).is_err());
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_timed_out_uploader_is_cancelled_and_stops_retrying() {
        let dir = tempfile::tempdir().unwrap();
        let (mut sink, sent) = start_sink(
            dir.path(),
            &["retry"; 50],
            false,
            Duration::from_millis(200),
        );
        sink.chunk_closed(&chunk_info(dir.path(), 0)).unwrap();
        assert!(sink.close(&end()).is_ok());
        let attempts = sent.lock().unwrap().len();
        // Past the first backoff: a live uploader would have retried by now.
        std::thread::sleep(BACKOFF_START + Duration::from_millis(500));
        assert_eq!(sent.lock().unwrap().len(), attempts);
    }

    #[test]
    fn nothing_is_sent_before_activation() {
        let dir = tempfile::tempdir().unwrap();
        let sent = Arc::new(Mutex::new(Vec::new()));
        let transport = Scripted {
            answers: ["ok"].into_iter().collect(),
            sent: sent.clone(),
        };
        let mut sink = DeliverySink::new(
            Box::new(transport),
            dir.path().to_path_buf(),
            DeliverySettings {
                required: true,
                flush_timeout: Duration::from_secs(10),
            },
        );
        sink.chunk_closed(&chunk_info(dir.path(), 0)).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert!(sent.lock().unwrap().is_empty());
        sink.activate().unwrap();
        sink.close(&end()).unwrap();
        assert_eq!(*sent.lock().unwrap(), vec![0]);
    }

    #[test]
    fn altered_local_chunks_are_not_sent() {
        let dir = tempfile::tempdir().unwrap();
        let (mut sink, sent) = start_sink(dir.path(), &[], true, Duration::from_secs(10));
        let info = chunk_info(dir.path(), 0);
        std::fs::write(dir.path().join(terminal_chunk_file_name(0)), b"tampered").unwrap();
        sink.chunk_closed(&info).unwrap();
        assert!(sink.close(&end()).is_err());
        assert!(sent.lock().unwrap().is_empty());
    }

    #[test]
    fn answers_are_classified() {
        assert!(matches!(
            classify(200, 3, r#"{"index":3}"#),
            Attempt::Delivered
        ));
        assert!(matches!(
            classify(200, 3, r#"{"index":4}"#),
            Attempt::Rejected(_)
        ));
        assert!(matches!(classify(503, 3, ""), Attempt::Transient(_)));
        assert!(matches!(classify(429, 3, ""), Attempt::Transient(_)));
        assert!(matches!(classify(409, 3, "conflict"), Attempt::Rejected(_)));
        assert!(matches!(classify(401, 3, ""), Attempt::Rejected(_)));
    }
}
