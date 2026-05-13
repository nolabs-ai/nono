use nono::supervisor::{AuditEntry, UrlOpenRequest};
use nono::undo::{AuditIntegritySummary, ContentHash, NetworkAuditEvent};
use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

pub(crate) const AUDIT_EVENTS_FILENAME: &str = "audit-events.ndjson";
const EVENT_DOMAIN: &[u8] = b"nono.audit.event.alpha\n";
const CHAIN_DOMAIN: &[u8] = b"nono.audit.chain.alpha\n";
const MERKLE_NODE_DOMAIN_ALPHA: &[u8] = b"nono.audit.merkle.alpha\n";
const MERKLE_SCHEME_LABEL: &str = "alpha";
const HASH_ALGORITHM: &str = "sha256";

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum AuditEventPayload {
    SessionStarted {
        started: String,
        command: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        redaction_policy: Option<nono::ScrubPolicyDiff>,
    },
    SessionEnded {
        ended: String,
        exit_code: i32,
    },
    CapabilityDecision {
        entry: AuditEntry,
    },
    UrlOpen {
        request: UrlOpenRequest,
        success: bool,
        error: Option<String>,
    },
    Network {
        event: NetworkAuditEvent,
    },
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct AuditEventRecord {
    pub(crate) sequence: u64,
    pub(crate) prev_chain: Option<ContentHash>,
    pub(crate) leaf_hash: ContentHash,
    pub(crate) chain_hash: ContentHash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) event_json: Option<String>,
    pub(crate) event: AuditEventPayload,
}

#[derive(Serialize)]
pub(crate) struct AuditVerificationResult {
    pub(crate) hash_algorithm: String,
    pub(crate) merkle_scheme: String,
    pub(crate) event_count: u64,
    pub(crate) computed_chain_head: Option<ContentHash>,
    pub(crate) computed_merkle_root: Option<ContentHash>,
    pub(crate) stored_event_count: Option<u64>,
    pub(crate) stored_chain_head: Option<ContentHash>,
    pub(crate) stored_merkle_root: Option<ContentHash>,
    pub(crate) event_count_matches: bool,
    pub(crate) records_verified: bool,
}

pub(crate) struct AuditRecorder {
    file: File,
    next_sequence: u64,
    previous_chain: Option<ContentHash>,
    leaf_hashes: Vec<ContentHash>,
    redaction_policy: nono::ScrubPolicy,
}

impl AuditRecorder {
    #[cfg(test)]
    pub(crate) fn new(session_dir: PathBuf) -> Result<Self> {
        Self::new_with_policy(session_dir, nono::ScrubPolicy::secure_default())
    }

    pub(crate) fn new_with_policy(
        session_dir: PathBuf,
        redaction_policy: nono::ScrubPolicy,
    ) -> Result<Self> {
        let path = session_dir.join(AUDIT_EVENTS_FILENAME);
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| {
                NonoError::Snapshot(format!(
                    "Failed to open audit event log {}: {e}",
                    path.display()
                ))
            })?;
        Ok(Self {
            file,
            next_sequence: 0,
            previous_chain: None,
            leaf_hashes: Vec::new(),
            redaction_policy,
        })
    }

    pub(crate) fn record_session_started(
        &mut self,
        started: String,
        command: Vec<String>,
    ) -> Result<()> {
        self.append_event(AuditEventPayload::SessionStarted {
            started,
            command: nono::scrub_argv_with_policy(&command, &self.redaction_policy),
            redaction_policy: self
                .redaction_policy
                .diff_from_secure_default()
                .into_option(),
        })
    }

    pub(crate) fn record_session_ended(&mut self, ended: String, exit_code: i32) -> Result<()> {
        self.append_event(AuditEventPayload::SessionEnded { ended, exit_code })
    }

    pub(crate) fn record_capability_decision(&mut self, entry: AuditEntry) -> Result<()> {
        self.append_event(AuditEventPayload::CapabilityDecision { entry })
    }

    pub(crate) fn record_open_url(
        &mut self,
        request: UrlOpenRequest,
        success: bool,
        error: Option<String>,
    ) -> Result<()> {
        self.append_event(AuditEventPayload::UrlOpen {
            request,
            success,
            error,
        })
    }

    pub(crate) fn record_network_event(&mut self, event: NetworkAuditEvent) -> Result<()> {
        self.append_event(AuditEventPayload::Network { event })
    }

    pub(crate) fn event_count(&self) -> u64 {
        self.leaf_hashes.len() as u64
    }

    pub(crate) fn finalize(&self) -> Option<AuditIntegritySummary> {
        let chain_head = self.previous_chain?;
        let merkle_root = merkle_root(&self.leaf_hashes);
        Some(AuditIntegritySummary {
            hash_algorithm: HASH_ALGORITHM.to_string(),
            event_count: self.event_count(),
            chain_head,
            merkle_root,
        })
    }

    fn append_event(&mut self, event: AuditEventPayload) -> Result<()> {
        let event_bytes = serde_json::to_vec(&event)
            .map_err(|e| NonoError::Snapshot(format!("Failed to serialize audit event: {e}")))?;
        let leaf_hash = hash_event(&event_bytes);
        let chain_hash = hash_chain(self.previous_chain.as_ref(), &leaf_hash);
        let record = AuditEventRecord {
            sequence: self.next_sequence,
            prev_chain: self.previous_chain,
            leaf_hash,
            chain_hash,
            event_json: Some(String::from_utf8(event_bytes.clone()).map_err(|e| {
                NonoError::Snapshot(format!(
                    "Failed to encode canonical audit event JSON as UTF-8: {e}"
                ))
            })?),
            event,
        };
        let line = serde_json::to_vec(&record)
            .map_err(|e| NonoError::Snapshot(format!("Failed to serialize audit record: {e}")))?;
        self.file
            .write_all(&line)
            .and_then(|_| self.file.write_all(b"\n"))
            .and_then(|_| self.file.flush())
            .map_err(|e| NonoError::Snapshot(format!("Failed to append audit record: {e}")))?;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.previous_chain = Some(chain_hash);
        self.leaf_hashes.push(leaf_hash);
        Ok(())
    }
}

/// Bounded queue capacity for the audit writer channel.
///
/// A typical event is a few hundred bytes; this bound caps in-flight memory
/// well under 10 MB even for the largest events. Bursts from a runaway
/// agent fit here; sustained overflow drops events with rate-limited
/// `warn!`s and bumps `dropped_events`.
const AUDIT_WRITER_QUEUE: usize = 16_384;

enum WriterCmd {
    /// A network event to append to the recorder. Dropped silently by the
    /// writer once `done` has been set (see `RecorderStreamingSink` docs).
    Event(NetworkAuditEvent),
    /// Drain marker. The writer flips `done` and acks via the included
    /// `SyncSender<()>`; `flush()` blocks on the ack to provide a
    /// synchronous "everything before this is on disk" barrier.
    Flush(SyncSender<()>),
    /// Terminate the writer loop. Sent from `Drop`.
    Shutdown,
}

/// Streaming sink that forwards each network audit event into an
/// `AuditRecorder` via a bounded channel drained by a dedicated writer
/// thread, instead of buffering until session exit.
///
/// `record()` is non-blocking: it `try_send`s into the queue and returns
/// immediately. The writer thread is the sole owner of the recorder mutex
/// on the audit path, so concurrent proxied connections never contend on
/// disk I/O. Order is preserved because a single consumer drains FIFO,
/// which is required by the recorder's hash chain and Merkle accumulator.
///
/// `flush()` seals the sink: once it returns, the writer has marked itself
/// `done` and silently drops any event that was enqueued during the
/// `AuditLog::close` race window. This guarantees the caller can append
/// further records (e.g. `session_ended`) directly to the same recorder
/// without the writer racing them through the recorder mutex and
/// extending the file past the Merkle root captured in `SessionMetadata`.
///
/// Errors are logged (not propagated) because audit recording must never
/// abort an in-flight network request — a poisoned mutex or transient I/O
/// failure should drop a single event rather than break the proxy.
pub(crate) struct RecorderStreamingSink {
    tx: SyncSender<WriterCmd>,
    /// Count of events rejected because the queue was full or the writer
    /// was gone. Surfaced via `dropped_events()` and a final `warn!` on
    /// `Drop` so the operator never silently loses count.
    dropped: AtomicU64,
    /// Set by the writer when it processes a `Flush` command. Subsequent
    /// `Event`s are silently ignored — see struct-level docs.
    done: Arc<AtomicBool>,
    writer: Mutex<Option<JoinHandle<()>>>,
}

impl RecorderStreamingSink {
    pub(crate) fn new(recorder: Arc<Mutex<AuditRecorder>>) -> Result<Self> {
        Self::with_capacity(recorder, AUDIT_WRITER_QUEUE)
    }

    fn with_capacity(recorder: Arc<Mutex<AuditRecorder>>, capacity: usize) -> Result<Self> {
        let (tx, rx) = sync_channel::<WriterCmd>(capacity);
        let done = Arc::new(AtomicBool::new(false));
        let done_writer = Arc::clone(&done);
        let writer = std::thread::Builder::new()
            .name("nono-audit-writer".to_string())
            .spawn(move || writer_loop(recorder, rx, done_writer))
            .map_err(|e| {
                NonoError::Snapshot(format!("Failed to spawn audit writer thread: {e}"))
            })?;
        Ok(Self {
            tx,
            dropped: AtomicU64::new(0),
            done,
            writer: Mutex::new(Some(writer)),
        })
    }

    #[cfg(test)]
    pub(crate) fn new_with_capacity(
        recorder: Arc<Mutex<AuditRecorder>>,
        capacity: usize,
    ) -> Result<Self> {
        Self::with_capacity(recorder, capacity)
    }

    /// Number of events dropped because the bounded queue was full or the
    /// writer thread had already terminated. Exposed mainly for tests and
    /// for surfacing in diagnostics; the final value is logged on `Drop`.
    pub(crate) fn dropped_events(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

fn writer_loop(
    recorder: Arc<Mutex<AuditRecorder>>,
    rx: Receiver<WriterCmd>,
    done: Arc<AtomicBool>,
) {
    while let Ok(cmd) = rx.recv() {
        match cmd {
            WriterCmd::Event(event) => {
                // Once Flush has sealed the sink, any Event that lost the
                // is_closed/record race in `push_event` and reached the
                // queue after the seal must NOT be appended — doing so
                // would extend the file past the Merkle root that
                // `finalize_supervised_exit` is about to commit, breaking
                // `verify_audit_log`.
                if done.load(Ordering::Acquire) {
                    continue;
                }
                match recorder.lock() {
                    Ok(mut r) => {
                        if let Err(e) = r.record_network_event(event) {
                            tracing::warn!("Audit writer: record_network_event failed: {}", e);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Audit writer: recorder mutex poisoned: {}", e);
                    }
                }
            }
            WriterCmd::Flush(ack) => {
                // Set `done` *before* acking so that any concurrent
                // producer that enqueues an Event after this Flush
                // observes the seal by the time the writer dequeues it.
                done.store(true, Ordering::Release);
                let _ = ack.send(());
            }
            WriterCmd::Shutdown => break,
        }
    }
}

impl nono_proxy::audit::NetworkAuditSink for RecorderStreamingSink {
    fn record(&self, event: &NetworkAuditEvent) {
        match self.tx.try_send(WriterCmd::Event(event.clone())) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                let prev = self.dropped.fetch_add(1, Ordering::Relaxed);
                if prev == 0 || prev.is_power_of_two() {
                    tracing::warn!(
                        "Audit writer queue full (cap {}); dropped {} events so far",
                        AUDIT_WRITER_QUEUE,
                        prev.saturating_add(1)
                    );
                }
            }
            Err(TrySendError::Disconnected(_)) => {
                let prev = self.dropped.fetch_add(1, Ordering::Relaxed);
                if prev == 0 || prev.is_power_of_two() {
                    tracing::warn!(
                        "Audit writer thread terminated; dropped {} events so far",
                        prev.saturating_add(1)
                    );
                }
            }
        }
    }

    fn flush(&self) {
        let (ack_tx, ack_rx) = sync_channel::<()>(1);
        if self.tx.send(WriterCmd::Flush(ack_tx)).is_err() {
            tracing::warn!("Audit writer thread is gone; flush is a no-op");
            // Seal locally so callers that observe a successful flush
            // (even degraded) cannot have late events appended — there
            // is no writer to append anything, but the contract still
            // holds.
            self.done.store(true, Ordering::Release);
            return;
        }
        if ack_rx.recv().is_err() {
            tracing::warn!("Audit writer disconnected before flush ack");
            self.done.store(true, Ordering::Release);
        }
    }
}

impl Drop for RecorderStreamingSink {
    fn drop(&mut self) {
        let dropped = self.dropped_events();
        if dropped > 0 {
            tracing::warn!(
                "Audit writer sink dropped {} events total over the session",
                dropped
            );
        }
        let _ = self.tx.send(WriterCmd::Shutdown);
        if let Ok(mut writer) = self.writer.lock() {
            if let Some(h) = writer.take() {
                let _ = h.join();
            }
        }
    }
}

fn hash_event(event_bytes: &[u8]) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(EVENT_DOMAIN);
    hasher.update(event_bytes);
    ContentHash::from_bytes(hasher.finalize().into())
}

fn hash_chain(previous: Option<&ContentHash>, leaf_hash: &ContentHash) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(CHAIN_DOMAIN);
    if let Some(prev) = previous {
        hasher.update(prev.as_bytes());
    } else {
        hasher.update([0u8; 32]);
    }
    hasher.update(leaf_hash.as_bytes());
    ContentHash::from_bytes(hasher.finalize().into())
}

fn merkle_root(leaves: &[ContentHash]) -> ContentHash {
    if leaves.is_empty() {
        return ContentHash::from_bytes(Sha256::digest(b"").into());
    }

    let mut level: Vec<[u8; 32]> = leaves.iter().map(|leaf| *leaf.as_bytes()).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = pair[0];
            if pair.len() == 1 {
                next.push(left);
                continue;
            }

            let right = pair[1];
            let mut hasher = Sha256::new();
            hasher.update(MERKLE_NODE_DOMAIN_ALPHA);
            hasher.update(left);
            hasher.update(right);
            next.push(hasher.finalize().into());
        }
        level = next;
    }
    ContentHash::from_bytes(level[0])
}

pub(crate) fn verify_audit_log(
    session_dir: &Path,
    stored: Option<&AuditIntegritySummary>,
) -> Result<AuditVerificationResult> {
    let path = session_dir.join(AUDIT_EVENTS_FILENAME);
    let file = File::open(&path).map_err(|e| {
        NonoError::Snapshot(format!(
            "Failed to open audit event log {}: {e}",
            path.display()
        ))
    })?;

    let reader = BufReader::new(file);
    let mut previous_chain: Option<ContentHash> = None;
    let mut leaf_hashes = Vec::new();
    let mut computed_chain_head: Option<ContentHash> = None;
    let mut missing_canonical_event_json = false;

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

        let expected_sequence = leaf_hashes.len() as u64;
        if record.sequence != expected_sequence {
            return Err(NonoError::Snapshot(format!(
                "Audit event record sequence mismatch at line {}: expected {}, got {}",
                index.saturating_add(1),
                expected_sequence,
                record.sequence
            )));
        }

        if record.prev_chain != previous_chain {
            return Err(NonoError::Snapshot(format!(
                "Audit event record prev_chain mismatch at line {}",
                index.saturating_add(1)
            )));
        }

        let event_bytes = if let Some(raw) = record.event_json.as_ref() {
            let reparsed: AuditEventPayload = serde_json::from_str(raw).map_err(|e| {
                NonoError::Snapshot(format!(
                    "Failed to parse canonical audit event JSON at line {}: {e}",
                    index.saturating_add(1)
                ))
            })?;
            let reparsed_value = serde_json::to_value(&reparsed).map_err(|e| {
                NonoError::Snapshot(format!(
                    "Failed to normalize canonical audit event JSON at line {}: {e}",
                    index.saturating_add(1)
                ))
            })?;
            let record_value = serde_json::to_value(&record.event).map_err(|e| {
                NonoError::Snapshot(format!(
                    "Failed to normalize audit event payload at line {}: {e}",
                    index.saturating_add(1)
                ))
            })?;
            if reparsed_value != record_value {
                return Err(NonoError::Snapshot(format!(
                    "Audit event JSON mismatch at line {}",
                    index.saturating_add(1)
                )));
            }
            raw.as_bytes().to_vec()
        } else {
            missing_canonical_event_json = true;
            serde_json::to_vec(&record.event).map_err(|e| {
                NonoError::Snapshot(format!(
                    "Failed to serialize audit event for verification at line {}: {e}",
                    index.saturating_add(1)
                ))
            })?
        };
        let leaf_hash = hash_event(&event_bytes);
        if record.leaf_hash != leaf_hash {
            return Err(NonoError::Snapshot(format!(
                "Audit event leaf hash mismatch at line {}",
                index.saturating_add(1)
            )));
        }

        let chain_hash = hash_chain(previous_chain.as_ref(), &leaf_hash);
        if record.chain_hash != chain_hash {
            return Err(NonoError::Snapshot(format!(
                "Audit event chain hash mismatch at line {}",
                index.saturating_add(1)
            )));
        }

        previous_chain = Some(chain_hash);
        computed_chain_head = Some(chain_hash);
        leaf_hashes.push(leaf_hash);
    }

    let computed_merkle_root = if leaf_hashes.is_empty() {
        None
    } else {
        Some(merkle_root(&leaf_hashes))
    };

    if stored.is_some() && !leaf_hashes.is_empty() && missing_canonical_event_json {
        return Err(NonoError::Snapshot(
            "Alpha audit log is missing canonical event_json bytes".to_string(),
        ));
    }

    let stored_event_count = stored.map(|s| s.event_count);
    let stored_chain_head = stored.map(|s| s.chain_head);
    let stored_merkle_root = stored.map(|s| s.merkle_root);
    let event_count = leaf_hashes.len() as u64;
    let event_count_matches = stored_event_count
        .map(|count| count == event_count)
        .unwrap_or(true);

    if let Some(stored_head) = stored_chain_head
        && Some(stored_head) != computed_chain_head
    {
        return Err(NonoError::Snapshot(
            "Alpha audit log chain head mismatch".to_string(),
        ));
    }

    if let Some(stored_root) = stored_merkle_root
        && Some(stored_root) != computed_merkle_root
    {
        return Err(NonoError::Snapshot(
            "Alpha audit log Merkle root mismatch".to_string(),
        ));
    }

    Ok(AuditVerificationResult {
        hash_algorithm: HASH_ALGORITHM.to_string(),
        merkle_scheme: MERKLE_SCHEME_LABEL.to_string(),
        event_count,
        computed_chain_head,
        computed_merkle_root,
        stored_event_count,
        stored_chain_head,
        stored_merkle_root,
        event_count_matches,
        records_verified: true,
    })
}

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
        assert_eq!(summary.hash_algorithm, HASH_ALGORITHM);
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
    fn recorder_streaming_sink_writes_events_to_ndjson() {
        use nono_proxy::audit::NetworkAuditSink;

        let dir = tempfile::tempdir().unwrap();
        let recorder = Arc::new(Mutex::new(
            AuditRecorder::new(dir.path().to_path_buf()).unwrap(),
        ));
        recorder
            .lock()
            .unwrap()
            .record_session_started("2026-04-21T00:00:00Z".to_string(), vec!["pwd".to_string()])
            .unwrap();

        let sink = RecorderStreamingSink::new(Arc::clone(&recorder)).unwrap();
        sink.record(&NetworkAuditEvent {
            timestamp_unix_ms: 1000,
            mode: NetworkAuditMode::Connect,
            decision: NetworkAuditDecision::Allow,
            route_id: None,
            auth_mechanism: None,
            auth_outcome: None,
            managed_credential_active: None,
            injection_mode: None,
            denial_category: None,
            target: "api.example.com".to_string(),
            port: Some(443),
            method: Some("CONNECT".to_string()),
            path: None,
            status: None,
            reason: None,
        });
        sink.record(&NetworkAuditEvent {
            timestamp_unix_ms: 2000,
            mode: NetworkAuditMode::Connect,
            decision: NetworkAuditDecision::Deny,
            route_id: None,
            auth_mechanism: None,
            auth_outcome: None,
            managed_credential_active: None,
            injection_mode: None,
            denial_category: None,
            target: "evil.example".to_string(),
            port: Some(443),
            method: None,
            path: None,
            status: None,
            reason: Some("blocked".to_string()),
        });
        // Drain the writer queue before appending session_ended directly.
        // In production this happens via AuditLog::close -> sink.flush().
        sink.flush();

        recorder
            .lock()
            .unwrap()
            .record_session_ended("2026-04-21T00:00:02Z".to_string(), 0)
            .unwrap();

        let summary = recorder.lock().unwrap().finalize().unwrap();
        assert_eq!(
            summary.event_count, 4,
            "session_started + 2 network + session_ended"
        );
        let verified = verify_audit_log(dir.path(), Some(&summary)).unwrap();
        assert_eq!(verified.event_count, 4);
        assert!(verified.records_verified);
    }

    #[test]
    fn recorder_streaming_sink_preserves_order_under_concurrent_writers() {
        use nono_proxy::audit::NetworkAuditSink;

        let dir = tempfile::tempdir().unwrap();
        let recorder = Arc::new(Mutex::new(
            AuditRecorder::new(dir.path().to_path_buf()).unwrap(),
        ));
        recorder
            .lock()
            .unwrap()
            .record_session_started("2026-04-21T00:00:00Z".to_string(), vec!["pwd".to_string()])
            .unwrap();

        let sink = Arc::new(RecorderStreamingSink::new(Arc::clone(&recorder)).unwrap());

        // Simulate the proxy hot path: many concurrent senders, none of
        // which should block waiting on the recorder mutex. With sync I/O
        // inside record() this would serialize through one lock + one
        // file.flush() per event.
        let threads: usize = 8;
        let per_thread: usize = 100;
        let handles: Vec<_> = (0..threads)
            .map(|t| {
                let sink = Arc::clone(&sink);
                std::thread::spawn(move || {
                    for i in 0..per_thread {
                        sink.record(&NetworkAuditEvent {
                            timestamp_unix_ms: (t * per_thread + i) as u64,
                            mode: NetworkAuditMode::Connect,
                            decision: NetworkAuditDecision::Allow,
                            route_id: None,
                            auth_mechanism: None,
                            auth_outcome: None,
                            managed_credential_active: None,
                            injection_mode: None,
                            denial_category: None,
                            target: format!("t{t}.example"),
                            port: Some(443),
                            method: Some("CONNECT".to_string()),
                            path: None,
                            status: None,
                            reason: None,
                        });
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        sink.flush();

        recorder
            .lock()
            .unwrap()
            .record_session_ended("2026-04-21T00:00:02Z".to_string(), 0)
            .unwrap();

        let summary = recorder.lock().unwrap().finalize().unwrap();
        let expected = 1 + threads * per_thread + 1;
        assert_eq!(summary.event_count as usize, expected);
        // The recorder builds its hash chain by appending in the order it
        // receives events. verify_audit_log re-derives that chain from the
        // file and refuses to validate if any link is broken — so a passing
        // verification proves the writer thread preserved FIFO order.
        let verified = verify_audit_log(dir.path(), Some(&summary)).unwrap();
        assert_eq!(verified.event_count as usize, expected);
        assert!(verified.records_verified);
    }

    fn make_audit_event(target: &str, ts: u64) -> NetworkAuditEvent {
        NetworkAuditEvent {
            timestamp_unix_ms: ts,
            mode: NetworkAuditMode::Connect,
            decision: NetworkAuditDecision::Allow,
            route_id: None,
            auth_mechanism: None,
            auth_outcome: None,
            managed_credential_active: None,
            injection_mode: None,
            denial_category: None,
            target: target.to_string(),
            port: Some(443),
            method: Some("CONNECT".to_string()),
            path: None,
            status: None,
            reason: None,
        }
    }

    #[test]
    fn recorder_streaming_sink_drops_events_when_queue_full() {
        use nono_proxy::audit::NetworkAuditSink;

        let dir = tempfile::tempdir().unwrap();
        let recorder = Arc::new(Mutex::new(
            AuditRecorder::new(dir.path().to_path_buf()).unwrap(),
        ));
        recorder
            .lock()
            .unwrap()
            .record_session_started("2026-04-21T00:00:00Z".to_string(), vec!["pwd".to_string()])
            .unwrap();

        // Block the writer thread by holding the recorder mutex. The
        // writer will dequeue at most one event before parking on the
        // recorder lock; everything else queues up to `capacity`, then
        // try_send starts returning Full and the sink increments
        // `dropped`.
        let blocker = recorder.lock().unwrap();
        let capacity: usize = 4;
        let sink =
            RecorderStreamingSink::new_with_capacity(Arc::clone(&recorder), capacity).unwrap();

        let burst: usize = 200;
        for i in 0..burst {
            sink.record(&make_audit_event("api.example.com", i as u64));
        }

        // The sink may not have observed every Full *yet* — the writer
        // is still parked. Just assert that the writer's drop accounting
        // saw at least some drops.
        let dropped_during_burst = sink.dropped_events();
        assert!(
            dropped_during_burst > 0,
            "expected the bounded queue to drop events when writer is parked, got 0"
        );

        // Releasing the blocker lets the writer drain whatever made it
        // into the queue.
        drop(blocker);
        sink.flush();

        recorder
            .lock()
            .unwrap()
            .record_session_ended("2026-04-21T00:00:02Z".to_string(), 0)
            .unwrap();

        let summary = recorder.lock().unwrap().finalize().unwrap();
        // session_started + at most (capacity + 1 in-flight on the
        // writer) network events + session_ended.
        let max_recorded = 1 + capacity + 1 + 1;
        assert!(
            (summary.event_count as usize) <= max_recorded,
            "wrote {} events; expected at most {} given queue cap {}",
            summary.event_count,
            max_recorded,
            capacity
        );
        let verified = verify_audit_log(dir.path(), Some(&summary)).unwrap();
        assert!(verified.records_verified);
        // dropped_events + recorded_network_events should match the burst.
        let recorded_network = (summary.event_count as usize).saturating_sub(2);
        assert_eq!(
            sink.dropped_events() as usize + recorded_network,
            burst,
            "every event must be either recorded or counted as dropped"
        );
    }

    #[test]
    fn recorder_streaming_sink_drops_post_flush_events() {
        use nono_proxy::audit::NetworkAuditSink;

        let dir = tempfile::tempdir().unwrap();
        let recorder = Arc::new(Mutex::new(
            AuditRecorder::new(dir.path().to_path_buf()).unwrap(),
        ));
        recorder
            .lock()
            .unwrap()
            .record_session_started("2026-04-21T00:00:00Z".to_string(), vec!["pwd".to_string()])
            .unwrap();

        let sink = RecorderStreamingSink::new(Arc::clone(&recorder)).unwrap();
        sink.record(&make_audit_event("before.example", 1));
        sink.flush();
        let count_after_flush = recorder.lock().unwrap().event_count();

        // After flush() returns the sink is sealed: events submitted now
        // must be silently dropped, otherwise they would land in the file
        // after the Merkle root that finalize_supervised_exit is about to
        // commit, breaking verify_audit_log.
        for i in 0..20 {
            sink.record(&make_audit_event("after.example", 100 + i));
        }

        // Give the writer enough wall-clock time to *try* appending the
        // post-flush events if the seal were missing.
        std::thread::sleep(std::time::Duration::from_millis(50));

        let count_now = recorder.lock().unwrap().event_count();
        assert_eq!(
            count_now, count_after_flush,
            "post-flush events must not extend the audit log"
        );

        // Append session_ended directly — this is the production pattern
        // that the seal protects.
        recorder
            .lock()
            .unwrap()
            .record_session_ended("2026-04-21T00:00:02Z".to_string(), 0)
            .unwrap();
        let summary = recorder.lock().unwrap().finalize().unwrap();
        // session_started + 1 network + session_ended = 3.
        assert_eq!(summary.event_count, 3);
        let verified = verify_audit_log(dir.path(), Some(&summary)).unwrap();
        assert!(verified.records_verified);
    }

    #[test]
    fn recorder_streaming_sink_flush_is_idempotent() {
        use nono_proxy::audit::NetworkAuditSink;

        let dir = tempfile::tempdir().unwrap();
        let recorder = Arc::new(Mutex::new(
            AuditRecorder::new(dir.path().to_path_buf()).unwrap(),
        ));
        recorder
            .lock()
            .unwrap()
            .record_session_started("2026-04-21T00:00:00Z".to_string(), vec!["pwd".to_string()])
            .unwrap();

        let sink = RecorderStreamingSink::new(Arc::clone(&recorder)).unwrap();
        sink.record(&make_audit_event("api.example.com", 1));
        sink.flush();
        let after_first = recorder.lock().unwrap().event_count();

        // Second flush on an already-sealed sink must not panic, deadlock,
        // or otherwise affect the recorder. The writer keeps acking
        // Flush commands; the seal is sticky.
        sink.flush();
        sink.flush();
        let after_extra = recorder.lock().unwrap().event_count();
        assert_eq!(
            after_first, after_extra,
            "extra flushes must not change the recorder state"
        );

        // Late events stay dropped, as before.
        sink.record(&make_audit_event("late.example", 999));
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert_eq!(after_extra, recorder.lock().unwrap().event_count());
    }

    #[test]
    fn recorder_streaming_sink_drop_joins_writer_cleanly() {
        use nono_proxy::audit::NetworkAuditSink;

        let dir = tempfile::tempdir().unwrap();
        let recorder = Arc::new(Mutex::new(
            AuditRecorder::new(dir.path().to_path_buf()).unwrap(),
        ));
        recorder
            .lock()
            .unwrap()
            .record_session_started("2026-04-21T00:00:00Z".to_string(), vec!["pwd".to_string()])
            .unwrap();

        {
            let sink = RecorderStreamingSink::new(Arc::clone(&recorder)).unwrap();
            for i in 0..5 {
                sink.record(&make_audit_event("api.example.com", i));
            }
            sink.flush();
            // sink dropped here: writer thread receives Shutdown and
            // joins synchronously inside Drop. After this block the
            // recorder is sole-owned by `recorder`.
        }

        // If the writer were still alive, this Arc count would be 2.
        assert_eq!(
            Arc::strong_count(&recorder),
            1,
            "writer thread must release its Arc clone on shutdown"
        );

        // Recorder is fully usable post-shutdown — no leftover state.
        recorder
            .lock()
            .unwrap()
            .record_session_ended("2026-04-21T00:00:02Z".to_string(), 0)
            .unwrap();
        let summary = recorder.lock().unwrap().finalize().unwrap();
        assert_eq!(summary.event_count, 1 + 5 + 1);
        let verified = verify_audit_log(dir.path(), Some(&summary)).unwrap();
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
