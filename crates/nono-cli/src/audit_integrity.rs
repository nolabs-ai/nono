use nono::supervisor::{AuditEntry, UrlOpenRequest};
use nono::undo::{AuditIntegritySummary, ContentHash, NetworkAuditEvent};
use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

const AUDIT_EVENTS_FILENAME: &str = "audit-events.ndjson";
// Plan 22-05a Task 5 (upstream 7b7815f7): unified Alpha integrity schema.
// All audit-integrity hashing now flows through a single "alpha" domain
// separator across event leaf, hash-chain, and Merkle root computation.
// This is the schema downstream cherry-picks (`0b1822a9` audit verify,
// `6ecade2e` attestation) verify against, and the schema Plan 22-05b's
// fork-only Windows signature-trust addition extends as a SIBLING field
// on the audit envelope (per RESEARCH Contradiction #2 — no mutation of
// upstream's `ExecutableIdentity`).
const EVENT_DOMAIN: &[u8] = b"nono.audit.event.alpha\n";
const CHAIN_DOMAIN: &[u8] = b"nono.audit.chain.alpha\n";
const MERKLE_NODE_DOMAIN_ALPHA: &[u8] = b"nono.audit.merkle.alpha\n";
const HASH_ALGORITHM: &str = "sha256";
/// Schema label persisted in `AuditIntegritySummary.hash_algorithm` /
/// downstream verification fixtures. "alpha" is the post-22-05a label.
#[allow(dead_code)] // consumed by audit verify in Task 6
pub(crate) const MERKLE_SCHEME_LABEL: &str = "alpha";

/// Windows-AIPC reject-stage discriminator (Phase 23 D-02).
///
/// Encodes whether a Denied capability decision was rejected BEFORE the
/// approval backend was consulted (`BeforePrompt` — Event/Mutex/JobObject
/// pre-broker mask gate at supervisor.rs:1891) or AFTER approval was
/// granted but the per-kind broker helper failed (`AfterPrompt` — Pipe
/// direction, Socket privileged-port + role allowlist; surfaced via the
/// G-04 broker-failure flip at supervisor.rs:1997).
///
/// `None` (the absent-field case in NDJSON) covers: Approved decisions,
/// the three pre-stage early rejections (duplicate replay, invalid token,
/// unknown HandleKind), and all non-Windows entries.
///
/// Currently observable for exactly two HandleKinds: Pipe and Socket.
/// Future kinds may extend this; until then the matrix is locked by the
/// WR-01 verdict matrix in `exec_strategy_windows/supervisor.rs`'s
/// `capability_handler_tests` module docstring (lines 2034-2076).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum RejectStage {
    BeforePrompt,
    AfterPrompt,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(dead_code)] // CapabilityDecision/UrlOpen/Network variants and their constructors land in
                    // follow-up cherry-picks 4ec61c29..9db06336 per Plan 22-05a Decision 5.
enum AuditEventPayload {
    SessionStarted {
        started: String,
        command: Vec<String>,
    },
    SessionEnded {
        ended: String,
        exit_code: i32,
    },
    CapabilityDecision {
        entry: AuditEntry,
        /// Windows-AIPC-specific reject-stage marker (Phase 23 D-02).
        /// `None` for Approved decisions, for non-Windows ledger entries,
        /// and for the three pre-stage rejections (duplicate replay, invalid
        /// token, unknown HandleKind). `Some(BeforePrompt)` when the mask gate
        /// at supervisor.rs:1891 denies before the approval backend is
        /// consulted (Event/Mutex/JobObject). `Some(AfterPrompt)` when the
        /// G-04 broker-failure flip at supervisor.rs:1997 denies after
        /// approval (Pipe direction allowlist + Socket privileged port /
        /// role allowlist).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reject_stage: Option<RejectStage>,
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
struct AuditEventRecord {
    sequence: u64,
    prev_chain: Option<ContentHash>,
    leaf_hash: ContentHash,
    chain_hash: ContentHash,
    event: AuditEventPayload,
}

/// Result returned by [`verify_audit_log`] (Plan 22-05a Task 6, upstream
/// `0b1822a9`). Reports whether the recomputed chain head and Merkle root
/// match the values stored in `SessionMetadata.audit_integrity`.
///
/// Verification is fail-closed: any per-record mismatch (sequence,
/// prev_chain, leaf_hash, or chain_hash) returns
/// `Ok(AuditVerificationResult { records_verified: false, .. })`. Callers
/// MUST treat that as a hard verification failure (`nono audit verify`
/// exits non-zero).
#[derive(Clone, Serialize)]
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
    pub(crate) chain_head_matches: bool,
    pub(crate) merkle_root_matches: bool,
    pub(crate) records_verified: bool,
}

impl AuditVerificationResult {
    /// Returns `true` only when every commitment in the stored summary
    /// (event count, chain head, Merkle root) matches the recomputed
    /// values AND every per-record hash check passed.
    pub(crate) fn is_valid(&self) -> bool {
        self.event_count_matches
            && self.chain_head_matches
            && self.merkle_root_matches
            && self.records_verified
    }
}

pub(crate) struct AuditRecorder {
    file: File,
    next_sequence: u64,
    previous_chain: Option<ContentHash>,
    leaf_hashes: Vec<ContentHash>,
}

impl AuditRecorder {
    pub(crate) fn new(session_dir: PathBuf) -> Result<Self> {
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
        })
    }

    pub(crate) fn record_session_started(
        &mut self,
        started: String,
        command: Vec<String>,
    ) -> Result<()> {
        self.append_event(AuditEventPayload::SessionStarted { started, command })
    }

    pub(crate) fn record_session_ended(&mut self, ended: String, exit_code: i32) -> Result<()> {
        self.append_event(AuditEventPayload::SessionEnded { ended, exit_code })
    }

    // Plan 22-05a Decision 5 minimal scope: capability-decision, URL-open,
    // and network event constructors are wired into supervisor callsites by
    // follow-up cherry-picks (4ec61c29..9db06336). They live here now so the
    // `AuditRecorder` API is upstream-compatible.
    #[allow(dead_code)]
    pub(crate) fn record_capability_decision(&mut self, entry: AuditEntry) -> Result<()> {
        // Phase 23 Task 1: the new `reject_stage` field defaults to `None`
        // until Task 2 promotes this API to take it as an explicit second
        // argument. Until then, the dispatcher does not call this function
        // (#[allow(dead_code)] above), so the `None` default is structurally
        // unreachable on the wire — included here only to satisfy the struct
        // initializer. Task 2 deletes this single-arg shape entirely.
        self.append_event(AuditEventPayload::CapabilityDecision {
            entry,
            reject_stage: None,
        })
    }

    #[allow(dead_code)]
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

    #[allow(dead_code)]
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
    // Alpha integrity schema (upstream 7b7815f7): every Merkle node is
    // domain-separated with `MERKLE_NODE_DOMAIN_ALPHA` so verifiers can
    // tell apart Alpha-schema digests from any future scheme version.
    // Empty leaf set hashes the empty string under the same domain prefix.
    if leaves.is_empty() {
        let mut hasher = Sha256::new();
        hasher.update(MERKLE_NODE_DOMAIN_ALPHA);
        return ContentHash::from_bytes(hasher.finalize().into());
    }

    let mut level: Vec<[u8; 32]> = leaves.iter().map(|leaf| *leaf.as_bytes()).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(left);
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

/// Re-read `<session_dir>/audit-events.ndjson`, recompute the per-event
/// leaf hash + chain hash, and return an [`AuditVerificationResult`]
/// reflecting whether the recomputed values match the supplied
/// `stored_summary`.
///
/// Plan 22-05a Task 6 (upstream `0b1822a9`): minimal-port replay. AUD-02
/// acceptance criterion #2 ("nono audit verify <id> succeeds for an
/// untampered session and rejects tampered ledgers fail-closed").
///
/// `stored_summary` may be `None` for sessions recorded before the
/// integrity flag was set; in that case `event_count_matches` /
/// `chain_head_matches` / `merkle_root_matches` are all `false` (callers
/// surface that as "no integrity summary recorded").
pub(crate) fn verify_audit_log(
    session_dir: &Path,
    stored_summary: Option<&AuditIntegritySummary>,
) -> Result<AuditVerificationResult> {
    let events_path = session_dir.join(AUDIT_EVENTS_FILENAME);
    let file = File::open(&events_path).map_err(|e| {
        NonoError::Snapshot(format!(
            "Failed to open audit event log {}: {e}",
            events_path.display()
        ))
    })?;
    let reader = BufReader::new(file);

    let mut next_sequence: u64 = 0;
    let mut previous_chain: Option<ContentHash> = None;
    let mut leaf_hashes: Vec<ContentHash> = Vec::new();
    let mut records_verified = true;

    for (line_idx, line_result) in reader.lines().enumerate() {
        let line = line_result.map_err(|e| {
            NonoError::Snapshot(format!(
                "Failed to read line {} from {}: {e}",
                line_idx + 1,
                events_path.display()
            ))
        })?;
        if line.trim().is_empty() {
            continue;
        }
        let record: AuditEventRecord = serde_json::from_str(&line).map_err(|e| {
            NonoError::Snapshot(format!(
                "Failed to parse audit record at line {}: {e}",
                line_idx + 1
            ))
        })?;

        if record.sequence != next_sequence {
            records_verified = false;
        }
        if record.prev_chain != previous_chain {
            records_verified = false;
        }

        let event_bytes = serde_json::to_vec(&record.event)
            .map_err(|e| NonoError::Snapshot(format!("Failed to re-serialize audit event: {e}")))?;
        let recomputed_leaf = hash_event(&event_bytes);
        if recomputed_leaf != record.leaf_hash {
            records_verified = false;
        }

        let recomputed_chain = hash_chain(previous_chain.as_ref(), &record.leaf_hash);
        if recomputed_chain != record.chain_hash {
            records_verified = false;
        }

        previous_chain = Some(record.chain_hash);
        leaf_hashes.push(record.leaf_hash);
        next_sequence = next_sequence.saturating_add(1);
    }

    let event_count = leaf_hashes.len() as u64;
    let computed_merkle_root = if leaf_hashes.is_empty() {
        None
    } else {
        Some(merkle_root(&leaf_hashes))
    };
    let computed_chain_head = previous_chain;

    let (stored_event_count, stored_chain_head, stored_merkle_root) = match stored_summary {
        Some(s) => (Some(s.event_count), Some(s.chain_head), Some(s.merkle_root)),
        None => (None, None, None),
    };

    let event_count_matches = stored_event_count == Some(event_count);
    let chain_head_matches = stored_chain_head == computed_chain_head;
    let merkle_root_matches = stored_merkle_root == computed_merkle_root;

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
        chain_head_matches,
        merkle_root_matches,
        records_verified,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

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
    fn verify_audit_log_accepts_untampered_session() {
        let dir = tempfile::tempdir().unwrap();
        let mut recorder = AuditRecorder::new(dir.path().to_path_buf()).unwrap();
        recorder
            .record_session_started("2026-04-21T00:00:00Z".to_string(), vec!["pwd".to_string()])
            .unwrap();
        recorder
            .record_session_ended("2026-04-21T00:00:01Z".to_string(), 0)
            .unwrap();
        let summary = recorder.finalize().unwrap();

        let result = verify_audit_log(dir.path(), Some(&summary)).unwrap();
        assert!(result.is_valid(), "untampered session must verify");
        assert_eq!(result.event_count, 2);
        assert!(result.event_count_matches);
        assert!(result.chain_head_matches);
        assert!(result.merkle_root_matches);
        assert!(result.records_verified);
        assert_eq!(result.merkle_scheme, "alpha");
    }

    /// Phase 23 Task 1 Test 1: serialization tag rendering for `Some(BeforePrompt)`
    /// and `Some(AfterPrompt)`. Asserts the field is emitted with the kebab-case
    /// `"before-prompt"` / `"after-prompt"` discriminants (per D-02 +
    /// `#[serde(rename_all = "kebab-case")]` on the enum).
    #[test]
    fn reject_stage_serializes_kebab_case_when_present() {
        let entry = synthetic_entry();
        let before = AuditEventPayload::CapabilityDecision {
            entry: entry.clone(),
            reject_stage: Some(RejectStage::BeforePrompt),
        };
        let json_before = serde_json::to_string(&before).unwrap();
        assert!(
            json_before.contains("\"reject_stage\":\"before-prompt\""),
            "BeforePrompt must serialize to kebab-case, got: {json_before}",
        );

        let after = AuditEventPayload::CapabilityDecision {
            entry,
            reject_stage: Some(RejectStage::AfterPrompt),
        };
        let json_after = serde_json::to_string(&after).unwrap();
        assert!(
            json_after.contains("\"reject_stage\":\"after-prompt\""),
            "AfterPrompt must serialize to kebab-case, got: {json_after}",
        );
    }

    /// Phase 23 Task 1 Test 2: when `reject_stage` is `None`, the field MUST be
    /// omitted from the wire — old NDJSON files written by Phase 22 (which lack
    /// the field entirely) stay byte-identical for the None path.
    #[test]
    fn reject_stage_omitted_when_none() {
        let payload = AuditEventPayload::CapabilityDecision {
            entry: synthetic_entry(),
            reject_stage: None,
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(
            !json.contains("reject_stage"),
            "reject_stage MUST be omitted when None (skip_serializing_if invariant); \
             got: {json}",
        );
    }

    /// Phase 23 Task 1 Test 3: round-trip every variant via serde to lock both
    /// `Serialize` and `Deserialize` derives + the kebab-case rename rule.
    #[test]
    fn reject_stage_round_trips_via_serde() {
        for stage in [
            None,
            Some(RejectStage::BeforePrompt),
            Some(RejectStage::AfterPrompt),
        ] {
            let payload = AuditEventPayload::CapabilityDecision {
                entry: synthetic_entry(),
                reject_stage: stage,
            };
            let json = serde_json::to_string(&payload).unwrap();
            let round_trip: AuditEventPayload = serde_json::from_str(&json).unwrap();
            match round_trip {
                AuditEventPayload::CapabilityDecision { reject_stage, .. } => {
                    assert_eq!(
                        reject_stage, stage,
                        "round-trip must preserve reject_stage; original={stage:?}, got={reject_stage:?}",
                    );
                }
                other => panic!(
                    "expected CapabilityDecision, got: {}",
                    std::any::type_name_of_val(&other),
                ),
            }
        }
    }

    /// Phase 23 Task 1 Test 4: a Phase-22-shaped NDJSON record (no
    /// `reject_stage` field) must deserialize cleanly with `reject_stage = None`.
    /// Locks the `#[serde(default)]` backward-compat invariant.
    #[test]
    fn reject_stage_deserializes_old_records_as_none() {
        // Construct a JSON literal mimicking a Phase-22 CapabilityDecision NDJSON
        // line WITHOUT the reject_stage field. The entry payload uses the
        // existing AuditEntry serde shape (timestamp + request + decision +
        // backend + duration_ms).
        let entry = synthetic_entry();
        let entry_json = serde_json::to_string(&entry).unwrap();
        let phase_22_shape = format!(r#"{{"type":"capability_decision","entry":{entry_json}}}"#);

        let parsed: AuditEventPayload = serde_json::from_str(&phase_22_shape)
            .expect("Phase-22-shape CapabilityDecision must deserialize cleanly");
        match parsed {
            AuditEventPayload::CapabilityDecision { reject_stage, .. } => {
                assert_eq!(
                    reject_stage, None,
                    "old NDJSON records (without reject_stage) MUST deserialize as None; got {reject_stage:?}",
                );
            }
            other => panic!(
                "expected CapabilityDecision variant, got: {}",
                std::any::type_name_of_val(&other),
            ),
        }
    }

    /// Phase 23 Task 1 helper: build a deterministic synthetic AuditEntry for
    /// the new serde tests. Uses UNIX_EPOCH for the timestamp so the JSON
    /// surface is stable across hosts; the assertions in the new tests do NOT
    /// inspect the entry sub-fields, only the parent variant + `reject_stage`.
    #[allow(deprecated)]
    fn synthetic_entry() -> AuditEntry {
        AuditEntry {
            timestamp: std::time::SystemTime::UNIX_EPOCH,
            request: nono::CapabilityRequest {
                request_id: "synthetic-test".to_string(),
                path: std::path::PathBuf::from("/tmp/synthetic"),
                access: nono::AccessMode::Read,
                reason: Some("phase 23 task 1 unit test".to_string()),
                child_pid: 0,
                session_id: "sess-synthetic".to_string(),
                session_token: String::new(),
                kind: nono::supervisor::HandleKind::File,
                target: None,
                access_mask: 0,
            },
            decision: nono::ApprovalDecision::Denied {
                reason: "test".to_string(),
            },
            backend: "test-backend".to_string(),
            duration_ms: 0,
        }
    }

    #[test]
    fn verify_audit_log_rejects_tampered_event_log_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let mut recorder = AuditRecorder::new(dir.path().to_path_buf()).unwrap();
        recorder
            .record_session_started("2026-04-21T00:00:00Z".to_string(), vec!["pwd".to_string()])
            .unwrap();
        recorder
            .record_session_ended("2026-04-21T00:00:01Z".to_string(), 0)
            .unwrap();
        let summary = recorder.finalize().unwrap();

        // Tamper with the event log: rewrite one event's exit_code without
        // updating the cryptographic commitments. The verifier MUST detect.
        let events_path = dir.path().join(AUDIT_EVENTS_FILENAME);
        let original = std::fs::read_to_string(&events_path).unwrap();
        let tampered = original.replace("\"exit_code\":0", "\"exit_code\":1");
        assert_ne!(original, tampered, "test setup: replace must mutate bytes");
        std::fs::write(&events_path, tampered).unwrap();

        let result = verify_audit_log(dir.path(), Some(&summary)).unwrap();
        assert!(
            !result.is_valid(),
            "tampered session must fail-close (records_verified=false or chain_head_matches=false)"
        );
        assert!(!result.records_verified || !result.chain_head_matches);
    }
}
