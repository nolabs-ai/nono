//! Append-only audit log primitives.
//!
//! The alpha scheme records each event as an NDJSON envelope containing a
//! monotonic sequence number, a rolling chain hash, and a Merkle leaf hash.
//! A final [`AuditIntegritySummary`] commits to the event count, chain head,
//! and Merkle root.

use crate::supervisor::{AuditEntry, UrlOpenRequest};
use crate::undo::{
    AuditAttestationSummary, AuditIntegritySummary, ContentHash, NetworkAuditEvent, SessionMetadata,
};
use crate::{NonoError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// Filename used for per-session audit event logs.
pub const AUDIT_EVENTS_FILENAME: &str = "audit-events.ndjson";

/// Domain separator for alpha event leaf hashes.
pub const EVENT_DOMAIN_ALPHA: &[u8] = b"nono.audit.event.alpha\n";
/// Domain separator for alpha rolling chain hashes.
pub const CHAIN_DOMAIN_ALPHA: &[u8] = b"nono.audit.chain.alpha\n";
/// Domain separator for alpha Merkle internal-node hashes.
pub const MERKLE_NODE_DOMAIN_ALPHA: &[u8] = b"nono.audit.merkle.alpha\n";
/// Merkle scheme label emitted by alpha verification.
pub const MERKLE_SCHEME_ALPHA: &str = "alpha";
/// Hash algorithm label emitted by alpha verification.
pub const AUDIT_HASH_ALGORITHM: &str = "sha256";
/// Domain separator for alpha session digests.
pub const SESSION_DIGEST_DOMAIN_ALPHA: &[u8] = b"nono.audit.session-digest.alpha\n";
/// Domain separator for alpha ledger chain links.
pub const LEDGER_CHAIN_DOMAIN_ALPHA: &[u8] = b"nono.audit.ledger.chain.alpha\n";

/// Event payloads written into the alpha audit log.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditEventPayload {
    /// Session start event.
    SessionStarted {
        /// ISO-8601 start timestamp.
        started: String,
        /// Redacted command line.
        command: Vec<String>,
        /// Redaction policy delta from the secure default, when configured.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        redaction_policy: Option<crate::ScrubPolicyDiff>,
    },
    /// Session end event.
    SessionEnded {
        /// ISO-8601 end timestamp.
        ended: String,
        /// Child process exit code.
        exit_code: i32,
    },
    /// Capability approval decision.
    CapabilityDecision {
        /// Supervisor audit entry.
        entry: AuditEntry,
    },
    /// URL-open request result.
    UrlOpen {
        /// URL-open request.
        request: UrlOpenRequest,
        /// Whether the request succeeded.
        success: bool,
        /// Error message, when the request failed.
        error: Option<String>,
    },
    /// Network audit event.
    Network {
        /// Network audit event emitted by the proxy or sandbox supervisor.
        event: NetworkAuditEvent,
    },
}

/// One line of `audit-events.ndjson`.
#[derive(Clone, Serialize, Deserialize)]
pub struct AuditEventRecord {
    /// Monotonic sequence number, starting at 0.
    pub sequence: u64,
    /// Previous record's chain hash, or `None` for the first record.
    pub prev_chain: Option<ContentHash>,
    /// Hash of the canonical event JSON bytes.
    pub leaf_hash: ContentHash,
    /// Rolling chain hash over the previous chain hash and this leaf.
    pub chain_hash: ContentHash,
    /// Canonical event JSON bytes used to derive `leaf_hash`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_json: Option<String>,
    /// Parsed event payload.
    pub event: AuditEventPayload,
}

/// Result of verifying an alpha audit log.
#[derive(Serialize)]
pub struct AuditVerificationResult {
    /// Hash algorithm used for event leaves and chain/root derivation.
    pub hash_algorithm: String,
    /// Merkle scheme label.
    pub merkle_scheme: String,
    /// Number of verified events.
    pub event_count: u64,
    /// Recomputed rolling chain head.
    pub computed_chain_head: Option<ContentHash>,
    /// Recomputed Merkle root over ordered event leaves.
    pub computed_merkle_root: Option<ContentHash>,
    /// Stored event count from session metadata, when supplied.
    pub stored_event_count: Option<u64>,
    /// Stored chain head from session metadata, when supplied.
    pub stored_chain_head: Option<ContentHash>,
    /// Stored Merkle root from session metadata, when supplied.
    pub stored_merkle_root: Option<ContentHash>,
    /// Whether the stored event count matches the recomputed count.
    pub event_count_matches: bool,
    /// True when all record-level checks passed.
    pub records_verified: bool,
}

#[derive(Serialize)]
struct SessionDigestPayload<'a> {
    session_id: &'a str,
    started: &'a str,
    ended: &'a Option<String>,
    command: &'a [String],
    executable_identity: Option<ExecutableIdentityDigestPayload>,
    tracked_paths: Vec<Vec<u8>>,
    snapshot_count: u32,
    exit_code: &'a Option<i32>,
    merkle_roots: &'a [ContentHash],
    network_events: &'a [NetworkAuditEvent],
    audit_event_count: u64,
    audit_integrity: &'a Option<AuditIntegritySummary>,
    audit_attestation: &'a Option<AuditAttestationSummary>,
}

#[derive(Serialize)]
struct ExecutableIdentityDigestPayload {
    resolved_path: Vec<u8>,
    sha256: ContentHash,
}

/// One line of the append-only session ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerRecord {
    /// Monotonic ledger sequence number.
    pub sequence: u64,
    /// Previous ledger record's chain hash, or `None` for the first record.
    pub prev_chain: Option<ContentHash>,
    /// Session ID committed by this ledger entry.
    pub session_id: String,
    /// Digest over protected session metadata fields.
    pub session_digest: ContentHash,
    /// Session completion timestamp used in the ledger link payload.
    pub completed_at: String,
    /// Rolling ledger chain hash.
    pub chain_hash: ContentHash,
}

#[derive(Serialize)]
struct LedgerLinkPayload<'a> {
    sequence: u64,
    session_id: &'a str,
    session_digest: ContentHash,
    completed_at: &'a str,
}

/// Result of checking a session against an append-only ledger.
#[derive(Debug, Clone, Serialize)]
pub struct LedgerVerificationResult {
    /// Hash algorithm used by the ledger.
    pub hash_algorithm: String,
    /// Number of verified ledger entries.
    pub entry_count: u64,
    /// Expected digest for the provided session metadata.
    pub session_digest: ContentHash,
    /// Whether the session ID was present in the ledger.
    pub session_found: bool,
    /// Whether the ledger digest matched the current session metadata digest.
    pub session_digest_matches: bool,
    /// Whether every ledger chain link verified.
    pub ledger_chain_verified: bool,
    /// Final ledger chain head.
    pub ledger_head: Option<ContentHash>,
}

/// Position of a sibling hash in an audit Merkle inclusion proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditProofDirection {
    /// The sibling hash is the left input to this Merkle node.
    Left,
    /// The sibling hash is the right input to this Merkle node.
    Right,
}

/// One sibling step in an audit Merkle inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditProofNode {
    /// Which side of the current hash this sibling occupies.
    pub direction: AuditProofDirection,
    /// Sibling hash.
    pub hash: ContentHash,
}

/// Compact proof that one audit leaf is included in an alpha Merkle root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditInclusionProof {
    /// Zero-based leaf index.
    pub leaf_index: u64,
    /// Total number of leaves in the tree.
    pub leaf_count: u64,
    /// Included audit leaf hash.
    pub leaf_hash: ContentHash,
    /// Claimed alpha Merkle root.
    pub merkle_root: ContentHash,
    /// Sibling path from leaf to root.
    pub siblings: Vec<AuditProofNode>,
}

/// Stateful writer for alpha-scheme audit records.
pub struct AuditRecorder {
    file: File,
    next_sequence: u64,
    previous_chain: Option<ContentHash>,
    leaf_hashes: Vec<ContentHash>,
    redaction_policy: crate::ScrubPolicy,
}

impl AuditRecorder {
    /// Create a recorder with the secure default redaction policy.
    pub fn new(session_dir: PathBuf) -> Result<Self> {
        Self::new_with_policy(session_dir, crate::ScrubPolicy::secure_default())
    }

    /// Create a recorder using a caller-supplied redaction policy.
    pub fn new_with_policy(
        session_dir: PathBuf,
        redaction_policy: crate::ScrubPolicy,
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

    /// Record a session start event.
    pub fn record_session_started(&mut self, started: String, command: Vec<String>) -> Result<()> {
        self.append_event(AuditEventPayload::SessionStarted {
            started,
            command: crate::scrub_argv_with_policy(&command, &self.redaction_policy),
            redaction_policy: self
                .redaction_policy
                .diff_from_secure_default()
                .into_option(),
        })
    }

    /// Record a session end event.
    pub fn record_session_ended(&mut self, ended: String, exit_code: i32) -> Result<()> {
        self.append_event(AuditEventPayload::SessionEnded { ended, exit_code })
    }

    /// Record a capability approval decision.
    pub fn record_capability_decision(&mut self, entry: AuditEntry) -> Result<()> {
        self.append_event(AuditEventPayload::CapabilityDecision { entry })
    }

    /// Record a URL-open request result.
    pub fn record_open_url(
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

    /// Record a network event.
    pub fn record_network_event(&mut self, event: NetworkAuditEvent) -> Result<()> {
        self.append_event(AuditEventPayload::Network { event })
    }

    /// Number of events appended by this recorder.
    #[must_use]
    pub fn event_count(&self) -> u64 {
        self.leaf_hashes.len() as u64
    }

    /// Final integrity summary for the current log, if at least one event exists.
    #[must_use]
    pub fn finalize(&self) -> Option<AuditIntegritySummary> {
        let chain_head = self.previous_chain?;
        let merkle_root = merkle_root(&self.leaf_hashes);
        Some(AuditIntegritySummary {
            hash_algorithm: AUDIT_HASH_ALGORITHM.to_string(),
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

/// Hash canonical event JSON bytes into an alpha event leaf.
#[must_use]
pub fn hash_event(event_bytes: &[u8]) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(EVENT_DOMAIN_ALPHA);
    hasher.update(event_bytes);
    ContentHash::from_bytes(hasher.finalize().into())
}

/// Hash one alpha rolling-chain link.
#[must_use]
pub fn hash_chain(previous: Option<&ContentHash>, leaf_hash: &ContentHash) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(CHAIN_DOMAIN_ALPHA);
    if let Some(prev) = previous {
        hasher.update(prev.as_bytes());
    } else {
        hasher.update([0u8; 32]);
    }
    hasher.update(leaf_hash.as_bytes());
    ContentHash::from_bytes(hasher.finalize().into())
}

/// Compute the alpha Merkle root over ordered leaves.
#[must_use]
pub fn merkle_root(leaves: &[ContentHash]) -> ContentHash {
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
            next.push(hash_merkle_node(left, right));
        }
        level = next;
    }
    ContentHash::from_bytes(level[0])
}

/// Build an alpha Merkle inclusion proof for one audit leaf.
pub fn build_inclusion_proof(
    leaves: &[ContentHash],
    leaf_index: usize,
) -> Result<AuditInclusionProof> {
    if leaves.is_empty() {
        return Err(NonoError::Snapshot(
            "Cannot build an audit inclusion proof for an empty log".to_string(),
        ));
    }
    if leaf_index >= leaves.len() {
        return Err(NonoError::Snapshot(format!(
            "Audit inclusion proof leaf index {} is out of range for {} leaves",
            leaf_index,
            leaves.len()
        )));
    }

    let mut siblings = Vec::new();
    let mut index = leaf_index;
    let mut level: Vec<[u8; 32]> = leaves.iter().map(|leaf| *leaf.as_bytes()).collect();
    while level.len() > 1 {
        let sibling_index = if index.is_multiple_of(2) {
            index.saturating_add(1)
        } else {
            index.saturating_sub(1)
        };
        if let Some(sibling) = level.get(sibling_index) {
            siblings.push(AuditProofNode {
                direction: if sibling_index < index {
                    AuditProofDirection::Left
                } else {
                    AuditProofDirection::Right
                },
                hash: ContentHash::from_bytes(*sibling),
            });
        }

        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = pair[0];
            if pair.len() == 1 {
                next.push(left);
                continue;
            }
            next.push(hash_merkle_node(left, pair[1]));
        }
        index /= 2;
        level = next;
    }

    Ok(AuditInclusionProof {
        leaf_index: leaf_index as u64,
        leaf_count: leaves.len() as u64,
        leaf_hash: leaves[leaf_index],
        merkle_root: ContentHash::from_bytes(level[0]),
        siblings,
    })
}

/// Verify an alpha Merkle inclusion proof.
#[must_use]
pub fn verify_inclusion_proof(proof: &AuditInclusionProof) -> bool {
    if proof.leaf_count == 0 || proof.leaf_index >= proof.leaf_count {
        return false;
    }

    let mut computed = *proof.leaf_hash.as_bytes();
    let mut index = proof.leaf_index;
    let mut width = proof.leaf_count;
    let mut siblings = proof.siblings.iter();

    while width > 1 {
        let expected_direction = if index.is_multiple_of(2) {
            if index.saturating_add(1) < width {
                Some(AuditProofDirection::Right)
            } else {
                None
            }
        } else {
            Some(AuditProofDirection::Left)
        };

        if let Some(direction) = expected_direction {
            let Some(node) = siblings.next() else {
                return false;
            };
            if node.direction != direction {
                return false;
            }
            computed = match node.direction {
                AuditProofDirection::Left => hash_merkle_node(*node.hash.as_bytes(), computed),
                AuditProofDirection::Right => hash_merkle_node(computed, *node.hash.as_bytes()),
            };
        }

        index /= 2;
        width = width.div_ceil(2);
    }

    if siblings.next().is_some() {
        return false;
    }

    computed == *proof.merkle_root.as_bytes()
}

fn hash_merkle_node(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(MERKLE_NODE_DOMAIN_ALPHA);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Compute the alpha session digest used by the append-only ledger.
pub fn compute_session_digest(metadata: &SessionMetadata) -> Result<ContentHash> {
    let payload = SessionDigestPayload {
        session_id: &metadata.session_id,
        started: &metadata.started,
        ended: &metadata.ended,
        command: &metadata.command,
        executable_identity: metadata.executable_identity.as_ref().map(|identity| {
            ExecutableIdentityDigestPayload {
                resolved_path: path_bytes(&identity.resolved_path),
                sha256: identity.sha256,
            }
        }),
        tracked_paths: metadata
            .tracked_paths
            .iter()
            .map(|path| path_bytes(path))
            .collect(),
        snapshot_count: metadata.snapshot_count,
        exit_code: &metadata.exit_code,
        merkle_roots: &metadata.merkle_roots,
        network_events: &metadata.network_events,
        audit_event_count: metadata.audit_event_count,
        audit_integrity: &metadata.audit_integrity,
        audit_attestation: &metadata.audit_attestation,
    };
    let bytes = serde_json::to_vec(&payload).map_err(|e| {
        NonoError::Snapshot(format!("Failed to serialize session digest payload: {e}"))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(SESSION_DIGEST_DOMAIN_ALPHA);
    hasher.update(bytes);
    Ok(ContentHash::from_bytes(hasher.finalize().into()))
}

#[cfg(unix)]
fn path_bytes(path: &std::path::Path) -> Vec<u8> {
    path.as_os_str().as_bytes().to_vec()
}

#[cfg(not(unix))]
fn path_bytes(path: &std::path::Path) -> Vec<u8> {
    path.to_string_lossy().into_owned().into_bytes()
}

/// Validate a session ID before committing it to the global audit ledger.
pub fn validate_ledger_session_id(session_id: &str) -> Result<()> {
    let valid = !session_id.is_empty()
        && session_id.len() <= 64
        && session_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'));
    if valid {
        Ok(())
    } else {
        Err(NonoError::ConfigParse(format!(
            "invalid audit session id: {session_id}"
        )))
    }
}

/// Append one session to an already opened and locked ledger file.
///
/// The caller owns storage decisions: where the ledger lives, whether the
/// file is locked, and how the parent directory is created.
pub fn append_session_to_ledger_file(
    file: &mut std::fs::File,
    metadata: &SessionMetadata,
) -> Result<LedgerRecord> {
    validate_ledger_session_id(&metadata.session_id)?;

    file.seek(SeekFrom::Start(0))
        .map_err(|e| NonoError::Snapshot(format!("Failed to seek audit ledger: {e}")))?;

    let mut previous_chain = None;
    let mut next_sequence = 0u64;
    {
        let reader = BufReader::new(&mut *file);
        for (index, line) in reader.lines().enumerate() {
            let line =
                line.map_err(|e| NonoError::Snapshot(format!("Failed to read audit ledger: {e}")))?;
            if line.trim().is_empty() {
                continue;
            }
            let record: LedgerRecord = serde_json::from_str(&line).map_err(|e| {
                NonoError::Snapshot(format!(
                    "Failed to parse audit ledger line {}: {e}",
                    index.saturating_add(1)
                ))
            })?;
            previous_chain = Some(record.chain_hash);
            next_sequence = record.sequence.saturating_add(1);
        }
    }

    let session_digest = compute_session_digest(metadata)?;
    let completed_at = metadata
        .ended
        .clone()
        .unwrap_or_else(|| metadata.started.clone());
    let chain_hash = hash_ledger_link(
        previous_chain.as_ref(),
        next_sequence,
        &metadata.session_id,
        &session_digest,
        &completed_at,
    )?;
    let record = LedgerRecord {
        sequence: next_sequence,
        prev_chain: previous_chain,
        session_id: metadata.session_id.clone(),
        session_digest,
        completed_at,
        chain_hash,
    };

    file.seek(SeekFrom::End(0))
        .map_err(|e| NonoError::Snapshot(format!("Failed to seek audit ledger for append: {e}")))?;
    let line = serde_json::to_vec(&record).map_err(|e| {
        NonoError::Snapshot(format!("Failed to serialize audit ledger record: {e}"))
    })?;
    file.write_all(&line)
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_data())
        .map_err(|e| NonoError::Snapshot(format!("Failed to append audit ledger record: {e}")))?;

    Ok(record)
}

/// Verification result for a missing ledger file.
pub fn missing_ledger_verification_result(
    metadata: &SessionMetadata,
) -> Result<LedgerVerificationResult> {
    Ok(LedgerVerificationResult {
        hash_algorithm: AUDIT_HASH_ALGORITHM.to_string(),
        entry_count: 0,
        session_digest: compute_session_digest(metadata)?,
        session_found: false,
        session_digest_matches: false,
        ledger_chain_verified: false,
        ledger_head: None,
    })
}

/// Verify an opened ledger reader and check whether it contains `metadata`.
pub fn verify_session_in_ledger_reader<R: BufRead>(
    reader: R,
    metadata: &SessionMetadata,
) -> Result<LedgerVerificationResult> {
    let expected_digest = compute_session_digest(metadata)?;

    let mut previous_chain = None;
    let mut entry_count = 0u64;
    let mut ledger_head = None;
    let mut session_found = false;
    let mut session_digest_matches = false;

    for (index, line) in reader.lines().enumerate() {
        let line =
            line.map_err(|e| NonoError::Snapshot(format!("Failed to read audit ledger: {e}")))?;
        if line.trim().is_empty() {
            continue;
        }
        let record: LedgerRecord = serde_json::from_str(&line).map_err(|e| {
            NonoError::Snapshot(format!(
                "Failed to parse audit ledger line {}: {e}",
                index.saturating_add(1)
            ))
        })?;
        if record.sequence != entry_count {
            return Err(NonoError::Snapshot(format!(
                "Audit ledger sequence mismatch at line {}",
                index.saturating_add(1)
            )));
        }
        if record.prev_chain != previous_chain {
            return Err(NonoError::Snapshot(format!(
                "Audit ledger prev_chain mismatch at line {}",
                index.saturating_add(1)
            )));
        }
        let chain_hash = hash_ledger_link(
            previous_chain.as_ref(),
            record.sequence,
            &record.session_id,
            &record.session_digest,
            &record.completed_at,
        )?;
        if chain_hash != record.chain_hash {
            return Err(NonoError::Snapshot(format!(
                "Audit ledger chain hash mismatch at line {}",
                index.saturating_add(1)
            )));
        }

        if record.session_id == metadata.session_id {
            session_found = true;
            session_digest_matches = record.session_digest == expected_digest;
        }

        previous_chain = Some(record.chain_hash);
        ledger_head = Some(record.chain_hash);
        entry_count = entry_count.saturating_add(1);
    }

    Ok(LedgerVerificationResult {
        hash_algorithm: AUDIT_HASH_ALGORITHM.to_string(),
        entry_count,
        session_digest: expected_digest,
        session_found,
        session_digest_matches,
        ledger_chain_verified: true,
        ledger_head,
    })
}

fn hash_ledger_link(
    previous: Option<&ContentHash>,
    sequence: u64,
    session_id: &str,
    session_digest: &ContentHash,
    completed_at: &str,
) -> Result<ContentHash> {
    let payload = LedgerLinkPayload {
        sequence,
        session_id,
        session_digest: *session_digest,
        completed_at,
    };
    let payload_bytes = serde_json::to_vec(&payload).map_err(|e| {
        NonoError::Snapshot(format!(
            "Failed to serialize audit ledger link payload: {e}"
        ))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(LEDGER_CHAIN_DOMAIN_ALPHA);
    if let Some(prev) = previous {
        hasher.update(prev.as_bytes());
    } else {
        hasher.update([0u8; 32]);
    }
    hasher.update(payload_bytes);
    Ok(ContentHash::from_bytes(hasher.finalize().into()))
}

/// Verify an alpha audit log and optionally cross-check stored metadata.
pub fn verify_audit_log(
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
            serde_json::from_str::<AuditEventPayload>(raw).map_err(|e| {
                NonoError::Snapshot(format!(
                    "Failed to parse canonical audit event JSON at line {}: {e}",
                    index.saturating_add(1)
                ))
            })?;
            let canonical_event_bytes = serde_json::to_vec(&record.event).map_err(|e| {
                NonoError::Snapshot(format!(
                    "Failed to serialize audit event payload at line {}: {e}",
                    index.saturating_add(1)
                ))
            })?;
            if raw.as_bytes() != canonical_event_bytes.as_slice() {
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
        hash_algorithm: AUDIT_HASH_ALGORITHM.to_string(),
        merkle_scheme: MERKLE_SCHEME_ALPHA.to_string(),
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
    use crate::AccessMode;
    use crate::supervisor::{ApprovalDecision, CapabilityRequest};
    use crate::undo::{ExecutableIdentity, NetworkAuditDecision, NetworkAuditMode};
    use std::io::BufReader;
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

    #[test]
    fn inclusion_proof_round_trips_each_leaf() {
        let leaves = vec![
            ContentHash::from_bytes([1; 32]),
            ContentHash::from_bytes([2; 32]),
            ContentHash::from_bytes([3; 32]),
            ContentHash::from_bytes([4; 32]),
            ContentHash::from_bytes([5; 32]),
        ];
        let root = merkle_root(&leaves);

        for index in 0..leaves.len() {
            let proof = build_inclusion_proof(&leaves, index).unwrap();
            assert_eq!(proof.merkle_root, root);
            assert_eq!(proof.leaf_hash, leaves[index]);
            assert!(verify_inclusion_proof(&proof));
        }
    }

    #[test]
    fn inclusion_proof_rejects_tampered_leaf() {
        let leaves = vec![
            ContentHash::from_bytes([1; 32]),
            ContentHash::from_bytes([2; 32]),
            ContentHash::from_bytes([3; 32]),
        ];
        let mut proof = build_inclusion_proof(&leaves, 1).unwrap();
        proof.leaf_hash = ContentHash::from_bytes([9; 32]);

        assert!(!verify_inclusion_proof(&proof));
    }

    fn sample_metadata(id: &str) -> SessionMetadata {
        SessionMetadata {
            session_id: id.to_string(),
            started: "2026-04-21T20:00:00Z".to_string(),
            ended: Some("2026-04-21T20:00:01Z".to_string()),
            command: vec!["/bin/pwd".to_string()],
            executable_identity: None,
            tracked_paths: vec![PathBuf::from("/tmp/work")],
            snapshot_count: 0,
            exit_code: Some(0),
            merkle_roots: Vec::new(),
            network_events: Vec::new(),
            audit_event_count: 2,
            audit_integrity: None,
            audit_attestation: None,
        }
    }

    #[test]
    fn ledger_appends_and_verifies_session_digest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.ndjson");
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .unwrap();

        let meta = sample_metadata("20260421-200000-11111");
        append_session_to_ledger_file(&mut file, &meta).unwrap();

        let reader = BufReader::new(std::fs::File::open(&path).unwrap());
        let verified = verify_session_in_ledger_reader(reader, &meta).unwrap();
        assert!(verified.session_found);
        assert!(verified.session_digest_matches);
        assert!(verified.ledger_chain_verified);
        assert_eq!(verified.entry_count, 1);
    }

    #[test]
    fn ledger_rejects_malformed_session_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.ndjson");
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .unwrap();
        let meta = sample_metadata("real-token\\|real-key");

        let err = match append_session_to_ledger_file(&mut file, &meta) {
            Ok(_) => panic!("malformed session id should be rejected"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("invalid audit session id"));
    }

    #[test]
    fn session_digest_changes_when_protected_fields_change() {
        let base = SessionMetadata {
            session_id: "20260421-200000-11111".to_string(),
            started: "2026-04-21T20:00:00Z".to_string(),
            ended: Some("2026-04-21T20:00:01Z".to_string()),
            command: vec!["/bin/pwd".to_string()],
            executable_identity: Some(ExecutableIdentity {
                resolved_path: PathBuf::from("/bin/pwd"),
                sha256: ContentHash::from_bytes([9; 32]),
            }),
            tracked_paths: vec![PathBuf::from("/tmp/work")],
            snapshot_count: 3,
            exit_code: Some(7),
            merkle_roots: vec![ContentHash::from_bytes([1; 32])],
            network_events: vec![NetworkAuditEvent {
                timestamp_unix_ms: 5,
                mode: NetworkAuditMode::Connect,
                decision: NetworkAuditDecision::Allow,
                route_id: None,
                auth_mechanism: None,
                auth_outcome: None,
                managed_credential_active: None,
                injection_mode: None,
                denial_category: None,
                target: "example.com".to_string(),
                port: Some(443),
                method: Some("GET".to_string()),
                path: Some("/".to_string()),
                status: Some(200),
                reason: None,
            }],
            audit_event_count: 9,
            audit_integrity: Some(AuditIntegritySummary {
                hash_algorithm: "sha256".to_string(),
                event_count: 9,
                chain_head: ContentHash::from_bytes([2; 32]),
                merkle_root: ContentHash::from_bytes([3; 32]),
            }),
            audit_attestation: None,
        };
        let base_digest = compute_session_digest(&base).unwrap();

        let mut changed = base.clone();
        changed.session_id.push('x');
        assert_ne!(base_digest, compute_session_digest(&changed).unwrap());

        let mut changed = base.clone();
        changed.network_events[0].target = "other.example.com".to_string();
        assert_ne!(base_digest, compute_session_digest(&changed).unwrap());

        let mut changed = base.clone();
        changed.audit_integrity = Some(AuditIntegritySummary {
            hash_algorithm: "sha256".to_string(),
            event_count: 9,
            chain_head: ContentHash::from_bytes([8; 32]),
            merkle_root: ContentHash::from_bytes([3; 32]),
        });
        assert_ne!(base_digest, compute_session_digest(&changed).unwrap());
    }

    /// Golden vectors shared with the Python port in
    /// nono-py/tests/test_audit.py (TestRustGoldenVectors keeps the same
    /// values). If this test fails, the wire format diverged across
    /// language bindings — fix the divergence, never the vector.
    #[test]
    fn rust_compatibility_golden_vectors() {
        let meta = sample_metadata("20260421-200000-11111");
        assert_eq!(
            compute_session_digest(&meta).unwrap().to_string(),
            "3a1ed53d426d6ea2544cec6cf6b95ccdc31fda4570d86931239ee0f7d7d39012"
        );

        let dir = tempfile::tempdir().unwrap();
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(dir.path().join("ledger.ndjson"))
            .unwrap();
        let record = append_session_to_ledger_file(&mut file, &meta).unwrap();
        assert_eq!(
            record.chain_hash.to_string(),
            "8b6dbc155d44df05e6b5e9948fb8fff142222b4b41fb37284fb0d1217000e9bb"
        );

        let leaves = vec![
            ContentHash::from_bytes([1; 32]),
            ContentHash::from_bytes([2; 32]),
            ContentHash::from_bytes([3; 32]),
            ContentHash::from_bytes([4; 32]),
            ContentHash::from_bytes([5; 32]),
        ];
        let proof = build_inclusion_proof(&leaves, 2).unwrap();
        assert_eq!(
            serde_json::to_string(&proof).unwrap(),
            concat!(
                r#"{"leaf_index":2,"leaf_count":5,"#,
                r#""leaf_hash":"0303030303030303030303030303030303030303030303030303030303030303","#,
                r#""merkle_root":"87f9319b8dbb3d3fd55d419aabf3c218aafd2dfd82d5e30fb22e8e89c10c0160","#,
                r#""siblings":[{"direction":"right","hash":"0404040404040404040404040404040404040404040404040404040404040404"},"#,
                r#"{"direction":"left","hash":"85fb11ff61817c3aa118af30f054a3ea63c042902722cf8ae35e704fff9624fe"},"#,
                r#"{"direction":"right","hash":"0505050505050505050505050505050505050505050505050505050505050505"}]}"#
            )
        );
    }
}
