use crate::audit_session::audit_root;
use nix::fcntl::{Flock, FlockArg};
use nono::undo::{
    AuditAttestationSummary, AuditIntegritySummary, ContentHash, NetworkAuditEvent, SessionMetadata,
};
use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

const AUDIT_LEDGER_FILENAME: &str = "ledger.ndjson";
const AUDIT_LEDGER_LOCK_FILENAME: &str = "ledger.lock";
const SESSION_DIGEST_DOMAIN: &[u8] = b"nono.audit.session-digest.alpha\n";
const LEDGER_CHAIN_DOMAIN: &[u8] = b"nono.audit.ledger.chain.alpha\n";
const LEDGER_HASH_ALGORITHM: &str = "sha256";

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

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct LedgerRecord {
    pub(crate) sequence: u64,
    pub(crate) prev_chain: Option<ContentHash>,
    pub(crate) session_id: String,
    pub(crate) session_digest: ContentHash,
    pub(crate) completed_at: String,
    pub(crate) chain_hash: ContentHash,
}

#[derive(Serialize)]
struct LedgerLinkPayload<'a> {
    sequence: u64,
    session_id: &'a str,
    session_digest: ContentHash,
    completed_at: &'a str,
}

#[derive(Serialize)]
pub(crate) struct LedgerVerificationResult {
    pub(crate) hash_algorithm: String,
    pub(crate) entry_count: u64,
    pub(crate) session_digest: ContentHash,
    pub(crate) session_found: bool,
    pub(crate) session_digest_matches: bool,
    pub(crate) ledger_chain_verified: bool,
    pub(crate) ledger_head: Option<ContentHash>,
}

pub(crate) fn compute_session_digest(metadata: &SessionMetadata) -> Result<ContentHash> {
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
    hasher.update(SESSION_DIGEST_DOMAIN);
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

pub(crate) fn append_session(metadata: &SessionMetadata) -> Result<LedgerRecord> {
    let root = audit_root()?;
    std::fs::create_dir_all(&root).map_err(|e| {
        NonoError::Snapshot(format!(
            "Failed to create audit root {}: {e}",
            root.display()
        ))
    })?;

    let path = root.join(AUDIT_LEDGER_FILENAME);
    let _lock = LedgerLock::acquire(root.join(AUDIT_LEDGER_LOCK_FILENAME))?;
    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| {
            NonoError::Snapshot(format!(
                "Failed to open audit ledger {}: {e}",
                path.display()
            ))
        })?;
    append_locked(&mut file, metadata)
}

fn append_locked(file: &mut std::fs::File, metadata: &SessionMetadata) -> Result<LedgerRecord> {
    let mut contents = String::new();
    file.seek(SeekFrom::Start(0))
        .map_err(|e| NonoError::Snapshot(format!("Failed to seek audit ledger: {e}")))?;
    file.read_to_string(&mut contents)
        .map_err(|e| NonoError::Snapshot(format!("Failed to read audit ledger: {e}")))?;

    let mut previous_chain = None;
    let mut next_sequence = 0u64;
    for (index, line) in contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record: LedgerRecord = serde_json::from_str(line).map_err(|e| {
            NonoError::Snapshot(format!(
                "Failed to parse audit ledger line {}: {e}",
                index.saturating_add(1)
            ))
        })?;
        previous_chain = Some(record.chain_hash);
        next_sequence = record.sequence.saturating_add(1);
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

pub(crate) fn verify_session_in_ledger(
    metadata: &SessionMetadata,
) -> Result<LedgerVerificationResult> {
    let root = audit_root()?;
    let path = root.join(AUDIT_LEDGER_FILENAME);
    if !path.exists() {
        return Ok(LedgerVerificationResult {
            hash_algorithm: LEDGER_HASH_ALGORITHM.to_string(),
            entry_count: 0,
            session_digest: compute_session_digest(metadata)?,
            session_found: false,
            session_digest_matches: false,
            ledger_chain_verified: false,
            ledger_head: None,
        });
    }

    let file = OpenOptions::new().read(true).open(&path).map_err(|e| {
        NonoError::Snapshot(format!(
            "Failed to open audit ledger {}: {e}",
            path.display()
        ))
    })?;
    let reader = BufReader::new(file);
    let expected_digest = compute_session_digest(metadata)?;

    let mut previous_chain = None;
    let mut entry_count = 0u64;
    let mut ledger_head = None;
    let mut session_found = false;
    let mut session_digest_matches = false;

    for (index, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| {
            NonoError::Snapshot(format!(
                "Failed to read audit ledger {}: {e}",
                path.display()
            ))
        })?;
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
        hash_algorithm: LEDGER_HASH_ALGORITHM.to_string(),
        entry_count,
        session_digest: expected_digest,
        session_found,
        session_digest_matches,
        ledger_chain_verified: true,
        ledger_head,
    })
}

struct LedgerLock {
    _file: Flock<std::fs::File>,
}

impl LedgerLock {
    fn acquire(path: PathBuf) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| {
                NonoError::Snapshot(format!(
                    "Failed to open audit ledger lock {}: {e}",
                    path.display()
                ))
            })?;
        let file = Flock::lock(file, FlockArg::LockExclusive).map_err(|(_, e)| {
            NonoError::Snapshot(format!(
                "Failed to acquire audit ledger lock {}: {e}",
                path.display()
            ))
        })?;
        Ok(Self { _file: file })
    }
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
    hasher.update(LEDGER_CHAIN_DOMAIN);
    if let Some(prev) = previous {
        hasher.update(prev.as_bytes());
    } else {
        hasher.update([0u8; 32]);
    }
    hasher.update(payload_bytes);
    Ok(ContentHash::from_bytes(hasher.finalize().into()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::test_env::{EnvVarGuard, ENV_LOCK};
    use nono::undo::{
        AuditAttestationSummary, ExecutableIdentity, NetworkAuditDecision, NetworkAuditMode,
    };
    #[cfg(unix)]
    use std::ffi::OsString;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;

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
        let _env_lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().to_string_lossy().to_string();
        let _env = EnvVarGuard::set_all(&[("HOME", &home)]);

        let meta = sample_metadata("20260421-200000-11111");
        append_session(&meta).unwrap();

        let verified = verify_session_in_ledger(&meta).unwrap();
        assert!(verified.session_found);
        assert!(verified.session_digest_matches);
        assert!(verified.ledger_chain_verified);
        assert_eq!(verified.entry_count, 1);
    }

    #[test]
    fn session_digest_changes_when_any_protected_field_changes() {
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
        changed.started.push('x');
        assert_ne!(base_digest, compute_session_digest(&changed).unwrap());

        let mut changed = base.clone();
        changed.ended = Some("2026-04-21T20:00:02Z".to_string());
        assert_ne!(base_digest, compute_session_digest(&changed).unwrap());

        let mut changed = base.clone();
        changed.command.push("--debug".to_string());
        assert_ne!(base_digest, compute_session_digest(&changed).unwrap());

        let mut changed = base.clone();
        changed.executable_identity = Some(ExecutableIdentity {
            resolved_path: PathBuf::from("/usr/bin/pwd"),
            sha256: ContentHash::from_bytes([9; 32]),
        });
        assert_ne!(base_digest, compute_session_digest(&changed).unwrap());

        let mut changed = base.clone();
        changed.tracked_paths.push(PathBuf::from("/tmp/other"));
        assert_ne!(base_digest, compute_session_digest(&changed).unwrap());

        let mut changed = base.clone();
        changed.snapshot_count = changed.snapshot_count.saturating_add(1);
        assert_ne!(base_digest, compute_session_digest(&changed).unwrap());

        let mut changed = base.clone();
        changed.exit_code = Some(0);
        assert_ne!(base_digest, compute_session_digest(&changed).unwrap());

        let mut changed = base.clone();
        changed.merkle_roots.push(ContentHash::from_bytes([4; 32]));
        assert_ne!(base_digest, compute_session_digest(&changed).unwrap());

        let mut changed = base.clone();
        changed.audit_attestation = Some(AuditAttestationSummary {
            predicate_type: "https://nono.sh/attestation/audit-session/alpha".to_string(),
            key_id: "test-key".to_string(),
            public_key: "Zm9v".to_string(),
            bundle_filename: "audit-attestation.bundle".to_string(),
        });
        assert_ne!(base_digest, compute_session_digest(&changed).unwrap());

        let mut changed = base.clone();
        changed.network_events[0].target = "other.example.com".to_string();
        assert_ne!(base_digest, compute_session_digest(&changed).unwrap());

        let mut changed = base.clone();
        changed.audit_event_count = changed.audit_event_count.saturating_add(1);
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

    #[cfg(unix)]
    #[test]
    fn session_digest_distinguishes_non_utf8_paths() {
        let mut base = sample_metadata("20260421-200000-11111");
        base.tracked_paths = vec![PathBuf::from(OsString::from_vec(vec![
            b'/', b't', b'm', b'p', b'/', 0xff,
        ]))];
        let mut changed = base.clone();
        changed.tracked_paths = vec![PathBuf::from(OsString::from_vec(vec![
            b'/', b't', b'm', b'p', b'/', 0xfe,
        ]))];

        assert_ne!(
            compute_session_digest(&base).unwrap(),
            compute_session_digest(&changed).unwrap()
        );
    }
}
