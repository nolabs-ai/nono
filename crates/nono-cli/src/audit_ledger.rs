use crate::audit_session::audit_root;
use crate::state_paths;
use nix::fcntl::{Flock, FlockArg};
use nono::audit::{
    LedgerRecord, LedgerVerificationResult, append_session_to_ledger_file,
    missing_ledger_verification_result, validate_ledger_session_id,
    verify_session_in_ledger_reader,
};
use nono::undo::SessionMetadata;
use nono::{NonoError, Result};
use std::fs::OpenOptions;
use std::io::BufReader;
use std::path::{Path, PathBuf};

const AUDIT_LEDGER_FILENAME: &str = "ledger.ndjson";
const AUDIT_LEDGER_LOCK_FILENAME: &str = "ledger.lock";

pub(crate) fn append_session(metadata: &SessionMetadata) -> Result<LedgerRecord> {
    validate_ledger_session_id(&metadata.session_id)?;

    let root = audit_root()?;
    state_paths::maybe_migrate_legacy_audit_ledger()?;
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
    append_session_to_ledger_file(&mut file, metadata)
}

pub(crate) fn verify_session_in_ledger(
    metadata: &SessionMetadata,
) -> Result<LedgerVerificationResult> {
    let primary = audit_root()?;
    let result = verify_session_in_ledger_at_root(&primary, metadata)?;
    if result.session_found {
        return Ok(result);
    }

    if let Ok(legacy) = state_paths::legacy_audit_root()
        && legacy != primary
    {
        let legacy_ledger = legacy.join(AUDIT_LEDGER_FILENAME);
        if legacy_ledger.exists() {
            state_paths::warn_legacy_audit_path(&legacy);
            return verify_session_in_ledger_at_root(&legacy, metadata);
        }
    }

    Ok(result)
}

fn verify_session_in_ledger_at_root(
    root: &Path,
    metadata: &SessionMetadata,
) -> Result<LedgerVerificationResult> {
    let path = root.join(AUDIT_LEDGER_FILENAME);
    if !path.exists() {
        return missing_ledger_verification_result(metadata);
    }

    let file = OpenOptions::new().read(true).open(&path).map_err(|e| {
        NonoError::Snapshot(format!(
            "Failed to open audit ledger {}: {e}",
            path.display()
        ))
    })?;
    verify_session_in_ledger_reader(BufReader::new(file), metadata)
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::test_env::{ENV_LOCK, EnvVarGuard};
    use nono::audit::compute_session_digest;
    use nono::undo::{
        AuditAttestationSummary, AuditIntegritySummary, ContentHash, ExecutableIdentity,
        NetworkAuditDecision, NetworkAuditEvent, NetworkAuditMode,
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
        let state = tmp.path().join("state");
        std::fs::create_dir_all(&state).unwrap();
        let home = tmp.path().to_string_lossy().to_string();
        let state_str = state.to_string_lossy().to_string();
        let _env = EnvVarGuard::set_all(&[("HOME", &home), ("XDG_STATE_HOME", &state_str)]);

        let meta = sample_metadata("20260421-200000-11111");
        append_session(&meta).unwrap();

        let verified = verify_session_in_ledger(&meta).unwrap();
        assert!(verified.session_found);
        assert!(verified.session_digest_matches);
        assert!(verified.ledger_chain_verified);
        assert_eq!(verified.entry_count, 1);
    }

    #[test]
    fn ledger_rejects_malformed_session_id() {
        let _env_lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("state");
        std::fs::create_dir_all(&state).unwrap();
        let home = tmp.path().to_string_lossy().to_string();
        let state_str = state.to_string_lossy().to_string();
        let _env = EnvVarGuard::set_all(&[("HOME", &home), ("XDG_STATE_HOME", &state_str)]);

        let meta = sample_metadata("real-token\\|real-key");
        let err = match append_session(&meta) {
            Ok(_) => panic!("malformed session id should be rejected"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("invalid audit session id"));
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
