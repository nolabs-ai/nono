//! Durable final-session audit delivery for audit-only platform enrollment.

use crate::cli::{AuditStatusArgs, AuditSyncArgs};
use crate::platform_client::{
    PlatformState, REQUEST_PROTOCOL_V1, canonical_request_v1, endpoint_url, http_agent,
    load_signing_key, load_state, write_json_secure,
};
use aws_lc_rs::rand::SystemRandom;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nono::audit::{
    AUDIT_EVENTS_FILENAME, canonical_session_digest_payload, compute_session_digest,
    verify_audit_log,
};
use nono::undo::{SessionMetadata, SnapshotManager};
use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const OUTBOX_DIRNAME: &str = "audit-outbox";
const RECEIPT_FILENAME: &str = "platform-ingest-receipt.json";
const RESPONSE_LIMIT_BYTES: u64 = 1024 * 1024;
const QUEUE_SCHEMA_V2: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AuditIngestEnvelope {
    pub ingest_id: Uuid,
    pub tenant_id: String,
    pub session_id: String,
    pub shipper_id: String,
    pub principal_id: Option<String>,
    pub profile_ref: Option<String>,
    pub merkle_root: String,
    pub hash_chain_head: Option<String>,
    pub started_at: String,
    pub ended_at: Option<String>,
    /// Exact canonical JSON bytes committed by `session_digest`.
    pub session_metadata_json: String,
    pub session_digest: String,
    pub events_ndjson: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct QueuedAuditV2 {
    #[serde(default = "current_queue_schema")]
    schema_version: u32,
    envelope: AuditIngestEnvelope,
    session_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyAuditIngestEnvelope {
    ingest_id: Uuid,
    tenant_id: String,
    session_id: String,
    shipper_id: String,
    principal_id: Option<String>,
    profile_ref: Option<String>,
    merkle_root: String,
    hash_chain_head: Option<String>,
    started_at: String,
    ended_at: Option<String>,
    events_ndjson: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QueuedAuditV1 {
    envelope: LegacyAuditIngestEnvelope,
    session_dir: PathBuf,
}

/// Queue v1 must retain its original wire envelope for idempotent retries.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum QueuedAudit {
    V2(QueuedAuditV2),
    V1(QueuedAuditV1),
}

impl QueuedAudit {
    fn ingest_id(&self) -> Uuid {
        match self {
            Self::V2(queued) => queued.envelope.ingest_id,
            Self::V1(queued) => queued.envelope.ingest_id,
        }
    }

    fn session_id(&self) -> &str {
        match self {
            Self::V2(queued) => &queued.envelope.session_id,
            Self::V1(queued) => &queued.envelope.session_id,
        }
    }

    fn shipper_id(&self) -> &str {
        match self {
            Self::V2(queued) => &queued.envelope.shipper_id,
            Self::V1(queued) => &queued.envelope.shipper_id,
        }
    }

    fn session_dir(&self) -> &Path {
        match self {
            Self::V2(queued) => &queued.session_dir,
            Self::V1(queued) => &queued.session_dir,
        }
    }

    fn wire_body(&self) -> Result<String> {
        let encoded = match self {
            Self::V2(queued) => serde_json::to_string(&queued.envelope),
            Self::V1(queued) => serde_json::to_string(&queued.envelope),
        };
        encoded.map_err(|error| {
            NonoError::ConfigParse(format!("failed to encode audit ingest: {error}"))
        })
    }

    #[cfg(test)]
    fn current_envelope(&self) -> Option<&AuditIngestEnvelope> {
        match self {
            Self::V2(queued) => Some(&queued.envelope),
            Self::V1(_) => None,
        }
    }
}

const fn current_queue_schema() -> u32 {
    QUEUE_SCHEMA_V2
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditIngestReceipt {
    ingest_id: Uuid,
    session_id: String,
    accepted_at: String,
    platform_attestation: String,
    event_count: u64,
    verification_status: String,
    object_path: String,
}

#[derive(Debug, Serialize)]
struct SyncSummary {
    attempted: usize,
    delivered: usize,
    remaining: usize,
    failures: Vec<String>,
}

pub(crate) fn maybe_ship_session(session_dir: &Path, metadata: &SessionMetadata) -> Result<()> {
    let Some(state) = load_state()? else {
        return Ok(());
    };
    let queued = build_queued_audit(session_dir, metadata, &state)?;
    let path = outbox_path(queued.ingest_id())?;
    write_json_secure(&path, &queued)?;
    deliver_queued(&state, &path, &queued)
}

pub(crate) fn run_sync(args: AuditSyncArgs) -> Result<()> {
    let Some(state) = load_state()? else {
        return Err(NonoError::ActionRequired(
            "nono is not enrolled with a platform; run `nono platform enroll` first".to_string(),
        ));
    };
    let mut attempted = 0;
    let mut delivered = 0;
    let mut failures = recover_missing_queue_items(&state)?;
    for path in queued_paths()? {
        attempted += 1;
        let result = load_queued(&path).and_then(|queued| {
            if queued.shipper_id() == state.subject_id {
                deliver_queued(&state, &path, &queued)
            } else {
                // Queued under a previous enrollment: the platform refuses an
                // envelope whose shipper is not the authenticated subject, so
                // re-mint it from the local session evidence before delivery.
                let (rebuilt_path, rebuilt) =
                    requeue_under_current_enrollment(&state, &path, &queued)?;
                deliver_queued(&state, &rebuilt_path, &rebuilt)
            }
        });
        match result {
            Ok(()) => delivered += 1,
            Err(error) => failures.push(format!("{}: {error}", path.display())),
        }
    }
    let remaining = queued_paths()?.len();
    let summary = SyncSummary {
        attempted,
        delivered,
        remaining,
        failures,
    };
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&summary)
                .map_err(|error| NonoError::ConfigParse(error.to_string()))?
        );
    } else {
        println!(
            "Audit sync: {} delivered, {} remaining ({} attempted)",
            summary.delivered, summary.remaining, summary.attempted
        );
        for failure in &summary.failures {
            eprintln!("  {failure}");
        }
    }
    if summary.failures.is_empty() {
        Ok(())
    } else {
        Err(NonoError::ActionRequired(
            "some audit sessions could not be delivered; retry `nono audit sync`".to_string(),
        ))
    }
}

pub(crate) fn run_status(args: AuditStatusArgs) -> Result<()> {
    let enrolled = load_state()?.is_some();
    let queued = queued_paths()?.len();
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "enrolled": enrolled,
                "queued": queued,
            }))
            .map_err(|error| NonoError::ConfigParse(error.to_string()))?
        );
    } else {
        println!("Audit delivery");
        println!("  Enrolled: {}", if enrolled { "yes" } else { "no" });
        println!("  Queued:   {queued}");
    }
    Ok(())
}

fn build_queued_audit(
    session_dir: &Path,
    metadata: &SessionMetadata,
    state: &PlatformState,
) -> Result<QueuedAudit> {
    let integrity = metadata.audit_integrity.as_ref().ok_or_else(|| {
        NonoError::Snapshot(
            "cannot ship audit session without local audit integrity summary".to_string(),
        )
    })?;
    verify_audit_log(session_dir, Some(integrity))?;
    let events_path = session_dir.join(AUDIT_EVENTS_FILENAME);
    let events_ndjson =
        fs::read_to_string(&events_path).map_err(|source| NonoError::ConfigRead {
            path: events_path,
            source,
        })?;
    let session_metadata_json = String::from_utf8(canonical_session_digest_payload(metadata)?)
        .map_err(|error| {
            NonoError::ConfigParse(format!(
                "canonical audit session metadata was not UTF-8: {error}"
            ))
        })?;
    let session_digest = compute_session_digest(metadata)?.to_string();
    Ok(QueuedAudit::V2(QueuedAuditV2 {
        schema_version: QUEUE_SCHEMA_V2,
        envelope: AuditIngestEnvelope {
            ingest_id: Uuid::now_v7(),
            tenant_id: state.tenant_id.clone(),
            session_id: metadata.session_id.clone(),
            shipper_id: state.subject_id.clone(),
            principal_id: None,
            profile_ref: None,
            merkle_root: integrity.merkle_root.to_string(),
            hash_chain_head: Some(integrity.chain_head.to_string()),
            started_at: metadata.started.clone(),
            ended_at: metadata.ended.clone(),
            session_metadata_json,
            session_digest,
            events_ndjson,
        },
        session_dir: session_dir.to_path_buf(),
    }))
}

/// Re-mint a queue item that names a previous enrollment's identity.
///
/// The envelope is rebuilt from the session evidence still on disk — which
/// re-verifies the hash chain — under the current subject, tenant, and a fresh
/// ingest ID. The replacement is durably queued before the stale item is
/// removed; a crash between the two steps double-queues the session, which is
/// safe: the platform refuses the twin with its duplicate-session conflict, so
/// nothing is silently dropped.
fn requeue_under_current_enrollment(
    state: &PlatformState,
    stale_path: &Path,
    stale: &QueuedAudit,
) -> Result<(PathBuf, QueuedAudit)> {
    let session_dir = stale.session_dir();
    if !session_dir.is_dir() {
        return Err(NonoError::Snapshot(format!(
            "queued under a previous enrollment as {} and the session evidence at {} is no \
             longer on disk; remove the outbox item to drop the session",
            stale.shipper_id(),
            session_dir.display()
        )));
    }
    let metadata = SnapshotManager::load_session_metadata(session_dir)?;
    let rebuilt = build_queued_audit(session_dir, &metadata, state)?;
    let rebuilt_path = outbox_path(rebuilt.ingest_id())?;
    write_json_secure(&rebuilt_path, &rebuilt)?;
    fs::remove_file(stale_path).map_err(|source| NonoError::ConfigWrite {
        path: stale_path.to_path_buf(),
        source,
    })?;
    Ok((rebuilt_path, rebuilt))
}

fn deliver_queued(state: &PlatformState, path: &Path, queued: &QueuedAudit) -> Result<()> {
    let endpoint = endpoint_url(&state.platform_url, "/api/v1/audit/ingest")?;
    let request_path = url::Url::parse(&endpoint)
        .map_err(|error| NonoError::ConfigParse(format!("invalid ingest endpoint: {error}")))?
        .path()
        .to_string();
    let body = queued.wire_body()?;
    let body_digest = format!("sha256:{}", sha256_hex(body.as_bytes()));
    let timestamp = current_timestamp_ms()?.to_string();
    let request_id = queued.ingest_id().to_string();
    let canonical = canonical_request_v1(
        "POST",
        &request_path,
        &state.subject_id,
        &timestamp,
        &request_id,
        &body_digest,
    );
    let key_pair = load_signing_key(state)?;
    let signature = key_pair
        .sign(&SystemRandom::new(), canonical.as_bytes())
        .map_err(|_| NonoError::KeystoreAccess("failed to sign audit request".to_string()))?;

    let mut response = http_agent(Duration::from_secs(15))
        .post(&endpoint)
        .config()
        .http_status_as_error(false)
        .build()
        .header("Content-Type", "application/json")
        .header("X-Nono-Protocol-Version", REQUEST_PROTOCOL_V1)
        .header("X-Nono-Subject-Id", &state.subject_id)
        .header("X-Nono-Timestamp", &timestamp)
        .header("X-Nono-Request-Id", &request_id)
        .header("X-Nono-Content-SHA256", &body_digest)
        .header(
            "X-Nono-Signature",
            format!("p256-sha256={}", URL_SAFE_NO_PAD.encode(signature.as_ref())),
        )
        .send(&body)
        .map_err(|error| NonoError::Snapshot(format!("audit ingest request failed: {error}")))?;
    if !response.status().is_success() {
        let status = response.status().as_u16();
        let message = response
            .body_mut()
            .with_config()
            .limit(RESPONSE_LIMIT_BYTES)
            .read_to_string()
            .unwrap_or_default();
        return Err(NonoError::Snapshot(format!(
            "audit ingest returned HTTP {status}: {message}"
        )));
    }
    let response_body = response
        .body_mut()
        .with_config()
        .limit(RESPONSE_LIMIT_BYTES)
        .read_to_string()
        .map_err(|error| NonoError::Snapshot(format!("invalid audit ingest receipt: {error}")))?;
    let receipt: AuditIngestReceipt = serde_json::from_str(&response_body)
        .map_err(|error| NonoError::Snapshot(format!("invalid audit ingest receipt: {error}")))?;
    if receipt.ingest_id != queued.ingest_id()
        || receipt.session_id != queued.session_id()
        || receipt.verification_status != "pending"
    {
        return Err(NonoError::Snapshot(
            "platform returned a mismatched or unsupported audit receipt".to_string(),
        ));
    }
    if queued.session_dir().is_dir() {
        write_json_secure(&queued.session_dir().join(RECEIPT_FILENAME), &receipt)?;
    }
    fs::remove_file(path).map_err(|source| NonoError::ConfigWrite {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

fn load_queued(path: &Path) -> Result<QueuedAudit> {
    let contents = fs::read_to_string(path).map_err(|source| NonoError::ConfigRead {
        path: path.to_path_buf(),
        source,
    })?;
    let queued = serde_json::from_str::<QueuedAudit>(&contents).map_err(|error| {
        NonoError::ConfigParse(format!(
            "invalid audit outbox item {}: {error}",
            path.display()
        ))
    })?;
    if let QueuedAudit::V2(queued) = &queued
        && queued.schema_version != QUEUE_SCHEMA_V2
    {
        return Err(NonoError::ConfigParse(format!(
            "unsupported audit outbox schema {} in {}",
            queued.schema_version,
            path.display()
        )));
    }
    Ok(queued)
}

fn recover_missing_queue_items(state: &PlatformState) -> Result<Vec<String>> {
    let enrolled_at =
        chrono::DateTime::parse_from_rfc3339(&state.enrolled_at).map_err(|error| {
            NonoError::ConfigParse(format!(
                "invalid platform enrollment timestamp {}: {error}",
                state.enrolled_at
            ))
        })?;
    let mut queued_session_ids = HashSet::new();
    for path in queued_paths()? {
        if let Some(session_id) = queued_session_id(&path) {
            queued_session_ids.insert(session_id);
        }
    }

    let mut failures = Vec::new();
    for session in crate::audit_session::discover_sessions()? {
        if queued_session_ids.contains(&session.metadata.session_id)
            || session.dir.join(RECEIPT_FILENAME).is_file()
            || session.metadata.audit_integrity.is_none()
        {
            continue;
        }
        let Some(ended) = session.metadata.ended.as_deref() else {
            continue;
        };
        let ended_at = match chrono::DateTime::parse_from_rfc3339(ended) {
            Ok(ended_at) => ended_at,
            Err(error) => {
                failures.push(format!(
                    "{}: invalid audit completion timestamp: {error}",
                    session.dir.display()
                ));
                continue;
            }
        };
        if ended_at < enrolled_at {
            continue;
        }

        match build_queued_audit(&session.dir, &session.metadata, state).and_then(|queued| {
            let path = outbox_path(queued.ingest_id())?;
            write_json_secure(&path, &queued)
        }) {
            Ok(()) => {
                queued_session_ids.insert(session.metadata.session_id);
            }
            Err(error) => failures.push(format!("{}: {error}", session.dir.display())),
        }
    }
    Ok(failures)
}

fn queued_session_id(path: &Path) -> Option<String> {
    // Outbox items embed the full event log, so deserialize only the one field
    // needed instead of materializing the whole document. Unknown fields —
    // including future schema versions — are skipped without allocating.
    #[derive(Deserialize)]
    struct SessionIdEnvelope {
        session_id: String,
    }
    #[derive(Deserialize)]
    struct SessionIdItem {
        envelope: SessionIdEnvelope,
    }
    let contents = fs::read_to_string(path).ok()?;
    serde_json::from_str::<SessionIdItem>(&contents)
        .ok()
        .map(|item| item.envelope.session_id)
}

pub(crate) fn queued_count() -> Result<usize> {
    Ok(queued_paths()?.len())
}

fn queued_paths() -> Result<Vec<PathBuf>> {
    let dir = outbox_dir()?;
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut paths = fs::read_dir(&dir)
        .map_err(|source| NonoError::ConfigRead {
            path: dir.clone(),
            source,
        })?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

fn outbox_path(ingest_id: Uuid) -> Result<PathBuf> {
    Ok(outbox_dir()?.join(format!("{ingest_id}.json")))
}

fn outbox_dir() -> Result<PathBuf> {
    Ok(crate::state_paths::user_state_dir()?.join(OUTBOX_DIRNAME))
}

fn current_timestamp_ms() -> Result<u128> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .map_err(|error| NonoError::Snapshot(format!("system clock is before Unix epoch: {error}")))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::audit_integrity::AuditRecorder;
    use crate::test_env::{ENV_LOCK, EnvVarGuard};
    use nono::undo::{AuditIntegritySummary, ContentHash, ExecutableIdentity};

    #[test]
    fn queued_audit_verifies_local_evidence_and_preserves_identity() {
        let dir = tempfile::tempdir().unwrap();
        let mut recorder = AuditRecorder::new(dir.path().to_path_buf()).unwrap();
        recorder
            .record_session_started("2026-07-01T10:00:00Z".to_string(), vec!["true".to_string()])
            .unwrap();
        recorder
            .record_session_ended("2026-07-01T10:00:01Z".to_string(), 0)
            .unwrap();
        let integrity = recorder.finalize().unwrap();
        let metadata = metadata("session-1", integrity);
        let state = state();

        let queued = build_queued_audit(dir.path(), &metadata, &state).unwrap();
        let envelope = queued.current_envelope().unwrap();
        assert_eq!(envelope.tenant_id, "acme");
        assert_eq!(envelope.shipper_id, "subject-1");
        assert_eq!(envelope.session_id, "session-1");
        assert!(envelope.events_ndjson.contains("session_started"));
        assert!(envelope.events_ndjson.contains("session_ended"));
        assert_eq!(
            envelope.session_digest,
            compute_session_digest(&metadata).unwrap().to_string()
        );
        let shipped_metadata: serde_json::Value =
            serde_json::from_str(&envelope.session_metadata_json).unwrap();
        assert_eq!(shipped_metadata["session_id"], "session-1");
        assert_eq!(shipped_metadata["command"], serde_json::json!(["true"]));
        assert_eq!(shipped_metadata["exit_code"], 0);
    }

    #[test]
    fn legacy_queue_preserves_original_wire_envelope() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.json");
        let legacy = QueuedAuditV1 {
            envelope: LegacyAuditIngestEnvelope {
                ingest_id: Uuid::parse_str("0197d04c-c000-7000-8000-000000000001").unwrap(),
                tenant_id: "acme".to_string(),
                session_id: "session-legacy".to_string(),
                shipper_id: "subject-1".to_string(),
                principal_id: None,
                profile_ref: None,
                merkle_root: "a".repeat(64),
                hash_chain_head: Some("b".repeat(64)),
                started_at: "2026-07-01T10:00:00Z".to_string(),
                ended_at: Some("2026-07-01T10:00:01Z".to_string()),
                events_ndjson: "{\"sequence\":0}\n".to_string(),
            },
            session_dir: dir.path().join("session-legacy"),
        };
        let expected_body = serde_json::to_string(&legacy.envelope).unwrap();
        fs::write(&path, serde_json::to_vec_pretty(&legacy).unwrap()).unwrap();

        let queued = load_queued(&path).unwrap();
        assert!(matches!(queued, QueuedAudit::V1(_)));
        assert_eq!(queued.session_id(), "session-legacy");
        assert_eq!(queued.wire_body().unwrap(), expected_body);
        assert!(!queued.wire_body().unwrap().contains("session_digest"));
    }

    #[test]
    fn current_queue_accepts_pre_versioned_items_and_rejects_unknown_versions() {
        let dir = tempfile::tempdir().unwrap();
        let mut recorder = AuditRecorder::new(dir.path().to_path_buf()).unwrap();
        recorder
            .record_session_started("2026-07-01T10:00:00Z".to_string(), vec!["true".to_string()])
            .unwrap();
        recorder
            .record_session_ended("2026-07-01T10:00:01Z".to_string(), 0)
            .unwrap();
        let metadata = metadata("session-current", recorder.finalize().unwrap());
        let queued = build_queued_audit(dir.path(), &metadata, &state()).unwrap();
        let mut encoded = serde_json::to_value(&queued).unwrap();
        let object = encoded.as_object_mut().unwrap();
        assert_eq!(
            object.remove("schema_version"),
            Some(serde_json::json!(QUEUE_SCHEMA_V2))
        );
        let path = dir.path().join("current.json");
        fs::write(&path, serde_json::to_vec_pretty(&encoded).unwrap()).unwrap();

        assert!(matches!(load_queued(&path).unwrap(), QueuedAudit::V2(_)));

        encoded
            .as_object_mut()
            .unwrap()
            .insert("schema_version".to_string(), serde_json::json!(99));
        fs::write(&path, serde_json::to_vec_pretty(&encoded).unwrap()).unwrap();
        assert!(load_queued(&path).is_err());
        assert_eq!(queued_session_id(&path).as_deref(), Some("session-current"));
    }

    #[test]
    fn sync_recovery_queues_finalized_session_once() {
        let _env_lock = ENV_LOCK.lock().unwrap();
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let state_home = root.path().join("state");
        fs::create_dir_all(&home).unwrap();
        let home = home.to_string_lossy().to_string();
        let state_home = state_home.to_string_lossy().to_string();
        let _env = EnvVarGuard::set_all(&[
            ("HOME", home.as_str()),
            ("XDG_STATE_HOME", state_home.as_str()),
        ]);
        let session_dir = crate::audit_session::audit_root()
            .unwrap()
            .join("session-recover");
        fs::create_dir_all(&session_dir).unwrap();
        let mut recorder = AuditRecorder::new(session_dir.clone()).unwrap();
        recorder
            .record_session_started("2026-07-01T10:00:00Z".to_string(), vec!["true".to_string()])
            .unwrap();
        recorder
            .record_session_ended("2026-07-01T10:00:01Z".to_string(), 0)
            .unwrap();
        let recovered_metadata = metadata("session-recover", recorder.finalize().unwrap());
        nono::undo::SnapshotManager::write_session_metadata(&session_dir, &recovered_metadata)
            .unwrap();

        let old_session_dir = crate::audit_session::audit_root()
            .unwrap()
            .join("session-before-enrollment");
        fs::create_dir_all(&old_session_dir).unwrap();
        let mut old_recorder = AuditRecorder::new(old_session_dir.clone()).unwrap();
        old_recorder
            .record_session_started("2026-07-01T08:00:00Z".to_string(), vec!["true".to_string()])
            .unwrap();
        old_recorder
            .record_session_ended("2026-07-01T08:00:01Z".to_string(), 0)
            .unwrap();
        let mut old_metadata = metadata(
            "session-before-enrollment",
            old_recorder.finalize().unwrap(),
        );
        old_metadata.started = "2026-07-01T08:00:00Z".to_string();
        old_metadata.ended = Some("2026-07-01T08:00:01Z".to_string());
        nono::undo::SnapshotManager::write_session_metadata(&old_session_dir, &old_metadata)
            .unwrap();

        assert!(recover_missing_queue_items(&state()).unwrap().is_empty());
        assert_eq!(queued_paths().unwrap().len(), 1);
        let queued = load_queued(&queued_paths().unwrap()[0]).unwrap();
        assert!(matches!(queued, QueuedAudit::V2(_)));
        assert_eq!(queued.session_id(), "session-recover");

        assert!(recover_missing_queue_items(&state()).unwrap().is_empty());
        assert_eq!(queued_paths().unwrap().len(), 1);
    }

    #[test]
    fn sync_requeues_stale_enrollment_items_under_the_current_identity() {
        let _env_lock = ENV_LOCK.lock().unwrap();
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let state_home = root.path().join("state");
        fs::create_dir_all(&home).unwrap();
        let home = home.to_string_lossy().to_string();
        let state_home = state_home.to_string_lossy().to_string();
        let _env = EnvVarGuard::set_all(&[
            ("HOME", home.as_str()),
            ("XDG_STATE_HOME", state_home.as_str()),
        ]);

        let session_dir = crate::audit_session::audit_root()
            .unwrap()
            .join("session-stale");
        fs::create_dir_all(&session_dir).unwrap();
        let mut recorder = AuditRecorder::new(session_dir.clone()).unwrap();
        recorder
            .record_session_started("2026-07-01T10:00:00Z".to_string(), vec!["true".to_string()])
            .unwrap();
        recorder
            .record_session_ended("2026-07-01T10:00:01Z".to_string(), 0)
            .unwrap();
        let session_metadata = metadata("session-stale", recorder.finalize().unwrap());
        nono::undo::SnapshotManager::write_session_metadata(&session_dir, &session_metadata)
            .unwrap();

        let mut old_state = state();
        old_state.subject_id = "subject-retired".to_string();
        old_state.tenant_id = "oldco".to_string();
        let stale = build_queued_audit(&session_dir, &session_metadata, &old_state).unwrap();
        let stale_path = outbox_path(stale.ingest_id()).unwrap();
        write_json_secure(&stale_path, &stale).unwrap();

        let current_state = state();
        let loaded = load_queued(&stale_path).unwrap();
        assert_ne!(loaded.shipper_id(), current_state.subject_id);

        let (rebuilt_path, rebuilt) =
            requeue_under_current_enrollment(&current_state, &stale_path, &loaded).unwrap();
        assert!(!stale_path.exists());
        assert!(rebuilt_path.exists());
        let envelope = rebuilt.current_envelope().unwrap();
        assert_eq!(envelope.shipper_id, "subject-1");
        assert_eq!(envelope.tenant_id, "acme");
        assert_eq!(envelope.session_id, "session-stale");
        assert_ne!(envelope.ingest_id, stale.ingest_id());
        assert_eq!(
            envelope.session_digest,
            compute_session_digest(&session_metadata)
                .unwrap()
                .to_string()
        );

        // Without the local session evidence a stale item cannot be re-minted:
        // it must fail loudly and stay queued rather than vanish.
        let second_stale = build_queued_audit(&session_dir, &session_metadata, &old_state).unwrap();
        let second_path = outbox_path(second_stale.ingest_id()).unwrap();
        write_json_secure(&second_path, &second_stale).unwrap();
        fs::remove_dir_all(&session_dir).unwrap();
        let error = requeue_under_current_enrollment(
            &current_state,
            &second_path,
            &load_queued(&second_path).unwrap(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("previous enrollment"));
        assert!(second_path.exists());
    }

    #[test]
    fn canonical_session_metadata_matches_cross_repository_fixture() {
        let metadata = SessionMetadata {
            session_id: "11822689bd7b29bd".to_string(),
            started: "2026-07-21T07:18:23.355693+01:00".to_string(),
            ended: Some("2026-07-21T07:18:23.431345+01:00".to_string()),
            command: vec!["/usr/bin/true".to_string()],
            executable_identity: Some(ExecutableIdentity {
                resolved_path: PathBuf::from("/usr/bin/true"),
                sha256: "ccb5264afd44f9c8539ef99ac96aec86d07bff579cabf1be3c0b57b1ed99afc5"
                    .parse::<ContentHash>()
                    .unwrap(),
            }),
            tracked_paths: vec![PathBuf::from("/Users/lukehinds/dev/nono-workspace/nono")],
            snapshot_count: 0,
            exit_code: Some(0),
            merkle_roots: Vec::new(),
            network_events: Vec::new(),
            audit_event_count: 2,
            audit_integrity: Some(AuditIntegritySummary {
                hash_algorithm: "sha256".to_string(),
                event_count: 2,
                chain_head: "95698453e92153a6b0b98cdb5d77f0ab3faa1b78e6bc52ca041b34212495a6e4"
                    .parse::<ContentHash>()
                    .unwrap(),
                merkle_root: "c106781324877481f027c7a7ccf85970e1dc186a8544f709e14a04dac024bb09"
                    .parse::<ContentHash>()
                    .unwrap(),
            }),
            audit_attestation: None,
        };
        let fixture =
            include_str!("../../../tests/fixtures/audit-session-metadata-v1.json").trim_end();
        assert_eq!(
            String::from_utf8(canonical_session_digest_payload(&metadata).unwrap()).unwrap(),
            fixture
        );
        assert_eq!(
            compute_session_digest(&metadata).unwrap().to_string(),
            "02022c14ce57dca6b392adfaaa922e4335d57ae6ce3d8ad962ec203cfd31dd0b"
        );
    }

    fn metadata(session_id: &str, integrity: AuditIntegritySummary) -> SessionMetadata {
        SessionMetadata {
            session_id: session_id.to_string(),
            started: "2026-07-01T10:00:00Z".to_string(),
            ended: Some("2026-07-01T10:00:01Z".to_string()),
            command: vec!["true".to_string()],
            executable_identity: None,
            tracked_paths: Vec::new(),
            snapshot_count: 0,
            exit_code: Some(0),
            merkle_roots: Vec::new(),
            network_events: Vec::new(),
            audit_event_count: integrity.event_count,
            audit_integrity: Some(integrity),
            audit_attestation: None,
        }
    }

    fn state() -> PlatformState {
        PlatformState {
            protocol_version: "1".to_string(),
            platform_url: "http://127.0.0.1:8090".to_string(),
            tenant_id: "acme".to_string(),
            subject_id: "subject-1".to_string(),
            subject_kind: "device".to_string(),
            management_mode: "audit_only".to_string(),
            key_algorithm: "ecdsa_p256_sha256_fixed".to_string(),
            key_ref: "file:///tmp/test-key".to_string(),
            enrolled_at: "2026-07-01T09:00:00Z".to_string(),
        }
    }
}
