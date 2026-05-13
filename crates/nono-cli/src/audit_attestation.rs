use crate::trust_cmd;
use nono::trust;
use nono::undo::{AuditAttestationSummary, ContentHash, SessionMetadata};
use nono::{NonoError, Result};
use serde::Serialize;
use std::fs;
use std::path::Path;
use zeroize::Zeroizing;

pub(crate) const AUDIT_ATTESTATION_BUNDLE_FILENAME: &str = "audit-attestation.bundle";
pub(crate) const AUDIT_ATTESTATION_PREDICATE_TYPE_ALPHA: &str =
    "https://nono.sh/attestation/audit-session/alpha";
const KEYSTORE_URI_PREFIX: &str = "keystore://";

pub(crate) struct AuditSigner {
    key_pair: trust::KeyPair,
    pub(crate) key_id: String,
    pub(crate) public_key_b64: String,
}

#[cfg(test)]
pub(crate) fn signer_from_key_pair(key_pair: trust::KeyPair) -> Result<AuditSigner> {
    let key_id = trust::key_id_hex(&key_pair)?;
    let public_key = trust::export_public_key(&key_pair)?;
    Ok(AuditSigner {
        key_pair,
        key_id,
        public_key_b64: trust::base64::base64_encode(public_key.as_bytes()),
    })
}

#[derive(Serialize)]
pub(crate) struct AuditAttestationVerificationResult {
    pub(crate) present: bool,
    pub(crate) predicate_type: Option<String>,
    pub(crate) key_id: Option<String>,
    pub(crate) key_id_matches: bool,
    pub(crate) signature_verified: bool,
    pub(crate) merkle_root_matches: bool,
    pub(crate) session_id_matches: bool,
    pub(crate) expected_public_key_matches: Option<bool>,
    pub(crate) verification_error: Option<String>,
}

#[derive(Serialize)]
struct AuditAttestationPredicate<'a> {
    version: u32,
    session_id: &'a str,
    started: &'a str,
    ended: &'a Option<String>,
    command: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    redaction_policy: Option<nono::ScrubPolicyDiff>,
    audit_log: AuditLogPredicate<'a>,
    signer: AuditSignerPredicate<'a>,
}

#[derive(Serialize)]
struct AuditLogPredicate<'a> {
    hash_algorithm: &'a str,
    event_count: u64,
    chain_head: &'a ContentHash,
    merkle_root: &'a ContentHash,
}

#[derive(Serialize)]
struct AuditSignerPredicate<'a> {
    kind: &'static str,
    key_id: &'a str,
}

pub(crate) fn prepare_audit_signer(secret_ref: Option<&str>) -> Result<Option<AuditSigner>> {
    let Some(secret_ref) = secret_ref.filter(|value| !value.trim().is_empty()) else {
        return Ok(None);
    };

    let normalized_ref = normalize_signing_secret_ref(secret_ref);
    let pkcs8_b64 = nono::load_secret_by_ref(trust_cmd::TRUST_SERVICE, &normalized_ref)?;
    let pkcs8_bytes =
        Zeroizing::new(trust_cmd::base64_decode(pkcs8_b64.as_str()).map_err(|e| {
            NonoError::TrustSigning {
                path: "<audit-sign-key>".to_string(),
                reason: format!("invalid base64 PKCS#8 signing key: {e}"),
            }
        })?);
    let key_pair = trust_cmd::reconstruct_key_pair(&pkcs8_bytes)?;
    let key_id = trust::key_id_hex(&key_pair)?;
    let public_key = trust::export_public_key(&key_pair)?;
    let public_key_b64 = trust::base64::base64_encode(public_key.as_bytes());

    Ok(Some(AuditSigner {
        key_pair,
        key_id,
        public_key_b64,
    }))
}

pub(crate) fn write_audit_attestation(
    session_dir: &Path,
    metadata: &SessionMetadata,
    signer: &AuditSigner,
    redaction_policy: &nono::ScrubPolicy,
) -> Result<AuditAttestationSummary> {
    let integrity = metadata
        .audit_integrity
        .as_ref()
        .ok_or_else(|| NonoError::TrustSigning {
            path: session_dir.display().to_string(),
            reason: "audit attestation requires audit integrity to be enabled".to_string(),
        })?;

    let scrubbed_command = nono::scrub_argv_with_policy(&metadata.command, redaction_policy);
    let predicate = serde_json::to_value(AuditAttestationPredicate {
        version: 1,
        session_id: &metadata.session_id,
        started: &metadata.started,
        ended: &metadata.ended,
        command: &scrubbed_command,
        redaction_policy: redaction_policy.diff_from_secure_default().into_option(),
        audit_log: AuditLogPredicate {
            hash_algorithm: &integrity.hash_algorithm,
            event_count: integrity.event_count,
            chain_head: &integrity.chain_head,
            merkle_root: &integrity.merkle_root,
        },
        signer: AuditSignerPredicate {
            kind: "keyed",
            key_id: &signer.key_id,
        },
    })
    .map_err(|e| NonoError::TrustSigning {
        path: session_dir.display().to_string(),
        reason: format!("failed to serialize audit attestation predicate: {e}"),
    })?;

    let statement = trust::new_statement(
        &format!("audit-session:{}", metadata.session_id),
        &integrity.merkle_root.to_string(),
        predicate,
        AUDIT_ATTESTATION_PREDICATE_TYPE_ALPHA,
    );
    let bundle_json = trust::sign_statement_bundle(&statement, &signer.key_pair)?;
    let bundle_path = session_dir.join(AUDIT_ATTESTATION_BUNDLE_FILENAME);
    fs::write(&bundle_path, bundle_json).map_err(|e| NonoError::TrustSigning {
        path: bundle_path.display().to_string(),
        reason: format!("failed to write audit attestation bundle: {e}"),
    })?;

    Ok(AuditAttestationSummary {
        predicate_type: AUDIT_ATTESTATION_PREDICATE_TYPE_ALPHA.to_string(),
        key_id: signer.key_id.clone(),
        public_key: signer.public_key_b64.clone(),
        bundle_filename: AUDIT_ATTESTATION_BUNDLE_FILENAME.to_string(),
    })
}

pub(crate) fn verify_audit_attestation(
    session_dir: &Path,
    metadata: &SessionMetadata,
    expected_public_key_file: Option<&Path>,
) -> Result<AuditAttestationVerificationResult> {
    let Some(summary) = metadata.audit_attestation.as_ref() else {
        return Ok(AuditAttestationVerificationResult {
            present: false,
            predicate_type: None,
            key_id: None,
            key_id_matches: false,
            signature_verified: false,
            merkle_root_matches: false,
            session_id_matches: false,
            expected_public_key_matches: expected_public_key_file.map(|_| false),
            verification_error: expected_public_key_file.map(|public_key_file| {
                format!(
                    "session has no audit attestation to verify against provided public key {}",
                    public_key_file.display()
                )
            }),
        });
    };

    let Some(integrity) = metadata.audit_integrity.as_ref() else {
        return Ok(attestation_failure(
            summary,
            expected_public_key_file.map(|_| true),
            "session has audit attestation metadata but no audit integrity summary".to_string(),
        ));
    };
    let bundle_path = session_dir.join(&summary.bundle_filename);
    let bundle = match trust::load_bundle(&bundle_path) {
        Ok(bundle) => bundle,
        Err(err) => {
            return Ok(attestation_failure(
                summary,
                expected_public_key_file.map(|_| true),
                err.to_string(),
            ));
        }
    };
    let predicate_type = match trust::extract_predicate_type(&bundle, &bundle_path) {
        Ok(predicate_type) => predicate_type,
        Err(err) => {
            return Ok(attestation_failure(
                summary,
                expected_public_key_file.map(|_| true),
                err.to_string(),
            ));
        }
    };
    if predicate_type != AUDIT_ATTESTATION_PREDICATE_TYPE_ALPHA {
        return Ok(attestation_failure(
            summary,
            expected_public_key_file.map(|_| true),
            format!(
                "wrong bundle type: expected {}, got {}",
                AUDIT_ATTESTATION_PREDICATE_TYPE_ALPHA, predicate_type
            ),
        ));
    }

    let signer_identity = match trust::extract_signer_identity(&bundle, &bundle_path) {
        Ok(identity) => identity,
        Err(err) => {
            return Ok(attestation_failure(
                summary,
                expected_public_key_file.map(|_| true),
                err.to_string(),
            ));
        }
    };
    let signer_key_id = match signer_identity {
        trust::SignerIdentity::Keyed { key_id } => key_id,
        trust::SignerIdentity::Keyless { .. } => {
            return Ok(attestation_failure(
                summary,
                expected_public_key_file.map(|_| true),
                "audit attestation must be keyed".to_string(),
            ));
        }
    };
    let public_key_der = match trust::base64::base64_decode(&summary.public_key) {
        Ok(public_key_der) => public_key_der,
        Err(err) => {
            return Ok(attestation_failure(
                summary,
                expected_public_key_file.map(|_| true),
                format!("invalid attested public key encoding: {err}"),
            ));
        }
    };
    let recomputed_key_id = trust::public_key_id_hex(&public_key_der);
    if recomputed_key_id != summary.key_id {
        return Ok(attestation_failure(
            summary,
            expected_public_key_file.map(|_| true),
            format!(
                "audit attestation metadata key mismatch: expected {}, got {}",
                summary.key_id, recomputed_key_id
            ),
        ));
    }
    if signer_key_id != summary.key_id {
        return Ok(attestation_failure(
            summary,
            expected_public_key_file.map(|_| true),
            format!(
                "audit attestation signer key mismatch: expected {}, got {}",
                summary.key_id, signer_key_id
            ),
        ));
    }
    if let Some(public_key_file) = expected_public_key_file {
        let expected_public_key = load_public_key_file(public_key_file)?;
        if expected_public_key != public_key_der {
            return Ok(attestation_failure(
                summary,
                Some(false),
                "provided public key does not match the attested signer key".to_string(),
            ));
        }
    }
    if let Err(err) = trust::verify_keyed_signature(&bundle, &public_key_der, &bundle_path) {
        return Ok(attestation_failure(
            summary,
            expected_public_key_file.map(|_| true),
            err.to_string(),
        ));
    }

    let attested_root = match trust::extract_bundle_digest(&bundle, &bundle_path) {
        Ok(attested_root) => attested_root,
        Err(err) => {
            return Ok(attestation_failure(
                summary,
                expected_public_key_file.map(|_| true),
                err.to_string(),
            ));
        }
    };
    if attested_root != integrity.merkle_root.to_string() {
        return Ok(attestation_failure(
            summary,
            expected_public_key_file.map(|_| true),
            "audit attestation Merkle root does not match session integrity summary".to_string(),
        ));
    }

    let statement = match extract_statement(&bundle) {
        Ok(statement) => statement,
        Err(err) => {
            return Ok(attestation_failure(
                summary,
                expected_public_key_file.map(|_| true),
                err.to_string(),
            ));
        }
    };
    let Some(statement_session_id) = statement
        .predicate
        .get("session_id")
        .and_then(|value| value.as_str())
    else {
        return Ok(attestation_failure(
            summary,
            expected_public_key_file.map(|_| true),
            "audit attestation predicate missing session_id".to_string(),
        ));
    };
    if statement_session_id != metadata.session_id {
        return Ok(attestation_failure(
            summary,
            expected_public_key_file.map(|_| true),
            format!(
                "audit attestation session_id mismatch: expected {}, got {}",
                metadata.session_id, statement_session_id
            ),
        ));
    }

    Ok(AuditAttestationVerificationResult {
        present: true,
        predicate_type: Some(predicate_type),
        key_id: Some(summary.key_id.clone()),
        key_id_matches: true,
        signature_verified: true,
        merkle_root_matches: true,
        session_id_matches: true,
        expected_public_key_matches: expected_public_key_file.map(|_| true),
        verification_error: None,
    })
}

fn attestation_failure(
    summary: &AuditAttestationSummary,
    expected_public_key_matches: Option<bool>,
    verification_error: String,
) -> AuditAttestationVerificationResult {
    AuditAttestationVerificationResult {
        present: true,
        predicate_type: Some(summary.predicate_type.clone()),
        key_id: Some(summary.key_id.clone()),
        key_id_matches: false,
        signature_verified: false,
        merkle_root_matches: false,
        session_id_matches: false,
        expected_public_key_matches,
        verification_error: Some(verification_error),
    }
}

fn normalize_signing_secret_ref(secret_ref: &str) -> String {
    secret_ref
        .strip_prefix(KEYSTORE_URI_PREFIX)
        .unwrap_or(secret_ref)
        .to_string()
}

fn extract_statement(bundle: &trust::Bundle) -> Result<trust::InTotoStatement> {
    let bundle_json = bundle.to_json().map_err(|e| NonoError::TrustVerification {
        path: String::new(),
        reason: format!("failed to serialize audit attestation bundle: {e}"),
    })?;
    let bundle_value: serde_json::Value =
        serde_json::from_str(&bundle_json).map_err(|e| NonoError::TrustVerification {
            path: String::new(),
            reason: format!("invalid audit attestation bundle JSON: {e}"),
        })?;
    let envelope_value =
        bundle_value
            .get("dsseEnvelope")
            .ok_or_else(|| NonoError::TrustVerification {
                path: String::new(),
                reason: "audit attestation bundle missing dsseEnvelope".to_string(),
            })?;
    let envelope: trust::DsseEnvelope =
        serde_json::from_value(envelope_value.clone()).map_err(|e| {
            NonoError::TrustVerification {
                path: String::new(),
                reason: format!("invalid audit attestation DSSE envelope: {e}"),
            }
        })?;
    envelope.extract_statement()
}

fn load_public_key_file(path: &Path) -> Result<Vec<u8>> {
    let contents = fs::read_to_string(path).map_err(|e| NonoError::TrustVerification {
        path: path.display().to_string(),
        reason: format!("failed to read public key file: {e}"),
    })?;
    let trimmed = contents.trim();
    if trimmed.starts_with("-----BEGIN PUBLIC KEY-----") {
        let base64_body: String = trimmed
            .lines()
            .filter(|line| !line.starts_with("-----BEGIN") && !line.starts_with("-----END"))
            .collect();
        trust::base64::base64_decode(&base64_body).map_err(|e| NonoError::TrustVerification {
            path: path.display().to_string(),
            reason: format!("invalid PEM public key: {e}"),
        })
    } else {
        trust::base64::base64_decode(trimmed).map_err(|e| NonoError::TrustVerification {
            path: path.display().to_string(),
            reason: format!("invalid base64 DER public key: {e}"),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use nono::undo::AuditIntegritySummary;
    use std::path::PathBuf;

    const TEST_SIGNING_KEY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgskOkyJkTwlMZkm/L
eEleLY6bARaHFnqauYJqxNoJWvihRANCAASt6g2Zt0STlgF+wZ64JzdDRlpPeNr1
h56ZLEEqHfVWFhJWIKRSabtxYPV/VJyMv+lo3L0QwSKsouHs3dtF1zVQ
-----END PRIVATE KEY-----";

    fn sample_metadata() -> SessionMetadata {
        SessionMetadata {
            session_id: "sess-1".to_string(),
            started: "2026-04-22T12:00:00Z".to_string(),
            ended: Some("2026-04-22T12:00:01Z".to_string()),
            command: vec!["/bin/pwd".to_string()],
            executable_identity: None,
            tracked_paths: vec![PathBuf::from("/tmp/project")],
            snapshot_count: 0,
            exit_code: Some(0),
            merkle_roots: Vec::new(),
            network_events: Vec::new(),
            audit_event_count: 2,
            audit_integrity: Some(AuditIntegritySummary {
                hash_algorithm: "sha256".to_string(),
                event_count: 2,
                chain_head: ContentHash::from_bytes([0x11; 32]),
                merkle_root: ContentHash::from_bytes([0x22; 32]),
            }),
            audit_attestation: None,
        }
    }

    #[test]
    fn audit_attestation_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let key_pair = trust::generate_signing_key().unwrap();
        let key_id = trust::key_id_hex(&key_pair).unwrap();
        let public_key = trust::export_public_key(&key_pair).unwrap();
        let signer = AuditSigner {
            key_pair,
            key_id,
            public_key_b64: trust::base64::base64_encode(public_key.as_bytes()),
        };
        let mut metadata = sample_metadata();
        let summary = write_audit_attestation(
            dir.path(),
            &metadata,
            &signer,
            &nono::ScrubPolicy::secure_default(),
        )
        .unwrap();
        metadata.audit_attestation = Some(summary);

        let verified = verify_audit_attestation(dir.path(), &metadata, None).unwrap();
        assert!(verified.present);
        assert!(verified.key_id_matches);
        assert!(verified.signature_verified);
        assert!(verified.merkle_root_matches);
        assert!(verified.session_id_matches);
        assert_eq!(verified.expected_public_key_matches, None);
        assert!(verified.verification_error.is_none());
    }

    #[test]
    fn audit_attestation_predicate_scrubs_command_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let key_pair = trust::generate_signing_key().unwrap();
        let key_id = trust::key_id_hex(&key_pair).unwrap();
        let public_key = trust::export_public_key(&key_pair).unwrap();
        let signer = AuditSigner {
            key_pair,
            key_id,
            public_key_b64: trust::base64::base64_encode(public_key.as_bytes()),
        };
        let mut metadata = sample_metadata();
        metadata.command = vec![
            "curl".to_string(),
            "-H".to_string(),
            "Authorization: Bearer real-token".to_string(),
            "https://example.com/api?token=query-secret&format=json".to_string(),
        ];

        write_audit_attestation(
            dir.path(),
            &metadata,
            &signer,
            &nono::ScrubPolicy::secure_default(),
        )
        .unwrap();

        let bundle_path = dir.path().join(AUDIT_ATTESTATION_BUNDLE_FILENAME);
        let bundle = trust::load_bundle(&bundle_path).unwrap();
        let statement = extract_statement(&bundle).unwrap();
        let command_json = statement
            .predicate
            .get("command")
            .and_then(|value| serde_json::to_string(value).ok())
            .unwrap();

        assert!(command_json.contains("[REDACTED]"));
        assert!(!command_json.contains("real-token"));
        assert!(!command_json.contains("query-secret"));
    }

    #[test]
    fn audit_attestation_predicate_records_redaction_policy_diff() {
        let dir = tempfile::tempdir().unwrap();
        let key_pair = trust::generate_signing_key().unwrap();
        let key_id = trust::key_id_hex(&key_pair).unwrap();
        let public_key = trust::export_public_key(&key_pair).unwrap();
        let signer = AuditSigner {
            key_pair,
            key_id,
            public_key_b64: trust::base64::base64_encode(public_key.as_bytes()),
        };
        let mut metadata = sample_metadata();
        metadata.command = vec![
            "curl".to_string(),
            "--private-token=private-secret".to_string(),
            "https://example.com/callback?state=visible&token=hidden".to_string(),
        ];
        let mut redactions = nono::ScrubPolicy::secure_default();
        redactions.add_flag("--private-token");
        redactions.remove_query_key("state");

        write_audit_attestation(dir.path(), &metadata, &signer, &redactions).unwrap();

        let bundle_path = dir.path().join(AUDIT_ATTESTATION_BUNDLE_FILENAME);
        let bundle = trust::load_bundle(&bundle_path).unwrap();
        let statement = extract_statement(&bundle).unwrap();
        let predicate_json = serde_json::to_string(&statement.predicate).unwrap();

        assert!(predicate_json.contains("--private-token=[REDACTED]"));
        assert!(predicate_json.contains("state=visible"));
        assert!(predicate_json.contains("\"added_flags\":[\"--private-token\"]"));
        assert!(predicate_json.contains("\"removed_query_keys\":[\"state\"]"));
        assert!(!predicate_json.contains("private-secret"));
        assert!(!predicate_json.contains("token=hidden"));
    }

    #[test]
    fn audit_attestation_file_uri_signer_loads() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("audit-signing-key.pk8.b64");
        let pkcs8_b64: String = TEST_SIGNING_KEY_PEM
            .lines()
            .filter(|line| !line.starts_with("-----BEGIN") && !line.starts_with("-----END"))
            .collect();
        fs::write(&key_file, pkcs8_b64).unwrap();

        let signer = prepare_audit_signer(Some(&format!("file://{}", key_file.display()))).unwrap();
        assert!(signer.is_some());
    }

    #[test]
    fn audit_attestation_mismatch_is_reported_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let key_pair = trust::generate_signing_key().unwrap();
        let key_id = trust::key_id_hex(&key_pair).unwrap();
        let public_key = trust::export_public_key(&key_pair).unwrap();
        let signer = AuditSigner {
            key_pair,
            key_id,
            public_key_b64: trust::base64::base64_encode(public_key.as_bytes()),
        };
        let mut metadata = sample_metadata();
        let summary = write_audit_attestation(
            dir.path(),
            &metadata,
            &signer,
            &nono::ScrubPolicy::secure_default(),
        )
        .unwrap();
        metadata.audit_attestation = Some(summary);
        metadata.session_id = "tampered-session".to_string();

        let verified = verify_audit_attestation(dir.path(), &metadata, None).unwrap();
        assert!(verified.present);
        assert!(!verified.signature_verified);
        assert!(verified.verification_error.is_some());
    }
}
