use crate::trust_cmd;
use nono::trust;
use nono::undo::{AuditAttestationSummary, SessionMetadata};
use nono::{NonoError, Result};
use std::fs;
use std::path::Path;
use zeroize::Zeroizing;

pub(crate) use nono::audit::AUDIT_ATTESTATION_BUNDLE_FILENAME;
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

pub(crate) type AuditAttestationVerificationResult =
    nono::audit::AuditAttestationVerificationResult;

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
    let (bundle_json, summary) = nono::audit::sign_audit_attestation_bundle(
        metadata,
        &signer.key_pair,
        &signer.key_id,
        &signer.public_key_b64,
        redaction_policy,
    )?;
    let bundle_path = session_dir.join(AUDIT_ATTESTATION_BUNDLE_FILENAME);
    fs::write(&bundle_path, bundle_json).map_err(|e| NonoError::TrustSigning {
        path: bundle_path.display().to_string(),
        reason: format!("failed to write audit attestation bundle: {e}"),
    })?;

    Ok(summary)
}

pub(crate) fn verify_audit_attestation(
    session_dir: &Path,
    metadata: &SessionMetadata,
    expected_public_key_file: Option<&Path>,
) -> Result<AuditAttestationVerificationResult> {
    let Some(summary) = metadata.audit_attestation.as_ref() else {
        return Ok(nono::audit::AuditAttestationVerificationResult {
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
    let bundle_path = session_dir.join(&summary.bundle_filename);
    let bundle = match trust::load_bundle(&bundle_path) {
        Ok(bundle) => bundle,
        Err(err) => {
            return Ok(nono::audit::AuditAttestationVerificationResult {
                present: true,
                predicate_type: Some(summary.predicate_type.clone()),
                key_id: Some(summary.key_id.clone()),
                key_id_matches: false,
                signature_verified: false,
                merkle_root_matches: false,
                session_id_matches: false,
                expected_public_key_matches: None,
                verification_error: Some(err.to_string()),
            });
        }
    };
    let expected_public_key = expected_public_key_file
        .map(load_public_key_file)
        .transpose()?;

    nono::audit::verify_audit_attestation_bundle(
        &bundle,
        &bundle_path,
        metadata,
        expected_public_key.as_deref(),
    )
}

fn normalize_signing_secret_ref(secret_ref: &str) -> String {
    secret_ref
        .strip_prefix(KEYSTORE_URI_PREFIX)
        .unwrap_or(secret_ref)
        .to_string()
}

#[cfg(test)]
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
    use nono::undo::{AuditIntegritySummary, ContentHash};
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
