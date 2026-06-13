//! DSSE (Dead Simple Signing Envelope) parsing and PAE construction
//!
//! Implements the DSSE protocol for instruction file attestation:
//! - Envelope parsing and serialization (JSON)
//! - Pre-Authentication Encoding (PAE) for signature verification
//! - In-toto Statement v1 extraction from envelope payload
//!
//! # References
//!
//! - [DSSE protocol](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md)
//! - [In-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)

use crate::error::{NonoError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The expected payload type for in-toto attestation statements.
pub const IN_TOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// The expected statement type for in-toto v1.
pub const IN_TOTO_STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";

/// The predicate type for nono instruction file attestations.
pub const NONO_PREDICATE_TYPE: &str = "https://nono.sh/attestation/instruction-file/v1";

/// The predicate type for nono trust policy attestations.
pub const NONO_POLICY_PREDICATE_TYPE: &str = "https://nono.sh/attestation/trust-policy/v1";

/// The predicate type for nono multi-file attestations.
///
/// Used when multiple files are signed together in a single bundle
/// (e.g., a skill's SKILL.md + companion scripts). All files appear
/// as subjects in the same in-toto statement.
pub const NONO_MULTI_SUBJECT_PREDICATE_TYPE: &str = "https://nono.sh/attestation/multi-file/v1";

/// A DSSE (Dead Simple Signing Envelope).
///
/// Contains a base64url-encoded payload, its type identifier, and one or
/// more signatures over `PAE(payloadType, payload)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseEnvelope {
    /// MIME type of the payload (e.g., `application/vnd.in-toto+json`)
    pub payload_type: String,
    /// Base64url-encoded payload (the in-toto statement)
    pub payload: String,
    /// One or more signatures over `PAE(payloadType, decoded_payload)`
    pub signatures: Vec<DsseSignature>,
}

impl DsseEnvelope {
    /// Parse a DSSE envelope from a JSON string.
    ///
    /// # Errors
    ///
    /// Returns `NonoError::TrustVerification` if the JSON is malformed.
    pub fn from_json(json: &str) -> Result<Self> {
        let envelope: Self =
            serde_json::from_str(json).map_err(|e| NonoError::TrustVerification {
                path: String::new(),
                reason: format!("invalid DSSE envelope: {e}"),
            })?;
        envelope.validate()?;
        Ok(envelope)
    }

    /// Serialize to JSON.
    ///
    /// # Errors
    ///
    /// Returns `NonoError::TrustVerification` if serialization fails.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| NonoError::TrustVerification {
            path: String::new(),
            reason: format!("failed to serialize DSSE envelope: {e}"),
        })
    }

    /// Validate structural integrity of the envelope.
    fn validate(&self) -> Result<()> {
        if self.payload_type.is_empty() {
            return Err(NonoError::TrustVerification {
                path: String::new(),
                reason: "DSSE envelope has empty payloadType".to_string(),
            });
        }
        if self.payload.is_empty() {
            return Err(NonoError::TrustVerification {
                path: String::new(),
                reason: "DSSE envelope has empty payload".to_string(),
            });
        }
        if self.signatures.is_empty() {
            return Err(NonoError::TrustVerification {
                path: String::new(),
                reason: "DSSE envelope has no signatures".to_string(),
            });
        }
        Ok(())
    }

    /// Decode the payload from base64url.
    ///
    /// # Errors
    ///
    /// Returns `NonoError::TrustVerification` if the payload is not valid base64url.
    pub fn decode_payload(&self) -> Result<Vec<u8>> {
        base64url_decode(&self.payload).map_err(|e| NonoError::TrustVerification {
            path: String::new(),
            reason: format!("failed to decode DSSE payload: {e}"),
        })
    }

    /// Decode and parse the payload as an in-toto Statement.
    ///
    /// # Errors
    ///
    /// Returns `NonoError::TrustVerification` if decoding or parsing fails,
    /// or if the payload type is not `application/vnd.in-toto+json`.
    pub fn extract_statement(&self) -> Result<InTotoStatement> {
        if self.payload_type != IN_TOTO_PAYLOAD_TYPE {
            return Err(NonoError::TrustVerification {
                path: String::new(),
                reason: format!(
                    "unexpected DSSE payloadType: expected '{}', got '{}'",
                    IN_TOTO_PAYLOAD_TYPE, self.payload_type
                ),
            });
        }
        let bytes = self.decode_payload()?;
        let json = std::str::from_utf8(&bytes).map_err(|e| NonoError::TrustVerification {
            path: String::new(),
            reason: format!("DSSE payload is not valid UTF-8: {e}"),
        })?;
        InTotoStatement::from_json(json)
    }

    /// Compute the PAE (Pre-Authentication Encoding) for this envelope.
    ///
    /// The PAE is the byte string that signatures are computed over:
    /// `PAE(payloadType, decoded_payload)`
    ///
    /// # Errors
    ///
    /// Returns `NonoError::TrustVerification` if the payload cannot be decoded.
    pub fn pae_bytes(&self) -> Result<Vec<u8>> {
        let decoded = self.decode_payload()?;
        Ok(pae(&self.payload_type, &decoded))
    }
}

/// A single signature within a DSSE envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsseSignature {
    /// Optional key identifier (not authenticated by DSSE)
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub keyid: String,
    /// Base64url-encoded signature over `PAE(payloadType, payload)`
    pub sig: String,
}

impl DsseSignature {
    /// Decode the signature bytes from base64url.
    ///
    /// # Errors
    ///
    /// Returns `NonoError::TrustVerification` if the signature is not valid base64url.
    pub fn decode_sig(&self) -> Result<Vec<u8>> {
        base64url_decode(&self.sig).map_err(|e| NonoError::TrustVerification {
            path: String::new(),
            reason: format!("failed to decode DSSE signature: {e}"),
        })
    }
}

/// An in-toto attestation Statement (v1).
///
/// The statement is the decoded payload of a DSSE envelope. It identifies
/// the artifact(s) being attested and the predicate (attestation metadata).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InTotoStatement {
    /// Statement type (must be `https://in-toto.io/Statement/v1`)
    #[serde(rename = "_type")]
    pub statement_type: String,
    /// Artifacts being attested
    pub subject: Vec<InTotoSubject>,
    /// Predicate type URI
    pub predicate_type: String,
    /// Predicate content (nono instruction file attestation metadata)
    pub predicate: serde_json::Value,
}

impl InTotoStatement {
    /// Parse from a JSON string.
    ///
    /// # Errors
    ///
    /// Returns `NonoError::TrustVerification` if parsing or validation fails.
    pub fn from_json(json: &str) -> Result<Self> {
        let stmt: Self = serde_json::from_str(json).map_err(|e| NonoError::TrustVerification {
            path: String::new(),
            reason: format!("invalid in-toto statement: {e}"),
        })?;
        stmt.validate()?;
        Ok(stmt)
    }

    /// Validate the statement structure.
    fn validate(&self) -> Result<()> {
        if self.statement_type != IN_TOTO_STATEMENT_TYPE {
            return Err(NonoError::TrustVerification {
                path: String::new(),
                reason: format!(
                    "unexpected in-toto statement type: expected '{}', got '{}'",
                    IN_TOTO_STATEMENT_TYPE, self.statement_type
                ),
            });
        }
        if self.subject.is_empty() {
            return Err(NonoError::TrustVerification {
                path: String::new(),
                reason: "in-toto statement has no subjects".to_string(),
            });
        }
        for subject in &self.subject {
            if subject.name.is_empty() {
                return Err(NonoError::TrustVerification {
                    path: String::new(),
                    reason: "in-toto subject has empty name".to_string(),
                });
            }
            if !subject.digest.contains_key("sha256") {
                return Err(NonoError::TrustVerification {
                    path: String::new(),
                    reason: format!("in-toto subject '{}' missing sha256 digest", subject.name),
                });
            }
        }
        Ok(())
    }

    /// Get the SHA-256 digest of the first subject.
    ///
    /// Returns `None` if the statement has no subjects or the first
    /// subject has no sha256 digest.
    #[must_use]
    pub fn first_subject_digest(&self) -> Option<&str> {
        self.subject
            .first()
            .and_then(|s| s.digest.get("sha256"))
            .map(String::as_str)
    }

    /// Get the name of the first subject.
    #[must_use]
    pub fn first_subject_name(&self) -> Option<&str> {
        self.subject.first().map(|s| s.name.as_str())
    }

    /// Extract the signer identity from the predicate.
    ///
    /// Parses the `predicate.signer` object to determine if the attestation
    /// was produced by a keyed or keyless signer.
    ///
    /// # Errors
    ///
    /// Returns `NonoError::TrustVerification` if the predicate is missing
    /// or has an unrecognized signer kind.
    pub fn extract_signer(&self) -> Result<super::types::SignerIdentity> {
        let signer = self
            .predicate
            .get("signer")
            .ok_or_else(|| NonoError::TrustVerification {
                path: String::new(),
                reason: "predicate missing 'signer' field".to_string(),
            })?;

        let kind = signer.get("kind").and_then(|v| v.as_str()).ok_or_else(|| {
            NonoError::TrustVerification {
                path: String::new(),
                reason: "signer missing 'kind' field".to_string(),
            }
        })?;

        match kind {
            "keyed" => {
                let key_id = signer
                    .get("key_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| NonoError::TrustVerification {
                        path: String::new(),
                        reason: "keyed signer missing 'key_id'".to_string(),
                    })?;
                Ok(super::types::SignerIdentity::Keyed {
                    key_id: key_id.to_string(),
                })
            }
            "keyless" => {
                let issuer = get_str_field(signer, "issuer")?;
                let repository = get_str_field(signer, "repository")?;
                let workflow = signer
                    .get("workflow_ref")
                    .and_then(|v| v.as_str())
                    .map(|s| {
                        // Strip @ref suffix if present (workflow_ref includes it)
                        s.split('@').next().unwrap_or(s).to_string()
                    })
                    .ok_or_else(|| NonoError::TrustVerification {
                        path: String::new(),
                        reason: "keyless signer missing 'workflow_ref'".to_string(),
                    })?;
                let git_ref = signer
                    .get("subject")
                    .and_then(|v| v.as_str())
                    .map(|s| {
                        // Extract ref from "repo:org/repo:ref:refs/..." format
                        extract_ref_from_subject(s)
                    })
                    .ok_or_else(|| NonoError::TrustVerification {
                        path: String::new(),
                        reason: "keyless signer missing 'subject'".to_string(),
                    })?;
                let build_signer_uri = get_str_field(signer, "build_signer_uri")?;
                Ok(super::types::SignerIdentity::Keyless {
                    issuer,
                    repository,
                    workflow,
                    git_ref,
                    build_signer_uri,
                })
            }
            other => Err(NonoError::TrustVerification {
                path: String::new(),
                reason: format!("unknown signer kind: '{other}'"),
            }),
        }
    }
}

/// A single subject in an in-toto statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InTotoSubject {
    /// Name of the artifact (typically the filename)
    pub name: String,
    /// Map of digest algorithm to hex-encoded digest value
    pub digest: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// PAE (Pre-Authentication Encoding)
// ---------------------------------------------------------------------------

/// Compute the DSSE Pre-Authentication Encoding.
///
/// ```text
/// PAE(type, body) = "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(body) + SP + body
/// ```
///
/// Where `SP` is ASCII space (0x20) and `LEN(s)` is the decimal byte length.
#[must_use]
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let header = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    );
    let mut result = Vec::with_capacity(header.len() + payload.len());
    result.extend_from_slice(header.as_bytes());
    result.extend_from_slice(payload);
    result
}

// ---------------------------------------------------------------------------
// In-toto statement construction helpers
// ---------------------------------------------------------------------------

/// Create a new in-toto statement with a custom predicate type.
///
/// Generic constructor used by both instruction file and trust policy
/// attestation builders.
#[must_use]
pub fn new_statement(
    subject_name: &str,
    sha256_digest: &str,
    predicate: serde_json::Value,
    predicate_type: &str,
) -> InTotoStatement {
    let mut digest = HashMap::new();
    digest.insert("sha256".to_string(), sha256_digest.to_string());

    InTotoStatement {
        statement_type: IN_TOTO_STATEMENT_TYPE.to_string(),
        subject: vec![InTotoSubject {
            name: subject_name.to_string(),
            digest,
        }],
        predicate_type: predicate_type.to_string(),
        predicate,
    }
}

/// Create a new in-toto statement for a nono instruction file attestation.
///
/// This is used during signing to build the statement that goes into the
/// DSSE envelope payload.
#[must_use]
pub fn new_instruction_statement(
    filename: &str,
    sha256_digest: &str,
    signer_predicate: serde_json::Value,
) -> InTotoStatement {
    new_statement(
        filename,
        sha256_digest,
        signer_predicate,
        NONO_PREDICATE_TYPE,
    )
}

/// Create a new in-toto statement for a nono trust policy attestation.
///
/// Uses the policy-specific predicate type to distinguish policy bundles
/// from instruction file bundles.
#[must_use]
pub fn new_policy_statement(
    filename: &str,
    sha256_digest: &str,
    signer_predicate: serde_json::Value,
) -> InTotoStatement {
    new_statement(
        filename,
        sha256_digest,
        signer_predicate,
        NONO_POLICY_PREDICATE_TYPE,
    )
}

/// Create a new in-toto statement for a multi-file attestation.
///
/// Each `(name, sha256_hex)` pair becomes a subject in the statement.
/// Used when signing multiple files together (e.g., SKILL.md + lib/script.py).
///
/// # Panics
///
/// Does not panic. Returns a statement with the provided subjects.
#[must_use]
pub fn new_multi_subject_statement(
    subjects: &[(String, String)],
    signer_predicate: serde_json::Value,
) -> InTotoStatement {
    let subject = subjects
        .iter()
        .map(|(name, sha256_hex)| {
            let mut digest = HashMap::new();
            digest.insert("sha256".to_string(), sha256_hex.clone());
            InTotoSubject {
                name: name.clone(),
                digest,
            }
        })
        .collect();

    InTotoStatement {
        statement_type: IN_TOTO_STATEMENT_TYPE.to_string(),
        subject,
        predicate_type: NONO_MULTI_SUBJECT_PREDICATE_TYPE.to_string(),
        predicate: signer_predicate,
    }
}

/// Create a DSSE envelope wrapping an in-toto statement.
///
/// The payload is base64url-encoded. Signatures must be added separately
/// after computing `PAE(payloadType, raw_payload)`.
///
/// # Errors
///
/// Returns `NonoError::TrustVerification` if statement serialization fails.
pub fn new_envelope(statement: &InTotoStatement) -> Result<DsseEnvelope> {
    let payload_json =
        serde_json::to_string(statement).map_err(|e| NonoError::TrustVerification {
            path: String::new(),
            reason: format!("failed to serialize in-toto statement: {e}"),
        })?;
    let payload_b64 = base64url_encode(payload_json.as_bytes());

    Ok(DsseEnvelope {
        payload_type: IN_TOTO_PAYLOAD_TYPE.to_string(),
        payload: payload_b64,
        signatures: Vec::new(),
    })
}

// Base64url helpers delegated to the shared base64 module
use super::base64::{base64url_decode, base64url_encode};

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Extract a required string field from a JSON value.
fn get_str_field(value: &serde_json::Value, field: &str) -> Result<String> {
    value
        .get(field)
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| NonoError::TrustVerification {
            path: String::new(),
            reason: format!("keyless signer missing '{field}'"),
        })
}

/// Extract the git ref from a Fulcio subject string.
///
/// Format: `repo:org/repo:ref:refs/heads/main` -> `refs/heads/main`
fn extract_ref_from_subject(subject: &str) -> String {
    // Look for ":ref:" separator
    if let Some(idx) = subject.find(":ref:") {
        return subject[idx + 5..].to_string();
    }
    // Fallback: return as-is
    subject.to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sample_statement_json() -> String {
        serde_json::json!({
            "_type": IN_TOTO_STATEMENT_TYPE,
            "subject": [{
                "name": "SKILLS.md",
                "digest": { "sha256": "abcdef1234567890" }
            }],
            "predicateType": NONO_PREDICATE_TYPE,
            "predicate": {
                "version": 1,
                "signer": {
                    "kind": "keyed",
                    "key_id": "nono-keystore:default"
                }
            }
        })
        .to_string()
    }

    fn sample_envelope_json() -> String {
        let payload = base64url_encode(sample_statement_json().as_bytes());
        serde_json::json!({
            "payloadType": IN_TOTO_PAYLOAD_TYPE,
            "payload": payload,
            "signatures": [{
                "keyid": "",
                "sig": base64url_encode(b"fake-signature")
            }]
        })
        .to_string()
    }

    mod pae {
        use super::super::*;

        #[test]
        fn pae_spec_test_vector() {
            // From the DSSE spec
            let result = pae("http://example.com/HelloWorld", b"hello world");
            let expected = b"DSSEv1 29 http://example.com/HelloWorld 11 hello world";
            assert_eq!(result, expected.to_vec());
        }

        #[test]
        fn pae_in_toto_type() {
            let payload = b"test payload";
            let result = pae(IN_TOTO_PAYLOAD_TYPE, payload);
            let expected_prefix = format!(
                "DSSEv1 {} {} {} ",
                IN_TOTO_PAYLOAD_TYPE.len(),
                IN_TOTO_PAYLOAD_TYPE,
                payload.len()
            );
            assert!(result.starts_with(expected_prefix.as_bytes()));
            assert!(result.ends_with(payload));
        }

        #[test]
        fn pae_empty_payload() {
            let result = pae("type", b"");
            assert_eq!(result, b"DSSEv1 4 type 0 ".to_vec());
        }

        #[test]
        fn pae_binary_payload() {
            let payload = vec![0x00, 0x01, 0xFF, 0xFE];
            let result = pae("binary", &payload);
            assert!(result.ends_with(&payload));
        }
    }

    mod dsse_envelope {
        use super::super::*;
        use super::sample_envelope_json;

        #[test]
        fn envelope_parse_valid() {
            let json = sample_envelope_json();
            let envelope = DsseEnvelope::from_json(&json).unwrap();
            assert_eq!(envelope.payload_type, IN_TOTO_PAYLOAD_TYPE);
            assert_eq!(envelope.signatures.len(), 1);
        }

        #[test]
        fn envelope_parse_invalid_json() {
            let result = DsseEnvelope::from_json("not json");
            assert!(result.is_err());
        }

        #[test]
        fn envelope_parse_empty_payload() {
            let json = serde_json::json!({
                "payloadType": IN_TOTO_PAYLOAD_TYPE,
                "payload": "",
                "signatures": [{"sig": "abc"}]
            })
            .to_string();
            let result = DsseEnvelope::from_json(&json);
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("empty payload"));
        }

        #[test]
        fn envelope_parse_no_signatures() {
            let json = serde_json::json!({
                "payloadType": IN_TOTO_PAYLOAD_TYPE,
                "payload": "dGVzdA",
                "signatures": []
            })
            .to_string();
            let result = DsseEnvelope::from_json(&json);
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("no signatures"));
        }

        #[test]
        fn envelope_decode_payload() {
            let json = sample_envelope_json();
            let envelope = DsseEnvelope::from_json(&json).unwrap();
            let decoded = envelope.decode_payload().unwrap();
            let decoded_str = std::str::from_utf8(&decoded).unwrap();
            assert!(decoded_str.contains(IN_TOTO_STATEMENT_TYPE));
        }

        #[test]
        fn envelope_extract_statement() {
            let json = sample_envelope_json();
            let envelope = DsseEnvelope::from_json(&json).unwrap();
            let stmt = envelope.extract_statement().unwrap();
            assert_eq!(stmt.statement_type, IN_TOTO_STATEMENT_TYPE);
            assert_eq!(stmt.subject.len(), 1);
            assert_eq!(stmt.subject[0].name, "SKILLS.md");
        }

        #[test]
        fn envelope_extract_statement_wrong_type() {
            let payload = base64url_encode(b"{}");
            let json = serde_json::json!({
                "payloadType": "text/plain",
                "payload": payload,
                "signatures": [{"sig": "abc"}]
            })
            .to_string();
            let envelope = DsseEnvelope::from_json(&json).unwrap();
            let result = envelope.extract_statement();
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("unexpected DSSE payloadType")
            );
        }

        #[test]
        fn envelope_pae_bytes() {
            let json = sample_envelope_json();
            let envelope = DsseEnvelope::from_json(&json).unwrap();
            let pae_result = envelope.pae_bytes().unwrap();
            // Should start with DSSEv1
            assert!(pae_result.starts_with(b"DSSEv1"));
        }

        #[test]
        fn envelope_to_json_roundtrip() {
            let original = sample_envelope_json();
            let envelope = DsseEnvelope::from_json(&original).unwrap();
            let serialized = envelope.to_json().unwrap();
            let reparsed = DsseEnvelope::from_json(&serialized).unwrap();
            assert_eq!(reparsed.payload_type, envelope.payload_type);
            assert_eq!(reparsed.payload, envelope.payload);
        }
    }

    mod dsse_signature {
        use super::super::*;

        #[test]
        fn signature_decode() {
            let sig = DsseSignature {
                keyid: String::new(),
                sig: base64url_encode(b"signature bytes"),
            };
            let decoded = sig.decode_sig().unwrap();
            assert_eq!(decoded, b"signature bytes");
        }
    }

    mod in_toto_statement {
        use super::super::*;
        use super::sample_statement_json;

        #[test]
        fn statement_parse_valid() {
            let json = sample_statement_json();
            let stmt = InTotoStatement::from_json(&json).unwrap();
            assert_eq!(stmt.statement_type, IN_TOTO_STATEMENT_TYPE);
            assert_eq!(stmt.predicate_type, NONO_PREDICATE_TYPE);
        }

        #[test]
        fn statement_wrong_type() {
            let json = serde_json::json!({
                "_type": "https://wrong.type/v1",
                "subject": [{ "name": "f", "digest": { "sha256": "abc" } }],
                "predicateType": NONO_PREDICATE_TYPE,
                "predicate": {}
            })
            .to_string();
            let result = InTotoStatement::from_json(&json);
            assert!(result.is_err());
        }

        #[test]
        fn statement_empty_subjects() {
            let json = serde_json::json!({
                "_type": IN_TOTO_STATEMENT_TYPE,
                "subject": [],
                "predicateType": NONO_PREDICATE_TYPE,
                "predicate": {}
            })
            .to_string();
            let result = InTotoStatement::from_json(&json);
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("no subjects"));
        }

        #[test]
        fn statement_subject_missing_digest() {
            let json = serde_json::json!({
                "_type": IN_TOTO_STATEMENT_TYPE,
                "subject": [{ "name": "f", "digest": {} }],
                "predicateType": NONO_PREDICATE_TYPE,
                "predicate": {}
            })
            .to_string();
            let result = InTotoStatement::from_json(&json);
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("sha256 digest"));
        }

        #[test]
        fn statement_first_subject_accessors() {
            let stmt = InTotoStatement::from_json(&sample_statement_json()).unwrap();
            assert_eq!(stmt.first_subject_name(), Some("SKILLS.md"));
            assert_eq!(stmt.first_subject_digest(), Some("abcdef1234567890"));
        }

        #[test]
        fn statement_extract_keyed_signer() {
            let stmt = InTotoStatement::from_json(&sample_statement_json()).unwrap();
            let identity = stmt.extract_signer().unwrap();
            match identity {
                super::super::super::types::SignerIdentity::Keyed { key_id } => {
                    assert_eq!(key_id, "nono-keystore:default");
                }
                _ => panic!("expected keyed signer"),
            }
        }

        #[test]
        fn statement_extract_keyless_signer() {
            let json = serde_json::json!({
            "_type": IN_TOTO_STATEMENT_TYPE,
            "subject": [{ "name": "SKILLS.md", "digest": { "sha256": "abc" } }],
            "predicateType": NONO_PREDICATE_TYPE,
            "predicate": {
                "version": 1,
                "signer": {
                    "kind": "keyless",
                    "issuer": "https://token.actions.githubusercontent.com",
                    "subject": "repo:org/repo:ref:refs/tags/v1.0.0",
                    "repository": "org/repo",
                    "workflow_ref": ".github/workflows/sign.yml@refs/heads/main",
                    "build_signer_uri": "https://github.com/org/repo/.github/workflows/sign.yml@refs/heads/main"
                }
            }
        })
        .to_string();
            let stmt = InTotoStatement::from_json(&json).unwrap();
            let identity = stmt.extract_signer().unwrap();
            match identity {
                super::super::super::types::SignerIdentity::Keyless {
                    issuer,
                    repository,
                    workflow,
                    git_ref,
                    build_signer_uri,
                } => {
                    assert_eq!(issuer, "https://token.actions.githubusercontent.com");
                    assert_eq!(repository, "org/repo");
                    assert_eq!(workflow, ".github/workflows/sign.yml");
                    assert_eq!(git_ref, "refs/tags/v1.0.0");
                    assert_eq!(
                        build_signer_uri,
                        "https://github.com/org/repo/.github/workflows/sign.yml@refs/heads/main"
                    );
                }
                _ => panic!("expected keyless signer"),
            }
        }

        #[test]
        fn statement_extract_keyless_gitlab_signer() {
            let json = serde_json::json!({
            "_type": IN_TOTO_STATEMENT_TYPE,
            "subject": [{ "name": "SKILLS.md", "digest": { "sha256": "abc" } }],
            "predicateType": NONO_PREDICATE_TYPE,
            "predicate": {
                "version": 1,
                "signer": {
                    "kind": "keyless",
                    "issuer": "https://gitlab.com",
                    "subject": "project_path:my-group/my-project:ref_type:branch:ref:main",
                    "repository": "my-group/my-project",
                    "workflow_ref": "gitlab.com/my-group/my-project//.gitlab-ci.yml@refs/heads/main",
                    "build_signer_uri": "gitlab.com/my-group/my-project//.gitlab-ci.yml@refs/heads/main"
                }
            }
        })
        .to_string();
            let stmt = InTotoStatement::from_json(&json).unwrap();
            let identity = stmt.extract_signer().unwrap();
            match identity {
                super::super::super::types::SignerIdentity::Keyless {
                    issuer,
                    repository,
                    workflow,
                    git_ref,
                    build_signer_uri,
                } => {
                    assert_eq!(issuer, "https://gitlab.com");
                    assert_eq!(repository, "my-group/my-project");
                    assert_eq!(workflow, "gitlab.com/my-group/my-project//.gitlab-ci.yml");
                    assert_eq!(git_ref, "main");
                    assert_eq!(
                        build_signer_uri,
                        "gitlab.com/my-group/my-project//.gitlab-ci.yml@refs/heads/main"
                    );
                }
                _ => panic!("expected keyless signer"),
            }
        }

        #[test]
        fn statement_extract_signer_unknown_kind() {
            let json = serde_json::json!({
                "_type": IN_TOTO_STATEMENT_TYPE,
                "subject": [{ "name": "f", "digest": { "sha256": "abc" } }],
                "predicateType": NONO_PREDICATE_TYPE,
                "predicate": {
                    "signer": { "kind": "unknown" }
                }
            })
            .to_string();
            let stmt = InTotoStatement::from_json(&json).unwrap();
            let result = stmt.extract_signer();
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("unknown signer kind")
            );
        }

        #[test]
        fn statement_extract_signer_missing() {
            let json = serde_json::json!({
                "_type": IN_TOTO_STATEMENT_TYPE,
                "subject": [{ "name": "f", "digest": { "sha256": "abc" } }],
                "predicateType": NONO_PREDICATE_TYPE,
                "predicate": {}
            })
            .to_string();
            let stmt = InTotoStatement::from_json(&json).unwrap();
            let result = stmt.extract_signer();
            assert!(result.is_err());
        }
    }

    mod construction_helpers {
        use super::super::*;

        #[test]
        fn new_instruction_statement_structure() {
            let predicate = serde_json::json!({
                "version": 1,
                "signer": { "kind": "keyed", "key_id": "test" }
            });
            let stmt = new_instruction_statement("SKILLS.md", "abcdef", predicate);
            assert_eq!(stmt.statement_type, IN_TOTO_STATEMENT_TYPE);
            assert_eq!(stmt.predicate_type, NONO_PREDICATE_TYPE);
            assert_eq!(stmt.subject.len(), 1);
            assert_eq!(stmt.subject[0].name, "SKILLS.md");
            assert_eq!(stmt.subject[0].digest["sha256"], "abcdef");
        }

        #[test]
        fn new_envelope_creates_valid_structure() {
            let predicate = serde_json::json!({
                "version": 1,
                "signer": { "kind": "keyed", "key_id": "test" }
            });
            let stmt = new_instruction_statement("SKILLS.md", "abcdef", predicate);
            let envelope = new_envelope(&stmt).unwrap();
            assert_eq!(envelope.payload_type, IN_TOTO_PAYLOAD_TYPE);
            assert!(envelope.signatures.is_empty());
            // Verify payload roundtrips
            let extracted = envelope.extract_statement().unwrap();
            assert_eq!(extracted.first_subject_name(), Some("SKILLS.md"));
        }

        #[test]
        fn new_policy_statement_uses_policy_predicate_type() {
            let predicate = serde_json::json!({
                "version": 1,
                "signer": { "kind": "keyed", "key_id": "test" }
            });
            let stmt = new_policy_statement("trust-policy.json", "abcdef", predicate);
            assert_eq!(stmt.statement_type, IN_TOTO_STATEMENT_TYPE);
            assert_eq!(stmt.predicate_type, NONO_POLICY_PREDICATE_TYPE);
            assert_eq!(stmt.subject[0].name, "trust-policy.json");
            assert_eq!(stmt.subject[0].digest["sha256"], "abcdef");
        }

        #[test]
        fn new_statement_accepts_custom_predicate_type() {
            let predicate = serde_json::json!({"version": 1});
            let stmt = new_statement("file.txt", "digest", predicate, "custom/type/v1");
            assert_eq!(stmt.predicate_type, "custom/type/v1");
            assert_eq!(stmt.subject[0].name, "file.txt");
        }

        #[test]
        fn instruction_and_policy_predicate_types_differ() {
            assert_ne!(NONO_PREDICATE_TYPE, NONO_POLICY_PREDICATE_TYPE);
        }

        #[test]
        fn multi_subject_predicate_type_is_unique() {
            assert_ne!(NONO_MULTI_SUBJECT_PREDICATE_TYPE, NONO_PREDICATE_TYPE);
            assert_ne!(
                NONO_MULTI_SUBJECT_PREDICATE_TYPE,
                NONO_POLICY_PREDICATE_TYPE
            );
        }
    }

    mod new_multi_subject_statement {
        use super::super::*;

        #[test]
        fn multi_subject_statement_structure() {
            let subjects = vec![
                ("SKILL.md".to_string(), "aaa111".to_string()),
                ("lib/script.py".to_string(), "bbb222".to_string()),
            ];
            let predicate = serde_json::json!({
                "version": 1,
                "signer": { "kind": "keyed", "key_id": "test" }
            });
            let stmt = new_multi_subject_statement(&subjects, predicate);

            assert_eq!(stmt.statement_type, IN_TOTO_STATEMENT_TYPE);
            assert_eq!(stmt.predicate_type, NONO_MULTI_SUBJECT_PREDICATE_TYPE);
            assert_eq!(stmt.subject.len(), 2);
            assert_eq!(stmt.subject[0].name, "SKILL.md");
            assert_eq!(stmt.subject[0].digest["sha256"], "aaa111");
            assert_eq!(stmt.subject[1].name, "lib/script.py");
            assert_eq!(stmt.subject[1].digest["sha256"], "bbb222");
        }

        #[test]
        fn multi_subject_statement_single_subject() {
            let subjects = vec![("only.md".to_string(), "digest123".to_string())];
            let predicate = serde_json::json!({"version": 1});
            let stmt = new_multi_subject_statement(&subjects, predicate);

            assert_eq!(stmt.subject.len(), 1);
            assert_eq!(stmt.subject[0].name, "only.md");
        }

        #[test]
        fn multi_subject_statement_roundtrips_through_envelope() {
            let subjects = vec![
                ("a.md".to_string(), "aaa".to_string()),
                ("b.py".to_string(), "bbb".to_string()),
                ("c.json".to_string(), "ccc".to_string()),
            ];
            let predicate = serde_json::json!({
                "version": 1,
                "signer": { "kind": "keyed", "key_id": "test" }
            });
            let stmt = new_multi_subject_statement(&subjects, predicate);
            let envelope = new_envelope(&stmt).unwrap();
            let extracted = envelope.extract_statement().unwrap();

            assert_eq!(extracted.subject.len(), 3);
            assert_eq!(extracted.predicate_type, NONO_MULTI_SUBJECT_PREDICATE_TYPE);
            assert_eq!(extracted.subject[0].name, "a.md");
            assert_eq!(extracted.subject[1].name, "b.py");
            assert_eq!(extracted.subject[2].name, "c.json");
        }

        #[test]
        fn multi_subject_statement_preserves_signer_predicate() {
            let subjects = vec![("f.md".to_string(), "ddd".to_string())];
            let predicate = serde_json::json!({
                "version": 1,
                "signer": { "kind": "keyed", "key_id": "nono-keystore:default" }
            });
            let stmt = new_multi_subject_statement(&subjects, predicate);
            let identity = stmt.extract_signer().unwrap();
            match identity {
                super::super::super::types::SignerIdentity::Keyed { key_id } => {
                    assert_eq!(key_id, "nono-keystore:default");
                }
                _ => panic!("expected keyed signer"),
            }
        }
    }

    mod extract_ref_from_subject {
        use super::super::*;

        #[test]
        fn extract_ref_standard_format() {
            assert_eq!(
                extract_ref_from_subject("repo:org/repo:ref:refs/tags/v1.0.0"),
                "refs/tags/v1.0.0"
            );
        }

        #[test]
        fn extract_ref_heads() {
            assert_eq!(
                extract_ref_from_subject("repo:org/repo:ref:refs/heads/main"),
                "refs/heads/main"
            );
        }

        #[test]
        fn extract_ref_fallback() {
            assert_eq!(
                extract_ref_from_subject("no-ref-separator"),
                "no-ref-separator"
            );
        }
    }
}
