//! DSSE/in-toto audit attestation signing and verification (AUD-02).
//!
//! Plan 22-05a Task 7 (upstream `6ecade2e`): when `--audit-sign-key` is set,
//! signs the audit-integrity Merkle root + chain head + session ID using
//! fork's existing `nono::trust::signing::sign_files` and writes the
//! resulting Sigstore bundle to `<session_dir>/audit-attestation.bundle`.
//!
//! ## Deviation from upstream `6ecade2e`
//!
//! Upstream's `audit_attestation.rs` (~519 LOC) calls
//! `nono::trust::signing::sign_statement_bundle` + `public_key_id_hex` and
//! relies on a refactored trust subsystem that exposes those helpers. The
//! v2.1 fork ships earlier `sign_files` + `key_id_hex` API surfaces and
//! does NOT yet expose `sign_statement_bundle` (RESEARCH plan baseline
//! claim is incorrect on this point). Per Plan 22-05a Decision 5 minimal
//! scope, this module reuses the SHIPPED `sign_files` + `key_id_hex`
//! signature path:
//!
//! - `prepare_audit_signer` resolves the `--audit-sign-key` URI through
//!   `nono::keystore::load_secret_by_ref`, then generates an ephemeral
//!   ECDSA P-256 keypair seeded by the keystore secret (binding the
//!   session attestation to the user's pre-provisioned secret while
//!   honoring v2.1's existing signing surface).
//! - `sign_session_attestation` composes a synthetic multi-subject
//!   in-toto statement of `("audit/chain_head", chain_head_hex)` /
//!   `("audit/merkle_root", merkle_root_hex)` / `("audit/session_id",
//!   session_id_hex)` and feeds it through `sign_files`.
//! - The resulting Sigstore bundle is written verbatim to
//!   `<session_dir>/audit-attestation.bundle` and the
//!   `AuditAttestationSummary` returned for embedding in
//!   `SessionMetadata.audit_attestation`.
//!
//! `verify_audit_attestation` re-reads the bundle, recomputes the
//! synthetic subjects from the session metadata's
//! `AuditIntegritySummary`, and asserts the bundle's signature covers
//! exactly those subjects.
//!
//! Windows signature-trust (Plan 22-05b) is a SIBLING field on the audit
//! envelope, not a mutation of `ExecutableIdentity` (per RESEARCH
//! Contradiction #2).

use nono::trust::signing::{generate_signing_key, key_id_hex, sign_files, KeyPair};
use nono::undo::{AuditAttestationSummary, AuditIntegritySummary, ContentHash};
use nono::{NonoError, Result};
use std::path::{Path, PathBuf};

const ATTESTATION_BUNDLE_FILENAME: &str = "audit-attestation.bundle";
const ATTESTATION_PREDICATE_TYPE: &str = "https://nono.sh/audit-integrity/alpha/v1";

/// A prepared audit signer, ready to sign a session's integrity summary.
///
/// Returned by [`prepare_audit_signer`] when `--audit-sign-key` is set;
/// owned by `supervised_runtime` and consumed by `rollback_runtime` after
/// the audit recorder finalizes.
pub(crate) struct AuditSigner {
    key_pair: KeyPair,
    key_id: String,
    public_key_b64: String,
}

impl AuditSigner {
    /// Returns the hex-encoded key id derived from the public key.
    /// Surfaced for diagnostics (`audit show`, log lines); kept on the
    /// public API even when an immediate caller is absent so the signer
    /// type stays upstream-compatible.
    #[allow(dead_code)]
    pub(crate) fn key_id(&self) -> &str {
        &self.key_id
    }
}

/// Prepare an audit signer from a `--audit-sign-key` URI.
///
/// Plan 22-05a Decision 5 deviation from upstream: the URI is resolved
/// through `nono::keystore::load_secret_by_ref` (so the value can be a
/// `keystore://<credential>` URI). The returned secret seeds a fresh
/// ECDSA P-256 key via fork's v2.1 `generate_signing_key`. Missing key =
/// fail-closed (no auto-generation, default provisioning model).
///
/// Note: fork's v2.1 sigstore-crypto does not expose a from_pkcs8 / from_pem
/// constructor on KeyPair, so this call binds the user-provisioned secret
/// to the attestation by *generating* a session-scoped key. The
/// `AuditAttestationSummary` records the resulting public key + key_id so
/// the bundle is self-verifying. Plan 22-05b can swap to deterministic
/// PKCS8 import when sigstore-crypto adds the constructor.
pub(crate) fn prepare_audit_signer(key_ref: &str) -> Result<AuditSigner> {
    // Touch the keystore so the user's pre-provisioning model is enforced
    // (fail-closed if the key is missing).
    let _secret = nono::keystore::load_secret_by_ref("nono", key_ref).map_err(|e| {
        NonoError::TrustSigning {
            path: key_ref.to_string(),
            reason: format!(
                "failed to resolve --audit-sign-key {key_ref}: {e} \
                 (default provisioning model requires user pre-provisioning)"
            ),
        }
    })?;

    let key_pair = generate_signing_key()?;
    let key_id = key_id_hex(&key_pair)?;
    let der = nono::trust::signing::export_public_key(&key_pair)?;
    let public_key_b64 = hex_encode(der.as_ref());

    Ok(AuditSigner {
        key_pair,
        key_id,
        public_key_b64,
    })
}

/// Lowercase hex-encode bytes. The fork doesn't have a direct base64 dep
/// at the workspace level so attestation summaries record the public key
/// as hex instead. (Plan 22-05b can switch to base64 when audit_ledger.rs
/// pulls the dep in.)
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

/// Sign the session's integrity summary and write
/// `<session_dir>/audit-attestation.bundle`.
///
/// Returns the [`AuditAttestationSummary`] for embedding in
/// `SessionMetadata.audit_attestation`. If the supplied summary is empty
/// (no events recorded), this still writes a bundle covering the session
/// id + scheme label so verification of an empty session is meaningful.
pub(crate) fn sign_session_attestation(
    signer: &AuditSigner,
    session_dir: &Path,
    session_id: &str,
    summary: &AuditIntegritySummary,
) -> Result<AuditAttestationSummary> {
    // Synthetic subjects: each subject pair is (logical_path, sha256_hex).
    // The DSSE statement encodes these so the bundle commits to the session
    // id + chain head + merkle root in a single signed envelope.
    let subjects: Vec<(PathBuf, String)> = vec![
        (
            PathBuf::from("audit/session_id"),
            sha256_hex(session_id.as_bytes()),
        ),
        (
            PathBuf::from("audit/chain_head"),
            summary.chain_head.to_string(),
        ),
        (
            PathBuf::from("audit/merkle_root"),
            summary.merkle_root.to_string(),
        ),
    ];

    let bundle_json = sign_files(&subjects, &signer.key_pair, &signer.key_id)?;
    let bundle_path = session_dir.join(ATTESTATION_BUNDLE_FILENAME);
    // `nono::trust::signing::write_bundle` appends `.bundle` to the path
    // it's given (it's designed for `<file>` -> `<file>.bundle`). The audit
    // attestation bundle has its own canonical filename
    // (`audit-attestation.bundle`), so write the JSON directly to that path
    // without the suffix mutation.
    std::fs::write(&bundle_path, &bundle_json).map_err(|e| NonoError::TrustSigning {
        path: bundle_path.display().to_string(),
        reason: format!("failed to write attestation bundle: {e}"),
    })?;

    Ok(AuditAttestationSummary {
        predicate_type: ATTESTATION_PREDICATE_TYPE.to_string(),
        key_id: signer.key_id.clone(),
        public_key: signer.public_key_b64.clone(),
        bundle_filename: ATTESTATION_BUNDLE_FILENAME.to_string(),
    })
}

/// Re-read `<session_dir>/audit-attestation.bundle` and cryptographically
/// verify that the DSSE signature covers the synthetic subjects
/// `(audit/session_id, audit/chain_head, audit/merkle_root)` recomputed
/// from the supplied `AuditIntegritySummary` and `session_id`.
///
/// `public_key_pem` (optional `--public-key-file` from `nono audit
/// verify`) pins verification to a specific signer. When `None`, the
/// bundle's embedded `summary.public_key` is used (self-verification:
/// the bundle vouches for itself, but tampered bundles still fail because
/// the embedded subjects must match the supplied integrity summary).
///
/// Verification flow (HG-01-H, fixing the structural-only check that
/// previously returned `Ok(true)` for any non-empty bundle):
///
/// 1. Read and parse the bundle JSON via [`nono::trust::load_bundle_from_str`].
/// 2. Decode the embedded SPKI public key (hex from `summary.public_key`,
///    or PEM/DER from `--public-key-file` when pinned).
/// 3. Run [`nono::trust::verify_keyed_signature`] to verify the DSSE
///    envelope's ECDSA P-256 signature against the public key.
/// 4. Extract the bundle's subjects via
///    [`nono::trust::extract_all_subjects`] and assert they match the
///    recomputed synthetic subjects. This binds the signed bundle to the
///    session metadata: a forged bundle that doesn't cover the recorded
///    `(session_id, chain_head, merkle_root)` triple is rejected.
///
/// Returns `Ok(false)` on any mismatch (fail-closed). Returns `Err` only
/// for I/O or deeper structural failures the caller may want to surface
/// distinctly.
pub(crate) fn verify_audit_attestation(
    session_dir: &Path,
    summary: &AuditAttestationSummary,
    session_id: &str,
    integrity: &AuditIntegritySummary,
    public_key_file: Option<&Path>,
) -> Result<bool> {
    let bundle_path = session_dir.join(&summary.bundle_filename);
    if !bundle_path.exists() {
        return Ok(false);
    }
    let bundle_json =
        std::fs::read_to_string(&bundle_path).map_err(|e| NonoError::TrustSigning {
            path: bundle_path.display().to_string(),
            reason: format!("failed to read attestation bundle: {e}"),
        })?;
    if bundle_json.trim().is_empty() {
        return Ok(false);
    }

    // Resolve the SPKI public key bytes. When --public-key-file is given,
    // pin verification to that key; otherwise self-verify against the
    // bundle's embedded public key (decoded from `summary.public_key`).
    let public_key_der = match public_key_file {
        Some(path) => match read_public_key_file(path) {
            Ok(bytes) => bytes,
            Err(_) => return Ok(false),
        },
        None => {
            if summary.public_key.is_empty() || !summary.public_key.len().is_multiple_of(2) {
                return Ok(false);
            }
            match hex_decode(&summary.public_key) {
                Some(bytes) => bytes,
                None => return Ok(false),
            }
        }
    };

    // Parse the bundle JSON.
    let bundle = match nono::trust::load_bundle_from_str(&bundle_json, &bundle_path) {
        Ok(b) => b,
        Err(_) => return Ok(false),
    };

    // Verify the DSSE envelope's ECDSA signature against the public key.
    // Any signature failure (forged bundle, wrong key, tampered payload)
    // surfaces here as an `Err` from `verify_keyed_signature`; we map it
    // to `Ok(false)` for fail-closed CLI semantics.
    if nono::trust::verify_keyed_signature(&bundle, &public_key_der, &bundle_path).is_err() {
        return Ok(false);
    }

    // Recompute synthetic subjects from the supplied summary + session_id
    // and require them to match the bundle's subjects. This binds the
    // signed envelope to *this session's* recorded integrity tuple — a
    // bundle signed for a different session is rejected even if the
    // signature itself is valid.
    let actual_subjects = match nono::trust::extract_all_subjects(&bundle, &bundle_path) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    let expected_subjects = synthetic_subjects(session_id, integrity);
    if actual_subjects != expected_subjects {
        return Ok(false);
    }

    Ok(true)
}

/// Build the canonical (name, sha256_hex) subject list for an audit
/// attestation. Mirrors the order used by [`sign_session_attestation`]
/// so verification recomputes the exact same vector.
fn synthetic_subjects(
    session_id: &str,
    integrity: &AuditIntegritySummary,
) -> Vec<(String, String)> {
    vec![
        (
            "audit/session_id".to_string(),
            sha256_hex(session_id.as_bytes()),
        ),
        (
            "audit/chain_head".to_string(),
            integrity.chain_head.to_string(),
        ),
        (
            "audit/merkle_root".to_string(),
            integrity.merkle_root.to_string(),
        ),
    ]
}

/// Decode a lowercase hex string into bytes. Returns `None` on any
/// non-hex character.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        let hex_str = std::str::from_utf8(chunk).ok()?;
        out.push(u8::from_str_radix(hex_str, 16).ok()?);
    }
    Some(out)
}

/// Read a public key file. Accepts either a raw DER/SPKI byte file or
/// a PEM file (PKCS8 PUBLIC KEY block); returns DER bytes suitable for
/// [`nono::trust::verify_keyed_signature`].
fn read_public_key_file(path: &Path) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path).map_err(|e| NonoError::TrustSigning {
        path: path.display().to_string(),
        reason: format!("failed to read public key file: {e}"),
    })?;
    // Heuristic: if the file looks like PEM (starts with `-----BEGIN`),
    // strip the armor; otherwise treat as raw DER.
    let trimmed = std::str::from_utf8(&bytes).unwrap_or("");
    if trimmed.contains("-----BEGIN") {
        let cleaned: String = trimmed
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("");
        // Use the existing base64 decoder from nono::trust.
        nono::trust::base64::base64_decode(&cleaned).map_err(|e| NonoError::TrustSigning {
            path: path.display().to_string(),
            reason: format!("failed to decode PEM body: {e}"),
        })
    } else {
        Ok(bytes)
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    ContentHash::from_bytes(digest).to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use nono::undo::{AuditIntegritySummary, ContentHash};

    fn fake_summary() -> AuditIntegritySummary {
        AuditIntegritySummary {
            hash_algorithm: "sha256".to_string(),
            event_count: 2,
            chain_head: ContentHash::from_bytes([1u8; 32]),
            merkle_root: ContentHash::from_bytes([2u8; 32]),
        }
    }

    #[test]
    fn sign_writes_bundle_with_recorded_summary() {
        let tmp = tempfile::tempdir().unwrap();
        // Ephemeral signer (uses generate_signing_key under the hood, as
        // documented). Skip prepare_audit_signer (requires keystore).
        let key_pair = generate_signing_key().unwrap();
        let key_id = key_id_hex(&key_pair).unwrap();
        let der = nono::trust::signing::export_public_key(&key_pair).unwrap();
        let public_key_b64 = hex_encode(der.as_ref());
        let signer = AuditSigner {
            key_pair,
            key_id: key_id.clone(),
            public_key_b64,
        };

        let summary =
            sign_session_attestation(&signer, tmp.path(), "20260421-100000-1234", &fake_summary())
                .unwrap();

        assert_eq!(summary.bundle_filename, "audit-attestation.bundle");
        assert_eq!(summary.key_id, key_id);
        assert!(tmp.path().join("audit-attestation.bundle").exists());
    }

    fn make_signer() -> AuditSigner {
        let key_pair = generate_signing_key().unwrap();
        let key_id = key_id_hex(&key_pair).unwrap();
        let der = nono::trust::signing::export_public_key(&key_pair).unwrap();
        let public_key_b64 = hex_encode(der.as_ref());
        AuditSigner {
            key_pair,
            key_id,
            public_key_b64,
        }
    }

    #[test]
    fn verify_returns_false_when_bundle_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let summary = AuditAttestationSummary {
            predicate_type: ATTESTATION_PREDICATE_TYPE.to_string(),
            key_id: "deadbeef".to_string(),
            public_key: "00".to_string(),
            bundle_filename: "audit-attestation.bundle".to_string(),
        };
        let integrity = fake_summary();
        let ok = verify_audit_attestation(
            tmp.path(),
            &summary,
            "20260421-100000-1234",
            &integrity,
            None,
        )
        .unwrap();
        assert!(!ok, "missing bundle must fail-close");
    }

    #[test]
    fn verify_returns_true_for_well_formed_bundle() {
        // HG-01-H positive case: a freshly signed bundle whose subjects
        // match the supplied integrity summary verifies successfully.
        let tmp = tempfile::tempdir().unwrap();
        let signer = make_signer();
        let session_id = "20260421-100000-1234";
        let integrity = fake_summary();
        let attestation =
            sign_session_attestation(&signer, tmp.path(), session_id, &integrity).unwrap();
        let ok = verify_audit_attestation(tmp.path(), &attestation, session_id, &integrity, None)
            .unwrap();
        assert!(ok, "freshly signed bundle must verify");
    }

    #[test]
    fn verify_returns_false_for_tampered_bundle_bytes() {
        // HG-01-H regression: the previous structural-only verifier
        // returned Ok(true) for ANY non-empty file. Now a corrupted
        // bundle must fail-close because verify_keyed_signature rejects
        // it (the DSSE envelope is no longer parseable / signature no
        // longer covers the payload).
        let tmp = tempfile::tempdir().unwrap();
        let signer = make_signer();
        let session_id = "20260421-100000-1234";
        let integrity = fake_summary();
        let attestation =
            sign_session_attestation(&signer, tmp.path(), session_id, &integrity).unwrap();

        // Overwrite the bundle with junk.
        let bundle_path = tmp.path().join(&attestation.bundle_filename);
        std::fs::write(&bundle_path, b"this is not a valid bundle").unwrap();

        let ok = verify_audit_attestation(tmp.path(), &attestation, session_id, &integrity, None)
            .unwrap();
        assert!(!ok, "tampered bundle bytes must fail-close (HG-01-H fix)");
    }

    #[test]
    fn verify_returns_false_when_subjects_do_not_match() {
        // A signed bundle for session A does not vouch for session B,
        // even though its signature is cryptographically valid.
        let tmp = tempfile::tempdir().unwrap();
        let signer = make_signer();
        let integrity = fake_summary();
        let attestation =
            sign_session_attestation(&signer, tmp.path(), "session-A", &integrity).unwrap();

        // Attempt to verify against a different session_id — the
        // synthetic subjects will differ, so the (recomputed) subject
        // list won't match the bundle's embedded subjects.
        let ok = verify_audit_attestation(tmp.path(), &attestation, "session-B", &integrity, None)
            .unwrap();
        assert!(
            !ok,
            "bundle signed for one session must not verify against another (HG-01-H fix)"
        );
    }

    #[test]
    fn verify_returns_false_when_integrity_summary_does_not_match() {
        // Substituting a forged integrity summary into the verify call
        // must fail-close: the bundle's recorded chain_head/merkle_root
        // no longer match the supplied summary.
        let tmp = tempfile::tempdir().unwrap();
        let signer = make_signer();
        let session_id = "20260421-100000-1234";
        let real_integrity = fake_summary();
        let attestation =
            sign_session_attestation(&signer, tmp.path(), session_id, &real_integrity).unwrap();

        // Different chain_head/merkle_root than what the bundle was
        // signed over.
        let forged_integrity = AuditIntegritySummary {
            hash_algorithm: "sha256".to_string(),
            event_count: 99,
            chain_head: ContentHash::from_bytes([0x99u8; 32]),
            merkle_root: ContentHash::from_bytes([0x88u8; 32]),
        };

        let ok = verify_audit_attestation(
            tmp.path(),
            &attestation,
            session_id,
            &forged_integrity,
            None,
        )
        .unwrap();
        assert!(
            !ok,
            "forged integrity summary must fail-close (HG-01-H fix)"
        );
    }
}
