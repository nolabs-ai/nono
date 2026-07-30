//! Sigstore bundle loading, verification, and identity extraction
//!
//! Wraps the `sigstore-verify` crate to provide bundle parsing, cryptographic
//! verification, and signer identity extraction integrated with nono's trust
//! policy types.
//!
//! # Bundle Format
//!
//! Bundles follow the Sigstore bundle v0.3 JSON format and contain:
//! - A DSSE envelope (or message signature) with the signed payload
//! - Verification material (Fulcio certificate or public key hint)
//! - Transparency log entries (Rekor inclusion proof)
//!
//! # Fulcio Certificate Extensions
//!
//! Keyless bundles contain a Fulcio-issued certificate with OIDC identity
//! claims encoded as X.509 extensions. We read v2 OIDs with v1 fallbacks:
//!
//! | OID (v2) | OID (v1) | Field | Description |
//! |----------|----------|-------|-------------|
//! | .1.1 | — | Issuer | OIDC issuer URL |
//! | .1.12 | .1.5 | Source Repository | `org/repo` (v2 URI normalized) |
//! | .1.14 | .1.6 | Source Repository Ref | Git ref at signing time |
//! | .1.9 | — | Build Signer URI | Build instructions responsible for signing |
//! | .1.18 | — | Build Config URI | Workflow path (v2 URI normalized) or GitLab CI config URI |

use crate::error::{NonoError, Result};
use crate::trust::types::SignerIdentity;
use std::path::Path;

// Re-export key sigstore types for downstream consumers
pub use sigstore_verify::crypto::CertificateInfo;
pub use sigstore_verify::trust_root::TrustedRoot;
pub use sigstore_verify::types::{Bundle, DerPublicKey, Sha256Hash};
pub use sigstore_verify::{VerificationPolicy, VerificationResult as SigstoreVerificationResult};

// Internal-only imports from sigstore
use sigstore_verify::crypto::parse_certificate_info;
use sigstore_verify::types::bundle::VerificationMaterialContent;

// ---------------------------------------------------------------------------
// Fulcio certificate extension OIDs
// ---------------------------------------------------------------------------
//
// Fulcio v2 extensions (1.3.6.1.4.1.57264.1.x) changed semantics from v1.
// The OIDs below are the correct v2 mappings for GitHub Actions OIDC certs.
//
// Reference: https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md

/// Fulcio OID for source repository URI: 1.3.6.1.4.1.57264.1.12
/// Value: `https://github.com/<org>/<repo>` (full URI, not just `org/repo`)
const OID_SOURCE_REPOSITORY_URI: &str = "1.3.6.1.4.1.57264.1.12";

/// Fulcio OID for source repository ref: 1.3.6.1.4.1.57264.1.14
/// Value: `refs/heads/main` (git ref at signing time)
const OID_SOURCE_REPOSITORY_REF: &str = "1.3.6.1.4.1.57264.1.14";

/// Fulcio OID for build config URI (workflow): 1.3.6.1.4.1.57264.1.18
/// Value: `https://github.com/<org>/<repo>/.github/workflows/<file>@<ref>`
const OID_BUILD_CONFIG_URI: &str = "1.3.6.1.4.1.57264.1.18";

/// Fulcio OID for build signer URI: 1.3.6.1.4.1.57264.1.9
/// Value: fully qualified reference to the build instructions responsible for signing.
/// For GitHub Actions this is a reusable workflow ref; for GitLab CI an Orb-style URI.
const OID_BUILD_SIGNER_URI: &str = "1.3.6.1.4.1.57264.1.9";

/// Fulcio v1 OID for source repository (short form): 1.3.6.1.4.1.57264.1.5
/// Value: `<org>/<repo>` (v1 fallback, no URI prefix)
const OID_SOURCE_REPOSITORY_V1: &str = "1.3.6.1.4.1.57264.1.5";

/// Fulcio v1 OID for source repository ref: 1.3.6.1.4.1.57264.1.6
/// Value: `refs/heads/main` (same semantics as v2 .1.14)
const OID_SOURCE_REPOSITORY_REF_V1: &str = "1.3.6.1.4.1.57264.1.6";

// ---------------------------------------------------------------------------
// Bundle loading
// ---------------------------------------------------------------------------

/// Load a Sigstore bundle from a JSON file.
///
/// Bundle files are typically named `<artifact>.bundle` (e.g., `SKILLS.md.bundle`).
///
/// # Errors
///
/// Returns `NonoError::Io` if the file cannot be read, or
/// `NonoError::TrustVerification` if the JSON is malformed.
pub fn load_bundle<P: AsRef<Path>>(path: P) -> Result<Bundle> {
    let path = path.as_ref();
    let json = std::fs::read_to_string(path).map_err(NonoError::Io)?;
    load_bundle_from_str(&json, path)
}

/// Parse a Sigstore bundle from a JSON string.
///
/// The `source_path` is used only for error messages.
///
/// # Errors
///
/// Returns `NonoError::TrustVerification` if the JSON is invalid.
pub fn load_bundle_from_str(json: &str, source_path: &Path) -> Result<Bundle> {
    Bundle::from_json(json).map_err(|e| NonoError::TrustVerification {
        path: source_path.display().to_string(),
        reason: format!("failed to parse bundle: {e}"),
    })
}

// ---------------------------------------------------------------------------
// Trust root loading
// ---------------------------------------------------------------------------

/// Load a Sigstore trusted root from a JSON file.
///
/// The trusted root contains Fulcio CA certificates, Rekor public keys,
/// and TSA certificates needed for verification.
///
/// # Errors
///
/// Returns `NonoError::TrustPolicy` if the file cannot be read or parsed.
pub fn load_trusted_root<P: AsRef<Path>>(path: P) -> Result<TrustedRoot> {
    TrustedRoot::from_file(path.as_ref())
        .map_err(|e| NonoError::TrustPolicy(format!("failed to load trusted root: {e}")))
}

/// Load a Sigstore trusted root from a JSON string.
///
/// # Errors
///
/// Returns `NonoError::TrustPolicy` if the JSON is invalid.
pub fn load_trusted_root_from_str(json: &str) -> Result<TrustedRoot> {
    TrustedRoot::from_json(json)
        .map_err(|e| NonoError::TrustPolicy(format!("failed to parse trusted root: {e}")))
}

/// Load the production Sigstore trusted root (embedded).
///
/// This uses the Sigstore public good instance trusted root that is
/// embedded in the `sigstore-trust-root` crate.
///
/// # Errors
///
/// Returns `NonoError::TrustPolicy` if the embedded root cannot be loaded.
pub fn load_production_trusted_root() -> Result<TrustedRoot> {
    TrustedRoot::from_json(sigstore_verify::trust_root::SIGSTORE_PRODUCTION_TRUSTED_ROOT)
        .map_err(|e| NonoError::TrustPolicy(format!("failed to load production trusted root: {e}")))
}

// ---------------------------------------------------------------------------
// Bundle verification
// ---------------------------------------------------------------------------

/// Verify a Sigstore bundle against an artifact's content.
///
/// Performs the full Sigstore verification pipeline:
/// 1. Bundle structural validation
/// 2. Certificate chain verification (Fulcio CA -> signing cert)
/// 3. Transparency log inclusion proof (Rekor)
/// 4. Signature verification (ECDSA over DSSE PAE)
/// 5. Artifact digest match (SHA-256 in in-toto statement vs actual file)
/// 6. Policy checks (identity/issuer matching)
///
/// # Errors
///
/// Returns `NonoError::TrustVerification` if any verification step fails.
pub fn verify_bundle(
    artifact_bytes: &[u8],
    bundle: &Bundle,
    trusted_root: &TrustedRoot,
    policy: &VerificationPolicy,
    artifact_path: &Path,
) -> Result<SigstoreVerificationResult> {
    sigstore_verify::verify(artifact_bytes, bundle, policy, trusted_root).map_err(|e| {
        NonoError::TrustVerification {
            path: artifact_path.display().to_string(),
            reason: format!("{e}"),
        }
    })
}

/// Verify a Sigstore bundle using a pre-computed SHA-256 digest.
///
/// This avoids re-reading the artifact when the digest is already known
/// (e.g., from blocklist checking earlier in the pipeline).
///
/// # Errors
///
/// Returns `NonoError::TrustVerification` if verification fails, or if
/// the digest hex string is invalid.
pub fn verify_bundle_with_digest(
    digest_hex: &str,
    bundle: &Bundle,
    trusted_root: &TrustedRoot,
    policy: &VerificationPolicy,
    artifact_path: &Path,
) -> Result<SigstoreVerificationResult> {
    let hash = Sha256Hash::from_hex(digest_hex).map_err(|e| NonoError::TrustVerification {
        path: artifact_path.display().to_string(),
        reason: format!("invalid digest hex: {e}"),
    })?;
    sigstore_verify::verify(hash, bundle, policy, trusted_root).map_err(|e| {
        NonoError::TrustVerification {
            path: artifact_path.display().to_string(),
            reason: format!("{e}"),
        }
    })
}

/// Verify a Sigstore bundle using a provided public key (keyed signing).
///
/// Used for bundles signed with a managed key (from the system keystore)
/// rather than a Fulcio-issued certificate.
///
/// # Errors
///
/// Returns `NonoError::TrustVerification` if verification fails.
pub fn verify_bundle_keyed(
    artifact_bytes: &[u8],
    bundle: &Bundle,
    public_key: &DerPublicKey,
    trusted_root: &TrustedRoot,
    artifact_path: &Path,
) -> Result<SigstoreVerificationResult> {
    sigstore_verify::verify_with_key(artifact_bytes, bundle, public_key, trusted_root).map_err(
        |e| NonoError::TrustVerification {
            path: artifact_path.display().to_string(),
            reason: format!("{e}"),
        },
    )
}

/// Verify a keyed bundle's ECDSA signature directly without a Sigstore TrustedRoot.
///
/// For keyed bundles (signed with a managed ECDSA P-256 key), this verifies the
/// DSSE envelope signature against the provided SPKI public key. This is the
/// standalone keyed verification path — it does not require Fulcio certificates,
/// Rekor transparency logs, or a TrustedRoot.
///
/// # Verification steps
///
/// 1. Serialize the bundle and extract the DSSE envelope
/// 2. Decode the payload and compute PAE(payloadType, payload)
/// 3. Decode the signature from the first signature entry
/// 4. Verify ECDSA P-256 SHA-256 signature over the PAE using the public key
///
/// # Errors
///
/// Returns `NonoError::TrustVerification` if any step fails (missing envelope
/// components, invalid encoding, or signature mismatch).
pub fn verify_keyed_signature(
    bundle: &Bundle,
    public_key_der: &[u8],
    artifact_path: &Path,
) -> Result<()> {
    use sigstore_verify::crypto::signing::SigningScheme;
    use sigstore_verify::crypto::verification::VerificationKey;
    use sigstore_verify::types::SignatureBytes;

    let contents = DsseContents::from_bundle(bundle, artifact_path)?;
    let sig_b64 = contents.signature_b64(artifact_path)?;

    // Compute PAE over the payload
    let pae_bytes = sigstore_verify::types::dsse::pae(
        crate::trust::dsse::IN_TOTO_PAYLOAD_TYPE,
        &contents.payload_bytes,
    );

    // Decode signature
    let sig_bytes =
        SignatureBytes::from_base64(&sig_b64).map_err(|e| NonoError::TrustVerification {
            path: artifact_path.display().to_string(),
            reason: format!("invalid base64 signature: {e}"),
        })?;

    // Verify ECDSA P-256 signature over the PAE
    let pub_key = DerPublicKey::from(public_key_der.to_vec());
    let vk = VerificationKey::from_spki(&pub_key, SigningScheme::EcdsaP256Sha256).map_err(|e| {
        NonoError::TrustVerification {
            path: artifact_path.display().to_string(),
            reason: format!("invalid public key: {e}"),
        }
    })?;

    vk.verify(&pae_bytes, &sig_bytes)
        .map_err(|e| NonoError::TrustVerification {
            path: artifact_path.display().to_string(),
            reason: format!("ECDSA signature verification failed: {e}"),
        })
}

// ---------------------------------------------------------------------------
// Pre-parsed DSSE envelope contents
// ---------------------------------------------------------------------------

/// Pre-parsed DSSE envelope contents from a Sigstore bundle.
///
/// Avoids repeated `bundle.to_json()` -> `serde_json::from_str()` round-trips
/// when multiple extraction functions need the same envelope fields.
struct DsseContents {
    /// The raw bundle JSON as a `serde_json::Value` (for signature extraction)
    bundle_value: serde_json::Value,
    /// Decoded DSSE payload bytes
    payload_bytes: Vec<u8>,
    /// The in-toto statement parsed from the DSSE payload
    statement: serde_json::Value,
}

impl DsseContents {
    /// Parse DSSE envelope contents from a bundle.
    fn from_bundle(bundle: &Bundle, context_path: &Path) -> Result<Self> {
        let bundle_json = bundle.to_json().map_err(|e| NonoError::TrustVerification {
            path: context_path.display().to_string(),
            reason: format!("failed to serialize bundle: {e}"),
        })?;
        let bundle_value: serde_json::Value =
            serde_json::from_str(&bundle_json).map_err(|e| NonoError::TrustVerification {
                path: context_path.display().to_string(),
                reason: format!("invalid bundle JSON: {e}"),
            })?;

        let payload_b64 = bundle_value["dsseEnvelope"]["payload"]
            .as_str()
            .ok_or_else(|| NonoError::TrustVerification {
                path: context_path.display().to_string(),
                reason: "missing DSSE payload".to_string(),
            })?;

        let payload_decoded = sigstore_verify::types::PayloadBytes::from_base64(payload_b64)
            .map_err(|e| NonoError::TrustVerification {
                path: context_path.display().to_string(),
                reason: format!("invalid DSSE payload encoding: {e}"),
            })?;

        let payload_str = std::str::from_utf8(payload_decoded.as_bytes()).map_err(|e| {
            NonoError::TrustVerification {
                path: context_path.display().to_string(),
                reason: format!("DSSE payload is not UTF-8: {e}"),
            }
        })?;

        let statement: serde_json::Value =
            serde_json::from_str(payload_str).map_err(|e| NonoError::TrustVerification {
                path: context_path.display().to_string(),
                reason: format!("invalid statement JSON: {e}"),
            })?;

        Ok(Self {
            bundle_value,
            payload_bytes: payload_decoded.as_bytes().to_vec(),
            statement,
        })
    }

    /// Extract the `subject[0].digest.sha256` from the in-toto statement.
    fn subject_digest(&self, context_path: &Path) -> Result<String> {
        self.statement["subject"][0]["digest"]["sha256"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| NonoError::TrustVerification {
                path: context_path.display().to_string(),
                reason: "no sha256 digest in statement subject".to_string(),
            })
    }

    /// Extract the `subject[0].name` from the in-toto statement.
    fn subject_name(&self, context_path: &Path) -> Result<String> {
        self.statement["subject"][0]["name"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| NonoError::TrustVerification {
                path: context_path.display().to_string(),
                reason: "no subject name in statement".to_string(),
            })
    }

    /// Extract the `predicateType` from the in-toto statement.
    fn predicate_type(&self, context_path: &Path) -> Result<String> {
        self.statement["predicateType"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| NonoError::TrustVerification {
                path: context_path.display().to_string(),
                reason: "missing predicateType in statement".to_string(),
            })
    }

    /// Extract the base64-encoded signature from the DSSE envelope.
    fn signature_b64(&self, context_path: &Path) -> Result<String> {
        self.bundle_value["dsseEnvelope"]["signatures"][0]["sig"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| NonoError::TrustVerification {
                path: context_path.display().to_string(),
                reason: "missing DSSE signature".to_string(),
            })
    }
}

// ---------------------------------------------------------------------------
// Bundle digest extraction
// ---------------------------------------------------------------------------

/// Extract the SHA-256 digest from a bundle's DSSE envelope payload.
///
/// Parses the bundle's DSSE envelope, decodes the base64 payload as an
/// in-toto statement, and returns the `subject[0].digest.sha256` value.
///
/// # Errors
///
/// Returns `NonoError::TrustVerification` if the bundle cannot be serialized,
/// the DSSE payload is missing or malformed, or the statement lacks a digest.
pub fn extract_bundle_digest(bundle: &Bundle, bundle_path: &Path) -> Result<String> {
    let contents = DsseContents::from_bundle(bundle, bundle_path)?;
    contents.subject_digest(bundle_path)
}

/// Verify that the bundle's in-toto subject name matches the expected filename.
///
/// Extracts `subject[0].name` from the DSSE payload and compares it against
/// the filename component of `expected_path`. This prevents bundle-swapping
/// attacks where a valid bundle signed for file A is used to vouch for file B.
///
/// # Errors
///
/// Returns `NonoError::TrustVerification` if the subject name cannot be extracted
/// or does not match the expected filename.
pub fn verify_bundle_subject_name(bundle: &Bundle, expected_path: &Path) -> Result<()> {
    let contents = DsseContents::from_bundle(bundle, expected_path)?;
    let subject_name = contents.subject_name(expected_path)?;

    let expected_name = expected_path
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();

    // Compare via &str directly. Going through `expected_name.as_ref()`
    // is ambiguous now that another transitive dep brings in an
    // additional `AsRef` impl for `Cow<'_, str>` (rustc can't pick).
    if subject_name.as_str() != &*expected_name {
        return Err(NonoError::TrustVerification {
            path: expected_path.display().to_string(),
            reason: format!(
                "bundle subject name '{}' does not match expected filename '{}'",
                subject_name, expected_name
            ),
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Predicate type extraction
// ---------------------------------------------------------------------------

/// Extract the `predicateType` from a bundle's DSSE envelope payload.
///
/// Returns the predicate type string (e.g., `nono.sh/attestation/instruction-file/v1`
/// or `nono.sh/attestation/trust-policy/v1`).
///
/// # Errors
///
/// Returns `NonoError::TrustVerification` if the bundle cannot be parsed or
/// the predicate type is missing.
pub fn extract_predicate_type(bundle: &Bundle, bundle_path: &Path) -> Result<String> {
    let contents = DsseContents::from_bundle(bundle, bundle_path)?;
    contents.predicate_type(bundle_path)
}

// ---------------------------------------------------------------------------
// Identity extraction
// ---------------------------------------------------------------------------

/// Extract the signer identity from a Sigstore bundle's verification material.
///
/// For bundles with a Fulcio certificate (keyless), extracts:
/// - OIDC issuer (OID .1.1)
/// - Build signer URI (OID .1.9)
/// - Source repository (OID .1.12, v1 fallback .1.5)
/// - Build config / workflow (OID .1.18)
/// - Source repository ref (OID .1.14, v1 fallback .1.6)
///
/// For bundles with a public key hint (keyed), extracts the human key ID
/// from the DSSE predicate's `signer.key_id` field. Falls back to the
/// public key hint (fingerprint) if predicate extraction fails.
///
/// # Errors
///
/// Returns `NonoError::TrustVerification` if the certificate cannot be
/// parsed or lacks required identity fields.
pub fn extract_signer_identity(bundle: &Bundle, bundle_path: &Path) -> Result<SignerIdentity> {
    match &bundle.verification_material.content {
        VerificationMaterialContent::PublicKey { hint } => {
            // Try to read the human key_id from the DSSE predicate
            match extract_keyed_identity_from_dsse(bundle, bundle_path) {
                Ok(identity) => Ok(identity),
                Err(_) => {
                    // Fall back to the public key hint (fingerprint)
                    Ok(SignerIdentity::Keyed {
                        key_id: hint.clone(),
                    })
                }
            }
        }
        VerificationMaterialContent::Certificate(cert_content) => {
            extract_identity_from_cert(cert_content.raw_bytes.as_bytes(), bundle_path)
        }
        VerificationMaterialContent::X509CertificateChain { certificates } => {
            let leaf = certificates
                .first()
                .ok_or_else(|| NonoError::TrustVerification {
                    path: bundle_path.display().to_string(),
                    reason: "empty certificate chain".to_string(),
                })?;
            extract_identity_from_cert(leaf.raw_bytes.as_bytes(), bundle_path)
        }
    }
}

/// Extract the human key_id from a keyed bundle's DSSE predicate.
///
/// Parses the bundle's DSSE envelope payload as an in-toto statement and
/// reads `predicate.signer.key_id`. This gives the operator-chosen key alias
/// (e.g., "default") rather than the cryptographic fingerprint in the hint.
fn extract_keyed_identity_from_dsse(bundle: &Bundle, bundle_path: &Path) -> Result<SignerIdentity> {
    let contents = DsseContents::from_bundle(bundle, bundle_path)?;
    let payload_str =
        std::str::from_utf8(&contents.payload_bytes).map_err(|e| NonoError::TrustVerification {
            path: bundle_path.display().to_string(),
            reason: format!("DSSE payload is not UTF-8: {e}"),
        })?;
    let statement = crate::trust::dsse::InTotoStatement::from_json(payload_str)?;
    statement.extract_signer()
}

/// Extract signer identity fields from a DER-encoded Fulcio certificate.
fn extract_identity_from_cert(cert_der: &[u8], bundle_path: &Path) -> Result<SignerIdentity> {
    let cert_info = parse_certificate_info(cert_der).map_err(|e| NonoError::TrustVerification {
        path: bundle_path.display().to_string(),
        reason: format!("failed to parse signing certificate: {e}"),
    })?;

    let issuer = cert_info
        .issuer
        .ok_or_else(|| NonoError::TrustVerification {
            path: bundle_path.display().to_string(),
            reason: "signing certificate missing OIDC issuer extension".to_string(),
        })?;

    // Extract extended Fulcio OIDs from the raw certificate
    let extensions = extract_fulcio_extensions(cert_der, bundle_path)?;

    let build_signer_uri =
        extensions
            .build_signer_uri
            .ok_or_else(|| NonoError::TrustVerification {
                path: bundle_path.display().to_string(),
                reason: "signing certificate missing build signer URI extension (OID .1.9)"
                    .to_string(),
            })?;

    let repository = extensions
        .repository
        .ok_or_else(|| NonoError::TrustVerification {
            path: bundle_path.display().to_string(),
            reason: "signing certificate missing source repository extension (OID .1.12 or .1.5)"
                .to_string(),
        })?;

    let workflow = extensions
        .workflow
        .ok_or_else(|| NonoError::TrustVerification {
            path: bundle_path.display().to_string(),
            reason: "signing certificate missing build config/workflow extension (OID .1.18)"
                .to_string(),
        })?;

    let git_ref = extensions
        .git_ref
        .ok_or_else(|| NonoError::TrustVerification {
            path: bundle_path.display().to_string(),
            reason: "signing certificate missing source ref extension (OID .1.14 or .1.6)"
                .to_string(),
        })?;

    Ok(SignerIdentity::Keyless {
        issuer,
        repository,
        workflow,
        git_ref,
        build_signer_uri,
    })
}

/// Fulcio certificate extension values beyond what `sigstore-crypto` extracts.
struct FulcioExtensions {
    build_signer_uri: Option<String>,
    repository: Option<String>,
    workflow: Option<String>,
    git_ref: Option<String>,
}

/// Extract Fulcio v2 extension values from a DER-encoded certificate.
///
/// Parses the X.509 certificate and reads the OID extensions for
/// source repository, build config (workflow), and source ref.
fn extract_fulcio_extensions(cert_der: &[u8], bundle_path: &Path) -> Result<FulcioExtensions> {
    use der::Decode;
    use x509_cert::Certificate;

    let cert = Certificate::from_der(cert_der).map_err(|e| NonoError::TrustVerification {
        path: bundle_path.display().to_string(),
        reason: format!("failed to decode certificate DER: {e}"),
    })?;

    let extensions = match &cert.tbs_certificate.extensions {
        Some(exts) => exts,
        None => {
            return Ok(FulcioExtensions {
                build_signer_uri: None,
                repository: None,
                workflow: None,
                git_ref: None,
            });
        }
    };

    let mut build_config_uri = None;
    let mut build_signer_uri = None;
    let mut repository_uri = None; // v2: full URI
    let mut repository_v1 = None; // v1: org/repo
    let mut git_ref = None;
    let mut git_ref_v1 = None;

    for ext in extensions.iter() {
        let oid_str = ext.extn_id.to_string();
        match oid_str.as_str() {
            OID_SOURCE_REPOSITORY_URI => {
                repository_uri = decode_utf8_extension(ext.extn_value.as_bytes());
            }
            OID_SOURCE_REPOSITORY_V1 => {
                repository_v1 = decode_utf8_extension(ext.extn_value.as_bytes());
            }
            OID_BUILD_CONFIG_URI => {
                build_config_uri = decode_utf8_extension(ext.extn_value.as_bytes());
            }
            OID_BUILD_SIGNER_URI => {
                build_signer_uri = decode_utf8_extension(ext.extn_value.as_bytes());
            }
            OID_SOURCE_REPOSITORY_REF => {
                git_ref = decode_utf8_extension(ext.extn_value.as_bytes());
            }
            OID_SOURCE_REPOSITORY_REF_V1 => {
                git_ref_v1 = decode_utf8_extension(ext.extn_value.as_bytes());
            }
            _ => {}
        }
    }

    // Normalize repository URI to org/repo form for policy matching.
    // v2 value: "https://github.com/org/repo" -> "org/repo"
    // v1 value: "org/repo" (already correct, but normalization handles edge cases)
    let repository = repository_uri
        .or(repository_v1)
        .map(|uri| normalize_github_uri(&uri));

    let workflow = build_config_uri.as_deref().map(normalize_workflow_uri);

    Ok(FulcioExtensions {
        build_signer_uri,
        repository,
        workflow,
        git_ref: git_ref.or(git_ref_v1),
    })
}

/// Normalize a GitHub repository URI to `org/repo` form.
///
/// Strips the `https://github.com/` prefix if present. Falls back to the
/// original value if the prefix is absent (e.g., v1 certs or non-GitHub issuers).
fn normalize_github_uri(uri: &str) -> String {
    uri.strip_prefix("https://github.com/")
        .unwrap_or(uri)
        .trim_end_matches('/')
        .to_string()
}

/// Normalize a Fulcio v2 build config URI to a relative workflow path.
///
/// v2 value: `https://github.com/org/repo/.github/workflows/file.yml@refs/heads/main`
/// Result:   `.github/workflows/file.yml`
///
/// Strips the `https://github.com/<org>/<repo>/` prefix and the `@<ref>` suffix.
/// Falls back to the original value if the format is unexpected.
fn normalize_workflow_uri(uri: &str) -> String {
    // Strip the @ref suffix first (take everything before the last @)
    let without_ref = if let Some(idx) = uri.rfind('@') {
        &uri[..idx]
    } else {
        uri
    };

    // Strip the https://github.com/org/repo/ prefix to get relative path
    if let Some(rest) = without_ref.strip_prefix("https://github.com/") {
        // rest = "org/repo/.github/workflows/file.yml"
        // Skip org/repo (first two path segments) to get ".github/..."
        let mut segments = rest.splitn(3, '/');
        let _org = segments.next();
        let _repo = segments.next();
        if let Some(relative) = segments.next() {
            return relative.trim_end_matches('/').to_string();
        }
    }

    // Fallback: return as-is
    without_ref.trim_end_matches('/').to_string()
}

/// Decode an X.509 extension value as a UTF-8 string.
///
/// Tries DER-encoded UTF8String first, then raw bytes as UTF-8 fallback.
fn decode_utf8_extension(value_bytes: &[u8]) -> Option<String> {
    // Try DER-encoded UTF8String
    if let Ok(utf8_str) = <der::asn1::Utf8StringRef<'_> as der::Decode>::from_der(value_bytes) {
        return Some(utf8_str.to_string());
    }
    // Fallback: interpret raw bytes as UTF-8
    std::str::from_utf8(value_bytes).ok().map(String::from)
}

// ---------------------------------------------------------------------------
// Helper: resolve bundle path from artifact path
// ---------------------------------------------------------------------------

/// Resolve the bundle file path for a given artifact.
///
/// Follows the convention `<artifact>.bundle` (e.g., `SKILLS.md.bundle`).
#[must_use]
pub fn bundle_path_for(artifact_path: &Path) -> std::path::PathBuf {
    let mut bundle = artifact_path.as_os_str().to_owned();
    bundle.push(".bundle");
    std::path::PathBuf::from(bundle)
}

/// Resolve the conventional path for a multi-subject trust bundle.
///
/// Multi-subject bundles are stored as `.nono-trust.bundle` in the given
/// directory (typically the project root or skill directory).
#[must_use]
pub fn multi_subject_bundle_path(dir_path: &Path) -> std::path::PathBuf {
    dir_path.join(".nono-trust.bundle")
}

// ---------------------------------------------------------------------------
// Multi-subject extraction
// ---------------------------------------------------------------------------

/// Extract all subjects from a bundle's DSSE envelope.
///
/// Returns `Vec<(name, sha256_hex)>` — one entry per subject in the
/// in-toto statement. Works for both single-subject and multi-subject bundles.
///
/// # Errors
///
/// Returns `NonoError::TrustVerification` if the bundle cannot be parsed
/// or any subject is missing a SHA-256 digest.
pub fn extract_all_subjects(bundle: &Bundle, bundle_path: &Path) -> Result<Vec<(String, String)>> {
    let contents = DsseContents::from_bundle(bundle, bundle_path)?;
    let subjects = contents
        .statement
        .get("subject")
        .and_then(|v| v.as_array())
        .ok_or_else(|| NonoError::TrustVerification {
            path: bundle_path.display().to_string(),
            reason: "no subjects array in statement".to_string(),
        })?;

    let mut result = Vec::with_capacity(subjects.len());
    for subject in subjects {
        let name = subject
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| NonoError::TrustVerification {
                path: bundle_path.display().to_string(),
                reason: "subject missing name".to_string(),
            })?;
        let digest = subject
            .get("digest")
            .and_then(|v| v.get("sha256"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| NonoError::TrustVerification {
                path: bundle_path.display().to_string(),
                reason: format!("subject '{name}' missing sha256 digest"),
            })?;
        result.push((name.to_string(), digest.to_string()));
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Helper: extract CertificateInfo (re-export for CLI use)
// ---------------------------------------------------------------------------

/// Parse certificate info from a DER-encoded certificate.
///
/// Thin wrapper around `sigstore_crypto::parse_certificate_info` that maps
/// errors to `NonoError`.
///
/// # Errors
///
/// Returns `NonoError::TrustVerification` if the certificate cannot be parsed.
pub fn parse_cert_info(cert_der: &[u8], bundle_path: &Path) -> Result<CertificateInfo> {
    parse_certificate_info(cert_der).map_err(|e| NonoError::TrustVerification {
        path: bundle_path.display().to_string(),
        reason: format!("failed to parse certificate: {e}"),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // bundle_path_for
    // -----------------------------------------------------------------------

    #[test]
    fn bundle_path_for_appends_extension() {
        let path = Path::new("SKILLS.md");
        assert_eq!(bundle_path_for(path), Path::new("SKILLS.md.bundle"));
    }

    #[test]
    fn bundle_path_for_nested_path() {
        let path = Path::new(".claude/commands/deploy.md");
        assert_eq!(
            bundle_path_for(path),
            Path::new(".claude/commands/deploy.md.bundle")
        );
    }

    #[test]
    fn bundle_path_for_absolute_path() {
        let path = Path::new("/home/user/project/CLAUDE.md");
        assert_eq!(
            bundle_path_for(path),
            Path::new("/home/user/project/CLAUDE.md.bundle")
        );
    }

    // -----------------------------------------------------------------------
    // load_bundle_from_str
    // -----------------------------------------------------------------------

    #[test]
    fn load_bundle_invalid_json() {
        let result = load_bundle_from_str("not json", Path::new("test.bundle"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("failed to parse bundle"));
    }

    #[test]
    fn load_bundle_missing_fields() {
        let json = r#"{"mediaType": "test"}"#;
        let result = load_bundle_from_str(json, Path::new("test.bundle"));
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // load_bundle from file
    // -----------------------------------------------------------------------

    #[test]
    fn load_bundle_nonexistent_file() {
        let result = load_bundle(Path::new("/nonexistent/path/test.bundle"));
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // load_trusted_root
    // -----------------------------------------------------------------------

    #[test]
    fn load_trusted_root_invalid_json() {
        let result = load_trusted_root_from_str("not json");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("failed to parse trusted root"));
    }

    #[test]
    fn load_trusted_root_nonexistent_file() {
        let result = load_trusted_root(Path::new("/nonexistent/trusted_root.json"));
        assert!(result.is_err());
    }

    #[test]
    fn load_production_trusted_root_succeeds() {
        let root = load_production_trusted_root();
        assert!(root.is_ok());
    }

    // -----------------------------------------------------------------------
    // extract_signer_identity
    // -----------------------------------------------------------------------

    #[test]
    fn extract_identity_public_key_bundle() {
        let json = make_public_key_bundle_json("nono-keystore:my-key");
        let bundle = Bundle::from_json(&json).unwrap();
        let identity = extract_signer_identity(&bundle, Path::new("test.bundle")).unwrap();
        match identity {
            SignerIdentity::Keyed { key_id } => {
                assert_eq!(key_id, "nono-keystore:my-key");
            }
            SignerIdentity::Keyless { .. } => panic!("expected keyed identity"),
        }
    }

    #[test]
    fn extract_identity_empty_cert_chain() {
        let json = make_empty_cert_chain_bundle_json();
        let bundle = Bundle::from_json(&json).unwrap();
        let result = extract_signer_identity(&bundle, Path::new("test.bundle"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("empty certificate chain"));
    }

    // -----------------------------------------------------------------------
    // verify_bundle_with_digest
    // -----------------------------------------------------------------------

    #[test]
    fn verify_bundle_with_invalid_digest() {
        let json = make_public_key_bundle_json("key");
        let bundle = Bundle::from_json(&json).unwrap();
        let root = load_production_trusted_root().unwrap();
        let policy = VerificationPolicy::default();
        let result =
            verify_bundle_with_digest("not-hex!", &bundle, &root, &policy, Path::new("test"));
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // decode_utf8_extension
    // -----------------------------------------------------------------------

    #[test]
    fn decode_utf8_extension_raw_bytes() {
        let value = b"https://github.com/org/repo";
        let result = decode_utf8_extension(value);
        assert_eq!(result, Some("https://github.com/org/repo".to_string()));
    }

    #[test]
    fn decode_utf8_extension_invalid_utf8() {
        let value = &[0xFF, 0xFE, 0x00];
        let result = decode_utf8_extension(value);
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // Helpers for constructing test bundles
    // -----------------------------------------------------------------------

    fn make_public_key_bundle_json(key_hint: &str) -> String {
        format!(
            r#"{{
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {{
                    "publicKey": {{
                        "hint": "{key_hint}"
                    }},
                    "tlogEntries": []
                }},
                "dsseEnvelope": {{
                    "payloadType": "application/vnd.in-toto+json",
                    "payload": "e30=",
                    "signatures": [
                        {{
                            "keyid": "",
                            "sig": "AAAA"
                        }}
                    ]
                }}
            }}"#
        )
    }

    // -----------------------------------------------------------------------
    // normalize_github_uri
    // -----------------------------------------------------------------------

    #[test]
    fn normalize_github_uri_strips_prefix() {
        assert_eq!(
            normalize_github_uri("https://github.com/always-further/test-sk-prov"),
            "always-further/test-sk-prov"
        );
    }

    #[test]
    fn normalize_github_uri_passthrough_v1() {
        assert_eq!(
            normalize_github_uri("always-further/test-sk-prov"),
            "always-further/test-sk-prov"
        );
    }

    #[test]
    fn normalize_github_uri_non_github() {
        assert_eq!(
            normalize_github_uri("https://gitlab.com/org/repo"),
            "https://gitlab.com/org/repo"
        );
    }

    // -----------------------------------------------------------------------
    // normalize_workflow_uri
    // -----------------------------------------------------------------------

    #[test]
    fn normalize_workflow_uri_full_v2() {
        assert_eq!(
            normalize_workflow_uri(
                "https://github.com/always-further/test-sk-prov/.github/workflows/sign-skills.yml@refs/heads/main"
            ),
            ".github/workflows/sign-skills.yml"
        );
    }

    #[test]
    fn normalize_workflow_uri_no_ref_suffix() {
        assert_eq!(
            normalize_workflow_uri("https://github.com/org/repo/.github/workflows/ci.yml"),
            ".github/workflows/ci.yml"
        );
    }

    #[test]
    fn normalize_workflow_uri_relative_passthrough() {
        assert_eq!(
            normalize_workflow_uri(".github/workflows/sign.yml"),
            ".github/workflows/sign.yml"
        );
    }

    // -----------------------------------------------------------------------
    // Real Fulcio cert identity extraction (nolabs-ai/test-sk-prov, formerly always-further/test-sk-prov)
    // -----------------------------------------------------------------------

    /// Base64-encoded Fulcio certificate from a real GitHub Actions keyless
    /// signing run on always-further/test-sk-prov (now nolabs-ai/test-sk-prov) (2026-02-21).
    const REAL_FULCIO_CERT_B64: &str = "MIIHHzCCBqSgAwIBAgIUdK++nu0/W/Lku0KJGD4t0g58ceEwCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjYwMjIxMjA0ODE1WhcNMjYwMjIxMjA1ODE1WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVjM9ubaPEkJEgCZaLottlVEXV8gaVA2+kBUlHdJeja3IIadZFJ97PM3M6vL7xmkvAm+wNKvobPua+FvAJ0OX4KOCBcMwggW/MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQU6FDp6EByF7oPn9PILe73U5HfvtswHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4YZD8wbgYDVR0RAQH/BGQwYoZgaHR0cHM6Ly9naXRodWIuY29tL2Fsd2F5cy1mdXJ0aGVyL3Rlc3Qtc2stcHJvdi8uZ2l0aHViL3dvcmtmbG93cy9zaWduLXNraWxscy55bWxAcmVmcy9oZWFkcy9tYWluMDkGCisGAQQBg78wAQEEK2h0dHBzOi8vdG9rZW4uYWN0aW9ucy5naXRodWJ1c2VyY29udGVudC5jb20wHwYKKwYBBAGDvzABAgQRd29ya2Zsb3dfZGlzcGF0Y2gwNgYKKwYBBAGDvzABAwQoYjFjYmVjMDIwZWQ4NWZiMmY1M2ExZjc4ZDIxY2RmYjE1ODI4NTJmZDAkBgorBgEEAYO/MAEEBBZTaWduIGluc3RydWN0aW9uIGZpbGVzMCkGCisGAQQBg78wAQUEG2Fsd2F5cy1mdXJ0aGVyL3Rlc3Qtc2stcHJvdjAdBgorBgEEAYO/MAEGBA9yZWZzL2hlYWRzL21haW4wOwYKKwYBBAGDvzABCAQtDCtodHRwczovL3Rva2VuLmFjdGlvbnMuZ2l0aHVidXNlcmNvbnRlbnQuY29tMHAGCisGAQQBg78wAQkEYgxgaHR0cHM6Ly9naXRodWIuY29tL2Fsd2F5cy1mdXJ0aGVyL3Rlc3Qtc2stcHJvdi8uZ2l0aHViL3dvcmtmbG93cy9zaWduLXNraWxscy55bWxAcmVmcy9oZWFkcy9tYWluMDgGCisGAQQBg78wAQoEKgwoYjFjYmVjMDIwZWQ4NWZiMmY1M2ExZjc4ZDIxY2RmYjE1ODI4NTJmZDAdBgorBgEEAYO/MAELBA8MDWdpdGh1Yi1ob3N0ZWQwPgYKKwYBBAGDvzABDAQwDC5odHRwczovL2dpdGh1Yi5jb20vYWx3YXlzLWZ1cnRoZXIvdGVzdC1zay1wcm92MDgGCisGAQQBg78wAQ0EKgwoYjFjYmVjMDIwZWQ4NWZiMmY1M2ExZjc4ZDIxY2RmYjE1ODI4NTJmZDAfBgorBgEEAYO/MAEOBBEMD3JlZnMvaGVhZHMvbWFpbjAaBgorBgEEAYO/MAEPBAwMCjExNjI4NTU2MDgwMQYKKwYBBAGDvzABEAQjDCFodHRwczovL2dpdGh1Yi5jb20vYWx3YXlzLWZ1cnRoZXIwGQYKKwYBBAGDvzABEQQLDAkyMzY3NzAwMDUwcAYKKwYBBAGDvzABEgRiDGBodHRwczovL2dpdGh1Yi5jb20vYWx3YXlzLWZ1cnRoZXIvdGVzdC1zay1wcm92Ly5naXRodWIvd29ya2Zsb3dzL3NpZ24tc2tpbGxzLnltbEByZWZzL2hlYWRzL21haW4wOAYKKwYBBAGDvzABEwQqDChiMWNiZWMwMjBlZDg1ZmIyZjUzYTFmNzhkMjFjZGZiMTU4Mjg1MmZkMCEGCisGAQQBg78wARQEEwwRd29ya2Zsb3dfZGlzcGF0Y2gwYgYKKwYBBAGDvzABFQRUDFJodHRwczovL2dpdGh1Yi5jb20vYWx3YXlzLWZ1cnRoZXIvdGVzdC1zay1wcm92L2FjdGlvbnMvcnVucy8yMjI2NDA4NzA1Ni9hdHRlbXB0cy8xMBYGCisGAQQBg78wARYECAwGcHVibGljMIGLBgorBgEEAdZ5AgQCBH0EewB5AHcA3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4pygC8p7o4AAAGcgfXMfQAABAMASDBGAiEAtmtISW6NgQSyHhcs4dsYno+Kc0hxAGB9b/KBqDPVfTgCIQCRmlb41GNcgy+6FEygkWWpoYPNQMTZ2ZxFBG4w7AQaNjAKBggqhkjOPQQDAwNpADBmAjEA0/ffhH9fK70Xbpl+FDq8Pffk4IT/eEteCN6EH6DtEbJxw9NdC2T71tUnJHksfNjYAjEArb5+ZZcAhR3bbUFvuZGlY+E+8h6C9Fsa3c5/vDzUrv7zXzBly6Et7Wfw1cDAM7Ke";

    #[test]
    fn extract_identity_from_real_fulcio_cert() {
        let cert_der = crate::trust::base64::base64_decode(REAL_FULCIO_CERT_B64).unwrap();

        let identity =
            extract_identity_from_cert(&cert_der, Path::new("SKILLS.md.bundle")).unwrap();

        match identity {
            SignerIdentity::Keyless {
                issuer,
                repository,
                workflow,
                git_ref,
                ..
            } => {
                assert_eq!(
                    issuer, "https://token.actions.githubusercontent.com",
                    "issuer mismatch"
                );
                assert_eq!(
                    repository, "always-further/test-sk-prov",
                    "repository mismatch — should be normalized from full URI"
                );
                assert_eq!(
                    workflow, ".github/workflows/sign-skills.yml",
                    "workflow mismatch — should be normalized from full URI"
                );
                assert_eq!(git_ref, "refs/heads/main", "git_ref mismatch");
            }
            SignerIdentity::Keyed { .. } => panic!("expected keyless identity"),
        }
    }

    #[test]
    fn real_fulcio_cert_matches_trust_policy() {
        let cert_der = crate::trust::base64::base64_decode(REAL_FULCIO_CERT_B64).unwrap();

        let identity =
            extract_identity_from_cert(&cert_der, Path::new("SKILLS.md.bundle")).unwrap();

        // Simulate a trust-policy.json publisher entry
        let publisher = crate::trust::types::Publisher {
            name: "test-sk-prov".to_string(),
            issuer: Some("https://token.actions.githubusercontent.com".to_string()),
            repository: Some("always-further/test-sk-prov".to_string()),
            workflow: Some(".github/workflows/sign-skills.yml".to_string()),
            ref_pattern: Some("refs/heads/main".to_string()),
            key_id: None,
            public_key: None,
            build_signer_uri: None,
        };

        assert!(
            publisher.matches(&identity),
            "publisher should match extracted identity"
        );
    }

    // -----------------------------------------------------------------------
    // multi_subject_bundle_path
    // -----------------------------------------------------------------------

    #[test]
    fn multi_subject_bundle_path_in_cwd() {
        let path = multi_subject_bundle_path(Path::new("."));
        assert_eq!(path, Path::new("./.nono-trust.bundle"));
    }

    #[test]
    fn multi_subject_bundle_path_in_dir() {
        let path = multi_subject_bundle_path(Path::new("/home/user/project"));
        assert_eq!(path, Path::new("/home/user/project/.nono-trust.bundle"));
    }

    // -----------------------------------------------------------------------
    // extract_all_subjects
    // -----------------------------------------------------------------------

    #[test]
    fn extract_all_subjects_single() {
        // Create a real signed bundle with one subject
        let kp = crate::trust::signing::generate_signing_key().unwrap();
        let json = crate::trust::signing::sign_bytes(b"content", "file.md", &kp, "key").unwrap();
        let bundle = Bundle::from_json(&json).unwrap();

        let subjects = extract_all_subjects(&bundle, Path::new("test.bundle")).unwrap();
        assert_eq!(subjects.len(), 1);
        assert_eq!(subjects[0].0, "file.md");
        assert_eq!(subjects[0].1.len(), 64); // SHA-256 hex
    }

    #[test]
    fn extract_all_subjects_multi() {
        // Create a real signed bundle with multiple subjects
        let kp = crate::trust::signing::generate_signing_key().unwrap();
        let files = vec![
            (
                std::path::PathBuf::from("SKILL.md"),
                crate::trust::digest::bytes_digest(b"skill"),
            ),
            (
                std::path::PathBuf::from("lib/helper.py"),
                crate::trust::digest::bytes_digest(b"helper"),
            ),
            (
                std::path::PathBuf::from("config.json"),
                crate::trust::digest::bytes_digest(b"config"),
            ),
        ];
        let json = crate::trust::signing::sign_files(&files, &kp, "key").unwrap();
        let bundle = Bundle::from_json(&json).unwrap();

        let subjects = extract_all_subjects(&bundle, Path::new("test.bundle")).unwrap();
        assert_eq!(subjects.len(), 3);
        assert_eq!(subjects[0].0, "SKILL.md");
        assert_eq!(subjects[1].0, "lib/helper.py");
        assert_eq!(subjects[2].0, "config.json");

        // Digests should match what we computed
        assert_eq!(subjects[0].1, crate::trust::digest::bytes_digest(b"skill"));
        assert_eq!(subjects[1].1, crate::trust::digest::bytes_digest(b"helper"));
        assert_eq!(subjects[2].1, crate::trust::digest::bytes_digest(b"config"));
    }

    fn make_empty_cert_chain_bundle_json() -> String {
        r#"{
            "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
            "verificationMaterial": {
                "x509CertificateChain": {
                    "certificates": []
                },
                "tlogEntries": []
            },
            "dsseEnvelope": {
                "payloadType": "application/vnd.in-toto+json",
                "payload": "e30=",
                "signatures": [
                    {
                        "keyid": "",
                        "sig": "AAAA"
                    }
                ]
            }
        }"#
        .to_string()
    }
}
