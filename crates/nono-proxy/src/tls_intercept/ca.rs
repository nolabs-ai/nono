//! Ephemeral, per-session CA used to sign minted leaf certificates.
//!
//! The CA exists only for the lifetime of one proxy session. Its private key
//! is held in `Zeroizing<Vec<u8>>` and destroyed via `Drop`; only the public
//! certificate is written to disk (and only by the caller — this module just
//! produces the PEM bytes).
//!
//! ## Properties
//!
//! * Algorithm: ECDSA P-256 (matches the rustls/ring stack already in use)
//! * Validity: 24 hours from generation. Long enough to outlive any plausible
//!   `nono` invocation; short enough that a leaked cert file becomes useless
//!   quickly.
//! * Subject: `CN=nono-session-ca`
//! * Basic constraints: `CA:TRUE`
//! * No CRL/OCSP — meaningless for an ephemeral, local-only CA.
//!
//! ## Security
//!
//! `EphemeralCa` deliberately holds the raw key as `Zeroizing<Vec<u8>>` *and*
//! the parsed `KeyPair`. The parsed form is what `rcgen` needs to sign leaves;
//! the byte form is what `Drop` zeroizes. We accept the redundancy because
//! `rcgen::KeyPair` does not expose its internal byte buffer to us.

use crate::error::{ProxyError, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::pki_types::pem::PemObject;
use std::time::{Duration, SystemTime};
use time::OffsetDateTime;
use zeroize::Zeroizing;

/// Default validity window for the ephemeral CA (1 day). Long enough to cover
/// any plausible session, short enough to limit blast radius if the cert file leaks.
pub const CA_VALIDITY_DEFAULT: Duration = Duration::from_secs(24 * 60 * 60);

/// Ephemeral CA used to sign per-hostname leaf certificates for TLS interception.
///
/// `Drop` zeroizes the private key bytes. The public certificate is exposed
/// via [`EphemeralCa::cert_pem`] for inclusion in the trust bundle written
/// for the sandboxed child.
pub struct EphemeralCa {
    /// Raw PKCS#8 DER bytes of the CA private key. Zeroized on `Drop`.
    /// Exposed via [`Self::key_der`] for persistence to macOS Keychain.
    key_pkcs8_der: Zeroizing<Vec<u8>>,
    /// Issuer for signing minted leaf certificates (owns CA params and key pair).
    issuer: Issuer<'static, KeyPair>,
    /// Authoritative DER bytes of the CA certificate, used in TLS chains.
    /// In `generate()` this comes from the self-signed cert. In `from_existing()`
    /// this is the original cert DER (not the re-signed reconstruction), ensuring
    /// the chain cert matches what's in the trust store.
    cert_der: Vec<u8>,
    /// Cached PEM encoding of the public certificate.
    cert_pem: String,
    /// CA certificate expiry. Leaf certificates are minted with this same
    /// `not_after` so they never outlive the issuer.
    not_after: SystemTime,
}

impl EphemeralCa {
    /// Reconstruct a CA from previously persisted key material.
    ///
    /// Used by `--trust-proxy-ca` to reuse a CA across sessions: the CLI
    /// loads the key and cert from macOS Keychain and passes them here so the
    /// proxy can sign leaves with the same CA that's already trusted in the
    /// user's system trust store.
    ///
    /// The re-signed `ca_cert` may differ in serial/timestamps from the
    /// original PEM — that's expected. We keep the original `cert_pem` and
    /// `cert_der` for the trust bundle and TLS chain; `ca_cert` is only used
    /// as rcgen's issuer type for `signed_by()`.
    pub fn from_existing(key_der: &[u8], cert_pem: &str) -> Result<Self> {
        let pkcs8 = PrivatePkcs8KeyDer::from(key_der);
        let key_pair = KeyPair::from_der_and_sign_algo(&pkcs8.into(), &PKCS_ECDSA_P256_SHA256)
            .map_err(|e| {
                ProxyError::Config(format!(
                    "failed to load CA key from persisted material: {e}"
                ))
            })?;
        let key_pkcs8_der = Zeroizing::new(key_der.to_vec());

        let cert_der = rustls::pki_types::CertificateDer::from_pem_slice(cert_pem.as_bytes())
            .map_err(|e| {
                ProxyError::Config(format!(
                    "failed to decode persisted CA cert PEM to DER: {e}"
                ))
            })?
            .to_vec();

        // Validate that the loaded key actually matches the cert's public key.
        // Without this, a corrupted Keychain (e.g. from a concurrent write race)
        // would silently produce a CA whose chain cert doesn't match its signing
        // key, causing TLS handshake failures.
        validate_key_cert_binding(&key_pair, &cert_der)?;

        let not_after = extract_not_after_from_der(&cert_der)?;
        let issuer = Issuer::from_ca_cert_pem(cert_pem, key_pair).map_err(|e| {
            ProxyError::Config(format!(
                "failed to reconstruct issuer from persisted material: {e}"
            ))
        })?;

        Ok(Self {
            key_pkcs8_der,
            issuer,
            cert_der,
            cert_pem: cert_pem.to_string(),
            not_after,
        })
    }

    /// Generate a fresh ephemeral CA with the default session CN and validity.
    ///
    /// All material is created in-memory; nothing is persisted.
    pub fn generate() -> Result<Self> {
        Self::generate_with_cn("nono-session-ca", CA_VALIDITY_DEFAULT)
    }

    /// Generate a fresh CA with a custom Common Name and validity duration.
    ///
    /// Used by `--trust-proxy-ca` to create a CA with `CN=nono-proxy-ca` so
    /// it appears with a recognizable name in macOS Keychain and trust store.
    pub fn generate_with_cn(cn: &str, validity: Duration) -> Result<Self> {
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| {
            ProxyError::Config(format!("failed to generate ephemeral CA key pair: {}", e))
        })?;
        let key_pkcs8_der = Zeroizing::new(key_pair.serialize_der());

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        let now = SystemTime::now();
        let not_after = now + validity;
        params.not_before = system_time_to_offset(now)?;
        params.not_after = system_time_to_offset(not_after)?;

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        params.distinguished_name = dn;

        let self_signed = params
            .self_signed(&key_pair)
            .map_err(|e| ProxyError::Config(format!("failed to self-sign ephemeral CA: {}", e)))?;
        let cert_pem = self_signed.pem();
        let cert_der = self_signed.der().to_vec();
        let issuer = Issuer::new(params, key_pair);

        Ok(Self {
            key_pkcs8_der,
            issuer,
            cert_der,
            cert_pem,
            not_after,
        })
    }

    /// Public certificate PEM for inclusion in the trust bundle.
    #[must_use]
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// PKCS#8 DER-encoded private key bytes for external persistence.
    ///
    /// Used by `--trust-proxy-ca` to store the CA key in macOS Keychain so it
    /// can be reused across sessions via [`Self::from_existing`].
    #[must_use]
    pub fn key_der(&self) -> &[u8] {
        &self.key_pkcs8_der
    }

    /// PKCS#8 PEM-encoded private key for combined storage. Zeroized on drop.
    #[must_use]
    pub fn key_pem(&self) -> Zeroizing<String> {
        use base64::Engine;
        use zeroize::Zeroize;
        let mut encoded = base64::engine::general_purpose::STANDARD.encode(&*self.key_pkcs8_der);
        let mut pem = String::with_capacity(encoded.len() + 64);
        pem.push_str("-----BEGIN PRIVATE KEY-----\n");
        for chunk in encoded.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
            pem.push('\n');
        }
        pem.push_str("-----END PRIVATE KEY-----\n");
        encoded.zeroize();
        Zeroizing::new(pem)
    }

    /// Authoritative DER bytes of the CA certificate for TLS chains.
    ///
    /// In `from_existing()` this is the original cert (matching the trust
    /// store), not the re-signed reconstruction.
    #[must_use]
    pub(super) fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// Issuer used by [`super::cert_cache`] to sign minted leaf certificates.
    pub(super) fn issuer(&self) -> &Issuer<'static, KeyPair> {
        &self.issuer
    }

    /// CA certificate expiry time. Leaf certs are minted with this same
    /// `not_after` so they never outlive the issuer.
    pub(super) fn not_after(&self) -> SystemTime {
        self.not_after
    }
}

impl std::fmt::Debug for EphemeralCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EphemeralCa")
            .field("subject", &"CN=nono-session-ca")
            .field("issuer", &"[REDACTED]")
            .field("key_pkcs8_der", &"[REDACTED]")
            .field("cert_pem_len", &self.cert_pem.len())
            .finish()
    }
}

// `Zeroizing<Vec<u8>>` already zeroes on drop — explicit `Drop` isn't strictly
// necessary, but keep the field for clarity and compile-time enforcement that
// the byte buffer travels with the struct.

/// Verify that the key pair's public key matches the SubjectPublicKeyInfo
/// embedded in the certificate DER.
fn validate_key_cert_binding(key_pair: &KeyPair, cert_der: &[u8]) -> Result<()> {
    use x509_parser::prelude::FromDer;

    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(cert_der).map_err(|e| {
        ProxyError::Config(format!("failed to parse cert DER for key binding: {e}"))
    })?;

    let cert_pubkey_raw = &cert.public_key().subject_public_key.data;
    let key_pubkey_raw = key_pair.public_key_raw();

    if &**cert_pubkey_raw != key_pubkey_raw {
        return Err(ProxyError::Config(
            "persisted CA key does not match cert public key (Keychain corruption?)".to_string(),
        ));
    }
    Ok(())
}

/// Extract the `not_after` timestamp from a DER-encoded X.509 certificate.
fn extract_not_after_from_der(cert_der: &[u8]) -> Result<SystemTime> {
    use x509_parser::prelude::FromDer;

    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(cert_der).map_err(|e| {
        ProxyError::Config(format!(
            "failed to parse cert DER for not_after extraction: {e}"
        ))
    })?;
    let not_after_epoch = cert.validity().not_after.timestamp();
    let secs = u64::try_from(not_after_epoch).map_err(|_| {
        ProxyError::Config(format!(
            "CA certificate not_after is before Unix epoch (timestamp={not_after_epoch})"
        ))
    })?;
    let not_after = SystemTime::UNIX_EPOCH + Duration::from_secs(secs);
    Ok(not_after)
}

/// Split a combined PEM bundle (PKCS#8 key + certificate) into DER key bytes
/// and certificate PEM. The key material is returned in `Zeroizing` for safe
/// memory handling.
pub fn split_key_cert_pem(combined: &str) -> Result<(Zeroizing<Vec<u8>>, String)> {
    use base64::Engine;
    use zeroize::Zeroize;

    const BEGIN_KEY: &str = "-----BEGIN PRIVATE KEY-----";
    const END_KEY: &str = "-----END PRIVATE KEY-----";

    let key_start = combined
        .find(BEGIN_KEY)
        .ok_or_else(|| ProxyError::Config("CA bundle missing PRIVATE KEY block".to_string()))?;
    let key_end = combined
        .find(END_KEY)
        .ok_or_else(|| ProxyError::Config("CA bundle missing END PRIVATE KEY".to_string()))?;

    let b64_start = key_start + BEGIN_KEY.len();
    let mut b64 = combined[b64_start..key_end].replace(['\n', '\r', ' '], "");
    let key_der = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .map_err(|e| ProxyError::Config(format!("CA key base64 invalid: {e}")))?,
    );
    b64.zeroize();

    let cert_pem = combined[key_end + END_KEY.len()..].trim_start().to_string();
    if cert_pem.is_empty() {
        return Err(ProxyError::Config(
            "CA bundle missing certificate PEM".to_string(),
        ));
    }

    Ok((key_der, cert_pem))
}

/// Convert `SystemTime` to the `time::OffsetDateTime` that `rcgen` expects.
fn system_time_to_offset(t: SystemTime) -> Result<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp(
        t.duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| ProxyError::Config(format!("system time before unix epoch: {}", e)))?
            .as_secs()
            .try_into()
            .map_err(|_| ProxyError::Config("system time exceeds i64::MAX".to_string()))?,
    )
    .map_err(|e| ProxyError::Config(format!("invalid system time for cert validity: {}", e)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;

    #[test]
    fn generate_produces_valid_pem() {
        let ca = EphemeralCa::generate().unwrap();
        assert!(ca.cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(ca.cert_pem().contains("END CERTIFICATE"));

        // Round-trip through rustls' PEM parser to confirm the output is a
        // syntactically valid X.509 certificate.
        let der = CertificateDer::from_pem_slice(ca.cert_pem().as_bytes()).unwrap();
        assert!(!der.as_ref().is_empty());
    }

    #[test]
    fn each_call_produces_distinct_keys() {
        let a = EphemeralCa::generate().unwrap();
        let b = EphemeralCa::generate().unwrap();
        assert_ne!(
            a.cert_pem(),
            b.cert_pem(),
            "ephemeral CAs must not reuse key material across sessions"
        );
    }

    #[test]
    fn debug_redacts_key_material() {
        let ca = EphemeralCa::generate().unwrap();
        let dbg = format!("{:?}", ca);
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn from_existing_roundtrips_key_material() {
        let original = EphemeralCa::generate().unwrap();
        let key_der = original.key_der().to_vec();
        let cert_pem = original.cert_pem().to_string();

        let reconstructed = EphemeralCa::from_existing(&key_der, &cert_pem).unwrap();
        assert_eq!(reconstructed.cert_pem(), cert_pem);
    }

    #[test]
    fn from_existing_can_sign_leaves() {
        use crate::tls_intercept::CertCache;
        use std::sync::Arc;

        let original = EphemeralCa::generate().unwrap();
        let key_der = original.key_der().to_vec();
        let cert_pem = original.cert_pem().to_string();

        let ca = EphemeralCa::from_existing(&key_der, &cert_pem).unwrap();
        let cache = CertCache::new(Arc::new(ca));
        let leaf = cache.get_or_mint("api.github.com").unwrap();
        assert_eq!(leaf.cert.len(), 2);
        assert!(!leaf.cert[0].as_ref().is_empty());
    }

    #[test]
    fn from_existing_preserves_original_cert_der() {
        let original = EphemeralCa::generate().unwrap();
        let key_der = original.key_der().to_vec();
        let cert_pem = original.cert_pem().to_string();
        let original_der = CertificateDer::from_pem_slice(cert_pem.as_bytes()).unwrap();

        let reconstructed = EphemeralCa::from_existing(&key_der, &cert_pem).unwrap();
        assert_eq!(
            reconstructed.cert_der(),
            original_der.as_ref(),
            "cert_der() must return the original cert DER, not the re-signed reconstruction"
        );
    }

    #[test]
    fn from_existing_rejects_mismatched_key_cert() {
        let a = EphemeralCa::generate().unwrap();
        let b = EphemeralCa::generate().unwrap();
        let result = EphemeralCa::from_existing(a.key_der(), b.cert_pem());
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("does not match"),
            "expected key binding error, got: {msg}"
        );
    }

    #[test]
    fn from_existing_rejects_garbage_key() {
        let garbage = vec![0u8; 64];
        assert!(
            EphemeralCa::from_existing(
                &garbage,
                "-----BEGIN CERTIFICATE-----\nfoo\n-----END CERTIFICATE-----"
            )
            .is_err()
        );
    }

    #[test]
    fn key_pem_roundtrips_to_der() {
        use base64::Engine;

        let ca = EphemeralCa::generate().unwrap();
        let pem = ca.key_pem();

        let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap();
        assert_eq!(decoded, ca.key_der());
    }

    #[test]
    fn split_key_cert_pem_roundtrips() {
        let ca = EphemeralCa::generate_with_cn("nono-proxy-ca", CA_VALIDITY_DEFAULT).unwrap();
        let combined = format!("{}{}", &*ca.key_pem(), ca.cert_pem());

        let (key_der, cert_pem) = split_key_cert_pem(&combined).unwrap();
        assert_eq!(&*key_der, ca.key_der());
        assert_eq!(cert_pem, ca.cert_pem());
    }

    #[test]
    fn split_key_cert_pem_rejects_missing_key() {
        let ca = EphemeralCa::generate().unwrap();
        assert!(split_key_cert_pem(ca.cert_pem()).is_err());
    }

    #[test]
    fn split_key_cert_pem_rejects_missing_cert() {
        let ca = EphemeralCa::generate().unwrap();
        assert!(split_key_cert_pem(&ca.key_pem()).is_err());
    }
}
