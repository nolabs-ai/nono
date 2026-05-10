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
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use std::time::{Duration, SystemTime};
use time::OffsetDateTime;
use zeroize::Zeroizing;

/// Validity window for the ephemeral CA. Long enough to cover any plausible
/// session, short enough to limit blast radius if the cert file leaks.
const CA_VALIDITY: Duration = Duration::from_secs(24 * 60 * 60);

/// Ephemeral CA used to sign per-hostname leaf certificates for TLS interception.
///
/// `Drop` zeroizes the private key bytes. The public certificate is exposed
/// via [`EphemeralCa::cert_pem`] for inclusion in the trust bundle written
/// for the sandboxed child.
pub struct EphemeralCa {
    /// Parsed key pair used by `rcgen` to sign minted leaves.
    key_pair: KeyPair,
    /// Raw PKCS#8 DER bytes of the CA private key, kept solely so `Drop`
    /// can zeroize them. Never written to disk, never logged, never returned.
    #[allow(dead_code)]
    key_pkcs8_der: Zeroizing<Vec<u8>>,
    /// The CA certificate in `rcgen` form so leaves can be signed against it.
    ca_cert: rcgen::Certificate,
    /// Cached PEM encoding of the public certificate.
    cert_pem: String,
}

impl EphemeralCa {
    /// Generate a fresh ephemeral CA.
    ///
    /// All material is created in-memory; nothing is persisted.
    pub fn generate() -> Result<Self> {
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| {
            ProxyError::Config(format!("failed to generate ephemeral CA key pair: {}", e))
        })?;
        // Capture the raw key bytes so Drop can zeroize them. The `KeyPair`
        // itself does not expose a byte view, so we keep this redundant copy.
        let key_pkcs8_der = Zeroizing::new(key_pair.serialize_der());

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        let now = SystemTime::now();
        params.not_before = system_time_to_offset(now)?;
        params.not_after = system_time_to_offset(now + CA_VALIDITY)?;

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "nono-session-ca");
        params.distinguished_name = dn;

        let ca_cert = params
            .self_signed(&key_pair)
            .map_err(|e| ProxyError::Config(format!("failed to self-sign ephemeral CA: {}", e)))?;
        let cert_pem = ca_cert.pem();

        Ok(Self {
            key_pair,
            key_pkcs8_der,
            ca_cert,
            cert_pem,
        })
    }

    /// Public certificate PEM for inclusion in the trust bundle.
    #[must_use]
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Borrow the parsed CA certificate (used by [`super::cert_cache`] to
    /// sign minted leaves).
    pub(super) fn ca_cert(&self) -> &rcgen::Certificate {
        &self.ca_cert
    }

    /// Borrow the parsed key pair (used by [`super::cert_cache`] to sign).
    pub(super) fn key_pair(&self) -> &KeyPair {
        &self.key_pair
    }
}

impl std::fmt::Debug for EphemeralCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EphemeralCa")
            .field("subject", &"CN=nono-session-ca")
            .field("key_pair", &"[REDACTED]")
            .field("key_pkcs8_der", &"[REDACTED]")
            .field("cert_pem_len", &self.cert_pem.len())
            .finish()
    }
}

// `Zeroizing<Vec<u8>>` already zeroes on drop — explicit `Drop` isn't strictly
// necessary, but keep the field for clarity and compile-time enforcement that
// the byte buffer travels with the struct.

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
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::CertificateDer;

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
}
