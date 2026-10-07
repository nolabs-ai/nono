//! Per-hostname leaf certificate minting and cache.
//!
//! The cache lives for the duration of one proxy session. Each entry is a
//! freshly minted ECDSA P-256 leaf certificate signed by the session's
//! [`EphemeralCa`] and matched against the SNI hostname presented by the
//! agent during the inner TLS handshake.
//!
//! ## Why no LRU eviction
//!
//! Typical agent workloads hit a handful of distinct hosts (`api.openai.com`,
//! `api.anthropic.com`, `api.github.com`, …). The cache is naturally bounded
//! by the per-session host set and is dropped — along with the CA — when the
//! proxy shuts down. An LRU policy would add complexity without payoff.
//!
//! ## Failure mode
//!
//! When `resolve()` is invoked by rustls during a handshake and minting
//! fails, the resolver returns `None`. rustls then fails the handshake,
//! the agent sees a TLS error, and the proxy's CONNECT handler records
//! the failure as a denied audit event. This matches the design constraint
//! "hard fail on cert pinning": we never silently fall back to a transparent
//! tunnel for a route that asked for L7 visibility.

use crate::error::{ProxyError, Result};
use crate::tls_intercept::ca::{EphemeralCa, certificate_not_before, system_time_to_offset};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tracing::{debug, warn};

/// Per-hostname leaf certificate cache backed by the session's [`EphemeralCa`].
pub struct CertCache {
    ca: Arc<EphemeralCa>,
    leaf_validity: Option<Duration>,
    /// Hostname → minted leaf. Kept behind a `Mutex` because rustls' cert
    /// resolver is invoked from sync handshake context.
    cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl CertCache {
    /// Construct a new cache backed by `ca`.
    #[must_use]
    pub fn new(ca: Arc<EphemeralCa>) -> Self {
        Self::new_with_leaf_validity(ca, None)
    }

    #[must_use]
    pub fn new_with_leaf_validity(ca: Arc<EphemeralCa>, leaf_validity: Option<Duration>) -> Self {
        Self {
            ca,
            leaf_validity,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Number of cached entries (test-only visibility).
    #[cfg(test)]
    fn len(&self) -> usize {
        self.cache
            .lock()
            .map(|guard| guard.len())
            .unwrap_or_default()
    }

    /// Look up or mint a leaf certificate for `hostname`.
    ///
    /// Used by tests; production code goes through [`ResolvesServerCert`].
    pub fn get_or_mint(&self, hostname: &str) -> Result<Arc<CertifiedKey>> {
        // Reject empty hostnames defensively. rustls already validates SNI
        // shape, but we don't trust upstream invariants for a key path.
        if hostname.is_empty() {
            return Err(ProxyError::Config(
                "cannot mint leaf certificate for empty hostname".to_string(),
            ));
        }

        let mut cache = self.cache.lock().map_err(|_| {
            ProxyError::Config("tls_intercept cert cache mutex poisoned".to_string())
        })?;
        if let Some(existing) = cache.get(hostname) {
            return Ok(Arc::clone(existing));
        }
        let minted = mint_leaf(self.ca.as_ref(), hostname, self.leaf_validity)?;
        cache.insert(hostname.to_string(), Arc::clone(&minted));
        debug!("tls_intercept: minted leaf certificate for {}", hostname);
        Ok(minted)
    }
}

impl std::fmt::Debug for CertCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let len = self.cache.lock().map(|g| g.len()).unwrap_or(0);
        f.debug_struct("CertCache")
            .field("entries", &len)
            .field("ca", &self.ca)
            .finish()
    }
}

impl ResolvesServerCert for CertCache {
    /// rustls invokes this synchronously during the server-side handshake.
    /// We extract the SNI hostname, look up (or mint) a leaf, and return it.
    /// On failure — empty SNI, mint error, mutex poison — we return `None`,
    /// causing rustls to fail the handshake. That's what we want: the agent
    /// sees a TLS error, the CONNECT handler records the failure, no
    /// silent fallback occurs.
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let hostname = client_hello.server_name()?;
        match self.get_or_mint(hostname) {
            Ok(ck) => Some(ck),
            Err(e) => {
                warn!(
                    "tls_intercept: failed to mint leaf for SNI '{}': {}",
                    hostname, e
                );
                None
            }
        }
    }
}

/// Mint a fresh leaf certificate for `hostname`, signed by `ca`.
///
/// The returned `CertifiedKey` contains a two-cert chain: [leaf, CA].
/// Go's TLS verifier (via `SecTrustEvaluateWithError`) requires the full
/// chain to be presented by the server even when the CA is in the user
/// trust store.
fn mint_leaf(
    ca: &EphemeralCa,
    hostname: &str,
    leaf_validity: Option<Duration>,
) -> Result<Arc<CertifiedKey>> {
    mint_leaf_at(ca, hostname, leaf_validity, SystemTime::now())
}

fn mint_leaf_at(
    ca: &EphemeralCa,
    hostname: &str,
    leaf_validity: Option<Duration>,
    now: SystemTime,
) -> Result<Arc<CertifiedKey>> {
    // Generate a new key pair for this leaf. Distinct from the CA key:
    // we never expose the CA's signing key in any TLS handshake.
    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|e| ProxyError::Config(format!("failed to generate leaf key pair: {}", e)))?;
    let leaf_key_der = leaf_key.serialize_der();

    let mut params = CertificateParams::default();
    params.subject_alt_names = vec![dns_san(hostname)?];
    // RFC 5280 §4.2.1.1 requires Authority Key Identifier on certs issued
    // by a CA; rcgen defaults the flag to false. Stricter verifiers
    // (OpenSSL 3.6+, BoringSSL) reject leaves without AKI with
    // "Missing Authority Key Identifier".
    params.use_authority_key_identifier_extension = true;

    let ca_not_after = ca.not_after();
    if ca_not_after <= now {
        return Err(ProxyError::Config(format!(
            "CA certificate has expired; cannot mint leaf for '{hostname}'"
        )));
    }
    let leaf_not_after = match leaf_validity {
        Some(validity) => now
            .checked_add(validity)
            .ok_or_else(|| {
                ProxyError::Config("leaf certificate expiry exceeds system time range".to_string())
            })?
            .min(ca_not_after),
        None => ca_not_after,
    };
    params.not_before = system_time_to_offset(certificate_not_before(now)?)?;
    params.not_after = system_time_to_offset(leaf_not_after)?;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, hostname);
    params.distinguished_name = dn;

    let cert = params
        .signed_by(&leaf_key, ca.issuer())
        .map_err(|e| ProxyError::Config(format!("failed to sign leaf certificate: {}", e)))?;
    let leaf_der = cert.der().clone();
    let ca_der = CertificateDer::from(ca.cert_der().to_vec());

    let private_key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key_der));
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&private_key_der)
        .map_err(|e| ProxyError::Config(format!("rustls rejected minted leaf key: {}", e)))?;

    Ok(Arc::new(CertifiedKey::new(
        vec![leaf_der, ca_der],
        signing_key,
    )))
}

/// Build a Subject Alternative Name entry for `hostname`. Reject anything
/// that isn't a plausible DNS name to avoid emitting bogus certs for
/// IP-literal or malformed CONNECT targets.
fn dns_san(hostname: &str) -> Result<SanType> {
    if !is_plausible_dns_name(hostname) {
        return Err(ProxyError::Config(format!(
            "tls_intercept: refusing to mint leaf for non-DNS hostname '{}'",
            hostname
        )));
    }
    Ok(SanType::DnsName(hostname.to_string().try_into().map_err(
        |e| ProxyError::Config(format!("invalid DNS name '{}': {}", hostname, e)),
    )?))
}

/// Lightweight DNS-name shape check. Not a full RFC 1035 validator —
/// rustls will reject syntactically malformed certs at handshake time —
/// but keeps obvious garbage out of the cache key.
fn is_plausible_dns_name(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && s.contains(|c: char| c.is_ascii_alphabetic())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn minted_leaf_tolerates_bounded_clock_skew()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        use rustls::client::WebPkiServerVerifier;
        use rustls::client::danger::ServerCertVerifier;
        use rustls::pki_types::{ServerName, UnixTime};
        use x509_parser::prelude::FromDer;

        let issued_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let ca = EphemeralCa::generate_with_cn_at(
            "nono-test-ca",
            Duration::from_secs(86400),
            issued_at,
        )?;
        let ck = mint_leaf_at(&ca, "api.example.com", None, issued_at)?;
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(ck.cert[0].as_ref())
            .map_err(|e| ProxyError::Config(format!("test certificate parse failed: {e}")))?;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ck.cert[1].clone())?;
        let verifier = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()?;
        let name = ServerName::try_from("api.example.com")?;
        verifier.verify_server_cert(
            &ck.cert[0],
            &[],
            &name,
            &[],
            UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000 - 3600)),
        )?;
        assert_eq!(cert.validity().not_before.timestamp(), 1_800_000_000 - 3600);
        assert_eq!(cert.validity().not_after.timestamp(), 1_800_000_000 + 86400);
        assert!(matches!(
            verifier.verify_server_cert(
                &ck.cert[0],
                &[],
                &name,
                &[],
                UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000 - 3601)),
            ),
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidYetContext { .. }
            ))
        ));
        assert!(matches!(
            verifier.verify_server_cert(
                &ck.cert[0],
                &[],
                &name,
                &[],
                UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000 + 86401)),
            ),
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ExpiredContext { .. }
            ))
        ));
        Ok(())
    }

    fn fresh_cache() -> CertCache {
        CertCache::new(Arc::new(EphemeralCa::generate().unwrap()))
    }

    #[test]
    fn mint_returns_well_formed_cert() {
        let cache = fresh_cache();
        let ck = cache.get_or_mint("api.openai.com").unwrap();
        assert_eq!(ck.cert.len(), 2, "chain should be [leaf, CA]");
        assert!(
            !ck.cert[0].as_ref().is_empty(),
            "leaf DER body must be non-empty"
        );
        assert!(
            !ck.cert[1].as_ref().is_empty(),
            "CA DER body must be non-empty"
        );
        // The first byte of an X.509 certificate's DER encoding is 0x30
        // (SEQUENCE). A trivial sanity check that we produced something
        // shaped like a certificate.
        assert_eq!(ck.cert[0].as_ref()[0], 0x30);
        assert_eq!(ck.cert[1].as_ref()[0], 0x30);
    }

    #[test]
    fn minted_leaf_carries_authority_key_identifier() {
        // OpenSSL 3.6+ (Python 3.14) rejects issued certs without AKI with
        // "Missing Authority Key Identifier". rcgen defaults the flag off,
        // so we set it explicitly in `mint_leaf`. Verify the extension OID
        // 2.5.29.35 (DER bytes 06 03 55 1d 23) is present in the leaf DER.
        let cache = fresh_cache();
        let ck = cache.get_or_mint("api.example.com").unwrap();
        let der = ck.cert[0].as_ref();
        let aki_oid = [0x06, 0x03, 0x55, 0x1d, 0x23];
        assert!(
            der.windows(aki_oid.len()).any(|w| w == aki_oid),
            "minted leaf must include Authority Key Identifier (OID 2.5.29.35)"
        );
    }

    #[test]
    fn minted_leaf_lifetime_is_measured_from_issuance() -> Result<()> {
        let issued_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let ca = EphemeralCa::generate_with_cn_at(
            "nono-test-ca",
            Duration::from_secs(86400),
            issued_at,
        )?;
        let ck = mint_leaf_at(
            &ca,
            "api.example.com",
            Some(Duration::from_secs(60)),
            issued_at,
        )?;
        assert_eq!(cert_validity(ck.cert[0].as_ref())?.1, 1_800_000_060);
        Ok(())
    }

    #[test]
    fn minted_leaf_uses_configured_shorter_validity()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let ca = Arc::new(EphemeralCa::generate()?);
        let cache = CertCache::new_with_leaf_validity(ca, Some(Duration::from_secs(60)));
        let ck = cache.get_or_mint("api.example.com")?;
        let leaf_not_after = cert_validity(ck.cert[0].as_ref())?.1;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs() as i64;
        assert!(leaf_not_after >= now + 30 && leaf_not_after <= now + 90);
        Ok(())
    }

    #[test]
    fn minted_leaf_clamps_clock_skew_at_unix_epoch() -> Result<()> {
        let issued_at = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let ca = EphemeralCa::generate_with_cn_at(
            "nono-test-ca",
            Duration::from_secs(86400),
            issued_at,
        )?;
        let ck = mint_leaf_at(&ca, "api.example.com", None, issued_at)?;
        assert_eq!(cert_validity(ck.cert[0].as_ref())?, (0, 86410));
        Ok(())
    }

    #[test]
    fn invalid_leaf_issuance_time_and_lifetime_return_errors() -> Result<()> {
        let issued_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let ca = EphemeralCa::generate_with_cn_at(
            "nono-test-ca",
            Duration::from_secs(86400),
            issued_at,
        )?;
        let before_epoch = SystemTime::UNIX_EPOCH
            .checked_sub(Duration::from_secs(1))
            .ok_or_else(|| ProxyError::Config("test pre-epoch time unavailable".to_string()))?;
        assert!(mint_leaf_at(&ca, "api.example.com", None, before_epoch).is_err());
        assert!(mint_leaf_at(&ca, "api.example.com", Some(Duration::MAX), issued_at).is_err());
        Ok(())
    }

    fn cert_validity(der: &[u8]) -> Result<(i64, i64)> {
        use x509_parser::prelude::FromDer;
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der)
            .map_err(|e| ProxyError::Config(format!("test certificate parse failed: {e}")))?;
        Ok((
            cert.validity().not_before.timestamp(),
            cert.validity().not_after.timestamp(),
        ))
    }

    #[test]
    fn persisted_ca_dates_are_preserved_and_bound_leaf_expiry() -> Result<()> {
        let issued_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let original =
            EphemeralCa::generate_with_cn_at("nono-test-ca", Duration::from_secs(600), issued_at)?;
        let reloaded = EphemeralCa::from_existing(original.key_der(), original.cert_pem())?;
        assert_eq!(reloaded.cert_der(), original.cert_der());
        assert_eq!(reloaded.cert_pem(), original.cert_pem());
        assert_eq!(
            cert_validity(reloaded.cert_der())?,
            cert_validity(original.cert_der())?
        );

        let mint_at = issued_at + Duration::from_secs(300);
        for (requested, expected_expiry) in [
            (None, 1_800_000_600),
            (Some(Duration::from_secs(30)), 1_800_000_330),
            (Some(Duration::from_secs(1200)), 1_800_000_600),
        ] {
            let ck = mint_leaf_at(&reloaded, "api.example.com", requested, mint_at)?;
            let (not_before, not_after) = cert_validity(ck.cert[0].as_ref())?;
            assert_eq!(not_before, 1_800_000_300 - 3600);
            assert_eq!(not_after, expected_expiry);
            assert!(not_after <= cert_validity(reloaded.cert_der())?.1);
        }
        Ok(())
    }

    #[test]
    fn expired_ca_cannot_mint_even_with_clock_tolerance() -> Result<()> {
        let issued_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let ca =
            EphemeralCa::generate_with_cn_at("nono-test-ca", Duration::from_secs(600), issued_at)?;
        for mint_at in [ca.not_after(), ca.not_after() + Duration::from_secs(1)] {
            let result = mint_leaf_at(&ca, "api.example.com", None, mint_at);
            assert!(
                matches!(result, Err(ProxyError::Config(message)) if message.contains("has expired"))
            );
        }
        Ok(())
    }

    #[test]
    fn cache_hits_on_repeated_lookup() {
        let cache = fresh_cache();
        let a = cache.get_or_mint("api.example.com").unwrap();
        let b = cache.get_or_mint("api.example.com").unwrap();
        assert!(Arc::ptr_eq(&a, &b), "second lookup should be a cache hit");
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn distinct_hostnames_get_distinct_certs() {
        let cache = fresh_cache();
        let a = cache.get_or_mint("api.openai.com").unwrap();
        let b = cache.get_or_mint("api.anthropic.com").unwrap();
        assert!(!Arc::ptr_eq(&a, &b));
        assert_ne!(a.cert[0].as_ref(), b.cert[0].as_ref());
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn empty_hostname_rejected() {
        let cache = fresh_cache();
        assert!(cache.get_or_mint("").is_err());
    }

    #[test]
    fn ip_literal_rejected() {
        // We refuse to mint for IP-literal CONNECT targets — the SNI shape
        // would be wrong and the agent would reject the cert anyway.
        let cache = fresh_cache();
        assert!(cache.get_or_mint("127.0.0.1").is_err());
        assert!(cache.get_or_mint("::1").is_err());
    }

    #[test]
    fn plausible_dns_name_filter() {
        assert!(is_plausible_dns_name("api.openai.com"));
        assert!(is_plausible_dns_name("internal-service.corp"));
        assert!(!is_plausible_dns_name(""));
        assert!(!is_plausible_dns_name("127.0.0.1")); // no alphabetic
        assert!(!is_plausible_dns_name("evil host"));
        assert!(!is_plausible_dns_name(&"a".repeat(254)));
    }
}
