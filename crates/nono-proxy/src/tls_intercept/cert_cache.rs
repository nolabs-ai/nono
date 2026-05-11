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
use crate::tls_intercept::ca::EphemeralCa;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256, SanType,
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use time::OffsetDateTime;
use tracing::{debug, warn};

/// Validity window for minted leaf certificates. Short enough that even a
/// stolen leaf becomes useless quickly; long enough that no plausible
/// HTTP request will outlive it.
const LEAF_VALIDITY: Duration = Duration::from_secs(60 * 60);

/// Per-hostname leaf certificate cache backed by the session's [`EphemeralCa`].
pub struct CertCache {
    ca: Arc<EphemeralCa>,
    /// Hostname → minted leaf. Kept behind a `Mutex` because rustls' cert
    /// resolver is invoked from sync handshake context.
    cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl CertCache {
    /// Construct a new cache backed by `ca`.
    #[must_use]
    pub fn new(ca: Arc<EphemeralCa>) -> Self {
        Self {
            ca,
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
        let minted = mint_leaf(self.ca.as_ref(), hostname)?;
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
fn mint_leaf(ca: &EphemeralCa, hostname: &str) -> Result<Arc<CertifiedKey>> {
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

    let now = SystemTime::now();
    params.not_before = system_time_to_offset(now)?;
    params.not_after = system_time_to_offset(now + LEAF_VALIDITY)?;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, hostname);
    params.distinguished_name = dn;

    let cert = params
        .signed_by(&leaf_key, ca.issuer())
        .map_err(|e| ProxyError::Config(format!("failed to sign leaf certificate: {}", e)))?;
    let leaf_der = cert.der().clone();

    let private_key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key_der));
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&private_key_der)
        .map_err(|e| ProxyError::Config(format!("rustls rejected minted leaf key: {}", e)))?;

    Ok(Arc::new(CertifiedKey::new(vec![leaf_der], signing_key)))
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

    fn fresh_cache() -> CertCache {
        CertCache::new(Arc::new(EphemeralCa::generate().unwrap()))
    }

    #[test]
    fn mint_returns_well_formed_cert() {
        let cache = fresh_cache();
        let ck = cache.get_or_mint("api.openai.com").unwrap();
        assert_eq!(ck.cert.len(), 1, "should be a single-cert chain");
        assert!(
            !ck.cert[0].as_ref().is_empty(),
            "DER body must be non-empty"
        );
        // The first byte of an X.509 certificate's DER encoding is 0x30
        // (SEQUENCE). A trivial sanity check that we produced something
        // shaped like a certificate.
        assert_eq!(ck.cert[0].as_ref()[0], 0x30);
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
