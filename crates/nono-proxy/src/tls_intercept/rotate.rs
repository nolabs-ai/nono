//! Mid-session replacement of the interception CA, for sessions that outlive the
//! certificate they started with. A cert re-issued over the same key is an
//! interchangeable anchor, so only the presented chain and the bundle change.

use crate::error::{ProxyError, Result};
use crate::tls_intercept::ca::EphemeralCa;
use crate::tls_intercept::cert_cache::CertCache;
use crate::tls_intercept::{BundleInputs, write_bundle};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;
use tracing::info;

/// Everything needed to install a renewed CA into a running proxy.
pub struct InterceptCaRotator {
    cache: Arc<CertCache>,
    bundle_dir: PathBuf,
    bundle_filename: &'static str,
    parent_ca_pems: Option<Vec<u8>>,
    /// Serializes rotations. The bundle write and the live-CA swap in
    /// `install` are two steps; interleaved across threads they can leave
    /// the on-disk bundle describing a different CA than the one serving
    /// certificates.
    rotation: std::sync::Mutex<()>,
}

impl InterceptCaRotator {
    #[must_use]
    pub fn new(
        cache: Arc<CertCache>,
        bundle_dir: PathBuf,
        bundle_filename: &'static str,
        parent_ca_pems: Option<Vec<u8>>,
    ) -> Self {
        Self {
            cache,
            bundle_dir,
            bundle_filename,
            parent_ca_pems,
            rotation: std::sync::Mutex::new(()),
        }
    }

    /// PEM of the certificate currently presented as the interception anchor.
    pub fn current_cert_pem(&self) -> Result<String> {
        Ok(self.cache.current_ca()?.cert_pem().to_string())
    }

    /// `not_after` of the certificate currently in use.
    pub fn current_not_after(&self) -> Result<SystemTime> {
        Ok(self.cache.current_ca()?.not_after())
    }

    /// Whether `key_der` is the key the currently served CA cert was issued
    /// over. Callers choose between [`Self::rotate`] and
    /// [`Self::rotate_across_keys`] with this; each still enforces its own
    /// key and expiry rules.
    pub fn serves_key(&self, key_der: &[u8]) -> Result<bool> {
        Ok(self.cache.current_ca()?.key_der() == key_der)
    }

    /// Install `cert_pem` (signed by `key_der`) as the live interception CA.
    ///
    /// Rejects a key/cert pair that doesn't agree, so a torn write to whatever
    /// store the caller read from cannot take the proxy down. Fail-secure order:
    /// validate, then write the on-disk bundle, then swap the live CA — so a
    /// client trusting only `SSL_CERT_FILE` is never ahead of what it can read.
    /// If the bundle write fails, the live CA is left exactly as it was.
    ///
    /// Only a same-key renewal is accepted here: this is the ordinary
    /// "re-signed over the same key" path, and the session's served key must
    /// never change silently (see the `supersedes` invariant this rotator
    /// exists to uphold). A cert whose key differs from what is currently
    /// live must go through [`Self::rotate_across_keys`] instead. The
    /// replacement must also be currently valid and outlive the cert
    /// currently served, so a stale, expired, or future-dated re-issue
    /// cannot walk the session backwards.
    pub fn rotate(&self, key_der: &[u8], cert_pem: &str) -> Result<PathBuf> {
        let _serialized = self
            .rotation
            .lock()
            .map_err(|_| ProxyError::Config("tls_intercept: rotation lock poisoned".to_string()))?;
        let ca = Arc::new(EphemeralCa::from_existing(key_der, cert_pem)?);
        self.ensure_same_key_as_current(&ca)?;
        self.ensure_supersedes_current(&ca)?;
        self.install(ca, cert_pem)
    }

    /// Install `cert_pem` (signed by `key_der`) as the live interception CA,
    /// even though its key differs from the one currently served.
    ///
    /// Only permitted once the currently-served cert has itself expired: a
    /// live session's key must not change while what it already handed out
    /// is still valid, since that is indistinguishable from an unrequested,
    /// silent CA swap. This is the explicit, narrow escape hatch for the
    /// case where the session's own cert has expired and nothing else can
    /// keep it serving intercepted TLS.
    pub fn rotate_across_keys(&self, key_der: &[u8], cert_pem: &str) -> Result<PathBuf> {
        let _serialized = self
            .rotation
            .lock()
            .map_err(|_| ProxyError::Config("tls_intercept: rotation lock poisoned".to_string()))?;
        let current_not_after = self.current_not_after()?;
        if current_not_after > SystemTime::now() {
            return Err(ProxyError::Config(
                "rotate_across_keys: refusing to change the CA key while the currently \
                 served certificate is still valid"
                    .to_string(),
            ));
        }
        let ca = Arc::new(EphemeralCa::from_existing(key_der, cert_pem)?);
        // Adopting a replacement outside its own validity window would trade
        // one dead anchor for another, or for one no client accepts yet.
        let now = SystemTime::now();
        if ca.not_before() > now || ca.not_after() <= now {
            return Err(ProxyError::Config(
                "rotate_across_keys: refusing to adopt a CA cert that is not currently valid"
                    .to_string(),
            ));
        }
        self.install(ca, cert_pem)
    }

    /// A same-key rotation is a renewal: the candidate's validity window
    /// must have started, its expiry must be in the future, and it must
    /// strictly outlive the cert currently served.
    fn ensure_supersedes_current(&self, candidate: &EphemeralCa) -> Result<()> {
        let current = self.current_not_after()?;
        let now = SystemTime::now();
        if candidate.not_before() > now
            || candidate.not_after() <= current
            || candidate.not_after() <= now
        {
            return Err(ProxyError::Config(
                "rotate: refusing to install a CA cert that is not currently valid or does \
                 not outlive the served one"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn ensure_same_key_as_current(&self, candidate: &EphemeralCa) -> Result<()> {
        let current_key_der = self.cache.current_ca()?.key_der().to_vec();
        if current_key_der != candidate.key_der() {
            return Err(ProxyError::Config(
                "rotate: refusing to switch the session's CA key; use \
                 rotate_across_keys for a deliberate key change"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn install(&self, ca: Arc<EphemeralCa>, cert_pem: &str) -> Result<PathBuf> {
        let path = write_bundle(BundleInputs {
            dir: &self.bundle_dir,
            filename: self.bundle_filename,
            parent_ssl_cert_file: self.parent_ca_pems.as_deref(),
            ephemeral_ca_pem: cert_pem,
        })?;
        self.cache.replace_ca(ca)?;
        info!(
            "tls_intercept: adopted renewed CA; trust bundle rewritten at {}",
            path.display()
        );
        Ok(path)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn rotator(ca: Arc<EphemeralCa>, dir: &std::path::Path) -> InterceptCaRotator {
        InterceptCaRotator::new(
            Arc::new(CertCache::new(ca)),
            dir.to_path_buf(),
            "intercept-ca.pem",
            None,
        )
    }

    #[test]
    fn rotate_installs_the_new_cert_and_rewrites_the_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let original =
            EphemeralCa::generate_with_cn("nono-proxy-ca", Duration::from_secs(60)).unwrap();
        let key_der = original.key_der().to_vec();
        let r = rotator(Arc::new(original), dir.path());

        let renewed =
            EphemeralCa::reissue_with_cn(&key_der, "nono-proxy-ca", Duration::from_secs(86_400))
                .unwrap();
        let path = r.rotate(&key_der, renewed.cert_pem()).unwrap();

        assert_eq!(r.current_cert_pem().unwrap(), renewed.cert_pem());
        assert!(r.current_not_after().unwrap() > SystemTime::now() + Duration::from_secs(3600));
        let bundle = std::fs::read_to_string(&path).unwrap();
        assert!(bundle.contains(renewed.cert_pem()));
    }

    #[test]
    fn rotate_serves_leaves_under_the_new_cert() {
        let dir = tempfile::tempdir().unwrap();
        let original =
            EphemeralCa::generate_with_cn("nono-proxy-ca", Duration::from_secs(60)).unwrap();
        let key_der = original.key_der().to_vec();
        let cache = Arc::new(CertCache::new(Arc::new(original)));
        let r = InterceptCaRotator::new(
            Arc::clone(&cache),
            dir.path().to_path_buf(),
            "intercept-ca.pem",
            None,
        );

        let before = cache.get_or_mint("api.github.com").unwrap();
        let renewed =
            EphemeralCa::reissue_with_cn(&key_der, "nono-proxy-ca", Duration::from_secs(86_400))
                .unwrap();
        r.rotate(&key_der, renewed.cert_pem()).unwrap();
        let after = cache.get_or_mint("api.github.com").unwrap();

        // Re-minted, and the chain now carries the renewed anchor.
        assert_ne!(before.cert[0], after.cert[0]);
        assert_eq!(after.cert[1].as_ref(), renewed.cert_der());
    }

    #[test]
    fn rotate_leaves_the_live_ca_untouched_if_the_bundle_write_fails() {
        let original =
            EphemeralCa::generate_with_cn("nono-proxy-ca", Duration::from_secs(60)).unwrap();
        let key_der = original.key_der().to_vec();
        let cert_pem = original.cert_pem().to_string();
        let r = InterceptCaRotator::new(
            Arc::new(CertCache::new(Arc::new(original))),
            // A directory whose parent doesn't exist: the bundle write fails
            // before any file is created, standing in for a native-roots load
            // error or IO failure.
            PathBuf::from("/nonexistent/nono-rotate-test/bundle-dir"),
            "intercept-ca.pem",
            None,
        );

        let renewed =
            EphemeralCa::reissue_with_cn(&key_der, "nono-proxy-ca", Duration::from_secs(86_400))
                .unwrap();
        assert!(r.rotate(&key_der, renewed.cert_pem()).is_err());
        assert_eq!(
            r.current_cert_pem().unwrap(),
            cert_pem,
            "a failed bundle write must leave the live CA untouched"
        );
    }

    #[test]
    fn rotate_rejects_a_switch_to_a_different_ca_key() {
        // `rotate()` today only checks that `key_der` and `cert_pem` are
        // internally consistent with each other (`from_existing`'s
        // `validate_key_cert_binding`). It never checks the new key against
        // the key the session is currently serving, so a caller can silently
        // switch a live session onto an unrelated CA key — exactly the
        // "session's key changes mid-session" bug: nothing that previously
        // trusted the old CA (e.g. the macOS Keychain trust settings) has any
        // relationship to the new one, and the `supersedes` invariant that
        // children keep working off the old anchor is violated the moment a
        // different key is installed.
        let dir = tempfile::tempdir().unwrap();
        let original =
            EphemeralCa::generate_with_cn("nono-proxy-ca", Duration::from_secs(60)).unwrap();
        let original_key_der = original.key_der().to_vec();
        let cert_pem = original.cert_pem().to_string();
        let r = rotator(Arc::new(original), dir.path());

        // Self-consistent (key matches cert), but a completely different key
        // from the one the rotator is currently serving.
        let different_key_ca =
            EphemeralCa::generate_with_cn("nono-proxy-ca", Duration::from_secs(86_400)).unwrap();
        let different_key_der = different_key_ca.key_der().to_vec();
        let different_key_cert_pem = different_key_ca.cert_pem().to_string();

        assert!(
            r.rotate(&different_key_der, &different_key_cert_pem)
                .is_err(),
            "rotate() must refuse to switch the session onto a different CA key"
        );
        assert_eq!(
            r.current_cert_pem().unwrap(),
            cert_pem,
            "a rejected same-session rotation must leave the live CA untouched"
        );
        // The rejected key is provably a *different* key, not a mismatched pair.
        assert_ne!(original_key_der, different_key_der);
    }

    #[test]
    fn rotate_across_keys_installs_a_different_key_when_asked_explicitly() {
        let dir = tempfile::tempdir().unwrap();
        let original =
            EphemeralCa::generate_with_cn("nono-proxy-ca", Duration::from_secs(0)).unwrap();
        let r = rotator(Arc::new(original), dir.path());
        // The clock must move past the (already-elapsed) validity window.
        std::thread::sleep(Duration::from_millis(50));

        let different_key_ca =
            EphemeralCa::generate_with_cn("nono-proxy-ca", Duration::from_secs(86_400)).unwrap();
        let different_key_der = different_key_ca.key_der().to_vec();
        let different_key_cert_pem = different_key_ca.cert_pem().to_string();

        r.rotate_across_keys(&different_key_der, &different_key_cert_pem)
            .unwrap();
        assert_eq!(r.current_cert_pem().unwrap(), different_key_cert_pem);
    }

    #[test]
    fn rotate_across_keys_refuses_while_the_current_cert_is_still_valid() {
        let dir = tempfile::tempdir().unwrap();
        let original =
            EphemeralCa::generate_with_cn("nono-proxy-ca", Duration::from_secs(86_400)).unwrap();
        let cert_pem = original.cert_pem().to_string();
        let r = rotator(Arc::new(original), dir.path());

        let different_key_ca =
            EphemeralCa::generate_with_cn("nono-proxy-ca", Duration::from_secs(86_400)).unwrap();

        assert!(
            r.rotate_across_keys(different_key_ca.key_der(), different_key_ca.cert_pem())
                .is_err(),
            "rotate_across_keys must refuse while the currently served cert is still valid"
        );
        assert_eq!(r.current_cert_pem().unwrap(), cert_pem);
    }

    #[test]
    fn rotate_rejects_a_same_key_renewal_that_does_not_outlive_the_served_cert() {
        let dir = tempfile::tempdir().unwrap();
        let original =
            EphemeralCa::generate_with_cn("nono-proxy-ca", Duration::from_secs(86_400)).unwrap();
        let key_der = original.key_der().to_vec();
        let cert_pem = original.cert_pem().to_string();
        let r = rotator(Arc::new(original), dir.path());

        // Shorter-lived than the cert currently served.
        let shorter =
            EphemeralCa::reissue_with_cn(&key_der, "nono-proxy-ca", Duration::from_secs(60))
                .unwrap();
        assert!(
            r.rotate(&key_der, shorter.cert_pem()).is_err(),
            "a renewal that does not outlive the served cert must be refused"
        );
        // Expired.
        let expired =
            EphemeralCa::reissue_with_cn(&key_der, "nono-proxy-ca", Duration::from_secs(0))
                .unwrap();
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            r.rotate(&key_der, expired.cert_pem()).is_err(),
            "an expired renewal must be refused"
        );
        assert_eq!(
            r.current_cert_pem().unwrap(),
            cert_pem,
            "refused renewals must leave the live CA untouched"
        );
    }

    #[test]
    fn rotate_across_keys_refuses_an_expired_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let original =
            EphemeralCa::generate_with_cn("nono-proxy-ca", Duration::from_secs(0)).unwrap();
        let r = rotator(Arc::new(original), dir.path());
        std::thread::sleep(Duration::from_millis(50));

        let expired_replacement =
            EphemeralCa::generate_with_cn("nono-proxy-ca", Duration::from_secs(0)).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            r.rotate_across_keys(
                expired_replacement.key_der(),
                expired_replacement.cert_pem()
            )
            .is_err(),
            "adopting an expired replacement over an expired cert fixes nothing; it must be \
             refused"
        );
    }

    #[test]
    fn rotate_rejects_a_renewal_whose_validity_has_not_started() {
        let dir = tempfile::tempdir().unwrap();
        let original =
            EphemeralCa::generate_with_cn("nono-proxy-ca", Duration::from_secs(86_400)).unwrap();
        let key_der = original.key_der().to_vec();
        let cert_pem = original.cert_pem().to_string();
        let r = rotator(Arc::new(original), dir.path());

        // Starts an hour from now and outlives the served cert, so the
        // expiry checks alone would accept it.
        let future = EphemeralCa::reissue_with_cn_starting_at(
            &key_der,
            "nono-proxy-ca",
            Duration::from_secs(3600),
            Duration::from_secs(30 * 86_400),
        )
        .unwrap();
        assert!(
            r.rotate(&key_der, future.cert_pem()).is_err(),
            "a renewal whose validity window has not started must be refused"
        );
        assert_eq!(
            r.current_cert_pem().unwrap(),
            cert_pem,
            "a refused renewal must leave the live CA untouched"
        );
    }

    #[test]
    fn rotate_across_keys_refuses_a_not_yet_valid_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let original =
            EphemeralCa::generate_with_cn("nono-proxy-ca", Duration::from_secs(0)).unwrap();
        let r = rotator(Arc::new(original), dir.path());
        std::thread::sleep(Duration::from_millis(50));

        let future = EphemeralCa::generate_with_cn_starting_at(
            "nono-proxy-ca",
            Duration::from_secs(3600),
            Duration::from_secs(30 * 86_400),
        )
        .unwrap();
        assert!(
            r.rotate_across_keys(future.key_der(), future.cert_pem())
                .is_err(),
            "adopting a replacement whose validity window has not started must be refused"
        );
    }

    #[test]
    fn rotate_rejects_a_cert_that_does_not_match_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let original =
            EphemeralCa::generate_with_cn("nono-proxy-ca", Duration::from_secs(60)).unwrap();
        let key_der = original.key_der().to_vec();
        let cert_pem = original.cert_pem().to_string();
        let r = rotator(Arc::new(original), dir.path());

        let unrelated =
            EphemeralCa::generate_with_cn("nono-proxy-ca", Duration::from_secs(86_400)).unwrap();
        assert!(r.rotate(&key_der, unrelated.cert_pem()).is_err());
        assert_eq!(
            r.current_cert_pem().unwrap(),
            cert_pem,
            "a rejected rotation must leave the live CA untouched"
        );
    }

    #[test]
    fn concurrent_rotations_keep_the_bundle_describing_the_served_ca() {
        // A renewal can overlap another rotation of the same bundle path;
        // the bundle write and the live-CA swap must not interleave across
        // threads, or the on-disk bundle ends up describing a different CA
        // than the one serving certificates.
        let dir = tempfile::tempdir().unwrap();
        let original =
            EphemeralCa::generate_with_cn("nono-proxy-ca", Duration::from_secs(3600)).unwrap();
        let key_der = original.key_der().to_vec();
        let r = std::sync::Arc::new(rotator(Arc::new(original), dir.path()));

        const ROUNDS: usize = 8;
        for round in 0..ROUNDS {
            // Every round's renewals strictly outlive the previous round's,
            // so both rotations pass validation and genuinely race.
            let low_secs = (100 + 2 * round as u64) * 86_400;
            let high_secs = low_secs + 86_400;
            let low = EphemeralCa::reissue_with_cn(
                &key_der,
                "nono-proxy-ca",
                Duration::from_secs(low_secs),
            )
            .unwrap();
            let high = EphemeralCa::reissue_with_cn(
                &key_der,
                "nono-proxy-ca",
                Duration::from_secs(high_secs),
            )
            .unwrap();

            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let handles: Vec<_> = [low, high]
                .iter()
                .map(|ca| {
                    let r = std::sync::Arc::clone(&r);
                    let barrier = std::sync::Arc::clone(&barrier);
                    let cert_pem = ca.cert_pem().to_string();
                    let key_der = key_der.clone();
                    std::thread::spawn(move || {
                        barrier.wait();
                        r.rotate(&key_der, &cert_pem)
                    })
                })
                .collect();
            for handle in handles {
                // Whichever rotation takes the lock first may leave the other
                // freshness-refused: both renewals outlive the previous
                // round, but not necessarily each other.
                let _ = handle.join().unwrap();
            }
            let live = r.current_cert_pem().unwrap();
            let bundle = std::fs::read_to_string(dir.path().join("intercept-ca.pem")).unwrap();
            assert!(
                bundle.contains(live.trim()),
                "the trust bundle a child reads must describe the CA actually being served"
            );
        }
    }
}
