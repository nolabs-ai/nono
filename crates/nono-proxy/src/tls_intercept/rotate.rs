//! Mid-session replacement of the interception CA, for sessions that outlive the
//! certificate they started with. A cert re-issued over the same key is an
//! interchangeable anchor, so only the presented chain and the bundle change.

use crate::error::Result;
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

    /// Install `cert_pem` (signed by `key_der`) as the live interception CA.
    ///
    /// Rejects a key/cert pair that doesn't agree, so a torn write to whatever
    /// store the caller read from cannot take the proxy down.
    pub fn rotate(&self, key_der: &[u8], cert_pem: &str) -> Result<PathBuf> {
        let ca = Arc::new(EphemeralCa::from_existing(key_der, cert_pem)?);
        self.cache.replace_ca(ca)?;
        let path = write_bundle(BundleInputs {
            dir: &self.bundle_dir,
            filename: self.bundle_filename,
            parent_ssl_cert_file: self.parent_ca_pems.as_deref(),
            ephemeral_ca_pem: cert_pem,
        })?;
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
}
