//! macOS system trust store integration for nono's proxy CA.
//!
//! Persists the CA private key in macOS Keychain and the public cert in the
//! user trust store via Security.framework. Regenerates when expired.
//!
//! This enables Go CLI tools (`gh`, `terraform`, etc.) that ignore
//! `SSL_CERT_FILE` and only use `com.apple.trustd` for TLS verification.

use nono::{NonoError, Result};
use nono_proxy::config::PreloadedCa;
use security_framework::certificate::SecCertificate;
use security_framework::os::macos::keychain::SecKeychain;
use security_framework::passwords;
use security_framework::trust_settings::{Domain, TrustSettings, TrustSettingsForCertificate};
use std::time::{Duration, SystemTime};
use tracing::{debug, info, warn};
use x509_parser::pem::parse_x509_pem;
use zeroize::Zeroizing;

/// Internal error type to distinguish user-cancelled trust prompts from other
/// failures without relying on string matching.
enum TrustCertError {
    UserCancelled,
    Other(NonoError),
}

// Service name for Keychain items. Sufficiently specific to avoid collision
// with other apps. set_generic_password overwrites on conflict (desired).
const KEYCHAIN_SERVICE: &str = "nono-proxy-ca";
const KEYCHAIN_ACCOUNT: &str = "ca-bundle";

/// Load or generate a shared CA and ensure it's trusted in the macOS user
/// trust store. Returns `Some(PreloadedCa)` on success, `None` if the user
/// cancelled the auth prompt or setup failed (fallback to ephemeral CA).
///
/// All logging happens internally — the caller just checks the Option.
pub(crate) fn load_or_generate_proxy_ca(validity: Duration) -> Option<PreloadedCa> {
    match try_ensure_trusted_ca(validity) {
        Ok(Some(ca)) => Some(ca),
        Ok(None) => None,
        Err(e) => {
            warn!("Shared CA setup failed: {e}. Falling back to ephemeral CA.");
            None
        }
    }
}

fn try_ensure_trusted_ca(validity: Duration) -> Result<Option<PreloadedCa>> {
    match load_existing_ca()? {
        Some((key_der, cert_pem)) => {
            if !cert_pem_is_valid(&cert_pem)? {
                debug!("stored proxy CA has expired; regenerating");
                remove_cert_from_keychain(&cert_pem);
                delete_existing_ca();
                return generate_and_trust_new_ca(validity);
            }

            let cert_der = pem_to_der(&cert_pem)?;
            let cert = SecCertificate::from_der(&cert_der).map_err(|e| {
                NonoError::SandboxInit(format!("failed to parse stored CA cert: {e}"))
            })?;

            if !is_cert_trusted(&cert) {
                info!("Re-trusting proxy CA (you may be prompted for authentication)...");
                if let Err(e) = trust_cert(&cert) {
                    match e {
                        TrustCertError::UserCancelled => {
                            warn!(
                                "Trust store auth cancelled. Falling back to ephemeral CA. \
                                 Go CLI tools won't validate proxy certs; other tools still work."
                            );
                            return Ok(None);
                        }
                        TrustCertError::Other(err) => return Err(err),
                    }
                }
                info!("Proxy CA re-trusted successfully");
            } else {
                info!("Reusing proxy CA from Keychain (already trusted)");
            }

            Ok(Some(PreloadedCa { key_der, cert_pem }))
        }
        None => {
            debug!("no existing proxy CA in Keychain; generating new one");
            generate_and_trust_new_ca(validity)
        }
    }
}

fn load_existing_ca() -> Result<Option<(Zeroizing<Vec<u8>>, String)>> {
    let bundle = match passwords::get_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT) {
        Ok(data) => data,
        Err(_) => return Ok(None),
    };
    let combined = String::from_utf8(bundle)
        .map_err(|e| NonoError::SandboxInit(format!("stored CA bundle is not valid UTF-8: {e}")))?;
    nono_proxy::tls_intercept::ca::split_key_cert_pem(&combined)
        .map(Some)
        .map_err(|e| NonoError::SandboxInit(format!("{e}")))
}

fn generate_and_trust_new_ca(validity: Duration) -> Result<Option<PreloadedCa>> {
    let ca =
        nono_proxy::tls_intercept::ca::EphemeralCa::generate_with_cn("nono-proxy-ca", validity)
            .map_err(|e| NonoError::SandboxInit(format!("failed to generate CA: {e}")))?;
    let key_der = Zeroizing::new(ca.key_der().to_vec());
    let cert_pem = ca.cert_pem().to_string();

    // Single atomic write — concurrent processes race, but the bundle is always
    // a coherent key+cert pair (second writer wins, no mismatch possible).
    let key_pem = ca.key_pem();
    let combined = Zeroizing::new(format!("{}{}", *key_pem, cert_pem));
    passwords::set_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, combined.as_bytes())
        .map_err(|e| {
            NonoError::SandboxInit(format!("failed to store CA bundle in Keychain: {e}"))
        })?;

    let cert_der = pem_to_der(&cert_pem)?;
    let sec_cert = SecCertificate::from_der(&cert_der)
        .map_err(|e| NonoError::SandboxInit(format!("failed to create SecCertificate: {e}")))?;

    info!("Adding proxy CA to macOS trust store (you may be prompted for authentication)...");
    if let Err(e) = trust_cert(&sec_cert) {
        // Trust failed — remove the orphaned CA bundle from Keychain so it
        // doesn't linger untrusted and confuse the next session's load path.
        delete_existing_ca();
        match e {
            TrustCertError::UserCancelled => {
                warn!(
                    "Trust store auth cancelled. Falling back to ephemeral CA. \
                     Go CLI tools won't validate proxy certs; other tools still work."
                );
                return Ok(None);
            }
            TrustCertError::Other(err) => return Err(err),
        }
    }

    info!("Proxy CA added to macOS trust store");
    Ok(Some(PreloadedCa { key_der, cert_pem }))
}

fn ensure_cert_in_keychain(cert: &SecCertificate) -> Result<()> {
    let keychain = SecKeychain::default()
        .map_err(|e| NonoError::SandboxInit(format!("failed to open default keychain: {e}")))?;
    if let Err(e) = cert.add_to_keychain(Some(keychain)) {
        // errSecDuplicateItem (-25299) — cert already imported from a prior run.
        if e.code() != -25299 {
            return Err(NonoError::SandboxInit(format!(
                "failed to add CA cert to keychain: {e}"
            )));
        }
    }
    Ok(())
}

/// OSStatus codes that indicate the user refused the authentication prompt.
const ERR_SEC_USER_CANCELED: i32 = -128;
const ERR_SEC_AUTH_FAILED: i32 = -25293;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;

fn is_user_cancelled_osstatus(code: i32) -> bool {
    matches!(
        code,
        ERR_SEC_USER_CANCELED | ERR_SEC_AUTH_FAILED | ERR_SEC_INTERACTION_NOT_ALLOWED
    )
}

fn trust_cert(cert: &SecCertificate) -> std::result::Result<(), TrustCertError> {
    ensure_cert_in_keychain(cert).map_err(TrustCertError::Other)?;
    TrustSettings::new(Domain::User)
        .set_trust_settings_always(cert)
        .map_err(|e| {
            if is_user_cancelled_osstatus(e.code()) {
                TrustCertError::UserCancelled
            } else {
                TrustCertError::Other(NonoError::SandboxInit(format!(
                    "failed to set trust settings: {e}"
                )))
            }
        })
}

fn is_cert_trusted(cert: &SecCertificate) -> bool {
    let ts = TrustSettings::new(Domain::User);
    match ts.tls_trust_settings_for_certificate(cert) {
        Ok(Some(r)) => {
            let trusted = matches!(
                r,
                TrustSettingsForCertificate::TrustRoot | TrustSettingsForCertificate::TrustAsRoot
            );
            debug!("trust store lookup: {:?}, trusted={}", r, trusted);
            trusted
        }
        Ok(None) => {
            // NULL/empty trust settings means "always trust for all purposes"
            // per Apple docs. SecTrustSettingsCopyTrustSettings returns
            // errSecItemNotFound (Err) when the cert isn't present, so Ok(None)
            // confirms presence + unconditional trust.
            debug!("trust store lookup: unconditionally trusted (empty settings)");
            true
        }
        Err(e) => {
            debug!("trust store lookup: {e} (cert not in trust store)");
            false
        }
    }
}

fn remove_cert_from_keychain(cert_pem: &str) {
    if let Ok(der) = pem_to_der(cert_pem)
        && let Ok(cert) = SecCertificate::from_der(&der)
        && let Err(e) = cert.delete()
    {
        warn!(
            "Failed to remove expired CA cert from keychain: {e}. \
             Run: security delete-certificate -c \"nono-proxy-ca\""
        );
    }
}

fn delete_existing_ca() {
    let _ = passwords::delete_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT);
}

fn cert_pem_is_valid(cert_pem: &str) -> Result<bool> {
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| NonoError::SandboxInit(format!("failed to parse stored CA cert PEM: {e}")))?;
    let cert = pem.parse_x509().map_err(|e| {
        NonoError::SandboxInit(format!("failed to parse X.509 from stored PEM: {e}"))
    })?;
    let not_after = cert.validity().not_after.timestamp();
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|e| NonoError::SandboxInit(format!("system clock before UNIX epoch: {e}")))?
        .as_secs() as i64;
    Ok(now < not_after)
}

fn pem_to_der(cert_pem: &str) -> Result<Vec<u8>> {
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| NonoError::SandboxInit(format!("failed to parse CA cert PEM: {e}")))?;
    Ok(pem.contents.to_vec())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use nono_proxy::tls_intercept::ca::EphemeralCa;

    fn generate_test_ca() -> EphemeralCa {
        EphemeralCa::generate_with_cn(
            "nono-proxy-ca",
            nono_proxy::tls_intercept::ca::CA_VALIDITY_DEFAULT,
        )
        .unwrap()
    }

    #[test]
    fn combined_pem_roundtrips() {
        use nono_proxy::tls_intercept::ca::split_key_cert_pem;

        let ca = generate_test_ca();
        let combined = format!("{}{}", *ca.key_pem(), ca.cert_pem());

        let (key_der, cert_pem) = split_key_cert_pem(&combined).unwrap();
        assert_eq!(&*key_der, ca.key_der());
        assert_eq!(cert_pem, ca.cert_pem());
        EphemeralCa::from_existing(&key_der, &cert_pem).unwrap();
    }

    #[test]
    fn cert_pem_is_valid_returns_true_for_fresh_cert() {
        let ca = generate_test_ca();
        assert!(cert_pem_is_valid(ca.cert_pem()).unwrap());
    }

    #[test]
    fn cert_pem_is_valid_rejects_garbage() {
        assert!(cert_pem_is_valid("not a cert").is_err());
    }

    #[test]
    fn pem_to_der_roundtrips() {
        use x509_parser::prelude::FromDer;

        let ca = generate_test_ca();
        let der = pem_to_der(ca.cert_pem()).unwrap();
        assert!(!der.is_empty());
        let (_, cert) = x509_parser::prelude::X509Certificate::from_der(&der).unwrap();
        assert_eq!(
            cert.subject()
                .iter_common_name()
                .next()
                .unwrap()
                .as_str()
                .unwrap(),
            "nono-proxy-ca"
        );
    }

    #[test]
    fn is_user_cancelled_osstatus_detects_known_codes() {
        assert!(is_user_cancelled_osstatus(ERR_SEC_USER_CANCELED));
        assert!(is_user_cancelled_osstatus(ERR_SEC_AUTH_FAILED));
        assert!(is_user_cancelled_osstatus(ERR_SEC_INTERACTION_NOT_ALLOWED));
        assert!(!is_user_cancelled_osstatus(-25299)); // errSecDuplicateItem
        assert!(!is_user_cancelled_osstatus(0));
    }
}
