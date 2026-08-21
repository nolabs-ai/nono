//! macOS system trust store integration for nono's proxy CA.
//!
//! Persists the CA private key in macOS Keychain and the public cert in the
//! user trust store via Security.framework. Regenerates when expired.
//!
//! This enables Go CLI tools (`gh`, `terraform`, etc.) that ignore
//! `SSL_CERT_FILE` and only use `com.apple.trustd` for TLS verification.

use core_foundation::base::TCFType;
use core_foundation_sys::base::OSStatus;
use nono::{NonoError, Result};
use nono_proxy::config::PreloadedCa;
use security_framework::certificate::SecCertificate;
use security_framework::item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult};
use security_framework::os::macos::keychain::SecKeychain;
use security_framework::passwords;
use security_framework::trust_settings::{Domain, TrustSettings, TrustSettingsForCertificate};
use security_framework_sys::base::SecCertificateRef;
use security_framework_sys::trust_settings::{SecTrustSettingsDomain, kSecTrustSettingsDomainUser};
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
            match cert_validity(&cert_pem)? {
                CertValidity::Valid => {}
                state => {
                    debug!("stored proxy CA needs renewal ({state:?}); re-issuing over stored key");
                    return rotate_ca(&key_der, &cert_pem, validity, state);
                }
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

/// The CA shared through Keychain, as `(key DER, cert PEM)`.
pub(crate) fn read_shared_ca() -> Result<Option<(Zeroizing<Vec<u8>>, String)>> {
    load_existing_ca()
}

/// Re-issue the shared CA over its stored key and retire the previous certificate.
///
/// `Ok(None)` means nothing changed: no stored CA, or a declined trust prompt.
pub(crate) fn renew_shared_ca(validity: Duration) -> Result<Option<PreloadedCa>> {
    let Some((key_der, cert_pem)) = load_existing_ca()? else {
        return Ok(None);
    };
    let state = cert_validity(&cert_pem)?;
    match rotate_ca(&key_der, &cert_pem, validity, state)? {
        Some(ca) if ca.cert_pem != cert_pem => Ok(Some(ca)),
        _ => Ok(None),
    }
}

/// Whether adopting `candidate` gains runway over `current`.
pub(crate) fn supersedes(candidate: &str, current: &str) -> Result<bool> {
    Ok(not_after_of(candidate)? > not_after_of(current)?)
}

pub(crate) fn stored_cert_is_trusted(cert_pem: &str) -> Result<bool> {
    let der = pem_to_der(cert_pem)?;
    let cert = SecCertificate::from_der(&der)
        .map_err(|e| NonoError::SandboxInit(format!("failed to parse stored CA cert: {e}")))?;
    Ok(is_cert_trusted(&cert))
}

fn not_after_of(cert_pem: &str) -> Result<i64> {
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| NonoError::SandboxInit(format!("failed to parse CA cert PEM: {e}")))?;
    let cert = pem
        .parse_x509()
        .map_err(|e| NonoError::SandboxInit(format!("failed to parse X.509 from PEM: {e}")))?;
    Ok(cert.validity().not_after.timestamp())
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

/// Re-issue the CA certificate over the stored key and hand the new one over.
///
/// Trust the new cert before retiring the old, so nothing fails mid-swap. The key is
/// unchanged, so leaves minted under the old cert still chain to the new one.
fn rotate_ca(
    key_der: &Zeroizing<Vec<u8>>,
    old_cert_pem: &str,
    validity: Duration,
    state: CertValidity,
) -> Result<Option<PreloadedCa>> {
    let ca = match nono_proxy::tls_intercept::ca::EphemeralCa::reissue_with_cn(
        key_der,
        "nono-proxy-ca",
        validity,
    ) {
        Ok(ca) => ca,
        Err(e) => {
            // No usable stored key: only a whole new anchor can recover.
            warn!("Cannot re-issue over the stored proxy CA key ({e}); generating a new CA.");
            remove_cert_from_keychain(old_cert_pem);
            delete_existing_ca();
            return generate_and_trust_new_ca(validity);
        }
    };
    let cert_pem = ca.cert_pem().to_string();

    let cert_der = pem_to_der(&cert_pem)?;
    let sec_cert = SecCertificate::from_der(&cert_der)
        .map_err(|e| NonoError::SandboxInit(format!("failed to create SecCertificate: {e}")))?;

    info!("Renewing proxy CA (you may be prompted for authentication)...");
    if let Err(e) = trust_cert(&sec_cert) {
        match e {
            TrustCertError::UserCancelled => {
                // The old cert is untouched, so declining costs nothing until it expires.
                if state == CertValidity::RenewDue {
                    warn!(
                        "Proxy CA renewal cancelled; continuing on the current \
                         certificate. It will be retried next launch."
                    );
                    return Ok(Some(PreloadedCa {
                        key_der: key_der.clone(),
                        cert_pem: old_cert_pem.to_string(),
                    }));
                }
                warn!(
                    "Proxy CA renewal cancelled and the stored certificate has \
                     expired. Falling back to ephemeral CA; Go CLI tools won't \
                     validate proxy certs."
                );
                return Ok(None);
            }
            TrustCertError::Other(err) => return Err(err),
        }
    }

    let key_pem = ca.key_pem();
    let combined = Zeroizing::new(format!("{}{}", *key_pem, cert_pem));
    passwords::set_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, combined.as_bytes())
        .map_err(|e| {
            NonoError::SandboxInit(format!(
                "failed to store renewed CA bundle in Keychain: {e}"
            ))
        })?;

    remove_cert_from_keychain(old_cert_pem);
    flush_trust_cache();

    info!("Proxy CA renewed");
    Ok(Some(PreloadedCa {
        key_der: Zeroizing::new(ca.key_der().to_vec()),
        cert_pem,
    }))
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
    // Trust before import: a cancelled/failed prompt then leaves nothing orphaned.
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
        })?;
    if let Err(e) = ensure_cert_in_keychain(cert) {
        // Import failed after trust succeeded — drop the now-orphaned trust settings.
        if let Err(status) = remove_trust_settings(cert) {
            warn!("Failed to roll back trust settings after import failure (OSStatus {status})");
        }
        return Err(TrustCertError::Other(e));
    }
    Ok(())
}

/// Trust-settings APIs don't report keychain presence, so we search for it.
fn find_keychain_cert(target_der: &[u8]) -> Option<SecCertificate> {
    let results = match ItemSearchOptions::new()
        .class(ItemClass::certificate())
        .load_refs(true)
        .limit(Limit::All)
        .search()
    {
        Ok(results) => results,
        Err(e) => {
            debug!("keychain certificate search failed: {e}");
            return None;
        }
    };
    results.into_iter().find_map(|item| match item {
        SearchResult::Ref(Reference::Certificate(c)) if c.to_der() == target_der => Some(c),
        _ => None,
    })
}

fn cert_in_keychain(cert: &SecCertificate) -> bool {
    find_keychain_cert(&cert.to_der()).is_some()
}

fn trust_settings_report_trusted(cert: &SecCertificate) -> bool {
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
            // Empty settings means unconditional trust, per Apple docs.
            debug!("trust store lookup: unconditionally trusted (empty settings)");
            true
        }
        Err(e) => {
            debug!("trust store lookup: {e} (cert not in trust store)");
            false
        }
    }
}

/// `trustd` needs both; trust-settings alone can be an orphaned entry.
fn cert_is_trusted(in_keychain: bool, trust_settings_trusted: bool) -> bool {
    in_keychain && trust_settings_trusted
}

fn is_cert_trusted(cert: &SecCertificate) -> bool {
    cert_is_trusted(cert_in_keychain(cert), trust_settings_report_trusted(cert))
}

fn remove_cert_from_keychain(cert_pem: &str) {
    let Ok(der) = pem_to_der(cert_pem) else {
        warn!("Failed to parse stored CA cert PEM while removing it; skipping cleanup.");
        return;
    };
    let Ok(cert) = SecCertificate::from_der(&der) else {
        warn!("Failed to reconstruct stored CA cert while removing it; skipping cleanup.");
        return;
    };

    match find_keychain_cert(&der) {
        Some(keychain_cert) => {
            if let Err(e) = keychain_cert.delete() {
                warn!(
                    "Failed to remove expired CA cert from keychain: {e}. \
                     Run: security delete-certificate -c \"nono-proxy-ca\""
                );
            }
        }
        None => debug!("no matching CA cert found in keychain; nothing to remove there"),
    }

    // Separate store, keyed by content — not removed by deleting the keychain item.
    if let Err(status) = remove_trust_settings(&cert) {
        warn!(
            "Failed to remove trust-settings entry for expired CA cert (OSStatus {status}). \
             Run: security remove-trusted-cert -d <exported-cert.pem>"
        );
    }
}

// Not wrapped by `security-framework`.
#[cfg_attr(target_vendor = "apple", link(name = "Security", kind = "framework"))]
unsafe extern "C" {
    fn SecTrustSettingsRemoveTrustSettings(
        cert_ref: SecCertificateRef,
        domain: SecTrustSettingsDomain,
    ) -> OSStatus;
}

fn remove_trust_settings(cert: &SecCertificate) -> std::result::Result<(), OSStatus> {
    // SAFETY: `cert` outlives the call; the ref is borrowed, not owned.
    let status = unsafe {
        SecTrustSettingsRemoveTrustSettings(cert.as_concrete_TypeRef(), kSecTrustSettingsDomainUser)
    };
    if status == 0 { Ok(()) } else { Err(status) }
}

fn delete_existing_ca() {
    let _ = passwords::delete_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT);
}

/// Remaining life below which the CA is renewed at launch, so every session starts
/// with runway.
const RENEWAL_HEADROOM: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CertValidity {
    Valid,
    RenewDue,
    Expired,
}

pub(crate) fn cert_validity(cert_pem: &str) -> Result<CertValidity> {
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| NonoError::SandboxInit(format!("failed to parse stored CA cert PEM: {e}")))?;
    let cert = pem.parse_x509().map_err(|e| {
        NonoError::SandboxInit(format!("failed to parse X.509 from stored PEM: {e}"))
    })?;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|e| NonoError::SandboxInit(format!("system clock before UNIX epoch: {e}")))?
        .as_secs() as i64;
    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();
    Ok(classify_validity(
        not_after,
        now,
        renewal_headroom(not_after.saturating_sub(not_before)),
    ))
}

/// Proportional, so a 7-day cert prompts at most weekly and a short-lived one still
/// gets warning.
pub(crate) fn renewal_headroom(lifetime_secs: i64) -> Duration {
    let quarter = Duration::from_secs(lifetime_secs.max(0) as u64 / 4);
    quarter.min(RENEWAL_HEADROOM)
}

fn classify_validity(not_after: i64, now: i64, headroom: Duration) -> CertValidity {
    if now >= not_after {
        CertValidity::Expired
    } else if not_after - now <= headroom.as_secs() as i64 {
        CertValidity::RenewDue
    } else {
        CertValidity::Valid
    }
}

/// Trust settings live in a data vault with no cache-invalidation API, so restarting
/// `trustd` is the only reliable flush. Best-effort: a stale cache only delays.
fn flush_trust_cache() {
    match std::process::Command::new("/usr/bin/killall")
        .args(["-q", "trustd"])
        .status()
    {
        Ok(status) => debug!("trustd flush exited with {status}"),
        Err(e) => debug!("could not run killall to flush trustd: {e}"),
    }
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
    fn cert_validity_sees_a_week_old_cert_as_valid() {
        let ca =
            EphemeralCa::generate_with_cn("nono-proxy-ca", Duration::from_secs(7 * 86400)).unwrap();
        assert_eq!(cert_validity(ca.cert_pem()).unwrap(), CertValidity::Valid);
    }

    #[test]
    fn cert_validity_scales_the_headroom_to_a_short_lived_cert() {
        // A 120s cert must not be born renew-due, or every launch rotates.
        let ca = EphemeralCa::generate_with_cn("nono-proxy-ca", Duration::from_secs(120)).unwrap();
        assert_eq!(cert_validity(ca.cert_pem()).unwrap(), CertValidity::Valid);

        let not_after = not_after_of(ca.cert_pem()).unwrap();
        assert_eq!(
            classify_validity(not_after, not_after - 20, renewal_headroom(120)),
            CertValidity::RenewDue,
            "20s of life left on a 120s cert is inside the 30s headroom"
        );
    }

    #[test]
    fn renewal_headroom_is_a_quarter_of_life_capped_at_a_day() {
        assert_eq!(renewal_headroom(120), Duration::from_secs(30));
        assert_eq!(
            renewal_headroom(7 * 86400),
            Duration::from_secs(24 * 60 * 60),
            "a week-long cert renews a day out, not 42 hours out"
        );
        assert_eq!(renewal_headroom(-1), Duration::ZERO);
    }

    #[test]
    fn cert_validity_rejects_garbage() {
        assert!(cert_validity("not a cert").is_err());
    }

    #[test]
    fn classify_validity_boundaries() {
        let headroom = Duration::from_secs(86400);
        // not_after exactly now, and one second past it, are both expired.
        assert_eq!(
            classify_validity(1_000, 1_000, headroom),
            CertValidity::Expired
        );
        assert_eq!(
            classify_validity(1_000, 1_001, headroom),
            CertValidity::Expired
        );
        // Exactly one headroom of life left still counts as due.
        assert_eq!(
            classify_validity(1_000 + 86_400, 1_000, headroom),
            CertValidity::RenewDue
        );
        assert_eq!(
            classify_validity(1_000 + 86_401, 1_000, headroom),
            CertValidity::Valid
        );
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
    fn cert_is_trusted_requires_both_keychain_presence_and_trust_settings() {
        assert!(cert_is_trusted(true, true));
        assert!(!cert_is_trusted(true, false));
        assert!(!cert_is_trusted(false, true)); // orphaned trust-settings entry
        assert!(!cert_is_trusted(false, false));
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
