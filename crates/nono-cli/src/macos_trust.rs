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
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use tracing::{debug, info, warn};
use x509_parser::pem::parse_x509_pem;
use zeroize::Zeroizing;

use crate::macos_ca_renewal::{BACKOFF_AFTER_FAILURE, RenewalLock};

/// Internal error type to distinguish user-cancelled trust prompts, and prompts
/// that couldn't be shown at all, from other failures without relying on string
/// matching.
enum TrustCertError {
    UserCancelled,
    /// No interactive session exists to show the prompt (e.g. a headless `nono
    /// proxy`). Unlike a decline, a later retry with the same session can't
    /// succeed either — only a new interactive session can.
    NoInteractionAvailable,
    Other(NonoError),
}

/// The result of a completed trust/rotate attempt, stripped of everything
/// that isn't relevant to deciding what happens next. `TrustCertError::Other`
/// (a genuine failure, not a user decision) never reaches this type — callers
/// propagate it with `?` before converting the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrustAttemptOutcome {
    Trusted,
    Declined,
    NoInteraction,
}

/// What the launch/renewal path should do, decided purely from already-known
/// facts about the stored cert — no Keychain or Security-framework access.
/// This is the single seam both the lock-free fast check and the re-check
/// taken under the [`RenewalLock`] call, so a decline (or a renewal by
/// another process) recorded in the gap between the two is always honored:
/// see `try_ensure_trusted_ca`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RenewalGate {
    /// Serve the stored cert as-is: it's Valid and trusted, or a recent
    /// decline is still in its backoff window and the stored cert still has
    /// life left to serve (untrusted, if this was a re-trust attempt).
    ServeStored,
    /// A recent decline is still in its backoff window and the stored cert
    /// has no life left to fall back on.
    ServeNone,
    /// Take the lock (if not already held) and attempt to re-trust (Valid,
    /// untrusted) or re-mint (RenewDue/Expired) the stored cert.
    Attempt,
}

fn renewal_gate(state: CertValidity, trusted: bool, backed_off: bool) -> RenewalGate {
    if state == CertValidity::Valid && trusted {
        return RenewalGate::ServeStored;
    }
    if backed_off {
        return if state == CertValidity::Expired {
            RenewalGate::ServeNone
        } else {
            RenewalGate::ServeStored
        };
    }
    RenewalGate::Attempt
}

/// Whether a completed attempt should record a backoff marker. Only an
/// affirmative decline throttles the next automatic retry (in this process or
/// any other); a missing interactive session is a per-session limitation, not
/// a decision to throttle future attempts.
fn should_record_backoff(outcome: TrustAttemptOutcome) -> bool {
    matches!(outcome, TrustAttemptOutcome::Declined)
}

/// What to hand back to the caller after a completed attempt, purely from the
/// outcome and the state the stored cert was in going into the attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PostAttemptAction {
    /// Trust succeeded: adopt whatever was just installed.
    AdoptNewlyTrusted,
    /// Declined (or no interactive session), but the previously stored cert
    /// still has life left: keep serving it.
    KeepStored,
    /// Declined (or no interactive session) and the previously stored cert
    /// has no life left to fall back on.
    Unavailable,
}

fn post_attempt_action(outcome: TrustAttemptOutcome, state: CertValidity) -> PostAttemptAction {
    match outcome {
        TrustAttemptOutcome::Trusted => PostAttemptAction::AdoptNewlyTrusted,
        TrustAttemptOutcome::Declined | TrustAttemptOutcome::NoInteraction => {
            if state == CertValidity::Expired {
                PostAttemptAction::Unavailable
            } else {
                PostAttemptAction::KeepStored
            }
        }
    }
}

fn trust_attempt_outcome(
    result: std::result::Result<(), TrustCertError>,
) -> Result<TrustAttemptOutcome> {
    match result {
        Ok(()) => Ok(TrustAttemptOutcome::Trusted),
        Err(TrustCertError::UserCancelled) => Ok(TrustAttemptOutcome::Declined),
        Err(TrustCertError::NoInteractionAvailable) => Ok(TrustAttemptOutcome::NoInteraction),
        Err(TrustCertError::Other(e)) => Err(e),
    }
}

// Service name for Keychain items. Sufficiently specific to avoid collision
// with other apps. set_generic_password overwrites on conflict (desired).
const KEYCHAIN_SERVICE: &str = "nono-proxy-ca";
const KEYCHAIN_ACCOUNT: &str = "ca-bundle";

// Fingerprint-keyed, so a marker from a since-rotated cert never suppresses
// renewal of the cert actually in use.
fn backoff_marker_path(fingerprint: &str) -> Result<PathBuf> {
    let dir = crate::state_paths::user_state_dir()?;
    std::fs::create_dir_all(&dir).map_err(|e| {
        NonoError::SandboxInit(format!("cannot create state dir '{}': {e}", dir.display()))
    })?;
    Ok(dir.join(format!("proxy-ca-renewal-backoff-{fingerprint}")))
}

// Hashes the DER, not the PEM text, so re-encoding the same cert never changes the fingerprint.
fn cert_fingerprint(cert_pem: &str) -> Result<String> {
    let der = pem_to_der(cert_pem)?;
    let digest = Sha256::digest(&der);
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

fn renewal_backed_off(cert_pem: &str) -> Result<bool> {
    let path = backoff_marker_path(&cert_fingerprint(cert_pem)?)?;
    let Ok(modified) = std::fs::metadata(&path).and_then(|m| m.modified()) else {
        return Ok(false);
    };
    let elapsed = SystemTime::now()
        .duration_since(modified)
        .unwrap_or(Duration::ZERO);
    Ok(elapsed < BACKOFF_AFTER_FAILURE)
}

fn record_renewal_backoff(cert_pem: &str) -> Result<()> {
    let path = backoff_marker_path(&cert_fingerprint(cert_pem)?)?;
    std::fs::write(&path, []).map_err(|e| {
        NonoError::SandboxInit(format!(
            "cannot write renewal backoff marker '{}': {e}",
            path.display()
        ))
    })
}

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

/// What `try_ensure_trusted_ca`'s lock-free fast check, and its re-check once
/// the lock is held, both decide from freshly re-read facts about the stored
/// cert — the thin, Security-framework-touching wrapper around the pure
/// [`renewal_gate`].
enum LaunchStep {
    Serve(PreloadedCa),
    ServeNone,
    Attempt,
}

fn launch_gate(key_der: &Zeroizing<Vec<u8>>, cert_pem: &str) -> Result<LaunchStep> {
    let state = cert_validity(cert_pem)?;
    let trusted = state == CertValidity::Valid && stored_cert_is_trusted(cert_pem)?;
    let backed_off = renewal_backed_off(cert_pem)?;
    Ok(match renewal_gate(state, trusted, backed_off) {
        RenewalGate::ServeStored => LaunchStep::Serve(PreloadedCa {
            key_der: key_der.clone(),
            cert_pem: cert_pem.to_string(),
        }),
        RenewalGate::ServeNone => LaunchStep::ServeNone,
        RenewalGate::Attempt => LaunchStep::Attempt,
    })
}

fn try_ensure_trusted_ca(validity: Duration) -> Result<Option<PreloadedCa>> {
    // Best-effort cleanup of stale `nono-proxy-ca` certs left by prior
    // rotations; a sweep failure must never block launch on the CA it's
    // actually there to serve.
    if let Err(e) = sweep_stale_ca_certs() {
        warn!("Stale-CA sweep failed (non-fatal): {e}");
    }

    let Some((key_der, cert_pem)) = load_existing_ca()? else {
        debug!("no existing proxy CA in Keychain; generating new one");
        return generate_new_trusted_ca(validity);
    };

    // Lock-free fast check: avoids taking the lock at all on the common paths
    // (already trusted, or a recent decline still in its backoff window).
    match launch_gate(&key_der, &cert_pem)? {
        LaunchStep::Serve(ca) => return Ok(Some(ca)),
        LaunchStep::ServeNone => return Ok(None),
        LaunchStep::Attempt => {}
    }

    // A prompt is on the table; serialize with any other process attempting
    // the same thing so at most one prompt happens machine-wide.
    let Some(_lock) = RenewalLock::acquire()? else {
        debug!("another process is acting on the proxy CA; serving current cert");
        return Ok(Some(PreloadedCa { key_der, cert_pem }));
    };

    // Re-read and re-decide now that the lock is held: another process may
    // have renewed, re-trusted, or recorded a decline in the gap between the
    // lock-free check above and actually acquiring the lock. This is the
    // fix for the marker/lock TOCTOU — the decision is never taken on the
    // stale, lock-free answer.
    let Some((key_der, cert_pem)) = load_existing_ca()? else {
        return generate_and_trust_new_ca(validity);
    };
    match launch_gate(&key_der, &cert_pem)? {
        LaunchStep::Serve(ca) => return Ok(Some(ca)),
        LaunchStep::ServeNone => return Ok(None),
        LaunchStep::Attempt => {}
    }

    let state = cert_validity(&cert_pem)?;
    if state == CertValidity::Valid {
        retrust_stored_ca(key_der, cert_pem)
    } else {
        match rotate_ca(&key_der, &cert_pem, validity, state)? {
            RotateOutcome::Cert(ca) => Ok(Some(ca)),
            RotateOutcome::NoInteraction { fallback } => Ok(fallback),
            RotateOutcome::Unavailable => Ok(None),
        }
    }
}

/// Re-trust an already-Valid stored cert in place, no re-mint. Shares the
/// `TrustAttemptOutcome`/`should_record_backoff`/`post_attempt_action` core
/// with [`rotate_ca`], so a decline here is throttled by the same backoff
/// marker (Fix 4) instead of re-prompting on every launch.
fn retrust_stored_ca(key_der: Zeroizing<Vec<u8>>, cert_pem: String) -> Result<Option<PreloadedCa>> {
    let cert_der = pem_to_der(&cert_pem)?;
    let cert = SecCertificate::from_der(&cert_der)
        .map_err(|e| NonoError::SandboxInit(format!("failed to parse stored CA cert: {e}")))?;

    info!("Re-trusting proxy CA (you may be prompted for authentication)...");
    let outcome = trust_attempt_outcome(trust_cert(&cert))?;

    if should_record_backoff(outcome) {
        record_renewal_backoff(&cert_pem)?;
    }

    match post_attempt_action(outcome, CertValidity::Valid) {
        // `state` is always `Valid` here, so `post_attempt_action` never
        // returns `Unavailable` — a declined re-trust always has a valid (if
        // untrusted) cert to keep serving (L2).
        PostAttemptAction::Unavailable => {
            unreachable!("post_attempt_action never returns Unavailable for CertValidity::Valid")
        }
        PostAttemptAction::AdoptNewlyTrusted => {
            info!("Proxy CA re-trusted successfully");
            Ok(Some(PreloadedCa { key_der, cert_pem }))
        }
        PostAttemptAction::KeepStored => {
            warn!(
                "Trust store auth cancelled or unavailable; continuing on the current \
                 certificate untrusted. Retry is rate-limited; it won't re-prompt on \
                 every launch."
            );
            Ok(Some(PreloadedCa { key_der, cert_pem }))
        }
    }
}

/// Generate a brand-new CA and trust it, under the same [`RenewalLock`] as
/// every other prompting path (Fix 5), so two processes racing to create the
/// very first CA don't both mint one and both prompt.
fn generate_new_trusted_ca(validity: Duration) -> Result<Option<PreloadedCa>> {
    let Some(_lock) = RenewalLock::acquire()? else {
        debug!("another process is creating the proxy CA; nothing to serve yet");
        return Ok(None);
    };
    // Someone may have created (and trusted) one while we waited for the lock.
    if let Some((key_der, cert_pem)) = load_existing_ca()? {
        return Ok(Some(PreloadedCa { key_der, cert_pem }));
    }
    generate_and_trust_new_ca(validity)
}

/// The CA shared through Keychain, as `(key DER, cert PEM)`.
pub(crate) fn read_shared_ca() -> Result<Option<(Zeroizing<Vec<u8>>, String)>> {
    load_existing_ca()
}

/// Outcome of a mid-session renewal attempt via [`renew_shared_ca`].
pub(crate) enum RenewOutcome {
    /// A new certificate was installed.
    Renewed(PreloadedCa),
    /// Nothing changed: no stored CA, a declined prompt, or a failed trust
    /// write. Safe to retry later — the same session may succeed next time.
    Unchanged,
    /// No interactive session exists to show the trust prompt (e.g. a headless
    /// `nono proxy`). Retrying later in the same session can't succeed either.
    NoInteraction,
}

/// Re-issue the shared CA over its stored key and retire the previous certificate.
pub(crate) fn renew_shared_ca(validity: Duration) -> Result<RenewOutcome> {
    let Some((key_der, cert_pem)) = load_existing_ca()? else {
        return Ok(RenewOutcome::Unchanged);
    };
    // Shares `launch_gate`'s decision core: the marker is keyed to this exact
    // cert and shared across processes, so a supervisor that hasn't itself
    // seen a decline yet must still honor one written moments ago by a
    // different session, rather than showing a second prompt. It also means
    // the supervisor never re-mints a cert that's still Valid, even if the
    // session that triggered this check is itself due for renewal — only the
    // stored cert's own state decides whether to act.
    let state = cert_validity(&cert_pem)?;
    match launch_gate(&key_der, &cert_pem)? {
        LaunchStep::Serve(_) | LaunchStep::ServeNone => return Ok(RenewOutcome::Unchanged),
        // A Valid-but-untrusted cert needs re-trusting, not re-minting; that's
        // the launch path's job (`retrust_stored_ca`), not a mid-session
        // renewal. `rotate_ca` always re-issues, so only hand it a stored
        // cert that's actually due for renewal.
        LaunchStep::Attempt if state == CertValidity::Valid => return Ok(RenewOutcome::Unchanged),
        LaunchStep::Attempt => {}
    }
    match rotate_ca(&key_der, &cert_pem, validity, state)? {
        RotateOutcome::Cert(ca) if ca.cert_pem != cert_pem => Ok(RenewOutcome::Renewed(ca)),
        // A headless session can't satisfy the trust prompt now or later in this
        // session, regardless of whether the launch path has a still-valid cert
        // to fall back on; the supervisor backs off on this outcome either way.
        RotateOutcome::NoInteraction { .. } => Ok(RenewOutcome::NoInteraction),
        RotateOutcome::Cert(_) | RotateOutcome::Unavailable => Ok(RenewOutcome::Unchanged),
    }
}

/// Whether adopting `candidate` gains runway over `current`.
///
/// Requires a matching SPKI: same-key re-issue is the invariant that makes
/// mid-session rotation safe, since a process's children may already have
/// loaded `current`'s anchor. A later-expiring cert under a *different* key
/// (e.g. the `generate_and_trust_new_ca` fallback that `rotate_ca` takes when
/// it can't re-issue over the stored key) is never worth adopting into a live
/// session — only a restart picks that one up.
pub(crate) fn supersedes(candidate: &str, current: &str) -> Result<bool> {
    if spki_of(candidate)? != spki_of(current)? {
        return Ok(false);
    }
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

/// SubjectPublicKeyInfo bytes, so two certs can be compared for same-key re-issue.
fn spki_of(cert_pem: &str) -> Result<Vec<u8>> {
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| NonoError::SandboxInit(format!("failed to parse CA cert PEM: {e}")))?;
    let cert = pem
        .parse_x509()
        .map_err(|e| NonoError::SandboxInit(format!("failed to parse X.509 from PEM: {e}")))?;
    Ok(cert.public_key().subject_public_key.data.to_vec())
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

/// Outcome of attempting to re-issue and re-trust the shared CA over its
/// stored key. Internal to the rotate/generate fallback chain — callers see
/// [`RenewOutcome`] (mid-session) or a plain `Option` (launch).
enum RotateOutcome {
    /// A certificate to serve: either genuinely re-issued, or (when the
    /// prompt was declined but the old one still has life left) the
    /// unchanged previous certificate.
    Cert(PreloadedCa),
    /// Declined or failed, and the previous certificate has expired; caller
    /// falls back to an ephemeral CA.
    Unavailable,
    /// No interactive session exists to show the trust prompt (e.g. a
    /// headless `nono proxy`). Retrying later in the same session can't
    /// succeed either. Carries the still-valid previous certificate when one
    /// exists, so the launch path can keep serving it instead of dropping to
    /// an untrusted ephemeral CA.
    NoInteraction { fallback: Option<PreloadedCa> },
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
) -> Result<RotateOutcome> {
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
            return Ok(match generate_and_trust_new_ca(validity)? {
                Some(ca) => RotateOutcome::Cert(ca),
                None => RotateOutcome::Unavailable,
            });
        }
    };
    let cert_pem = ca.cert_pem().to_string();

    let cert_der = pem_to_der(&cert_pem)?;
    let sec_cert = SecCertificate::from_der(&cert_der)
        .map_err(|e| NonoError::SandboxInit(format!("failed to create SecCertificate: {e}")))?;

    info!("Renewing proxy CA (you may be prompted for authentication)...");
    let outcome = trust_attempt_outcome(trust_cert(&sec_cert))?;

    if should_record_backoff(outcome) {
        record_renewal_backoff(old_cert_pem)?;
    }

    match post_attempt_action(outcome, state) {
        PostAttemptAction::Unavailable => {
            warn!(
                "Proxy CA renewal cancelled or unavailable and the stored certificate \
                 has expired. Falling back to ephemeral CA; Go CLI tools won't validate \
                 proxy certs."
            );
            return Ok(RotateOutcome::Unavailable);
        }
        PostAttemptAction::KeepStored => {
            // The old cert is untouched, so declining costs nothing until it expires.
            let fallback = PreloadedCa {
                key_der: key_der.clone(),
                cert_pem: old_cert_pem.to_string(),
            };
            return Ok(match outcome {
                TrustAttemptOutcome::NoInteraction => {
                    warn!(
                        "Proxy CA renewal needs authentication but no interactive \
                         session is available to authorize it. Continuing on the \
                         current certificate."
                    );
                    RotateOutcome::NoInteraction {
                        fallback: Some(fallback),
                    }
                }
                _ => {
                    warn!(
                        "Proxy CA renewal cancelled; continuing on the current \
                         certificate. Retry is rate-limited; it won't re-prompt on \
                         every launch."
                    );
                    RotateOutcome::Cert(fallback)
                }
            });
        }
        PostAttemptAction::AdoptNewlyTrusted => {}
    }

    let key_pem = ca.key_pem();
    let combined = Zeroizing::new(format!("{}{}", *key_pem, cert_pem));
    passwords::set_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, combined.as_bytes())
        .map_err(|e| {
            NonoError::SandboxInit(format!(
                "failed to store renewed CA bundle in Keychain: {e}"
            ))
        })?;

    // Same-key renewal (Fix 6): the old cert's trust settings apply to a key
    // that's still current, so leave it in the keychain rather than dropping
    // it — only the key-change fallback above (a fresh anchor, unrelated key)
    // needs the old entry actively removed.

    info!("Proxy CA renewed");
    Ok(RotateOutcome::Cert(PreloadedCa {
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
    let outcome = trust_attempt_outcome(trust_cert(&sec_cert))?;

    if should_record_backoff(outcome) {
        // Keyed to this cert's own fingerprint: the bundle stays in Keychain
        // (see below), so a later launch loads this exact cert and consults
        // the same marker via `renewal_gate` instead of re-prompting.
        record_renewal_backoff(&cert_pem)?;
    }

    if outcome != TrustAttemptOutcome::Trusted {
        // Declined or no interactive session: keep the bundle rather than
        // deleting it (Fix 5) — an untrusted-but-Valid cert is still useful
        // to serve, and deleting it would throw away the backoff marker's
        // referent, forcing a re-mint (and a re-prompt) on the very next
        // launch instead of honoring the backoff window.
        warn!(
            "Trust store auth cancelled or unavailable. Falling back to ephemeral CA. \
             Go CLI tools won't validate proxy certs; other tools still work."
        );
        return Ok(None);
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
/// No interactive session exists to show the prompt at all (e.g. a headless
/// `nono proxy`). Distinct from a decline: retrying later in the same session
/// can't succeed either, since there's still nobody to ask.
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;

fn is_user_cancelled_osstatus(code: i32) -> bool {
    matches!(code, ERR_SEC_USER_CANCELED | ERR_SEC_AUTH_FAILED)
}

fn trust_cert(cert: &SecCertificate) -> std::result::Result<(), TrustCertError> {
    // Trust before import: a cancelled/failed prompt then leaves nothing orphaned.
    TrustSettings::new(Domain::User)
        .set_trust_settings_always(cert)
        .map_err(|e| {
            if e.code() == ERR_SEC_INTERACTION_NOT_ALLOWED {
                TrustCertError::NoInteractionAvailable
            } else if is_user_cancelled_osstatus(e.code()) {
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

fn pem_to_der(cert_pem: &str) -> Result<Vec<u8>> {
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| NonoError::SandboxInit(format!("failed to parse CA cert PEM: {e}")))?;
    Ok(pem.contents.to_vec())
}

// --- Fix 7: stale-CA-cert sweep -------------------------------------------
//
// Cleans up `nono-proxy-ca` certs left behind by prior key rotations or
// interrupted renewals. Runs at launch, under the same `RenewalLock` as the
// other prompting paths, scoped to the default (login) keychain only.
// Deletes keychain items only — never calls `SecTrustSettingsRemoveTrustSettings`,
// which Apple's header documents as itself prompting.

/// At most one sweep run per day, enforced via a marker file (same pattern
/// as the renewal backoff marker), so a busy machine launching nono
/// repeatedly doesn't re-enumerate and re-classify the whole keychain on
/// every launch.
const SWEEP_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Ceiling on deletions in a single run, so a misclassification (or an
/// unexpectedly large keychain) can't cascade into an unbounded purge.
const SWEEP_MAX_DELETIONS: usize = 100;

/// The commonName attribute OID (2.5.4.3), compared as a dotted string so the
/// exact-identity check below doesn't depend on any OID registry constant
/// being linked in.
const OID_COMMON_NAME: &str = "2.5.4.3";

/// One RDN attribute as (attribute-type OID, value) rather than a
/// display-formatted DN string, so the exact-identity check is a structural
/// comparison instead of a summary-string/substring match.
type DnAttrs = Vec<(String, String)>;

/// True only for a DN consisting of exactly one RDN of type commonName with
/// value exactly `"nono-proxy-ca"` — never a superset DN, a different CN, or
/// a value that merely contains that string.
fn is_exact_nono_ca_dn(dn: &DnAttrs) -> bool {
    matches!(dn.as_slice(), [(oid, value)] if oid == OID_COMMON_NAME && value == "nono-proxy-ca")
}

/// A keychain certificate under consideration for the stale-CA sweep,
/// already reduced to the facts the classifier needs. Everything below this
/// point is pure — no Security-framework or Keychain access.
#[derive(Debug, Clone)]
struct SweepCandidate {
    spki: Vec<u8>,
    der: Vec<u8>,
    issuer: DnAttrs,
    subject: DnAttrs,
    /// The certificate's signature verifies against its own public key.
    self_signed: bool,
    not_after: i64,
    /// This is literally the cert currently stored as the shared proxy CA —
    /// never a deletion candidate, whatever tier it would otherwise match.
    is_currently_stored: bool,
    /// Defense in depth: the real enumeration is scoped to the default
    /// (login) keychain, but the classifier refuses a non-default-keychain
    /// candidate too, so a future change to the enumeration call can't
    /// silently widen the sweep's blast radius without also changing this.
    is_default_keychain: bool,
}

/// Which tier of the stale-cert sweep selected a candidate for deletion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SweepTier {
    /// Same public key as the currently-stored cert, different DER: an
    /// artifact of a prior same-key renewal. Only fires when the currently
    /// stored cert is itself trusted — deleting a same-key sibling while the
    /// stored cert is untrusted could delete the only trusted anchor still
    /// standing.
    SameKeySibling,
    /// Different public key, expired: not provable as nono's own (public
    /// keys are public), but low-risk since an expired cert can't anchor
    /// anything.
    ExpiredForeignKey,
}

/// Decide whether `candidate` should be deleted, and under which tier,
/// purely from already-known facts — no Keychain access.
fn classify_sweep_candidate(
    candidate: &SweepCandidate,
    stored_spki: &[u8],
    stored_der: &[u8],
    stored_trusted: bool,
    now: i64,
) -> Option<SweepTier> {
    if candidate.is_currently_stored || candidate.der == stored_der {
        return None;
    }
    if !candidate.is_default_keychain {
        return None;
    }
    if !candidate.self_signed {
        return None;
    }
    if candidate.issuer != candidate.subject || !is_exact_nono_ca_dn(&candidate.issuer) {
        return None;
    }
    if candidate.spki == stored_spki {
        stored_trusted.then_some(SweepTier::SameKeySibling)
    } else if candidate.not_after <= now {
        Some(SweepTier::ExpiredForeignKey)
    } else {
        None
    }
}

/// Classify every candidate and cap the result at [`SWEEP_MAX_DELETIONS`].
/// Returns the index into `candidates` and the tier that selected it, in
/// input order, so the caller can stop partway through a batch and still
/// know exactly which ones were already acted on.
fn plan_stale_ca_sweep(
    candidates: &[SweepCandidate],
    stored_spki: &[u8],
    stored_der: &[u8],
    stored_trusted: bool,
    now: i64,
) -> Vec<(usize, SweepTier)> {
    candidates
        .iter()
        .enumerate()
        .filter_map(|(i, c)| {
            classify_sweep_candidate(c, stored_spki, stored_der, stored_trusted, now)
                .map(|t| (i, t))
        })
        .take(SWEEP_MAX_DELETIONS)
        .collect()
}

fn sweep_marker_path() -> Result<PathBuf> {
    let dir = crate::state_paths::user_state_dir()?;
    std::fs::create_dir_all(&dir).map_err(|e| {
        NonoError::SandboxInit(format!("cannot create state dir '{}': {e}", dir.display()))
    })?;
    Ok(dir.join("proxy-ca-sweep-last-run"))
}

/// Whether the sweep already ran within [`SWEEP_INTERVAL`] — at most once a
/// day, so every launch doesn't re-enumerate the whole keychain.
fn sweep_ran_recently() -> Result<bool> {
    let path = sweep_marker_path()?;
    let Ok(modified) = std::fs::metadata(&path).and_then(|m| m.modified()) else {
        return Ok(false);
    };
    let elapsed = SystemTime::now()
        .duration_since(modified)
        .unwrap_or(Duration::ZERO);
    Ok(elapsed < SWEEP_INTERVAL)
}

fn record_sweep_ran() -> Result<()> {
    let path = sweep_marker_path()?;
    std::fs::write(&path, []).map_err(|e| {
        NonoError::SandboxInit(format!(
            "cannot write sweep marker '{}': {e}",
            path.display()
        ))
    })
}

/// Verify a certificate's signature against its own public key — true only
/// for a genuinely self-signed cert, never a look-alike signed by something
/// else. No Keychain or Security-framework access; pure DER parsing + `ring`
/// (via x509-parser's `verify` feature).
fn cert_is_self_signed(der: &[u8]) -> Result<bool> {
    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|e| NonoError::SandboxInit(format!("failed to parse candidate cert DER: {e}")))?;
    Ok(cert.verify_signature(None).is_ok())
}

/// Extract a DN's attributes in structural form for [`is_exact_nono_ca_dn`].
/// No Keychain or Security-framework access; pure DER parsing.
fn dn_attrs(name: &x509_parser::x509::X509Name<'_>) -> DnAttrs {
    name.iter_rdn()
        .flat_map(|rdn| rdn.iter())
        .map(|atv| {
            (
                atv.attr_type().to_id_string(),
                atv.as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

/// Enumerate `nono-proxy-ca` certs in the default (login) keychain, delete the
/// ones [`plan_stale_ca_sweep`] selects, and record the marker. Thin by
/// design, like `trust_cert`/`find_keychain_cert` — this touches Security
/// framework and Keychain APIs directly and stays untested by unit tests; all
/// the actual decision logic lives in `classify_sweep_candidate`/
/// `plan_stale_ca_sweep`.
pub(crate) fn sweep_stale_ca_certs() -> Result<()> {
    if sweep_ran_recently()? {
        return Ok(());
    }

    // Serialize with the other prompting/mutating paths under the same lock;
    // if another process is already busy, skip rather than wait — the sweep
    // is opportunistic cleanup, not something worth blocking launch on.
    let Some(_lock) = RenewalLock::acquire()? else {
        debug!("another process holds the renewal lock; skipping the stale-CA sweep");
        return Ok(());
    };
    // Another process may have just run the sweep while we waited for the lock.
    if sweep_ran_recently()? {
        return Ok(());
    }

    let Some((_key_der, stored_cert_pem)) = load_existing_ca()? else {
        debug!("no stored proxy CA; nothing to sweep against");
        record_sweep_ran()?;
        return Ok(());
    };
    let stored_der = pem_to_der(&stored_cert_pem)?;
    let stored_spki = spki_of(&stored_cert_pem)?;
    let stored_trusted = stored_cert_is_trusted(&stored_cert_pem)?;

    let default_keychain = SecKeychain::default()
        .map_err(|e| NonoError::SandboxInit(format!("failed to open default keychain: {e}")))?;
    let results = ItemSearchOptions::new()
        .class(ItemClass::certificate())
        .load_refs(true)
        .limit(Limit::All)
        .keychains(&[default_keychain])
        .search()
        .map_err(|e| NonoError::SandboxInit(format!("keychain certificate search failed: {e}")))?;

    let certs: Vec<SecCertificate> = results
        .into_iter()
        .filter_map(|item| match item {
            SearchResult::Ref(Reference::Certificate(c)) => Some(c),
            _ => None,
        })
        .collect();

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64;

    // Certs we couldn't parse are simply excluded (never a deletion
    // candidate); `certs_by_candidate` keeps the two lists in lockstep so a
    // plan index still refers to the right `SecCertificate`.
    let mut candidates = Vec::with_capacity(certs.len());
    let mut certs_by_candidate = Vec::with_capacity(certs.len());
    for cert in &certs {
        let der = cert.to_der();
        let Ok((_, parsed)) = x509_parser::parse_x509_certificate(&der) else {
            continue;
        };
        let spki = parsed.public_key().subject_public_key.data.to_vec();
        let issuer = dn_attrs(parsed.issuer());
        let subject = dn_attrs(parsed.subject());
        let self_signed = cert_is_self_signed(&der).unwrap_or(false);
        let not_after = parsed.validity().not_after.timestamp();
        let is_currently_stored = der == stored_der;
        candidates.push(SweepCandidate {
            spki,
            der,
            issuer,
            subject,
            self_signed,
            not_after,
            is_currently_stored,
            is_default_keychain: true,
        });
        certs_by_candidate.push(cert);
    }

    let plan = plan_stale_ca_sweep(&candidates, &stored_spki, &stored_der, stored_trusted, now);
    for (index, tier) in plan {
        let cert = certs_by_candidate[index];
        match cert.delete() {
            Ok(()) => debug!("stale-CA sweep: deleted a {tier:?} candidate"),
            Err(e)
                if is_user_cancelled_osstatus(e.code())
                    || e.code() == ERR_SEC_INTERACTION_NOT_ALLOWED =>
            {
                warn!(
                    "Stale-CA sweep interrupted by an auth prompt cancel/failure \
                     (OSStatus {}); stopping this run rather than continuing through \
                     the rest of the batch.",
                    e.code()
                );
                break;
            }
            Err(e) => warn!("Failed to delete a stale CA cert during the sweep: {e}"),
        }
    }

    record_sweep_ran()?;
    Ok(())
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
    fn supersedes_requires_matching_spki() {
        let key =
            EphemeralCa::generate_with_cn("nono-proxy-ca", Duration::from_secs(3600)).unwrap();
        let live = key.cert_pem().to_string();
        let same_key_renewal = EphemeralCa::reissue_with_cn(
            key.key_der(),
            "nono-proxy-ca",
            Duration::from_secs(86400),
        )
        .unwrap();
        // A later-expiring cert minted under a brand new key, standing in for
        // the `generate_and_trust_new_ca` fallback path.
        let different_key =
            EphemeralCa::generate_with_cn("nono-proxy-ca", Duration::from_secs(86400)).unwrap();

        assert!(
            supersedes(same_key_renewal.cert_pem(), &live).unwrap(),
            "a same-key re-issue with more runway is adoptable"
        );
        assert!(
            !supersedes(different_key.cert_pem(), &live).unwrap(),
            "a different-SPKI cert must never supersede the live CA, however long-lived"
        );
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
        assert!(!is_user_cancelled_osstatus(-25299)); // errSecDuplicateItem
        assert!(!is_user_cancelled_osstatus(0));
        // interaction-not-allowed is a distinct case, handled separately in trust_cert
        assert!(!is_user_cancelled_osstatus(ERR_SEC_INTERACTION_NOT_ALLOWED));
    }

    fn with_fake_state_home<T>(f: impl FnOnce() -> T) -> T {
        let home = tempfile::tempdir().unwrap();
        let _env_lock = crate::test_env::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _guard = crate::test_env::EnvVarGuard::set_all(&[(
            "XDG_STATE_HOME",
            &home.path().display().to_string(),
        )]);
        f()
    }

    #[test]
    fn cert_fingerprint_differs_for_different_certs() {
        let a = generate_test_ca();
        let b = generate_test_ca();
        assert_ne!(
            cert_fingerprint(a.cert_pem()).unwrap(),
            cert_fingerprint(b.cert_pem()).unwrap()
        );
        assert_eq!(
            cert_fingerprint(a.cert_pem()).unwrap(),
            cert_fingerprint(a.cert_pem()).unwrap()
        );
    }

    #[test]
    fn renewal_backoff_is_keyed_to_the_specific_cert() {
        with_fake_state_home(|| {
            let a = generate_test_ca();
            let b = generate_test_ca();

            assert!(!renewal_backed_off(a.cert_pem()).unwrap());
            record_renewal_backoff(a.cert_pem()).unwrap();

            assert!(
                renewal_backed_off(a.cert_pem()).unwrap(),
                "a just-declined cert must be backed off"
            );
            assert!(
                !renewal_backed_off(b.cert_pem()).unwrap(),
                "a marker for one cert must never suppress renewal of a different cert"
            );
        });
    }

    // --- renewal_gate: the pure check-then-lock decision core (Fix 3/4/5) ---
    //
    // These are the seam that fixes the launch-path TOCTOU: `try_ensure_trusted_ca`
    // calls this same function once lock-free (fast path) and once again after
    // acquiring `RenewalLock`, re-reading `state`/`trusted`/`backed_off` fresh each
    // time. Because both calls go through one tested decision core, a decline (or a
    // renewal by another process) recorded in the gap between the two calls is
    // always honored on the re-check — nothing tests the lock-free path's stale
    // answer twice.

    #[test]
    fn renewal_gate_serves_a_valid_trusted_cert_without_acting() {
        assert_eq!(
            renewal_gate(CertValidity::Valid, true, false),
            RenewalGate::ServeStored
        );
        // Even a stale backoff marker is irrelevant once the cert is trusted again.
        assert_eq!(
            renewal_gate(CertValidity::Valid, true, true),
            RenewalGate::ServeStored
        );
    }

    #[test]
    fn renewal_gate_attempts_when_nothing_is_backed_off() {
        assert_eq!(
            renewal_gate(CertValidity::Valid, false, false),
            RenewalGate::Attempt,
            "an untrusted-but-valid cert must be re-trusted"
        );
        assert_eq!(
            renewal_gate(CertValidity::RenewDue, false, false),
            RenewalGate::Attempt
        );
        assert_eq!(
            renewal_gate(CertValidity::Expired, false, false),
            RenewalGate::Attempt
        );
    }

    #[test]
    fn renewal_gate_serves_the_stored_cert_untrusted_when_a_retrust_was_just_declined() {
        // This is the L2 row: a Valid-but-untrusted cert whose re-trust was
        // just declined is still served (untrusted) rather than dropped to an
        // ephemeral CA, until the backoff window lapses.
        assert_eq!(
            renewal_gate(CertValidity::Valid, false, true),
            RenewalGate::ServeStored
        );
    }

    #[test]
    fn renewal_gate_serves_the_old_cert_when_a_renewal_was_just_declined() {
        assert_eq!(
            renewal_gate(CertValidity::RenewDue, false, true),
            RenewalGate::ServeStored
        );
    }

    #[test]
    fn renewal_gate_gives_up_when_an_expired_cert_renewal_was_just_declined() {
        // L4: unlike RenewDue, an expired cert has nothing left to fall back
        // on, so a recent decline must not re-prompt, but also can't serve
        // anything — the caller falls back to an ephemeral CA.
        assert_eq!(
            renewal_gate(CertValidity::Expired, false, true),
            RenewalGate::ServeNone
        );
    }

    #[test]
    fn should_record_backoff_only_for_an_actual_decline() {
        assert!(should_record_backoff(TrustAttemptOutcome::Declined));
        assert!(!should_record_backoff(TrustAttemptOutcome::Trusted));
        assert!(
            !should_record_backoff(TrustAttemptOutcome::NoInteraction),
            "a missing interactive session isn't a decision to throttle later attempts"
        );
    }

    #[test]
    fn post_attempt_action_adopts_on_success_regardless_of_prior_state() {
        for state in [
            CertValidity::Valid,
            CertValidity::RenewDue,
            CertValidity::Expired,
        ] {
            assert_eq!(
                post_attempt_action(TrustAttemptOutcome::Trusted, state),
                PostAttemptAction::AdoptNewlyTrusted
            );
        }
    }

    #[test]
    fn post_attempt_action_keeps_a_still_valid_stored_cert_on_decline() {
        assert_eq!(
            post_attempt_action(TrustAttemptOutcome::Declined, CertValidity::Valid),
            PostAttemptAction::KeepStored,
            "L2: a declined re-trust still has a valid (if untrusted) cert to serve"
        );
        assert_eq!(
            post_attempt_action(TrustAttemptOutcome::Declined, CertValidity::RenewDue),
            PostAttemptAction::KeepStored,
            "a declined renewal still has runway on the old cert"
        );
        assert_eq!(
            post_attempt_action(TrustAttemptOutcome::NoInteraction, CertValidity::RenewDue),
            PostAttemptAction::KeepStored
        );
    }

    #[test]
    fn post_attempt_action_gives_up_only_once_the_stored_cert_has_expired() {
        assert_eq!(
            post_attempt_action(TrustAttemptOutcome::Declined, CertValidity::Expired),
            PostAttemptAction::Unavailable
        );
        assert_eq!(
            post_attempt_action(TrustAttemptOutcome::NoInteraction, CertValidity::Expired),
            PostAttemptAction::Unavailable
        );
    }

    #[test]
    fn trust_attempt_outcome_maps_every_trust_cert_error_variant() {
        assert_eq!(
            trust_attempt_outcome(Ok(())).unwrap(),
            TrustAttemptOutcome::Trusted
        );
        assert_eq!(
            trust_attempt_outcome(Err(TrustCertError::UserCancelled)).unwrap(),
            TrustAttemptOutcome::Declined
        );
        assert_eq!(
            trust_attempt_outcome(Err(TrustCertError::NoInteractionAvailable)).unwrap(),
            TrustAttemptOutcome::NoInteraction
        );
        assert!(
            trust_attempt_outcome(Err(TrustCertError::Other(NonoError::SandboxInit(
                "boom".to_string()
            ))))
            .is_err(),
            "a genuine failure must propagate as an error, not a decision outcome"
        );
    }

    fn nono_ca_dn() -> DnAttrs {
        vec![(OID_COMMON_NAME.to_string(), "nono-proxy-ca".to_string())]
    }

    /// A candidate that would be selected by neither tier unless a test
    /// deliberately changes one field to make it match.
    fn base_sweep_candidate() -> SweepCandidate {
        SweepCandidate {
            spki: b"candidate-spki".to_vec(),
            der: b"candidate-der".to_vec(),
            issuer: nono_ca_dn(),
            subject: nono_ca_dn(),
            self_signed: true,
            not_after: 1_000,
            is_currently_stored: false,
            is_default_keychain: true,
        }
    }

    const STORED_SPKI: &[u8] = b"stored-spki";
    const STORED_DER: &[u8] = b"stored-der";
    const NOW: i64 = 2_000;

    #[test]
    fn classify_sweep_candidate_selects_a_same_key_sibling_only_when_stored_is_trusted() {
        let candidate = SweepCandidate {
            spki: STORED_SPKI.to_vec(),
            not_after: NOW + 1, // still valid — tier 1 doesn't care about validity
            ..base_sweep_candidate()
        };
        assert_eq!(
            classify_sweep_candidate(&candidate, STORED_SPKI, STORED_DER, true, NOW),
            Some(SweepTier::SameKeySibling)
        );
        assert_eq!(
            classify_sweep_candidate(&candidate, STORED_SPKI, STORED_DER, false, NOW),
            None,
            "a same-key sibling is never deleted while the stored cert is itself untrusted"
        );
    }

    #[test]
    fn classify_sweep_candidate_selects_an_expired_foreign_key_only_when_expired() {
        let candidate = SweepCandidate {
            not_after: NOW - 1,
            ..base_sweep_candidate()
        };
        assert_eq!(
            classify_sweep_candidate(&candidate, STORED_SPKI, STORED_DER, true, NOW),
            Some(SweepTier::ExpiredForeignKey)
        );
        let still_valid = SweepCandidate {
            not_after: NOW + 1,
            ..base_sweep_candidate()
        };
        assert_eq!(
            classify_sweep_candidate(&still_valid, STORED_SPKI, STORED_DER, true, NOW),
            None,
            "a foreign-key cert that hasn't expired yet is never deleted"
        );
    }

    #[test]
    fn classify_sweep_candidate_never_deletes_the_currently_stored_cert() {
        let flagged = SweepCandidate {
            spki: STORED_SPKI.to_vec(),
            is_currently_stored: true,
            ..base_sweep_candidate()
        };
        assert_eq!(
            classify_sweep_candidate(&flagged, STORED_SPKI, STORED_DER, true, NOW),
            None
        );

        // Belt-and-suspenders: matching DER is also treated as "the stored
        // cert", even if the enumeration wrapper failed to set the flag.
        let matching_der = SweepCandidate {
            der: STORED_DER.to_vec(),
            spki: STORED_SPKI.to_vec(),
            ..base_sweep_candidate()
        };
        assert_eq!(
            classify_sweep_candidate(&matching_der, STORED_SPKI, STORED_DER, true, NOW),
            None
        );
    }

    #[test]
    fn classify_sweep_candidate_rejects_a_bad_self_signature_look_alike() {
        let candidate = SweepCandidate {
            self_signed: false,
            not_after: NOW - 1, // otherwise a clean tier-2 match
            ..base_sweep_candidate()
        };
        assert_eq!(
            classify_sweep_candidate(&candidate, STORED_SPKI, STORED_DER, true, NOW),
            None,
            "the right CN with a bad self-signature must never be deleted"
        );
    }

    #[test]
    fn classify_sweep_candidate_rejects_a_dn_that_is_not_exactly_nono_proxy_ca() {
        let wrong_cn = SweepCandidate {
            issuer: vec![(OID_COMMON_NAME.to_string(), "not-nono-proxy-ca".to_string())],
            subject: vec![(OID_COMMON_NAME.to_string(), "not-nono-proxy-ca".to_string())],
            not_after: NOW - 1,
            ..base_sweep_candidate()
        };
        assert_eq!(
            classify_sweep_candidate(&wrong_cn, STORED_SPKI, STORED_DER, true, NOW),
            None
        );

        let extra_rdn = SweepCandidate {
            issuer: {
                let mut dn = nono_ca_dn();
                dn.push(("2.5.4.10".to_string(), "Extra Org".to_string()));
                dn
            },
            subject: {
                let mut dn = nono_ca_dn();
                dn.push(("2.5.4.10".to_string(), "Extra Org".to_string()));
                dn
            },
            not_after: NOW - 1,
            ..base_sweep_candidate()
        };
        assert_eq!(
            classify_sweep_candidate(&extra_rdn, STORED_SPKI, STORED_DER, true, NOW),
            None,
            "a DN with the right CN plus another attribute is not an exact match"
        );

        let mismatched_issuer_subject = SweepCandidate {
            issuer: nono_ca_dn(),
            subject: vec![(OID_COMMON_NAME.to_string(), "nono-proxy-ca".to_string())],
            not_after: NOW - 1,
            ..base_sweep_candidate()
        };
        // Structurally equal in this case, so assert the inequality path
        // separately by constructing a genuine mismatch.
        let issuer_differs = SweepCandidate {
            issuer: vec![("2.5.4.3".to_string(), "nono-proxy-ca".to_string())],
            subject: vec![("2.5.4.3".to_string(), "nono-proxy-ca ".to_string())],
            not_after: NOW - 1,
            ..base_sweep_candidate()
        };
        assert_eq!(
            classify_sweep_candidate(
                &mismatched_issuer_subject,
                STORED_SPKI,
                STORED_DER,
                true,
                NOW
            ),
            Some(SweepTier::ExpiredForeignKey),
            "sanity: identical issuer/subject content is still an exact match"
        );
        assert_eq!(
            classify_sweep_candidate(&issuer_differs, STORED_SPKI, STORED_DER, true, NOW),
            None,
            "issuer and subject must match exactly, not just both resemble the CA CN"
        );
    }

    #[test]
    fn classify_sweep_candidate_rejects_a_non_default_keychain_item() {
        let candidate = SweepCandidate {
            is_default_keychain: false,
            not_after: NOW - 1,
            ..base_sweep_candidate()
        };
        assert_eq!(
            classify_sweep_candidate(&candidate, STORED_SPKI, STORED_DER, true, NOW),
            None,
            "the sweep must never touch an item outside the default (login) keychain"
        );
    }

    #[test]
    fn plan_stale_ca_sweep_caps_deletions_at_the_limit() {
        let candidates: Vec<SweepCandidate> = (0..150)
            .map(|i| SweepCandidate {
                der: format!("der-{i}").into_bytes(),
                not_after: NOW - 1,
                ..base_sweep_candidate()
            })
            .collect();

        let plan = plan_stale_ca_sweep(&candidates, STORED_SPKI, STORED_DER, true, NOW);

        assert_eq!(plan.len(), SWEEP_MAX_DELETIONS);
        assert_eq!(
            plan.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
            (0..SWEEP_MAX_DELETIONS).collect::<Vec<_>>(),
            "the cap takes the first matches in input order, not an arbitrary subset"
        );
    }

    #[test]
    fn sweep_marker_throttles_to_once_a_day() {
        with_fake_state_home(|| {
            assert!(!sweep_ran_recently().unwrap());
            record_sweep_ran().unwrap();
            assert!(
                sweep_ran_recently().unwrap(),
                "a run recorded moments ago must suppress another run today"
            );
        });
    }

    #[test]
    fn cert_is_self_signed_detects_a_genuine_self_signed_cert() {
        let ca = generate_test_ca();
        let der = pem_to_der(ca.cert_pem()).unwrap();
        assert!(cert_is_self_signed(&der).unwrap());
    }

    #[test]
    fn cert_is_self_signed_rejects_a_tampered_signature() {
        let ca = generate_test_ca();
        let mut der = pem_to_der(ca.cert_pem()).unwrap();
        // The signature BIT STRING is the certificate's last field; flipping
        // its final byte changes the signature without changing any ASN.1
        // length or tag, so the DER still parses but no longer verifies.
        let last = der.len() - 1;
        der[last] ^= 0xFF;
        assert!(
            !cert_is_self_signed(&der).unwrap_or(true),
            "a tampered signature must never be reported as self-signed"
        );
    }

    #[test]
    fn dn_attrs_extracts_the_exact_common_name_of_a_generated_ca() {
        let ca = generate_test_ca();
        let der = pem_to_der(ca.cert_pem()).unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();

        let subject = dn_attrs(cert.subject());
        let issuer = dn_attrs(cert.issuer());

        assert_eq!(subject, nono_ca_dn());
        assert_eq!(issuer, nono_ca_dn());
        assert!(is_exact_nono_ca_dn(&subject));
        assert!(is_exact_nono_ca_dn(&issuer));
    }

    #[test]
    fn is_exact_nono_ca_dn_rejects_look_alikes() {
        assert!(!is_exact_nono_ca_dn(&vec![]));
        assert!(!is_exact_nono_ca_dn(&vec![(
            OID_COMMON_NAME.to_string(),
            "nono-proxy-ca-evil".to_string()
        )]));
        assert!(!is_exact_nono_ca_dn(&vec![
            (OID_COMMON_NAME.to_string(), "nono-proxy-ca".to_string()),
            ("2.5.4.10".to_string(), "Extra Org".to_string()),
        ]));
        assert!(!is_exact_nono_ca_dn(&vec![(
            "2.5.4.10".to_string(),
            "nono-proxy-ca".to_string()
        )]));
        assert!(is_exact_nono_ca_dn(&nono_ca_dn()));
    }
}
