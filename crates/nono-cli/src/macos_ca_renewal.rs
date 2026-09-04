//! Keeps a running session's interception CA usable across its own expiry, which
//! would otherwise kill every intercepted route until a restart.
//!
//! Adopting a certificate another launch already renewed is preferred over renewing
//! here, because only the latter writes to the trust store and prompts.

use crate::macos_trust::{self, CertValidity, RenewOutcome};
use nono_proxy::tls_intercept::InterceptCaRotator;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Each check is a Keychain read, and a 7-day certificate needs nothing tighter.
const MAX_CHECK_INTERVAL: Duration = Duration::from_secs(3600);

/// Floor, so a misconfigured tiny `ca_validity` can't spin.
const MIN_CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// After a declined prompt or failed trust write: re-prompting hourly would be
/// worse than the expiry.
const BACKOFF_AFTER_FAILURE: Duration = Duration::from_secs(6 * 3600);

/// Watch the live interception CA and keep it renewed for the life of the process.
///
/// A plain thread, not a tokio task: every step is a blocking Security.framework
/// call, and it must outlive the caller's stack frame.
pub(crate) fn spawn_supervisor(rotator: Arc<InterceptCaRotator>, validity: Duration) {
    let interval = check_interval(validity);
    std::thread::Builder::new()
        .name("nono-ca-renewal".to_string())
        .spawn(move || {
            let mut delay = interval;
            // Sticky once set: this session can never satisfy a trust prompt, but
            // it should keep polling so it can still adopt a cert some other,
            // interactive session renews in the meantime.
            let mut renewal_disabled = false;
            loop {
                std::thread::sleep(delay);
                let outcome = supervise_once(&rotator, validity, renewal_disabled);
                if matches!(outcome, Ok(Outcome::NoInteraction)) {
                    renewal_disabled = true;
                }
                delay = next_delay(outcome, interval);
            }
        })
        .map(|_| ())
        .unwrap_or_else(|e| warn!("Could not start proxy CA renewal supervisor: {e}"));
}

/// Several checks per headroom, so the renewal window is never missed however
/// short the configured validity is.
fn check_interval(validity: Duration) -> Duration {
    let headroom = macos_trust::renewal_headroom(validity.as_secs().min(i64::MAX as u64) as i64);
    (headroom / 2).clamp(MIN_CHECK_INTERVAL, MAX_CHECK_INTERVAL)
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// Live certificate has life left and nothing newer is stored.
    NothingToDo,
    /// Swapped in a certificate another process had already renewed.
    Adopted,
    /// Re-issued and installed a certificate ourselves.
    Renewed,
    /// Lost the lock race to another session renewing right now. Retries on the
    /// normal interval, by which point that session's certificate is adoptable.
    Busy,
    /// A trust prompt was declined or a trust write failed; still serving the old
    /// cert. Backs off, since re-prompting hourly would be worse than the expiry.
    Deferred,
    /// No interactive session exists to show the trust prompt (e.g. a headless
    /// `nono proxy`). This session will never prompt again, but keeps polling
    /// at the normal interval in case another, interactive session renews the
    /// CA in the meantime and this one can adopt it.
    NoInteraction,
}

/// How long to sleep before the next check, given the last one's outcome.
///
/// Only a declined prompt or a failed trust write backs off; losing the lock
/// race to another session, and having no interactive session to prompt, are
/// both routine and retry on the normal interval — the former so this session
/// adopts what the winner just wrote, the latter so it can still adopt a cert
/// renewed elsewhere even though it can never renew one itself.
fn next_delay(outcome: nono::Result<Outcome>, interval: Duration) -> Duration {
    match outcome {
        Ok(Outcome::Deferred) => BACKOFF_AFTER_FAILURE,
        Ok(_) => interval,
        Err(e) => {
            warn!("Proxy CA renewal check failed: {e}");
            BACKOFF_AFTER_FAILURE
        }
    }
}

fn supervise_once(
    rotator: &InterceptCaRotator,
    validity: Duration,
    renewal_disabled: bool,
) -> nono::Result<Outcome> {
    let live = rotator
        .current_cert_pem()
        .map_err(|e| nono::NonoError::SandboxInit(format!("{e}")))?;

    if let Some(outcome) = try_adopt(rotator, &live)? {
        return Ok(outcome);
    }
    if macos_trust::cert_validity(&live)? == CertValidity::Valid {
        return Ok(Outcome::NothingToDo);
    }
    if renewal_disabled {
        debug!(
            "proxy CA renewal needs authentication but no interactive session is available in \
             this run; only adopting certs renewed by another session"
        );
        return Ok(Outcome::NoInteraction);
    }

    // Renewal writes to the trust store and prompts; one winner per machine.
    let Some(_lock) = RenewalLock::acquire()? else {
        debug!("another process is renewing the proxy CA; will retry on the normal interval");
        return Ok(Outcome::Busy);
    };
    // It may have finished while we waited for the lock.
    if let Some(outcome) = try_adopt(rotator, &live)? {
        return Ok(outcome);
    }

    match macos_trust::renew_shared_ca(validity)? {
        RenewOutcome::Renewed(renewed) => {
            install(rotator, &renewed.key_der, &renewed.cert_pem)?;
            info!("Proxy CA renewed mid-session; no restart needed");
            Ok(Outcome::Renewed)
        }
        RenewOutcome::Unchanged => {
            warn!(
                "Proxy CA could not be renewed (authentication declined or trust write failed). \
                 Still serving the current certificate; will retry later. Intercepted routes will \
                 fail once it expires — restart the agent to recover."
            );
            Ok(Outcome::Deferred)
        }
        RenewOutcome::NoInteraction => {
            tracing::error!(
                "Proxy CA needs renewal but no interactive session is available to authorize it \
                 (headless session). Won't prompt again this run; the current certificate will \
                 expire and intercepted routes will fail unless another, interactive session \
                 renews it and this one adopts the result."
            );
            Ok(Outcome::NoInteraction)
        }
    }
}

/// Swap in the stored CA if it supersedes what we're serving.
fn try_adopt(rotator: &InterceptCaRotator, live: &str) -> nono::Result<Option<Outcome>> {
    let Some((key_der, cert_pem)) = macos_trust::read_shared_ca()? else {
        return Ok(None);
    };
    if !worth_adopting(&cert_pem, live)? {
        return Ok(None);
    }
    if !macos_trust::stored_cert_is_trusted(&cert_pem)? {
        debug!("stored proxy CA is newer but not trusted; not adopting");
        return Ok(None);
    }
    install(rotator, &key_der, &cert_pem)?;
    info!("Adopted renewed proxy CA from Keychain");
    Ok(Some(Outcome::Adopted))
}

fn worth_adopting(stored: &str, live: &str) -> nono::Result<bool> {
    Ok(stored != live && macos_trust::supersedes(stored, live)?)
}

fn install(rotator: &InterceptCaRotator, key_der: &[u8], cert_pem: &str) -> nono::Result<PathBuf> {
    rotator
        .rotate(key_der, cert_pem)
        .map_err(|e| nono::NonoError::SandboxInit(format!("failed to install renewed CA: {e}")))
}

/// Advisory lock so two sessions renewing at once produce one prompt, and one
/// Keychain write, rather than two.
struct RenewalLock {
    _lock: nix::fcntl::Flock<std::fs::File>,
}

impl RenewalLock {
    fn acquire() -> nono::Result<Option<Self>> {
        let dir = crate::state_paths::user_state_dir()?;
        std::fs::create_dir_all(&dir).map_err(|e| {
            nono::NonoError::SandboxInit(format!(
                "cannot create state dir '{}': {e}",
                dir.display()
            ))
        })?;
        let path = dir.join("proxy-ca-renewal.lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|e| {
                nono::NonoError::SandboxInit(format!(
                    "cannot open renewal lock '{}': {e}",
                    path.display()
                ))
            })?;
        match nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock) {
            Ok(lock) => Ok(Some(Self { _lock: lock })),
            Err((_, nix::errno::Errno::EWOULDBLOCK)) => Ok(None),
            Err((_, e)) => Err(nono::NonoError::SandboxInit(format!(
                "cannot lock '{}': {e}",
                path.display()
            ))),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use nono_proxy::tls_intercept::{CertCache, EphemeralCa};

    fn rotator_with(ca: EphemeralCa, dir: &std::path::Path) -> InterceptCaRotator {
        InterceptCaRotator::new(
            Arc::new(CertCache::new(Arc::new(ca))),
            dir.to_path_buf(),
            "intercept-ca.pem",
            None,
        )
    }

    #[test]
    fn the_check_interval_fits_inside_the_renewal_headroom() {
        // 7 days: 24h headroom, so hourly is the cap that bites.
        assert_eq!(
            check_interval(Duration::from_secs(7 * 86400)),
            MAX_CHECK_INTERVAL
        );
        // 120s: 30s headroom, so checks must be far tighter than hourly or the
        // window closes unnoticed.
        assert_eq!(
            check_interval(Duration::from_secs(120)),
            Duration::from_secs(15)
        );
        assert_eq!(check_interval(Duration::from_secs(1)), MIN_CHECK_INTERVAL);
    }

    #[test]
    fn losing_the_lock_race_retries_on_the_normal_interval_not_backoff() {
        assert_eq!(
            next_delay(Ok(Outcome::Busy), Duration::from_secs(42)),
            Duration::from_secs(42),
            "lock contention is routine; it must not trigger the failure backoff"
        );
    }

    #[test]
    fn a_declined_or_failed_trust_attempt_backs_off() {
        assert_eq!(
            next_delay(Ok(Outcome::Deferred), Duration::from_secs(42)),
            BACKOFF_AFTER_FAILURE
        );
    }

    #[test]
    fn no_interactive_session_retries_on_the_normal_interval_not_forever() {
        assert_eq!(
            next_delay(Ok(Outcome::NoInteraction), Duration::from_secs(42)),
            Duration::from_secs(42),
            "a headless session can't renew, but must keep polling so it can still adopt a cert \
             renewed by another, interactive session"
        );
    }

    #[test]
    fn only_a_longer_lived_stored_cert_is_worth_adopting() {
        let key =
            EphemeralCa::generate_with_cn("nono-proxy-ca", Duration::from_secs(3600)).unwrap();
        let live = key.cert_pem().to_string();
        let renewed = EphemeralCa::reissue_with_cn(
            key.key_der(),
            "nono-proxy-ca",
            Duration::from_secs(86400),
        )
        .unwrap();

        assert!(worth_adopting(renewed.cert_pem(), &live).unwrap());
        assert!(
            !worth_adopting(&live, &live).unwrap(),
            "the cert we already serve is not an upgrade"
        );
        assert!(
            !worth_adopting(&live, renewed.cert_pem()).unwrap(),
            "a shorter-lived cert must never displace a renewed one"
        );
    }

    #[test]
    fn a_rotation_replaces_the_live_cert_and_the_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let ca = EphemeralCa::generate_with_cn("nono-proxy-ca", Duration::from_secs(3600)).unwrap();
        let old = ca.cert_pem().to_string();
        let key_der = ca.key_der().to_vec();
        let r = rotator_with(ca, dir.path());

        let renewed =
            EphemeralCa::reissue_with_cn(&key_der, "nono-proxy-ca", Duration::from_secs(7 * 86400))
                .unwrap();
        let bundle = install(&r, &key_der, renewed.cert_pem()).unwrap();

        assert_eq!(r.current_cert_pem().unwrap(), renewed.cert_pem());
        assert_ne!(r.current_cert_pem().unwrap(), old);
        assert!(
            std::fs::read_to_string(&bundle)
                .unwrap()
                .contains(renewed.cert_pem()),
            "the bundle a child reads must carry the renewed anchor"
        );
    }

    #[test]
    fn the_lock_is_exclusive_across_holders() {
        let home = tempfile::tempdir().unwrap();
        let _env_lock = crate::test_env::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _guard = crate::test_env::EnvVarGuard::set_all(&[(
            "XDG_STATE_HOME",
            &home.path().display().to_string(),
        )]);

        let first = RenewalLock::acquire().unwrap();
        assert!(first.is_some(), "first acquisition must succeed");
        assert!(
            RenewalLock::acquire().unwrap().is_none(),
            "a second holder must be turned away, so concurrent sessions prompt once"
        );
        drop(first);
        assert!(
            RenewalLock::acquire().unwrap().is_some(),
            "the lock must be released with its holder"
        );
    }
}
