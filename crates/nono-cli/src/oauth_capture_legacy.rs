//! Cleanup of a leftover plaintext OAuth-capture store.
//!
//! `$XDG_STATE_HOME/nono/oauth-capture/providers.json` holds captured OAuth
//! access/refresh tokens in plaintext (`PersistedOAuthToken.real`), protected
//! only by file mode 0600. Under the macOS Keychain backend
//! (`oauth_capture_store_backend = "auto" | "keychain"`) the proxy never opens
//! that file — it is passed to
//! `OAuthCaptureStore::load_with_runtime_persistence` only as the "persistence
//! enabled" signal. So a copy written by an earlier file-backend session
//! lingers indefinitely with live tokens in it.
//!
//! ## Two surfaces, and why they differ
//!
//! [`check_and_offer_removal`] — the interactive offer — lives in `nono setup`.
//! It is deliberately *not* on the `nono run` path. A full-screen TUI coding
//! agent owns the terminal and clears the screen, so a pre-launch notice is
//! never read and a prompt cannot be answered while the agent runs. Asking after
//! the child exits only relocates the problem: it interrupts someone who has
//! finished their session, and answering leaves them to relaunch the agent to
//! keep working. A one-time migration artifact belongs behind a one-time
//! deliberate action, which is the same placement — and reasoning —
//! `legacy_cleanup` uses.
//!
//! [`remind_post_exit`] — a passive two-line notice — does run after the child
//! exits, so a leftover store is still discoverable without anyone having to
//! think to run `nono setup`. It asks nothing, blocks nothing, and points at the
//! command that does the cleanup. It fires only on a clean exit: a failing run
//! already has diagnostics competing for attention, and a stale credential file
//! is not what that user needs to read about.
//!
//! ## Why we ask rather than delete
//!
//! The file is the live store again the moment a profile sets `"file"` back, and
//! it is the only copy of those tokens: removing it forces a fresh login for
//! every captured provider. Deleting it on nono's own judgement would violate
//! AGENTS.md "Explicit Over Implicit", so the prompt defaults to no.

use crate::state_paths;
use nono::{NonoError, Result};
use nono_proxy::config::OAuthCaptureStoreBackend;
use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

thread_local! {
    /// Set once the post-exit reminder has been emitted, so a session that
    /// somehow reaches the tail twice reminds only once.
    static POST_EXIT_REMINDED: Cell<bool> = const { Cell::new(false) };
}

/// A plaintext store found on disk. Its contents are never read — see
/// [`scan_at`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StalePlaintextStore {
    /// Uncanonicalized store path, exactly as the writer computes it.
    pub(crate) path: PathBuf,
    pub(crate) size_bytes: u64,
    /// Last-write time, when the filesystem reports one.
    pub(crate) modified: Option<SystemTime>,
}

/// True when a session persists captured phantoms to the macOS Keychain rather
/// than to `providers.json`.
///
/// Used by `sandbox_prepare::prepare_sandbox` to gate the derived `security`
/// mediation. Off macOS this is always `false`:
/// `OAuthCaptureStore::resolve_backend` maps every preference to
/// `PersistBackend::File` there.
///
/// `credential_providers` are OAuth-capture providers (the only provider type
/// today), so a non-zero count means OAuth capture is enabled.
pub(crate) fn keychain_backend_active(
    credential_provider_count: usize,
    backend: OAuthCaptureStoreBackend,
) -> bool {
    cfg!(target_os = "macos")
        && credential_provider_count > 0
        && backend != OAuthCaptureStoreBackend::File
}

/// Classify a path that may hold a stale plaintext store.
///
/// Detection is a single `fs::metadata` call — existence, regular file, and
/// non-empty. The file's *contents* are deliberately never read:
///
/// 1. `load_persisted_tokens` deserializes `PersistedOAuthToken.real: String`;
///    that `String`, the `fs::read` buffer, and serde's scratch are not
///    zeroized. Pulling live OAuth tokens into this process just to decide
///    whether to offer a cleanup is a gratuitous secret-exposure widening.
/// 2. It is `pub(super)` in `nono-proxy`; reaching it from nono-cli would move
///    a plaintext-token type across the library/CLI boundary.
/// 3. It hard-errors on a parse failure, which would turn a best-effort offer
///    into a failure.
///
/// Accepted imprecision: a file holding exactly `{"version":1,"tokens":{}}`
/// is reported despite containing no tokens. That is the right trade — the
/// remediation is identical and harmless either way, and the alternatives are
/// reading secrets or inventing a byte-count threshold we cannot justify.
///
/// Takes the path rather than resolving it so tests can point at a tempdir.
pub(crate) fn scan_at(path: &Path) -> Option<StalePlaintextStore> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() == 0 {
        return None;
    }
    Some(StalePlaintextStore {
        path: path.to_path_buf(),
        size_bytes: metadata.len(),
        modified: metadata.modified().ok(),
    })
}

/// Resolve the canonical store path and scan it.
pub(crate) fn scan() -> Result<Option<StalePlaintextStore>> {
    Ok(scan_at(&state_paths::oauth_capture_store_path()?))
}

/// Remove a leftover plaintext store, pruning the parent directory when that
/// leaves it empty.
///
/// This is an `unlink`, not a secure erase: the plaintext blocks stay on the
/// device until reused, and any filesystem snapshot taken while the file existed
/// still holds the tokens. Callers must have confirmed with the user first.
///
/// Deliberately does not migrate: folding the tokens into the Keychain first
/// would mean reading plaintext token material here, and the captured providers
/// can simply be logged into again.
pub(crate) fn remove(store: &StalePlaintextStore) -> Result<()> {
    fs::remove_file(&store.path).map_err(NonoError::Io)?;

    // The `oauth-capture/` directory exists only to hold this file. Leaving an
    // empty one behind would make a later `scan` look at a path whose parent
    // implies a store that is not there.
    if let Some(parent) = store.path.parent()
        && fs::read_dir(parent).is_ok_and(|mut entries| entries.next().is_none())
    {
        // Best-effort: a concurrent write recreating the file is not an error.
        let _ = fs::remove_dir(parent);
    }
    Ok(())
}

/// Remind, once, that a leftover plaintext store is still on disk. Called from
/// the supervised runtime after the child exits.
///
/// Passive by design: two lines, no question, nothing to answer. It points at
/// `nono setup`, which owns the interactive removal.
///
/// Silent unless every condition holds — a clean exit, a Keychain-backed
/// session, and a file actually present. Cheap on the overwhelming majority of
/// runs: without credential providers the predicate short-circuits before any
/// syscall. Respects `--silent`.
pub(crate) fn remind_post_exit(
    credential_provider_count: usize,
    backend: OAuthCaptureStoreBackend,
    silent: bool,
    exit_code: i32,
) {
    // Only on a clean exit. A failing run already has a diagnostic footer and
    // possibly a denied-paths review competing for attention.
    if silent || exit_code != 0 || !keychain_backend_active(credential_provider_count, backend) {
        return;
    }

    let store = match scan() {
        Ok(Some(store)) => store,
        Ok(None) => return,
        Err(error) => {
            tracing::debug!(%error, "could not resolve OAuth-capture store path");
            return;
        }
    };

    // Claim the one-shot only once there is something to say.
    if POST_EXIT_REMINDED.with(|done| done.replace(true)) {
        return;
    }

    // Structured record so `--log-file` captures the condition too.
    tracing::warn!(
        path = %store.path.display(),
        size_bytes = store.size_bytes,
        "plaintext OAuth-capture store present while the Keychain backend is active"
    );
    crate::output::print_stale_oauth_capture_store_reminder(&store);
}

/// Offer to remove a leftover plaintext store. Entry point for `nono setup`.
///
/// A silent no-op when there is nothing to clean up, so a normal `nono setup` on
/// a clean install prints nothing — same contract as
/// `legacy_cleanup::check_and_offer_cleanup`.
///
/// macOS only. On Linux the file backend is the only backend, so
/// `providers.json` is always the live store and offering to delete it would be
/// actively wrong.
///
/// Note this cannot consult [`keychain_backend_active`]: `nono setup` takes no
/// `--profile`, so no backend preference is in scope. It therefore offers
/// whenever the file exists on macOS, where `auto` (the default) resolves to the
/// Keychain. A profile that explicitly sets `"file"` still uses this file, which
/// is why the prompt says so and defaults to no.
pub(crate) fn check_and_offer_removal() -> Result<()> {
    if !cfg!(target_os = "macos") {
        return Ok(());
    }

    let store = match scan() {
        Ok(Some(store)) => store,
        Ok(None) => return Ok(()),
        // A path-resolution failure must not fail `nono setup`.
        Err(error) => {
            tracing::debug!(%error, "could not resolve OAuth-capture store path");
            return Ok(());
        }
    };

    tracing::debug!(
        path = %store.path.display(),
        size_bytes = store.size_bytes,
        "found a plaintext OAuth-capture store"
    );

    match crate::output::prompt_stale_oauth_capture_store_removal(&store) {
        Some(true) => {
            remove(&store)?;
            crate::output::print_stale_oauth_capture_store_removed(&store);
        }
        // Declined, no TTY to ask, or stdin closed mid-prompt: leave the file
        // and say how to remove it by hand.
        Some(false) | None => {
            crate::output::print_stale_oauth_capture_store_declined(&store);
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::test_env::{ENV_LOCK, EnvVarGuard};

    // -- keychain_backend_active ------------------------------------------

    #[test]
    fn keychain_backend_active_false_without_credential_providers() {
        assert!(!keychain_backend_active(0, OAuthCaptureStoreBackend::Auto));
        assert!(!keychain_backend_active(
            0,
            OAuthCaptureStoreBackend::Keychain
        ));
    }

    #[test]
    fn keychain_backend_active_false_for_file_backend() {
        // True on every platform: an explicit `file` backend means
        // providers.json is the live store, never a leftover.
        assert!(!keychain_backend_active(1, OAuthCaptureStoreBackend::File));
    }

    /// Requirement guard: nothing about this feature may fire on Linux, where
    /// `resolve_backend` maps every preference to the file backend and
    /// `providers.json` is the live store.
    #[test]
    fn keychain_backend_active_matches_platform_for_auto() {
        let active = keychain_backend_active(1, OAuthCaptureStoreBackend::Auto);
        #[cfg(target_os = "macos")]
        assert!(active);
        #[cfg(not(target_os = "macos"))]
        assert!(!active);
    }

    #[test]
    fn keychain_backend_active_matches_platform_for_keychain() {
        let active = keychain_backend_active(1, OAuthCaptureStoreBackend::Keychain);
        #[cfg(target_os = "macos")]
        assert!(active);
        #[cfg(not(target_os = "macos"))]
        assert!(!active);
    }

    // -- scan_at ------------------------------------------------------------

    #[test]
    fn scan_at_missing_file_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(scan_at(&tmp.path().join("providers.json")).is_none());
    }

    #[test]
    fn scan_at_empty_file_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("providers.json");
        fs::write(&path, b"").unwrap();
        assert!(scan_at(&path).is_none());
    }

    #[test]
    fn scan_at_populated_file_reports_size() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("providers.json");
        let blob = br#"{"version":1,"tokens":{"phantom":{"real":"secret"}}}"#;
        fs::write(&path, blob).unwrap();

        let found = scan_at(&path).expect("populated store is detected");
        assert_eq!(found.path, path);
        assert_eq!(found.size_bytes, blob.len() as u64);
    }

    #[test]
    fn scan_at_directory_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("providers.json");
        fs::create_dir(&path).unwrap();
        assert!(scan_at(&path).is_none());
    }

    /// This test pins the design: it passes only while detection is
    /// `metadata`-based, and fails the moment someone "improves" `scan_at` to
    /// open or parse the file. Detection must never read token material.
    #[cfg(unix)]
    #[test]
    fn scan_at_does_not_read_contents() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("providers.json");
        fs::write(&path, b"unreadable but present").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();

        assert!(
            scan_at(&path).is_some(),
            "detection must rely on metadata, not on reading the file"
        );
    }

    // -- scan ---------------------------------------------------------------

    #[test]
    fn scan_resolves_under_xdg_state_home() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("state");
        let store = state.join("nono").join("oauth-capture");
        fs::create_dir_all(&store).unwrap();
        fs::write(store.join("providers.json"), b"{}").unwrap();

        let state_str = state.to_string_lossy().to_string();
        let _env = EnvVarGuard::set_all(&[("XDG_STATE_HOME", &state_str)]);

        let found = scan()
            .unwrap()
            .expect("store under XDG_STATE_HOME is found");
        assert_eq!(found.path, store.join("providers.json"));
    }

    // -- remind_post_exit ---------------------------------------------------

    fn reset_reminder() {
        POST_EXIT_REMINDED.with(|done| done.set(false));
    }

    /// A failing run already has a diagnostic footer and possibly a denied-paths
    /// review competing for attention; a stale credential file is not what that
    /// user needs to read about.
    #[test]
    fn remind_post_exit_is_silent_on_a_failing_exit() {
        reset_reminder();
        remind_post_exit(1, OAuthCaptureStoreBackend::Auto, false, 1);
        assert!(!POST_EXIT_REMINDED.with(Cell::get));
    }

    #[test]
    fn remind_post_exit_is_silent_for_the_file_backend() {
        reset_reminder();
        remind_post_exit(1, OAuthCaptureStoreBackend::File, false, 0);
        assert!(!POST_EXIT_REMINDED.with(Cell::get));
    }

    #[test]
    fn remind_post_exit_silent_does_not_consume_the_flag() {
        reset_reminder();
        remind_post_exit(1, OAuthCaptureStoreBackend::Auto, true, 0);
        assert!(
            !POST_EXIT_REMINDED.with(Cell::get),
            "a silent call must leave the one-shot unclaimed so a later \
             non-silent call still reminds"
        );
    }

    // -- check_and_offer_removal --------------------------------------------

    /// Must print nothing and touch nothing when there is no store, so a normal
    /// `nono setup` on a clean install is unaffected.
    #[test]
    fn check_and_offer_removal_is_silent_without_a_store() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("state");
        fs::create_dir_all(&state).unwrap();
        let state_str = state.to_string_lossy().to_string();
        let _env = EnvVarGuard::set_all(&[("XDG_STATE_HOME", &state_str)]);

        check_and_offer_removal().expect("clean install is a no-op");
    }

    // -- remove -------------------------------------------------------------

    fn store_at(path: &Path) -> StalePlaintextStore {
        StalePlaintextStore {
            path: path.to_path_buf(),
            size_bytes: 1,
            modified: None,
        }
    }

    #[test]
    fn remove_deletes_the_store_and_prunes_the_empty_parent() {
        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().join("oauth-capture");
        fs::create_dir_all(&parent).unwrap();
        let path = parent.join("providers.json");
        fs::write(&path, b"{}").unwrap();

        remove(&store_at(&path)).expect("removal succeeds");

        assert!(!path.exists(), "store file is gone");
        assert!(!parent.exists(), "empty parent directory is pruned");
    }

    #[test]
    fn remove_keeps_a_parent_that_still_holds_other_files() {
        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().join("oauth-capture");
        fs::create_dir_all(&parent).unwrap();
        let path = parent.join("providers.json");
        fs::write(&path, b"{}").unwrap();
        let sibling = parent.join("providers.json.tmp");
        fs::write(&sibling, b"partial").unwrap();

        remove(&store_at(&path)).expect("removal succeeds");

        assert!(!path.exists());
        assert!(
            sibling.exists(),
            "an unrelated sibling must survive, and keep its directory"
        );
        assert!(parent.exists());
    }

    #[test]
    fn remove_reports_a_missing_store_as_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        // Racing another nono that already cleaned up: surface it rather than
        // reporting a removal that did not happen.
        assert!(remove(&store_at(&tmp.path().join("providers.json"))).is_err());
    }
}
