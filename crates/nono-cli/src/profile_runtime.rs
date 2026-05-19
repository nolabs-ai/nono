use crate::cli::SandboxArgs;
use crate::{hooks, profile};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub(crate) struct PreparedProfile {
    pub(crate) loaded_profile: Option<profile::Profile>,
    pub(crate) capability_elevation: bool,
    #[cfg(target_os = "linux")]
    pub(crate) wsl2_proxy_policy: profile::Wsl2ProxyPolicy,
    pub(crate) workdir_access: Option<profile::WorkdirAccess>,
    pub(crate) rollback_exclude_patterns: Vec<String>,
    pub(crate) rollback_exclude_globs: Vec<String>,
    pub(crate) network_profile: Option<String>,
    pub(crate) allow_domain: Vec<String>,
    pub(crate) credentials: Vec<String>,
    pub(crate) custom_credentials: HashMap<String, profile::CustomCredentialDef>,
    pub(crate) upstream_proxy: Option<String>,
    pub(crate) upstream_bypass: Vec<String>,
    pub(crate) listen_ports: Vec<u16>,
    pub(crate) open_url_origins: Vec<String>,
    pub(crate) open_url_allow_localhost: bool,
    pub(crate) allow_launch_services: bool,
    pub(crate) bypass_protection_paths: Vec<PathBuf>,
    /// Plan 34-08a Task 3 (D-20 manual replay of upstream `1b412a7`):
    /// allow-list of environment variable names from `profile.environment.allow_vars`.
    /// `None` means inherit-all (default upstream behaviour); `Some([])`
    /// means strip all (fail-closed). Wired to the Unix execution path via
    /// `ExecConfig.allowed_env_vars`. Windows execution path uses the
    /// separate `exec_strategy_windows` module and does not consume this
    /// field; full Windows env-filter wiring tracked for a future plan
    /// (P34-DEFER-08a-1 if needed).
    pub(crate) allowed_env_vars: Option<Vec<String>>,
    /// Plan 34-08a Task 4 (D-20 replay of v0.52.0 `3657c935`): operator-
    /// controlled deny-list of environment variable names from
    /// `profile.environment.deny_vars`. `None` means no deny filter active.
    /// Wired to the Unix execution path via `ExecConfig.denied_env_vars`.
    pub(crate) denied_env_vars: Option<Vec<String>>,
}

fn install_profile_hooks(profile_name: Option<&str>, profile: &profile::Profile, silent: bool) {
    if profile.hooks.hooks.is_empty() {
        return;
    }

    match hooks::install_profile_hooks(profile_name, &profile.hooks.hooks) {
        Ok(results) => {
            for (target, result) in results {
                match result {
                    hooks::HookInstallResult::Installed => {
                        if !silent {
                            eprintln!(
                                "  Installing {} hook to ~/.claude/hooks/nono-hook.sh",
                                target
                            );
                        }
                    }
                    hooks::HookInstallResult::Updated => {
                        if !silent {
                            eprintln!("  Updating {} hook (new version available)", target);
                        }
                    }
                    hooks::HookInstallResult::AlreadyInstalled
                    | hooks::HookInstallResult::Skipped => {}
                }
            }
        }
        Err(e) => {
            tracing::warn!("Failed to install profile hooks: {}", e);
            if !silent {
                eprintln!("  Warning: Failed to install hooks: {}", e);
            }
        }
    }
}

fn expand_bypass_protection_path(path: &Path, workdir: &Path) -> PathBuf {
    let path_str = path.to_string_lossy();
    let expanded = profile::expand_vars(&path_str, workdir).unwrap_or_else(|_| path.to_path_buf());
    if expanded.exists() {
        expanded.canonicalize().unwrap_or(expanded)
    } else {
        expanded
    }
}

fn collect_bypass_protection_paths(
    loaded_profile: Option<&profile::Profile>,
    cli_bypass_protection: &[PathBuf],
    workdir: &Path,
) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = loaded_profile
        .map(|profile| {
            profile
                .policy
                .bypass_protection
                .iter()
                .filter_map(|template| {
                    profile::expand_vars(template, workdir)
                        .ok()
                        .map(|expanded| {
                            if expanded.exists() {
                                expanded.canonicalize().unwrap_or(expanded)
                            } else {
                                expanded
                            }
                        })
                })
                .collect()
        })
        .unwrap_or_default();

    for path in cli_bypass_protection {
        let canonical = expand_bypass_protection_path(path, workdir);
        if !paths.contains(&canonical) {
            paths.push(canonical);
        }
    }

    paths
}

/// Plan 35-02 (REQ-PORT-CLOSURE-06 / P34-DEFER-09-1): cherry-pick of
/// upstream `bdf183e9` (v0.44.0) — pre-create `~/.config/nono/profiles/`
/// BEFORE the caller (sandbox_prepare.rs:298 → Sandbox::apply →
/// landlock::restrict_self) locks the filesystem ruleset. Landlock is
/// strictly allow-list and requires the parent directory of any
/// granted child path to exist at ruleset-apply time, even when the
/// child path is explicitly granted write. Without this pre-create,
/// first-run `nono run` on a clean install (with `~/.config/nono/`
/// missing) produces a confusing `No such file or directory` error
/// pointing at the profiles path.
///
/// macOS and Windows are compile-time no-ops (Seatbelt and Windows
/// Job-Object sandbox have no equivalent restriction).
#[cfg(target_os = "linux")]
fn pre_create_landlock_profiles_dir() -> crate::Result<()> {
    let dir = crate::config::user_profiles_dir()?;
    std::fs::create_dir_all(&dir).map_err(nono::NonoError::Io)?;
    Ok(())
}

/// Pre-create the profile-drafts directory if missing. Cross-platform
/// (unlike the Linux-only `pre_create_landlock_profiles_dir`). Best-effort:
/// non-fatal if the create fails (the actual create happens in setup_profiles).
/// Phase 36.5 D-36.5-B1.
fn pre_create_drafts_dir() {
    if let Ok(drafts_dir) = crate::package::profile_drafts_dir() {
        let _ = std::fs::create_dir_all(&drafts_dir);
    }
}

/// Prepare the profile-derived configuration for sandbox execution.
///
/// Phase 37 D-12: takes a [`profile::ResolveContext`] so callers in the
/// `nono run` / `nono wrap` handlers can honor `--no-auto-pull`. Sites that
/// don't care about auto-pull suppression supply
/// `&profile::ResolveContext::default()` (or go through the
/// [`crate::sandbox_prepare::prepare_sandbox`] legacy wrapper, which does so
/// automatically).
pub(crate) fn prepare_profile_with_context(
    args: &SandboxArgs,
    silent: bool,
    workdir: &Path,
    resolve_ctx: &profile::ResolveContext,
) -> crate::Result<PreparedProfile> {
    #[cfg(target_os = "linux")]
    pre_create_landlock_profiles_dir()?;

    // Phase 36.5: pre-create profile-drafts dir cross-platform (D-36.5-B1).
    pre_create_drafts_dir();

    let loaded_profile = if let Some(ref profile_name) = args.profile {
        let profile = profile::load_profile_with_context(profile_name, resolve_ctx)?;
        // Phase 36.5: enforce package status (e.g., refuse load if installed
        // pack is yanked). Mitigates T-36.5-06 (registry-spoof — RegistryClient
        // routes through resolve_registry_url allowlist) and provides the
        // upstream's ActionRequired second-callsite for yanked packs.
        // Advisory-only by default; strict via NONO_REQUIRE_PACK_STATUS=1.
        crate::package_status::enforce_for_active_profile(Some(profile_name.as_str()), silent)?;
        install_profile_hooks(Some(profile_name.as_str()), &profile, silent);
        Some(profile)
    } else {
        None
    };

    Ok(PreparedProfile {
        capability_elevation: loaded_profile
            .as_ref()
            .and_then(|profile| profile.security.capability_elevation)
            .unwrap_or(false),
        #[cfg(target_os = "linux")]
        wsl2_proxy_policy: loaded_profile
            .as_ref()
            .and_then(|profile| profile.security.wsl2_proxy_policy)
            .unwrap_or_default(),
        workdir_access: loaded_profile
            .as_ref()
            .map(|profile| profile.workdir.access.clone()),
        rollback_exclude_patterns: loaded_profile
            .as_ref()
            .map(|profile| profile.rollback.exclude_patterns.clone())
            .unwrap_or_default(),
        rollback_exclude_globs: loaded_profile
            .as_ref()
            .map(|profile| profile.rollback.exclude_globs.clone())
            .unwrap_or_default(),
        network_profile: loaded_profile.as_ref().and_then(|profile| {
            profile
                .network
                .resolved_network_profile()
                .map(|value| value.to_string())
        }),
        allow_domain: loaded_profile
            .as_ref()
            .map(|profile| profile.network.allow_domain.clone())
            .unwrap_or_default(),
        credentials: loaded_profile
            .as_ref()
            .and_then(|profile| profile.network.credentials.clone())
            .unwrap_or_default(),
        custom_credentials: loaded_profile
            .as_ref()
            .map(|profile| profile.network.custom_credentials.clone())
            .unwrap_or_default(),
        upstream_proxy: loaded_profile
            .as_ref()
            .and_then(|profile| profile.network.upstream_proxy.clone()),
        upstream_bypass: loaded_profile
            .as_ref()
            .map(|profile| profile.network.upstream_bypass.clone())
            .unwrap_or_default(),
        listen_ports: loaded_profile
            .as_ref()
            .map(|profile| profile.network.listen_port.clone())
            .unwrap_or_default(),
        open_url_origins: loaded_profile
            .as_ref()
            .and_then(|profile| profile.open_urls.as_ref())
            .map(|open_urls| open_urls.allow_origins.clone())
            .unwrap_or_default(),
        open_url_allow_localhost: loaded_profile
            .as_ref()
            .and_then(|profile| profile.open_urls.as_ref())
            .map(|open_urls| open_urls.allow_localhost)
            .unwrap_or(false),
        allow_launch_services: loaded_profile
            .as_ref()
            .and_then(|profile| profile.allow_launch_services)
            .unwrap_or(false),
        bypass_protection_paths: collect_bypass_protection_paths(
            loaded_profile.as_ref(),
            &args.bypass_protection,
            workdir,
        ),
        // Plan 34-08a Task 3 (D-20 manual replay of upstream `1b412a7`):
        // surface `profile.environment.allow_vars` as a runtime allow-list.
        // Plan 34-08a Task 5 (D-20 replay of v0.52.0 `780965d7`): preserve
        // fail-closed semantics for empty allow_vars. An empty `allow_vars`
        // list returns `Some([])` (strip all inherited vars) rather than
        // `None` (no filtering). Profiles that set env_credentials but omit
        // allow_vars would otherwise silently inherit every parent env var.
        //
        // Phase 41 Plan 09 (REQ-CI-01 SC#4 gap closure + WR-06 close-out):
        // Delegates to the canonical
        // `crate::exec_strategy::validate_env_var_patterns` re-export
        // (declared at `exec_strategy.rs:50`). The previously local copy
        // was retained on the (incorrect) assumption that calling into
        // `exec_strategy::*` would reach across the
        // `exec_strategy_windows/` module boundary — but
        // `exec_strategy/env_sanitization.rs` lives in `exec_strategy/`
        // (platform-agnostic), not `exec_strategy_windows/` (Windows-only),
        // so D-34-E1 is not implicated. CI run 25972316892 surfaced the
        // local copy as the canonical fn's only-on-Windows live caller,
        // making the canonical fn dead-code on Linux/macOS. Folding the
        // duplicate into a delegate call (a) clears the dead-code lint and
        // (b) closes WR-06 (drift risk from byte-identical local copy).
        allowed_env_vars: loaded_profile.as_ref().and_then(|profile| {
            profile.environment.as_ref().map(|env_config| {
                if let Some(err) = crate::exec_strategy::validate_env_var_patterns(
                    &env_config.allow_vars,
                    "allow_vars",
                ) {
                    eprintln!("Warning: {}", err);
                }
                env_config.allow_vars.clone()
            })
        }),
        denied_env_vars: loaded_profile.as_ref().and_then(|profile| {
            profile.environment.as_ref().and_then(|env_config| {
                if env_config.deny_vars.is_empty() {
                    return None;
                }
                if let Some(err) = crate::exec_strategy::validate_env_var_patterns(
                    &env_config.deny_vars,
                    "deny_vars",
                ) {
                    eprintln!("Warning: {}", err);
                }
                Some(env_config.deny_vars.clone())
            })
        }),
        loaded_profile,
    })
}

#[cfg(test)]
mod tests {
    use crate::profile::{EnvironmentConfig, Profile};

    /// RAII guard that saves and restores an environment variable.
    ///
    /// Required per CLAUDE.md § "Environment variables in tests": tests that
    /// modify `HOME`, `XDG_CONFIG_HOME`, or other env vars MUST save and
    /// restore the original value, because Rust runs unit tests in parallel
    /// within the same process.
    #[cfg(target_os = "linux")]
    struct EnvGuard {
        key: String,
        prior: Option<std::ffi::OsString>,
    }

    #[allow(clippy::disallowed_methods)]
    // EnvGuard IS the Drop-restore primitive — same role as
    // crate::test_env::EnvVarGuard. Lint applies to consumers.
    #[cfg(target_os = "linux")]
    impl EnvGuard {
        fn set(key: &str, value: &std::path::Path) -> Self {
            let prior = std::env::var_os(key);
            // SAFETY per CLAUDE.md: set_var is sound in single-threaded test
            // setup; the Drop impl unwinds the change before parallel tests
            // resume. The modified window is as short as possible.
            std::env::set_var(key, value);
            Self {
                key: key.to_string(),
                prior,
            }
        }
    }

    #[allow(clippy::disallowed_methods)] // Restoring env vars is the other half of the safe wrapper.
    #[cfg(target_os = "linux")]
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.prior.take() {
                Some(val) => std::env::set_var(&self.key, val),
                None => std::env::remove_var(&self.key),
            }
        }
    }

    /// Plan 35-02 (REQ-PORT-CLOSURE-06): regression test locking the
    /// idempotent + first-run-creates-dir invariant for the Landlock
    /// pre-create hunk. Runs in CI Linux lane (D-35-D3); compile-time
    /// no-op on Windows/macOS.
    ///
    /// Verifies:
    /// 1. Calling `pre_create_landlock_profiles_dir()` creates
    ///    `<XDG_CONFIG_HOME>/nono/profiles/` on a clean fixture.
    /// 2. A second call succeeds without error (idempotency via
    ///    `std::fs::create_dir_all`).
    #[cfg(target_os = "linux")]
    #[test]
    fn test_pre_create_landlock_profiles_dir_idempotent() {
        // WR-03 fix (REVIEW.md): acquire the process-wide env lock BEFORE
        // mutating XDG_CONFIG_HOME so parallel tests don't read the tempdir
        // value during the modified window. EnvGuard::Drop restores on the
        // way out, but other tests reading XDG_CONFIG_HOME during this
        // test's runtime would still see the tempdir value without this
        // lock. Matches the convention in policy.rs / profile_save_runtime
        // tests per CLAUDE.md § Environment variables in tests.
        let _env_lock = crate::test_env::lock_env();
        let tmp = tempfile::TempDir::new().expect("create tempdir");
        let _xdg_guard = EnvGuard::set("XDG_CONFIG_HOME", tmp.path());

        // First call — creates <tmp>/nono/profiles/
        super::pre_create_landlock_profiles_dir()
            .expect("first pre-create call must succeed on clean fixture");
        let expected = tmp.path().join("nono").join("profiles");
        assert!(
            expected.is_dir(),
            "Expected profiles dir at {} after first pre-create call",
            expected.display(),
        );

        // Second call — idempotent (create_dir_all succeeds on existing dir)
        super::pre_create_landlock_profiles_dir()
            .expect("second pre-create call must succeed (idempotent on existing dir)");
        assert!(
            expected.is_dir(),
            "Profiles dir should still exist after second call",
        );
    }

    /// Plan 34-08a Task 5 regression test (v0.52.0 `780965d7`):
    /// an `EnvironmentConfig` with empty `allow_vars` MUST surface as
    /// `Some(vec![])` (strip-all / fail-closed) rather than `None`
    /// (no filter / inherit-all). This is the security invariant that
    /// `3657c935` regressed and `780965d7` restored.
    ///
    /// Direct-tests the closure shape used in `prepare_profile`:
    /// `profile.environment.as_ref().map(|cfg| cfg.allow_vars.clone())`.
    #[test]
    fn empty_allow_vars_fails_closed() {
        let profile = Profile {
            environment: Some(EnvironmentConfig {
                allow_vars: vec![],
                deny_vars: vec![],
            }),
            ..Default::default()
        };
        let allowed: Option<Vec<String>> = profile
            .environment
            .as_ref()
            .map(|env_config| env_config.allow_vars.clone());
        // Must be Some(vec![]) -- strip all -- NOT None.
        assert_eq!(allowed, Some(Vec::<String>::new()));
        assert!(
            allowed.as_ref().is_some_and(|v| v.is_empty()),
            "empty allow_vars must surface as Some(vec![]), not None"
        );
    }

    /// Companion: no `environment` block at all -> None (inherit-all).
    /// Distinguishes "absent" (None) from "explicit empty" (Some([])).
    #[test]
    fn absent_environment_block_returns_none() {
        let profile = Profile {
            environment: None,
            ..Default::default()
        };
        let allowed: Option<Vec<String>> = profile
            .environment
            .as_ref()
            .map(|env_config| env_config.allow_vars.clone());
        assert_eq!(allowed, None);
    }
}
