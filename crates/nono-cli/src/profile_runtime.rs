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
    pub(crate) override_deny_paths: Vec<PathBuf>,
    /// Plan 34-08a Task 3 (D-20 manual replay of upstream `1b412a7`):
    /// allow-list of environment variable names from `profile.environment.allow_vars`.
    /// `None` means inherit-all (default upstream behaviour); `Some([])`
    /// means strip all (fail-closed). Wired to the Unix execution path via
    /// `ExecConfig.allowed_env_vars`. Windows execution path uses the
    /// separate `exec_strategy_windows` module and does not consume this
    /// field; full Windows env-filter wiring tracked for a future plan
    /// (P34-DEFER-08a-1 if needed).
    pub(crate) allowed_env_vars: Option<Vec<String>>,
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

fn expand_override_deny_path(path: &Path, workdir: &Path) -> PathBuf {
    let path_str = path.to_string_lossy();
    let expanded = profile::expand_vars(&path_str, workdir).unwrap_or_else(|_| path.to_path_buf());
    if expanded.exists() {
        expanded.canonicalize().unwrap_or(expanded)
    } else {
        expanded
    }
}

fn collect_override_deny_paths(
    loaded_profile: Option<&profile::Profile>,
    cli_override_deny: &[PathBuf],
    workdir: &Path,
) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = loaded_profile
        .map(|profile| {
            profile
                .policy
                .override_deny
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

    for path in cli_override_deny {
        let canonical = expand_override_deny_path(path, workdir);
        if !paths.contains(&canonical) {
            paths.push(canonical);
        }
    }

    paths
}

pub(crate) fn prepare_profile(
    args: &SandboxArgs,
    silent: bool,
    workdir: &Path,
) -> crate::Result<PreparedProfile> {
    let loaded_profile = if let Some(ref profile_name) = args.profile {
        let profile = profile::load_profile(profile_name)?;
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
        override_deny_paths: collect_override_deny_paths(
            loaded_profile.as_ref(),
            &args.override_deny,
            workdir,
        ),
        // Plan 34-08a Task 3 (D-20 manual replay of upstream `1b412a7`):
        // surface `profile.environment.allow_vars` as a runtime allow-list.
        // Validation is best-effort — invalid patterns emit a warning to
        // stderr but the field is still forwarded (matching upstream
        // semantics in `1b412a7`'s `prepare_profile_with_options`).
        //
        // Validation logic is duplicated here from
        // `exec_strategy::env_sanitization::validate_allow_vars_pattern`
        // to avoid needing a Windows-side re-export (D-34-E1 invariant:
        // `exec_strategy_windows/` files must remain untouched in this plan).
        // Kept in lock-step with the canonical helper via tests in
        // `exec_strategy/env_sanitization.rs`.
        allowed_env_vars: loaded_profile.as_ref().and_then(|profile| {
            profile.environment.as_ref().map(|env_config| {
                if let Some(err) = validate_allow_vars_pattern_local(&env_config.allow_vars) {
                    eprintln!("Warning: {}", err);
                }
                env_config.allow_vars.clone()
            })
        }),
        loaded_profile,
    })
}

/// Local copy of `validate_allow_vars_pattern` to avoid crossing the
/// `exec_strategy_windows` module boundary (D-34-E1).
fn validate_allow_vars_pattern_local(allow_vars: &[String]) -> Option<String> {
    for pattern in allow_vars {
        if pattern.contains('*') && !pattern.ends_with('*') {
            return Some(format!(
                "Invalid allow_vars pattern '{}': '*' is only valid as a trailing suffix",
                pattern
            ));
        }
        if pattern.starts_with('*') && pattern.len() > 1 {
            return Some(format!(
                "Invalid allow_vars pattern '{}': use a bare '*' to match all variables, or a specific prefix like 'AWS_*'",
                pattern
            ));
        }
    }
    None
}
