use crate::capability_ext::{self, CapabilitySetExt};
use crate::cli::SandboxArgs;
#[cfg(target_os = "linux")]
use crate::config;
use crate::credential_runtime::load_env_credentials;
use crate::network_policy;
use crate::profile;
use crate::profile::WorkdirAccess;
use crate::profile_runtime::prepare_profile;
use crate::{output, policy, protected_paths, sandbox_state};
use colored::Colorize;
use nono::{AccessMode, CapabilitySet, FsCapability, NonoError, Result, Sandbox};
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use tracing::info;

fn print_allow_domain_port_warnings(entries: &[String], context: &str, silent: bool) {
    if silent {
        return;
    }

    for warning in network_policy::collect_allow_domain_port_warnings(entries, context) {
        output::print_warning(&warning);
    }
}

fn collect_missing_cli_requested_paths(args: &SandboxArgs) -> Vec<String> {
    let mut missing = Vec::new();

    for path in &args.allow {
        if !path.exists() {
            missing.push(format!("--allow {}", path.display()));
        }
    }
    for path in &args.read {
        if !path.exists() {
            missing.push(format!("--read {}", path.display()));
        }
    }
    for path in &args.write {
        if !path.exists() {
            missing.push(format!("--write {}", path.display()));
        }
    }
    for path in &args.allow_file {
        if !path.exists() && !capability_ext::retains_missing_exact_file_grants() {
            missing.push(format!("--allow-file {}", path.display()));
        }
    }
    for path in &args.read_file {
        if !path.exists() && !capability_ext::retains_missing_exact_file_grants() {
            missing.push(format!("--read-file {}", path.display()));
        }
    }
    for path in &args.write_file {
        if !path.exists() && !capability_ext::retains_missing_exact_file_grants() {
            missing.push(format!("--write-file {}", path.display()));
        }
    }

    missing
}

/// Result of sandbox preparation.
pub(crate) struct PreparedSandbox {
    pub(crate) caps: CapabilitySet,
    pub(crate) secrets: Vec<nono::LoadedSecret>,
    pub(crate) rollback_exclude_patterns: Vec<String>,
    pub(crate) rollback_exclude_globs: Vec<String>,
    pub(crate) network_profile: Option<String>,
    pub(crate) allow_domain: Vec<String>,
    pub(crate) credentials: Vec<String>,
    pub(crate) custom_credentials: HashMap<String, profile::CustomCredentialDef>,
    pub(crate) upstream_proxy: Option<String>,
    pub(crate) upstream_bypass: Vec<String>,
    pub(crate) listen_ports: Vec<u16>,
    pub(crate) capability_elevation: bool,
    #[cfg(target_os = "linux")]
    pub(crate) wsl2_proxy_policy: crate::profile::Wsl2ProxyPolicy,
    pub(crate) allow_launch_services_active: bool,
    pub(crate) open_url_origins: Vec<String>,
    pub(crate) open_url_allow_localhost: bool,
    pub(crate) override_deny_paths: Vec<PathBuf>,
    /// Plan 34-08a Task 3 (D-20 manual replay of upstream `1b412a7`):
    /// allow-list of environment variable names from the loaded profile's
    /// `environment.allow_vars` block. See [`crate::profile_runtime::PreparedProfile::allowed_env_vars`]
    /// for semantics.
    pub(crate) allowed_env_vars: Option<Vec<String>>,
    /// Plan 34-08a Task 4 (D-20 replay of v0.52.0 `3657c935`): operator-
    /// controlled deny-list of environment variable names from the loaded
    /// profile's `environment.deny_vars` block.
    pub(crate) denied_env_vars: Option<Vec<String>>,
    /// Plan 18.1-03 G-06: the loaded profile (if any) is preserved past
    /// profile destructuring so its `capabilities.aipc` widening can be
    /// resolved at Windows supervisor construction time via
    /// `Profile::resolve_aipc_allowlist`. `None` when the run has no
    /// `--profile` argument; widening falls back to hard-coded defaults.
    pub(crate) loaded_profile: Option<profile::Profile>,
}

fn finalize_prepared_sandbox(
    prepared: PreparedSandbox,
    args: &SandboxArgs,
    silent: bool,
) -> Result<PreparedSandbox> {
    output::print_skipped_requested_paths(&collect_missing_cli_requested_paths(args), silent);
    output::print_capabilities(&prepared.caps, args.verbose, silent);

    #[cfg(target_os = "linux")]
    output::print_abi_info(silent);

    if !Sandbox::is_supported() {
        return Err(NonoError::SandboxInit(Sandbox::support_info().details));
    }

    info!("{}", Sandbox::support_info().details);

    Ok(prepared)
}

pub(crate) fn validate_external_proxy_bypass(
    args: &SandboxArgs,
    prepared: &PreparedSandbox,
) -> Result<()> {
    let has_bypass = !args.external_proxy_bypass.is_empty() || !prepared.upstream_bypass.is_empty();
    let has_external_proxy = args.external_proxy.is_some() || prepared.upstream_proxy.is_some();

    if has_bypass && !has_external_proxy {
        return Err(NonoError::ConfigParse(
            "--upstream-bypass requires --upstream-proxy \
             (or upstream_proxy in profile network config)"
                .to_string(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn maybe_enable_macos_launch_services(
    caps: &mut CapabilitySet,
    cli_requested: bool,
    profile_allowed: bool,
    open_url_origins: &[String],
    open_url_allow_localhost: bool,
) -> Result<bool> {
    if !cli_requested {
        return Ok(false);
    }

    if !profile_allowed {
        return Err(NonoError::ConfigParse(
            "--allow-launch-services requires a profile that opts into allow_launch_services"
                .to_string(),
        ));
    }

    if open_url_origins.is_empty() && !open_url_allow_localhost {
        return Err(NonoError::ConfigParse(
            "--allow-launch-services requires the selected profile to configure open_urls"
                .to_string(),
        ));
    }

    caps.add_platform_rule("(allow lsopen)")?;
    tracing::debug!(
        "--allow-launch-services enabled: allowing direct LaunchServices opens on macOS"
    );
    Ok(true)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn maybe_enable_macos_launch_services(
    _caps: &mut CapabilitySet,
    cli_requested: bool,
    _profile_allowed: bool,
    _open_url_origins: &[String],
    _open_url_allow_localhost: bool,
) -> Result<bool> {
    if cli_requested {
        return Err(NonoError::ConfigParse(
            "--allow-launch-services is only supported on macOS".to_string(),
        ));
    }
    Ok(false)
}

pub(crate) fn print_allow_launch_services_warning(silent: bool) {
    if silent {
        return;
    }

    eprintln!(
        "  {}",
        "WARNING: --allow-launch-services permits the sandboxed process to ask macOS \
         LaunchServices to open URLs, files, or apps."
            .yellow()
    );
    eprintln!("  Use this only for temporary login/setup flows, then exit and rerun without it.");
    eprintln!("  Prefer using it from a trusted directory, not inside an untrusted project.");
}

pub(crate) fn prepare_sandbox(args: &SandboxArgs, silent: bool) -> Result<PreparedSandbox> {
    sandbox_state::cleanup_stale_state_files();

    let workdir = args
        .workdir
        .clone()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));

    if let Some(ref config_path) = args.config {
        let json = std::fs::read_to_string(config_path).map_err(|e| {
            NonoError::ConfigParse(format!(
                "failed to read manifest file '{}': {e}",
                config_path.display()
            ))
        })?;
        let mut manifest = nono::manifest::CapabilityManifest::from_json(&json)?;
        manifest.validate()?;

        if let Some(ref mut fs) = manifest.filesystem {
            for grant in &mut fs.grants {
                let expanded = profile::expand_vars(grant.path.as_str(), &workdir)?;
                grant.path = expanded
                    .to_string_lossy()
                    .parse()
                    .map_err(|e| NonoError::ConfigParse(format!("invalid path: {e}")))?;
            }
            for deny in &mut fs.deny {
                let expanded = profile::expand_vars(deny.path.as_str(), &workdir)?;
                deny.path = expanded
                    .to_string_lossy()
                    .parse()
                    .map_err(|e| NonoError::ConfigParse(format!("invalid path: {e}")))?;
            }
        }

        let caps = CapabilitySet::try_from(&manifest)?;
        let protected_roots = protected_paths::ProtectedRoots::from_defaults()?;
        protected_paths::validate_caps_against_protected_roots(&caps, protected_roots.as_paths())?;

        let (rollback_exclude_patterns, rollback_exclude_globs) =
            if let Some(ref rb) = manifest.rollback {
                (rb.exclude_patterns.clone(), rb.exclude_globs.clone())
            } else {
                (Vec::new(), Vec::new())
            };

        let allow_domain = manifest
            .network
            .as_ref()
            .map(|network| network.allow_domains.clone())
            .unwrap_or_default();
        print_allow_domain_port_warnings(&allow_domain, "manifest allow_domain", silent);
        let credentials = manifest
            .credentials
            .iter()
            .map(|credential| credential.name.as_str().to_string())
            .collect();

        return finalize_prepared_sandbox(
            PreparedSandbox {
                caps,
                secrets: Vec::new(),
                rollback_exclude_patterns,
                rollback_exclude_globs,
                network_profile: None,
                allow_domain,
                credentials,
                custom_credentials: HashMap::new(),
                upstream_proxy: None,
                upstream_bypass: Vec::new(),
                listen_ports: Vec::new(),
                capability_elevation: false,
                #[cfg(target_os = "linux")]
                wsl2_proxy_policy: crate::profile::Wsl2ProxyPolicy::default(),
                allow_launch_services_active: false,
                open_url_origins: Vec::new(),
                open_url_allow_localhost: false,
                override_deny_paths: Vec::new(),
                // Plan 34-08a Task 3 (D-20 replay of `1b412a7`): manifest path
                // has no loaded Profile and no env-filter block.
                allowed_env_vars: None,
                // Plan 34-08a Task 4 (D-20 replay of v0.52.0 `3657c935`):
                // deny_vars also unset on the manifest path.
                denied_env_vars: None,
                // Plan 18.1-03 G-06: manifest path has no loaded Profile —
                // AIPC widening defaults to hard-coded supervisor allowlist.
                loaded_profile: None,
            },
            args,
            silent,
        );
    }

    let prepared_profile = prepare_profile(args, silent, &workdir)?;
    let crate::profile_runtime::PreparedProfile {
        loaded_profile,
        capability_elevation,
        #[cfg(target_os = "linux")]
        wsl2_proxy_policy,
        workdir_access: profile_workdir_access,
        rollback_exclude_patterns: profile_rollback_patterns,
        rollback_exclude_globs: profile_rollback_globs,
        network_profile: profile_network_profile,
        allow_domain: profile_allow_domain,
        credentials: profile_credentials,
        custom_credentials: profile_custom_credentials,
        upstream_proxy: profile_upstream_proxy,
        upstream_bypass: profile_upstream_bypass,
        listen_ports: profile_listen_ports,
        open_url_origins,
        open_url_allow_localhost,
        allow_launch_services: profile_allow_launch_services,
        override_deny_paths,
        allowed_env_vars: profile_allowed_env_vars,
        denied_env_vars: profile_denied_env_vars,
    } = prepared_profile;

    // OAUTH-03 (Plan 22-04): warn when allow_domain entries include `:port`
    // suffixes — nono now ignores ports in allow-domain rules and only applies
    // hostname filtering through the proxy. Cherry-picked from upstream
    // 005579a9 + 60ad1eb3 (DRY helper). The deprecation-warning call from
    // upstream's loaded_profile.as_ref() block is intentionally omitted —
    // fork has no `command_blocking_deprecation` flow at this site
    // (deprecation warnings emit at profile-load time instead).
    print_allow_domain_port_warnings(&profile_allow_domain, "profile allow_domain", silent);
    print_allow_domain_port_warnings(&args.allow_proxy, "--allow-domain", silent);

    #[cfg(target_os = "linux")]
    if args.profile.as_deref() == Some("claude-code") {
        let home = config::validated_home()?;
        let home_path = std::path::Path::new(&home);

        let precreate = |path: &std::path::Path, is_dir: bool| {
            let result = if is_dir {
                std::fs::create_dir_all(path)
            } else {
                std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(path)
                    .map(|_| ())
            };
            if let Err(e) = result {
                if e.kind() != std::io::ErrorKind::AlreadyExists {
                    warn!("Failed to pre-create {}: {}", path.display(), e);
                }
            }
        };

        precreate(&home_path.join(".claude.json.lock"), false);
        precreate(&home_path.join(".cache/claude-cli-nodejs"), true);
    }

    let prepared = if let Some(ref profile) = loaded_profile {
        CapabilitySet::from_profile(profile, &workdir, args)?
    } else {
        CapabilitySet::from_args(args)?
    };
    let mut caps = prepared.caps;
    let needs_unlink_overrides = prepared.needs_unlink_overrides;
    // Resolved policy denies (groups + profile add_deny_access). Used to
    // re-run validate_deny_overlaps after CWD/pack grants are added below,
    // because Landlock cannot enforce a deny that lives under a later allow.
    let prepared_deny_paths = prepared.deny_paths;

    // PROF-01 (Phase 22): apply raw Seatbelt rules from the profile (macOS only).
    // On Linux/Windows the field deserializes but is intentionally ignored —
    // there is no equivalent escape hatch on those platforms (REQ-PROF-01).
    #[cfg(target_os = "macos")]
    if let Some(ref profile) = loaded_profile {
        if !profile.unsafe_macos_seatbelt_rules.is_empty() {
            tracing::warn!(
                "Profile uses {} raw Seatbelt rule(s) via unsafe_macos_seatbelt_rules — review carefully",
                profile.unsafe_macos_seatbelt_rules.len()
            );
            for rule in &profile.unsafe_macos_seatbelt_rules {
                caps.add_platform_rule(rule).map_err(|e| {
                    NonoError::ConfigParse(format!(
                        "unsafe_macos_seatbelt_rules: invalid rule {rule:?}: {e}"
                    ))
                })?;
            }
        }
    }

    let allow_launch_services_active = maybe_enable_macos_launch_services(
        &mut caps,
        args.allow_launch_services,
        profile_allow_launch_services,
        &open_url_origins,
        open_url_allow_localhost,
    )?;

    let cwd_access = if let Some(ref access) = profile_workdir_access {
        match access {
            WorkdirAccess::Read => Some(AccessMode::Read),
            WorkdirAccess::Write => Some(AccessMode::Write),
            WorkdirAccess::ReadWrite => Some(AccessMode::ReadWrite),
            WorkdirAccess::None => None,
        }
    } else {
        Some(AccessMode::Read)
    };

    if let Some(access) = cwd_access {
        let cwd_canonical =
            workdir
                .canonicalize()
                .map_err(|e| NonoError::PathCanonicalization {
                    path: workdir.clone(),
                    source: e,
                })?;

        if !caps.path_covered_with_access(&cwd_canonical, access) {
            if args.allow_cwd {
                info!("Auto-including CWD with {} access (--allow-cwd)", access);
                let cap = FsCapability::new_dir(cwd_canonical.clone(), access)?;
                caps.add_fs(cap);
            } else if silent {
                return Err(NonoError::CwdPromptRequired);
            } else {
                let confirmed = output::prompt_cwd_sharing(&cwd_canonical, &access)?;
                if confirmed {
                    let cap = FsCapability::new_dir(cwd_canonical.clone(), access)?;
                    caps.add_fs(cap);
                } else {
                    info!("User declined CWD sharing. Continuing without automatic CWD access.");
                }
            }
            caps.deduplicate();
        }
    }

    // Re-validate against the full deny set (groups + profile add_deny_access)
    // now that CWD, pack dirs, and any GPU/launch-services grants have been
    // added on top of the caps produced by from_profile/from_args. The initial
    // validation inside finalize_caps did not see those later grants, so a
    // profile deny that lands under e.g. --allow-cwd would otherwise be a
    // silent no-op on Linux (Landlock cannot deny under an allow).
    policy::validate_deny_overlaps(&prepared_deny_paths, &caps)?;
    let protected_roots = protected_paths::ProtectedRoots::from_defaults()?;
    protected_paths::validate_caps_against_protected_roots(&caps, protected_roots.as_paths())?;

    if needs_unlink_overrides {
        policy::apply_unlink_overrides(&mut caps);
    }

    if !caps.has_fs() && caps.is_network_blocked() {
        return Err(NonoError::NoCapabilities);
    }

    // Plan 18.1-03 G-06: clone env_credentials.mappings out by reference so
    // `loaded_profile` stays owned and can be preserved in `PreparedSandbox`
    // for downstream AIPC-allowlist resolution at Windows supervisor
    // construction time. The previous shape MOVED `loaded_profile` out here;
    // G-06 wiring needs the profile to survive past this point.
    let profile_secrets = loaded_profile
        .as_ref()
        .map(|profile| profile.env_credentials.mappings.clone())
        .unwrap_or_default();
    let loaded_secrets = load_env_credentials(args, &profile_secrets, silent)?;

    finalize_prepared_sandbox(
        PreparedSandbox {
            caps,
            secrets: loaded_secrets,
            rollback_exclude_patterns: profile_rollback_patterns,
            rollback_exclude_globs: profile_rollback_globs,
            network_profile: profile_network_profile,
            allow_domain: profile_allow_domain,
            credentials: profile_credentials,
            custom_credentials: profile_custom_credentials,
            upstream_proxy: profile_upstream_proxy,
            upstream_bypass: profile_upstream_bypass,
            listen_ports: profile_listen_ports,
            capability_elevation,
            #[cfg(target_os = "linux")]
            wsl2_proxy_policy,
            allow_launch_services_active,
            open_url_origins,
            open_url_allow_localhost,
            override_deny_paths,
            // Plan 34-08a Task 3 (D-20 replay of `1b412a7`): forward the
            // env-filter allow-list from PreparedProfile to PreparedSandbox.
            allowed_env_vars: profile_allowed_env_vars,
            // Plan 34-08a Task 4 (D-20 replay of v0.52.0 `3657c935`):
            // forward the env-filter deny-list.
            denied_env_vars: profile_denied_env_vars,
            // Plan 18.1-03 G-06: preserve the loaded profile so
            // `Profile::resolve_aipc_allowlist` can be consulted at the
            // Windows supervisor construction site.
            loaded_profile,
        },
        args,
        silent,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[cfg(target_os = "macos")]
    #[test]
    fn missing_exact_file_cli_grants_are_not_reported_as_skipped() {
        let dir = tempdir().expect("tmpdir");
        let args = SandboxArgs {
            allow_file: vec![dir.path().join("future.lock")],
            ..SandboxArgs::default()
        };

        assert!(
            collect_missing_cli_requested_paths(&args).is_empty(),
            "macOS exact-file grants should not be reported as skipped when the file is absent"
        );
    }

    #[test]
    fn missing_directory_cli_grants_are_reported_as_skipped() {
        let dir = tempdir().expect("tmpdir");
        let args = SandboxArgs {
            allow: vec![dir.path().join("future-dir")],
            ..SandboxArgs::default()
        };

        assert_eq!(
            collect_missing_cli_requested_paths(&args),
            vec![format!(
                "--allow {}",
                dir.path().join("future-dir").display()
            )]
        );
    }
}
