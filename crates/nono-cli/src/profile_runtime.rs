use crate::cli::SandboxArgs;
use crate::{package, profile};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub(crate) struct PreparedProfile {
    pub(crate) loaded_profile: Option<profile::Profile>,
    pub(crate) command_policies: Option<crate::command_policy::CommandPoliciesConfig>,
    pub(crate) capability_elevation: bool,
    #[cfg(target_os = "linux")]
    pub(crate) wsl2_proxy_policy: profile::Wsl2ProxyPolicy,
    #[cfg(target_os = "linux")]
    pub(crate) af_unix_mediation: profile::LinuxAfUnixMediation,
    #[cfg(target_os = "linux")]
    pub(crate) sandbox_policy: profile::LinuxSandboxPolicy,
    pub(crate) workdir_access: Option<profile::WorkdirAccess>,
    pub(crate) rollback_exclude_patterns: Vec<String>,
    pub(crate) rollback_exclude_globs: Vec<String>,
    pub(crate) network_profile: Option<String>,
    pub(crate) allow_domain: Vec<profile::AllowDomainEntry>,
    pub(crate) credentials: Vec<String>,
    pub(crate) custom_credentials: HashMap<String, profile::CustomCredentialDef>,
    pub(crate) tls_intercept: Option<profile::TlsInterceptConfig>,
    pub(crate) upstream_proxy: Option<String>,
    pub(crate) upstream_bypass: Vec<String>,
    pub(crate) listen_ports: Vec<u16>,
    pub(crate) open_url_origins: Vec<String>,
    pub(crate) open_url_allow_localhost: bool,
    pub(crate) allow_launch_services: bool,
    pub(crate) allow_gpu: bool,
    pub(crate) allow_parent_of_protected: bool,
    pub(crate) bypass_protection_paths: Vec<PathBuf>,
    pub(crate) ignored_denial_paths: Vec<PathBuf>,
    pub(crate) suppressed_system_service_operations: Vec<String>,
    pub(crate) allowed_env_vars: Option<Vec<String>>,
    pub(crate) denied_env_vars: Option<Vec<String>>,
    /// Expanded `environment.set_vars` entries (key, expanded-value). `None`
    /// when the profile has no `set_vars`. Values are expanded with
    /// [`profile::expand_vars`] at prepare time.
    pub(crate) set_vars: Option<Vec<(String, String)>>,
}

#[derive(Clone, Copy)]
struct PrepareProfileOptions {
    install_hooks: bool,
    hook_output_silent: bool,
}

fn install_profile_hooks(_profile_name: Option<&str>, profile: &profile::Profile, silent: bool) {
    // In-binary hook installation was removed in v0.44.0 alongside
    // the hooks.rs module. Profiles that ship a `hooks.<target>`
    // block are surfaced as a one-line note; the actual wiring
    // belongs in the pack's `wiring` directives now.
    if profile.hooks.hooks.is_empty() {
        return;
    }
    if !silent {
        for target in profile.hooks.hooks.keys() {
            eprintln!(
                "  Note: profile declares hooks.{target} but in-profile hook \
                 installation has been removed; move the wiring into the pack's \
                 package.json `wiring` directives."
            );
        }
    }
}

/// Verify that all packs declared in the profile are installed and intact.
///
/// For each pack:
/// 1. Check the pack directory exists
/// 2. Verify artifact SHA-256 digests against the lockfile
/// 3. Re-verify Sigstore bundles from the stored `.nono-trust.bundle` file
fn verify_profile_packs(packs: &[String], profile: &profile::Profile) -> crate::Result<()> {
    if let Some(hook) = [&profile.session_hooks.before, &profile.session_hooks.after]
        .into_iter()
        .flatten()
        .find(|hook| {
            hook.source_pack
                .as_ref()
                .is_some_and(|sp| !packs.contains(&sp.key()))
        })
    {
        // This indicates an internal logic error where the Profile was parsed, but the source_pack
        // the session hook references is not present in packs_to check
        return Err(nono::NonoError::PackageInstall(format!(
            "session_hook {} unexpectedly is not part of the packs to verify",
            hook.script.display()
        )));
    }

    if packs.is_empty() {
        return Ok(());
    }

    let lockfile = package::read_lockfile()?;

    for pack_ref in packs {
        let parts: Vec<&str> = pack_ref.splitn(2, '/').collect();
        if parts.len() != 2 {
            return Err(nono::NonoError::PackageInstall(format!(
                "invalid pack reference '{}': expected <namespace>/<name>",
                pack_ref
            )));
        }
        let (namespace, name) = (parts[0], parts[1]);

        let install_dir = package::package_install_dir(namespace, name)?;
        if !install_dir.exists() {
            tracing::warn!(
                "Pack '{}' declared by profile but not installed. \
                 Install it with: nono pull {}",
                pack_ref,
                pack_ref
            );
            continue;
        }

        let locked_pkg = lockfile.packages.get(pack_ref).ok_or_else(|| {
            nono::NonoError::PackageVerification {
                package: pack_ref.clone(),
                reason: format!(
                    "pack '{}' has no lockfile entry - reinstall with: nono pull {} --force",
                    pack_ref, pack_ref
                ),
            }
        })?;

        for (artifact_name, locked_artifact) in &locked_pkg.artifacts {
            let artifact_path = install_dir.join(artifact_name);
            if !artifact_path.exists() {
                return Err(nono::NonoError::PackageInstall(format!(
                    "pack '{}' is missing artifact '{}'. Reinstall with: nono pull {} --force",
                    pack_ref, artifact_name, pack_ref
                )));
            }

            let bytes = std::fs::read(&artifact_path).map_err(|e| {
                nono::NonoError::PackageInstall(format!(
                    "failed to read artifact '{}' in pack '{}': {}",
                    artifact_name, pack_ref, e
                ))
            })?;
            let digest = Sha256::digest(&bytes);
            let hash = digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            if hash != locked_artifact.sha256 {
                return Err(nono::NonoError::PackageInstall(format!(
                    "pack '{}' artifact '{}' has been tampered with.\n\
                     Expected: {}\n\
                     Found:    {}\n\
                     Reinstall with: nono pull {} --force",
                    pack_ref, artifact_name, locked_artifact.sha256, hash, pack_ref
                )));
            }
        }

        for script_path in [&profile.session_hooks.before, &profile.session_hooks.after]
            .into_iter()
            .flatten()
            .filter(|hook| {
                hook.source_pack
                    .as_ref()
                    .is_some_and(|sp| sp.key() == *pack_ref)
            })
            .map(|hook| hook.script.as_path())
        {
            let relative_path = script_path
                .strip_prefix(&install_dir)
                .map_err(|_| {
                    nono::NonoError::PackageInstall(format!(
                        "session_hook with path {} is not within the pack",
                        script_path.display()
                    ))
                })?
                .to_str()
                .ok_or_else(|| {
                    nono::NonoError::PackageInstall("Invalid script_path characters".to_string())
                })?;
            if !locked_pkg.artifacts.contains_key(relative_path) {
                return Err(nono::NonoError::PackageInstall(format!(
                    "session_hook with path {} is not a declared artifact in the pack lockfile",
                    script_path.display()
                )));
            }
        }

        let bundle_path = install_dir.join(".nono-trust.bundle");
        if !bundle_path.exists() {
            return Err(nono::NonoError::PackageVerification {
                package: pack_ref.clone(),
                reason: format!(
                    "pack '{}' is missing .nono-trust.bundle - reinstall with: nono pull {} --force",
                    pack_ref, pack_ref
                ),
            });
        }

        let pinned_signer = locked_pkg
            .provenance
            .as_ref()
            .map(|p| p.signer_identity.as_str())
            .ok_or_else(|| nono::NonoError::PackageVerification {
                package: pack_ref.clone(),
                reason: format!(
                    "pack '{}' has no signer identity in the lockfile - reinstall with: nono pull {} --force",
                    pack_ref, pack_ref
                ),
            })?;
        verify_stored_bundles(&install_dir, &bundle_path, pack_ref, Some(pinned_signer))?;
    }

    Ok(())
}

fn canonical_signer(uri: &str) -> &str {
    uri.rsplit_once('@').map_or(uri, |(prefix, _)| prefix)
}

/// Re-verify each artifact's Sigstore bundle from the stored trust bundle file.
fn verify_stored_bundles(
    install_dir: &Path,
    bundle_path: &Path,
    pack_ref: &str,
    pinned_signer: Option<&str>,
) -> crate::Result<()> {
    let bundle_content = std::fs::read_to_string(bundle_path).map_err(|e| {
        nono::NonoError::PackageInstall(format!(
            "failed to read trust bundle for pack '{}': {}",
            pack_ref, e
        ))
    })?;

    let entries: Vec<serde_json::Value> = serde_json::from_str(&bundle_content).map_err(|e| {
        nono::NonoError::PackageInstall(format!(
            "failed to parse trust bundle for pack '{}': {}",
            pack_ref, e
        ))
    })?;

    let trusted_root = nono::trust::load_production_trusted_root()?;
    let policy = nono::trust::VerificationPolicy::default();

    for entry in &entries {
        let artifact_name = entry
            .get("artifact")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                nono::NonoError::PackageInstall(format!(
                    "trust bundle entry missing 'artifact' field in pack '{}'",
                    pack_ref
                ))
            })?;
        let installed_path = entry
            .get("installed_path")
            .and_then(|v| v.as_str())
            .unwrap_or(artifact_name);

        let bundle_value = entry.get("bundle").ok_or_else(|| {
            nono::NonoError::PackageInstall(format!(
                "trust bundle entry missing 'bundle' field for '{}' in pack '{}'",
                artifact_name, pack_ref
            ))
        })?;
        let expected_digest = entry
            .get("digest")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                nono::NonoError::PackageInstall(format!(
                    "trust bundle entry missing 'digest' field for '{}' in pack '{}'",
                    artifact_name, pack_ref
                ))
            })?;

        let artifact_path = install_dir.join(validate_bundle_relative_path(
            installed_path,
            artifact_name,
            pack_ref,
        )?);
        if !artifact_path.exists() {
            continue;
        }

        let artifact_bytes = std::fs::read(&artifact_path).map_err(|e| {
            nono::NonoError::PackageInstall(format!(
                "failed to read '{}' for bundle verification in pack '{}': {}",
                artifact_name, pack_ref, e
            ))
        })?;

        let bundle_json = serde_json::to_string(bundle_value).map_err(|e| {
            nono::NonoError::PackageInstall(format!(
                "failed to serialize bundle for '{}' in pack '{}': {}",
                artifact_name, pack_ref, e
            ))
        })?;

        let bundle = nono::trust::load_bundle_from_str(
            &bundle_json,
            Path::new(&format!("{}.bundle", artifact_name)),
        )?;

        let subjects = nono::trust::extract_all_subjects(
            &bundle,
            Path::new(&format!("{}.bundle", artifact_name)),
        )?;
        if !subjects
            .iter()
            .any(|(name, digest)| name == artifact_name && digest == expected_digest)
        {
            return Err(nono::NonoError::PackageInstall(format!(
                "trust bundle for '{}' in pack '{}' does not contain the expected subject digest",
                artifact_name, pack_ref
            )));
        }
        nono::trust::verify_bundle(
            &artifact_bytes,
            &bundle,
            &trusted_root,
            &policy,
            Path::new(artifact_name),
        )
        .map_err(|e| {
            nono::NonoError::PackageInstall(format!(
                "Sigstore verification failed for '{}' in pack '{}': {}\n\
                 Reinstall with: nono pull {} --force",
                artifact_name, pack_ref, e, pack_ref
            ))
        })?;

        // Check the verified signer identity against the lockfile pin.
        // All artifacts in a pack share the same signer, so we check on each
        // entry and fail fast on any mismatch.
        if let Some(pinned) = pinned_signer {
            let identity = nono::trust::extract_signer_identity(&bundle, Path::new(artifact_name))?;
            let verified_uri = match &identity {
                nono::trust::SignerIdentity::Keyless {
                    repository,
                    workflow,
                    git_ref,
                    ..
                } => format!("https://github.com/{repository}/{workflow}@{git_ref}"),
                nono::trust::SignerIdentity::Keyed { key_id } => {
                    format!("keyed:{key_id}")
                }
            };
            // Strip @<git_ref> for canonical comparison — we pin repo+workflow,
            // not the specific tag that triggered each release.
            if canonical_signer(verified_uri.as_str()) != canonical_signer(pinned) {
                return Err(nono::NonoError::PackageVerification {
                    package: pack_ref.to_string(),
                    reason: format!(
                        "signer identity mismatch for '{}': bundle was signed by '{}' \
                         but lockfile pins '{}'. Reinstall with: nono pull {} --force",
                        artifact_name, verified_uri, pinned, pack_ref
                    ),
                });
            }
        }
    }

    Ok(())
}

fn validate_bundle_relative_path<'a>(
    installed_path: &'a str,
    artifact_name: &str,
    pack_ref: &str,
) -> crate::Result<&'a Path> {
    let path = Path::new(installed_path);
    if installed_path.is_empty() || path.is_absolute() {
        return Err(nono::NonoError::PackageInstall(format!(
            "trust bundle entry for '{}' in pack '{}' has unsafe installed_path '{}'",
            artifact_name, pack_ref, installed_path
        )));
    }
    for component in path.components() {
        match component {
            std::path::Component::Normal(_) => {}
            _ => {
                return Err(nono::NonoError::PackageInstall(format!(
                    "trust bundle entry for '{}' in pack '{}' has unsafe installed_path '{}'",
                    artifact_name, pack_ref, installed_path
                )));
            }
        }
    }
    Ok(path)
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
                .filesystem
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

fn expand_ignored_denial_path(path: &Path, workdir: &Path) -> PathBuf {
    let path_str = path.to_string_lossy();
    let expanded = profile::expand_vars(&path_str, workdir).unwrap_or_else(|_| path.to_path_buf());
    nono::try_canonicalize(&expanded)
}

/// Expand the values of `environment.set_vars` using the same variable
/// substitution as profile paths (`$HOME`, `~`, `$WORKDIR`, `$TMPDIR`,
/// `$XDG_*`, `$NONO_PACKAGES`). Keys are preserved verbatim. Returns `None`
/// when the profile has no `set_vars`. Expansion errors are fatal so a
/// misconfigured value never silently reaches the child.
fn expand_profile_set_vars(
    loaded_profile: Option<&profile::Profile>,
    workdir: &Path,
) -> crate::Result<Option<Vec<(String, String)>>> {
    let Some(env_config) = loaded_profile.and_then(|profile| profile.environment.as_ref()) else {
        return Ok(None);
    };
    if env_config.set_vars.is_empty() {
        return Ok(None);
    }

    // Sort keys for deterministic ordering (HashMap iteration order is random).
    let mut keys: Vec<&String> = env_config.set_vars.keys().collect();
    keys.sort();

    let mut expanded = Vec::with_capacity(keys.len());
    for key in keys {
        let Some(value) = env_config.set_vars.get(key) else {
            continue;
        };
        let expanded_value = profile::expand_vars(value, workdir)?
            .to_string_lossy()
            .into_owned();
        expanded.push((key.clone(), expanded_value));
    }
    Ok(Some(expanded))
}

fn collect_ignored_denial_paths(
    loaded_profile: Option<&profile::Profile>,
    cli_ignored_denials: &[PathBuf],
    workdir: &Path,
) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = loaded_profile
        .map(|profile| {
            profile
                .filesystem
                .suppress_save_prompt
                .iter()
                .filter_map(|template| {
                    profile::expand_vars(template, workdir)
                        .ok()
                        .map(|expanded| nono::try_canonicalize(&expanded))
                })
                .collect()
        })
        .unwrap_or_default();

    for path in cli_ignored_denials {
        let canonical = expand_ignored_denial_path(path, workdir);
        if !paths.contains(&canonical) {
            paths.push(canonical);
        }
    }

    paths
}

fn prepare_profile_with_options(
    args: &SandboxArgs,
    workdir: &Path,
    options: PrepareProfileOptions,
) -> crate::Result<PreparedProfile> {
    // Ensure nono-managed profile dirs exist before the sandbox is built.
    // Landlock can't mkdir a path that's only granted by name — the
    // parent needs write permission. Pre-creating here means the leaf
    // grants in pack profiles are sufficient.
    if let Ok(config_dir) = profile::resolve_user_config_dir() {
        let profiles_dir = config_dir.join("nono").join("profiles");
        if !profiles_dir.exists() {
            let _ = std::fs::create_dir_all(&profiles_dir);
        }
        let drafts_dir = config_dir.join("nono").join("profile-drafts");
        if !drafts_dir.exists() {
            let _ = std::fs::create_dir_all(&drafts_dir);
        }
    }

    let loaded_profile = if let Some(ref profile_name) = args.profile {
        // The claude-code → registry-pack migration is wired into
        // `load_profile` itself so it fires from every call site (run,
        // wrap, shell, profile show, why, learn) without duplication.
        let profile = profile::load_profile(profile_name)?;
        crate::package_status::enforce_for_active_profile(
            Some(profile_name),
            options.hook_output_silent,
        )?;
        // If the profile was addressed by pack ref (e.g. --profile always-further/hermes),
        // ensure that pack is verified even if the profile JSON doesn't list it in `packs`.
        // Pack refs are injected into profile.packs at load time for every
        // pack-store resolution — both direct registry refs and name/alias
        // paths — so no post-hoc lookup is needed here.
        let mut packs_to_verify = profile.packs.clone();
        validate_command_policy_runtime_support(&profile)?;

        // For direct registry refs the pack key may not yet be in packs if
        // load_registry_profile found the pack installed but the profile JSON
        // predates the injection convention. Guard with a fallback.
        if profile::is_registry_ref(profile_name) {
            let key = profile_name
                .split_once('@')
                .map_or(profile_name.as_str(), |(p, _)| p)
                .to_string();
            if !packs_to_verify.contains(&key) {
                packs_to_verify.push(key);
            }
        }

        // `--dry-run` resolves the profile and prints the capabilities it
        // *would* apply, then exits without ever building the sandbox or
        // executing the target command (see command_runtime::run_command).
        // Pack verification (lockfile digest + signed trust bundle) gates the
        // execution of pack-shipped code; a preview executes nothing, so it is
        // not a verification boundary. Skipping it here keeps `--dry-run`
        // usable to inspect a pack's profile before a managed `nono pull`
        // completes (or while recovering missing metadata). A real run still
        // hits verify_profile_packs below and is rejected if unverified.
        if args.dry_run {
            if !packs_to_verify.is_empty() && !options.hook_output_silent {
                eprintln!(
                    "  Skipping pack verification on --dry-run ({} pack(s)); a real run verifies them",
                    packs_to_verify.len()
                );
            }
        } else {
            verify_profile_packs(&packs_to_verify, &profile)?;
            if !packs_to_verify.is_empty() && !options.hook_output_silent {
                eprintln!("  Verified {} pack(s)", packs_to_verify.len());
            }
        }

        if options.install_hooks {
            install_profile_hooks(Some(profile_name), &profile, options.hook_output_silent);
        }
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
        #[cfg(target_os = "linux")]
        af_unix_mediation: loaded_profile
            .as_ref()
            .and_then(|profile| profile.linux.af_unix_mediation)
            .unwrap_or_default(),
        #[cfg(target_os = "linux")]
        sandbox_policy: loaded_profile
            .as_ref()
            .and_then(|profile| profile.linux.sandbox_policy)
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
        tls_intercept: loaded_profile
            .as_ref()
            .and_then(|profile| profile.network.tls_intercept.clone()),
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
        allow_gpu: loaded_profile
            .as_ref()
            .and_then(|profile| profile.allow_gpu)
            .unwrap_or(false),
        allow_parent_of_protected: loaded_profile
            .as_ref()
            .and_then(|profile| profile.allow_parent_of_protected)
            .unwrap_or(false),
        bypass_protection_paths: collect_bypass_protection_paths(
            loaded_profile.as_ref(),
            &args.bypass_protection,
            workdir,
        ),
        ignored_denial_paths: collect_ignored_denial_paths(
            loaded_profile.as_ref(),
            &args.suppress_save_prompt,
            workdir,
        ),
        suppressed_system_service_operations: loaded_profile
            .as_ref()
            .map(|profile| profile.diagnostics.suppress_system_services.clone())
            .unwrap_or_default(),
        allowed_env_vars: loaded_profile.as_ref().and_then(|profile| {
            profile.environment.as_ref().and_then(|env_config| {
                let vars = env_config.allow_vars.as_ref()?;
                if let Some(err) =
                    crate::exec_strategy::validate_env_var_patterns(vars, "allow_vars")
                {
                    eprintln!("Warning: {}", err);
                }
                Some(vars.clone())
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
        command_policies: loaded_profile
            .as_ref()
            .and_then(|profile| profile.command_policies.clone()),
        set_vars: expand_profile_set_vars(loaded_profile.as_ref(), workdir)?,
        loaded_profile,
    })
}

fn validate_command_policy_runtime_support(profile: &profile::Profile) -> crate::Result<()> {
    let Some(command_policies) = profile.command_policies.as_ref() else {
        return Ok(());
    };
    if !command_policies.is_active() {
        return Ok(());
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(nono::NonoError::UnsupportedPlatform(
            "tool-sandbox command_policies are only supported on Linux and macOS".to_string(),
        ))
    }

    #[cfg(target_os = "linux")]
    {
        validate_linux_command_policy_runtime_support(profile)
    }

    #[cfg(target_os = "macos")]
    {
        validate_macos_command_policy_runtime_support(profile)
    }
}

#[cfg(target_os = "linux")]
fn validate_linux_command_policy_runtime_support(profile: &profile::Profile) -> crate::Result<()> {
    if let Some(command_policies) = profile.command_policies.as_ref() {
        let _resolved = crate::command_policy::resolve_policy_command_binaries(
            command_policies,
            std::env::var_os("PATH"),
        )?;
    }

    if !command_policies_use_tcp_port_rules(profile) {
        return Ok(());
    }

    let abi = nono::detect_abi().map_err(|err| {
        nono::NonoError::UnsupportedPlatform(format!(
            "tool-sandbox profile uses TCP port network rules but Landlock enforcement is unavailable: {err}"
        ))
    })?;
    if !abi.has_network() {
        return Err(nono::NonoError::UnsupportedPlatform(format!(
            "tool-sandbox profile uses TCP port network rules but {} lacks Landlock TCP support (requires ABI V4+)",
            abi
        )));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn validate_macos_command_policy_runtime_support(profile: &profile::Profile) -> crate::Result<()> {
    if let Some(command_policies) = profile.command_policies.as_ref() {
        let _resolved = crate::command_policy::resolve_policy_command_binaries(
            command_policies,
            std::env::var_os("PATH"),
        )?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn command_policies_use_tcp_port_rules(profile: &profile::Profile) -> bool {
    let Some(command_policies) = profile.command_policies.as_ref() else {
        return false;
    };

    for command in command_policies.commands.values() {
        if command
            .sandbox
            .as_ref()
            .is_some_and(command_sandbox_uses_tcp_port_rules)
        {
            return true;
        }

        for from_policy in command.from.values() {
            if let crate::command_policy::CommandFromConfig::Policy(sandbox) = from_policy
                && command_sandbox_uses_tcp_port_rules(sandbox)
            {
                return true;
            }
        }
    }

    false
}

#[cfg(target_os = "linux")]
fn command_sandbox_uses_tcp_port_rules(
    sandbox: &crate::command_policy::CommandSandboxConfig,
) -> bool {
    sandbox.network.as_ref().is_some_and(|network| {
        !network.tcp_connect_ports.is_empty() || !network.tcp_bind_ports.is_empty()
    })
}

pub(crate) fn prepare_profile(
    args: &SandboxArgs,
    silent: bool,
    workdir: &Path,
) -> crate::Result<PreparedProfile> {
    prepare_profile_with_options(
        args,
        workdir,
        PrepareProfileOptions {
            install_hooks: true,
            hook_output_silent: silent,
        },
    )
}

pub(crate) fn prepare_profile_for_preflight(
    args: &SandboxArgs,
    workdir: &Path,
) -> crate::Result<PreparedProfile> {
    prepare_profile_with_options(
        args,
        workdir,
        PrepareProfileOptions {
            install_hooks: false,
            hook_output_silent: true,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    use crate::command_policy::{CommandPoliciesConfig, CommandPolicyConfig, CommandSandboxConfig};
    use profile::{SessionHook, SessionHooks};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::fs;
    use tempfile::tempdir;

    // -------------------------------------------------------------------------
    // Test helpers
    // -------------------------------------------------------------------------

    /// Run `f` inside a temporary directory that is set as `XDG_CONFIG_HOME`.
    ///
    /// Acquires `ENV_LOCK`, creates a canonicalized temp dir, sets the env var,
    /// and calls `f(config_dir)`.  The lock and env guard are dropped *after*
    /// `f` returns so the caller can return owned values and assert outside
    /// the locked region.
    fn with_config_env<F, R>(f: F) -> R
    where
        F: FnOnce(&std::path::Path) -> R,
    {
        let _guard = match crate::test_env::ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let tmp = tempdir().expect("tmpdir");
        let config_dir = tmp.path().canonicalize().expect("canonicalize");
        let _env = crate::test_env::EnvVarGuard::set_all(&[(
            "XDG_CONFIG_HOME",
            config_dir.to_str().expect("utf8"),
        )]);
        f(&config_dir)
    }

    #[test]
    fn expand_profile_set_vars_expands_home() {
        let _guard = match crate::test_env::ENV_LOCK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let _env = crate::test_env::EnvVarGuard::set_all(&[("HOME", "/home/tester")]);

        let mut profile = profile::Profile::default();
        let mut set_vars = std::collections::HashMap::new();
        set_vars.insert("RUST_LOG".to_string(), "debug".to_string());
        set_vars.insert("CFG".to_string(), "$HOME/.config".to_string());
        profile.environment = Some(profile::EnvironmentConfig {
            allow_vars: None,
            deny_vars: vec![],
            set_vars,
        });

        let workdir = Path::new("/tmp/work");
        let expanded = expand_profile_set_vars(Some(&profile), workdir)
            .expect("expansion should succeed")
            .expect("set_vars should be present");

        // Keys are sorted for determinism: CFG before RUST_LOG.
        assert_eq!(
            expanded,
            vec![
                ("CFG".to_string(), "/home/tester/.config".to_string()),
                ("RUST_LOG".to_string(), "debug".to_string()),
            ]
        );
    }

    #[test]
    fn expand_profile_set_vars_none_when_absent() {
        let profile = profile::Profile::default();
        let result = expand_profile_set_vars(Some(&profile), Path::new("/tmp/work"))
            .expect("expansion should succeed");
        assert!(result.is_none());
    }

    /// Build a minimal pack on disk under `<config_dir>/nono/packages/<ns>/<name>/`
    /// and return the install directory.
    ///
    /// `scripts` is a list of `(relative_path, content)` pairs.  Each file is
    /// written under the install directory and its SHA-256 is recorded in the
    /// returned `BTreeMap<String, package::LockedArtifact>` so the caller can
    /// incorporate it into a lockfile entry.
    fn build_pack_with_scripts(
        config_dir: &std::path::Path,
        ns: &str,
        pack_name: &str,
        scripts: &[(&str, &str)],
    ) -> (PathBuf, BTreeMap<String, package::LockedArtifact>) {
        let install_dir = config_dir
            .join("nono")
            .join("packages")
            .join(ns)
            .join(pack_name);

        fs::create_dir_all(&install_dir).expect("create install dir");

        let mut artifacts: BTreeMap<String, package::LockedArtifact> = BTreeMap::new();

        for (rel_path, content) in scripts {
            let full_path = install_dir.join(rel_path);
            if let Some(parent) = full_path.parent() {
                fs::create_dir_all(parent).expect("create script dir");
            }
            fs::write(&full_path, content.as_bytes()).expect("write script");

            let digest = Sha256::digest(content.as_bytes());
            let sha256 = digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();

            artifacts.insert(
                rel_path.to_string(),
                package::LockedArtifact {
                    sha256,
                    artifact_type: package::ArtifactType::Profile,
                },
            );
        }

        (install_dir, artifacts)
    }

    /// Write a lockfile at `<config_dir>/nono/packages/lockfile.json` containing
    /// the given entries.  Merges with any existing lockfile so multiple packs
    /// can be added across calls.
    fn write_test_lockfile(
        config_dir: &std::path::Path,
        entries: &[(&str, BTreeMap<String, package::LockedArtifact>)],
    ) {
        let lockfile_path = config_dir
            .join("nono")
            .join("packages")
            .join("lockfile.json");
        fs::create_dir_all(lockfile_path.parent().expect("parent")).expect("create packages dir");

        let mut lockfile = if lockfile_path.exists() {
            let content = fs::read_to_string(&lockfile_path).expect("read lockfile");
            serde_json::from_str::<package::Lockfile>(&content).expect("parse lockfile")
        } else {
            package::Lockfile {
                lockfile_version: package::LOCKFILE_VERSION,
                registry: String::new(),
                packages: BTreeMap::new(),
            }
        };

        for (pack_ref, artifacts) in entries {
            let pkg = package::LockedPackage {
                artifacts: artifacts.clone(),
                ..package::LockedPackage::default()
            };
            lockfile.packages.insert(pack_ref.to_string(), pkg);
        }

        let json = serde_json::to_string_pretty(&lockfile).expect("serialize lockfile");
        fs::write(&lockfile_path, format!("{json}\n")).expect("write lockfile");
    }

    /// Construct a `SessionHook` with the given script path and optional
    /// `source_pack`.  Used to build `SessionHooks` directly in tests without
    /// going through profile loading.
    fn make_hook(script: PathBuf, source_pack: Option<&str>) -> SessionHook {
        SessionHook {
            script,
            timeout_secs: None,
            source_pack: source_pack
                .map(|s| crate::package::parse_package_ref(s).expect("valid pack ref in test")),
        }
    }

    // -------------------------------------------------------------------------
    // Test 0: source_pack is set but not present in the packs list
    //
    // This guards against a future regression where a call site of
    // resolve_store_pack_session_hooks forgets to push the pack key into
    // profile.packs.  verify_profile_packs must catch this and hard-error
    // rather than silently skipping the containment check.
    // -------------------------------------------------------------------------
    #[test]
    fn test_verify_source_pack_not_in_packs_list_is_an_error() {
        // No env/disk setup needed: the guard fires before the lockfile is read.
        let hooks = SessionHooks {
            before: Some(make_hook(
                PathBuf::from("/some/path/script.sh"),
                Some("acme/widget"), // source_pack set …
            )),
            after: None,
        };
        let p = profile::Profile {
            session_hooks: hooks,
            ..profile::Profile::default()
        };

        // … but "acme/widget" is absent from the packs list.
        let result = verify_profile_packs(&[], &p);

        assert!(
            result.is_err(),
            "source_pack not in packs list must be a hard error"
        );
        let err = result.expect_err("expected an error from verify_profile_packs");
        let msg = err.to_string();
        assert!(
            msg.contains("/some/path/script.sh"),
            "error must reference the offending hook script: {msg}"
        );
    }

    // -------------------------------------------------------------------------
    // Test 1: local profile with an absolute-path hook
    //
    // A local (non-store) profile has source_pack = None on its hooks.
    // packs_to_verify is empty so verify_profile_packs returns Ok(()) immediately
    // without reading the lockfile.  The hook is never checked — this is
    // intentional: local hooks are validated at execution time by
    // validate_hook_script, not here.
    // -------------------------------------------------------------------------
    #[test]
    fn test_verify_local_profile_hook_not_checked() {
        // No env/disk setup needed: packs_to_verify is empty so
        // verify_profile_packs returns Ok(()) before reading anything from disk.
        let hooks = SessionHooks {
            before: Some(make_hook(
                PathBuf::from("/usr/local/bin/my-setup.sh"),
                None, // source_pack = None → local hook
            )),
            after: None,
        };
        let p = profile::Profile {
            session_hooks: hooks,
            ..profile::Profile::default()
        };

        assert!(
            verify_profile_packs(&[], &p).is_ok(),
            "local profile hooks must not be checked by verify_profile_packs"
        );
    }

    // -------------------------------------------------------------------------
    // Test 2: store pack whose hook script is a declared, locked artifact
    //
    // $PACK_DIR/scripts/before.sh was expanded at load time and appears in the
    // lockfile artifacts.  The hook-containment check must pass: the only
    // remaining error is the absent trust bundle (a later, independent step).
    // -------------------------------------------------------------------------
    #[test]
    fn test_verify_store_pack_hook_in_artifacts_passes() {
        let result = with_config_env(|config_dir| {
            let (install_dir, artifacts) = build_pack_with_scripts(
                config_dir,
                "acme",
                "widget",
                &[("scripts/before.sh", "#!/bin/sh\necho before\n")],
            );
            write_test_lockfile(config_dir, &[("acme/widget", artifacts)]);

            let hooks = SessionHooks {
                before: Some(make_hook(
                    install_dir.join("scripts/before.sh"),
                    Some("acme/widget"),
                )),
                after: None,
            };
            let p = profile::Profile {
                session_hooks: hooks,
                ..profile::Profile::default()
            };
            verify_profile_packs(&["acme/widget".to_string()], &p)
        });

        // Artifact + hook containment passed; the only remaining blocker is the
        // missing trust bundle (tested separately in test 7).
        assert!(
            matches!(result, Err(ref e) if e.to_string().contains(".nono-trust.bundle")),
            "expected only a missing-trust-bundle error after hook containment passed, got: {result:?}"
        );
    }

    // -------------------------------------------------------------------------
    // Test 3: store pack hook script exists on disk but is NOT in artifacts
    //
    // An attacker (or a mistaken author) places a script inside the pack
    // directory that was never declared in the lockfile.  verify_profile_packs
    // must reject this with an error.
    // -------------------------------------------------------------------------
    #[test]
    fn test_verify_store_pack_hook_not_in_artifacts_fails() {
        let result = with_config_env(|config_dir| {
            // Lockfile only declares "scripts/real.sh"; the profile hook
            // points at "scripts/non-existing.sh" which is not locked.
            let (install_dir, artifacts) = build_pack_with_scripts(
                config_dir,
                "acme",
                "widget",
                &[("scripts/real.sh", "#!/bin/sh\necho real\n")],
            );
            // Also write the unlocked file on disk to confirm presence alone
            // is not sufficient for the check to pass.
            let unlocked = install_dir.join("scripts/non-existing.sh");
            fs::write(&unlocked, "#!/bin/sh\necho unlocked\n").expect("write unlocked");

            write_test_lockfile(config_dir, &[("acme/widget", artifacts)]);

            let hooks = SessionHooks {
                before: Some(make_hook(
                    install_dir.join("scripts/non-existing.sh"),
                    Some("acme/widget"),
                )),
                after: None,
            };
            let p = profile::Profile {
                session_hooks: hooks,
                ..profile::Profile::default()
            };
            verify_profile_packs(&["acme/widget".to_string()], &p)
        });

        assert!(
            result.is_err(),
            "hook script not in lockfile artifacts must be rejected"
        );
    }

    // -------------------------------------------------------------------------
    // Test 4: store-extends-store — each hook from its own pack's artifacts
    //
    // acme/base provides the before hook; acme/top provides the after hook.
    // Both scripts are in their respective packs' lockfile artifacts.
    // The hook-containment check must pass for both packs: the only remaining
    // error is the absent trust bundle (a later, independent step).
    // -------------------------------------------------------------------------
    #[test]
    fn test_verify_store_extends_store_hooks_in_correct_packs_passes() {
        let result = with_config_env(|config_dir| {
            let (base_install_dir, base_artifacts) = build_pack_with_scripts(
                config_dir,
                "acme",
                "base",
                &[("hooks/setup.sh", "#!/bin/sh\necho setup\n")],
            );
            let (top_install_dir, top_artifacts) = build_pack_with_scripts(
                config_dir,
                "acme",
                "top",
                &[("hooks/teardown.sh", "#!/bin/sh\necho teardown\n")],
            );
            write_test_lockfile(
                config_dir,
                &[("acme/base", base_artifacts), ("acme/top", top_artifacts)],
            );

            let hooks = SessionHooks {
                before: Some(make_hook(
                    base_install_dir.join("hooks/setup.sh"),
                    Some("acme/base"),
                )),
                after: Some(make_hook(
                    top_install_dir.join("hooks/teardown.sh"),
                    Some("acme/top"),
                )),
            };
            let p = profile::Profile {
                session_hooks: hooks,
                ..profile::Profile::default()
            };
            verify_profile_packs(&["acme/base".to_string(), "acme/top".to_string()], &p)
        });

        // Artifact + hook containment passed for both packs; the only remaining
        // blocker is the missing trust bundle (tested separately in test 7).
        assert!(
            matches!(result, Err(ref e) if e.to_string().contains(".nono-trust.bundle")),
            "expected only a missing-trust-bundle error after hook containment passed, got: {result:?}"
        );
    }

    // -------------------------------------------------------------------------
    // Test 5: pack confusion — hook source_pack does not match the pack that
    // owns the script on disk
    //
    // The before hook has source_pack = "acme/top" but its script path lives
    // inside acme/base's install directory (i.e. not in acme/top's artifacts).
    // verify_profile_packs must reject this.
    // -------------------------------------------------------------------------
    #[test]
    fn test_verify_store_extends_store_pack_confusion_fails() {
        let result = with_config_env(|config_dir| {
            let (base_install_dir, base_artifacts) = build_pack_with_scripts(
                config_dir,
                "acme",
                "base",
                &[("hooks/setup.sh", "#!/bin/sh\necho setup\n")],
            );
            let (_top_install_dir, top_artifacts) = build_pack_with_scripts(
                config_dir,
                "acme",
                "top",
                &[("hooks/teardown.sh", "#!/bin/sh\necho teardown\n")],
            );
            write_test_lockfile(
                config_dir,
                &[("acme/base", base_artifacts), ("acme/top", top_artifacts)],
            );

            // Confusion: the script lives in acme/base but source_pack claims
            // acme/top.  acme/top's artifacts do not include hooks/setup.sh.
            let hooks = SessionHooks {
                before: Some(make_hook(
                    base_install_dir.join("hooks/setup.sh"),
                    Some("acme/top"), // wrong pack
                )),
                after: None,
            };
            let p = profile::Profile {
                session_hooks: hooks,
                ..profile::Profile::default()
            };
            verify_profile_packs(&["acme/base".to_string(), "acme/top".to_string()], &p)
        });

        assert!(
            result.is_err(),
            "hook script not in the claimed pack's artifacts must be rejected"
        );
    }

    // -------------------------------------------------------------------------
    // Test 6: installed pack with no lockfile entry must be rejected
    //
    // If a pack directory exists on disk but there is no corresponding entry in
    // the lockfile, verify_profile_packs must return an error rather than
    // silently treating the pack as uninstalled.
    // -------------------------------------------------------------------------
    #[test]
    fn verify_profile_packs_requires_lockfile_entry_for_installed_pack() {
        let result = with_config_env(|config_dir| {
            // Create the pack directory without writing any lockfile entry.
            let (_, _empty_artifacts) = build_pack_with_scripts(config_dir, "acme", "widget", &[]);
            verify_profile_packs(&["acme/widget".to_string()], &profile::Profile::default())
        });

        let err = match result {
            Ok(()) => panic!("installed pack without lockfile entry must fail verification"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("no lockfile entry"),
            "unexpected error: {err}"
        );
    }

    // -------------------------------------------------------------------------
    // Test 7: pack with a lockfile entry but no trust bundle must be rejected
    //
    // Artifact digest verification passes (the file is on disk and its hash
    // matches the lockfile), but the absence of `.nono-trust.bundle` means the
    // Sigstore provenance chain cannot be re-verified — this must be a hard
    // error.
    // -------------------------------------------------------------------------
    #[test]
    fn verify_profile_packs_requires_trust_bundle_for_locked_pack() {
        let result = with_config_env(|config_dir| {
            let artifact_content = r#"{"meta":{"name":"widget"}}"#;
            let (_, artifacts) = build_pack_with_scripts(
                config_dir,
                "acme",
                "widget",
                &[("package.json", artifact_content)],
            );
            write_test_lockfile(config_dir, &[("acme/widget", artifacts)]);

            verify_profile_packs(&["acme/widget".to_string()], &profile::Profile::default())
        });

        let err = match result {
            Ok(()) => panic!("locked pack without trust bundle must fail verification"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("missing .nono-trust.bundle"),
            "unexpected error: {err}"
        );
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn active_command_policy_profile() -> profile::Profile {
        profile::Profile {
            command_policies: Some(CommandPoliciesConfig {
                entrypoint: Some("git".to_string()),
                commands: BTreeMap::from([(
                    "git".to_string(),
                    CommandPolicyConfig {
                        sandbox: Some(CommandSandboxConfig::default()),
                        ..Default::default()
                    },
                )]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn inactive_command_policy_runtime_support_is_ok() {
        assert!(validate_command_policy_runtime_support(&profile::Profile::default()).is_ok());
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn active_command_policy_runtime_support_rejects_unsupported_platform() {
        let err = validate_command_policy_runtime_support(&active_command_policy_profile())
            .expect_err("active tool-sandbox runtime must fail on unsupported platforms");

        assert!(
            err.to_string().contains("Linux and macOS"),
            "error should describe supported platforms: {err}"
        );
    }

    #[test]
    fn prepare_profile_for_preflight_matches_runtime_resolution() {
        let workdir = match tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("failed to create tempdir: {err}"),
        };
        let cli_override = workdir.path().join("cli-override");
        if let Err(err) = fs::create_dir_all(&cli_override) {
            panic!("failed to create CLI override path: {err}");
        }
        let cli_ignore = workdir.path().join("cli-ignore");
        if let Err(err) = fs::create_dir_all(&cli_ignore) {
            panic!("failed to create CLI ignore path: {err}");
        }

        let profile_path = workdir.path().join("preflight-profile.json");
        if let Err(err) = fs::write(
            &profile_path,
            r#"{
                "extends": "default",
                "meta": { "name": "preflight-profile" },
                "workdir": { "access": "write" },
                "rollback": { "exclude_patterns": ["target"] },
                "network": {
                    "allow_domain": ["example.com"],
                    "upstream_bypass": ["localhost"],
                    "listen_port": [8080]
                },
                "filesystem": {
                    "bypass_protection": ["$WORKDIR/.git"],
                    "suppress_save_prompt": ["$WORKDIR/.copilot/settings.json"]
                }
            }"#,
        ) {
            panic!("failed to write profile: {err}");
        }

        let args = SandboxArgs {
            profile: Some(profile_path.to_string_lossy().into_owned()),
            bypass_protection: vec![cli_override],
            suppress_save_prompt: vec![cli_ignore],
            ..SandboxArgs::default()
        };

        let runtime = match prepare_profile(&args, true, workdir.path()) {
            Ok(profile) => profile,
            Err(err) => panic!("runtime prepare_profile failed: {err}"),
        };
        let preflight = match prepare_profile_for_preflight(&args, workdir.path()) {
            Ok(profile) => profile,
            Err(err) => panic!("preflight prepare_profile failed: {err}"),
        };

        assert_eq!(runtime.capability_elevation, preflight.capability_elevation);
        #[cfg(target_os = "linux")]
        assert_eq!(runtime.wsl2_proxy_policy, preflight.wsl2_proxy_policy);
        assert_eq!(runtime.workdir_access, preflight.workdir_access);
        assert_eq!(
            runtime.rollback_exclude_patterns,
            preflight.rollback_exclude_patterns
        );
        assert_eq!(
            runtime.rollback_exclude_globs,
            preflight.rollback_exclude_globs
        );
        assert_eq!(runtime.network_profile, preflight.network_profile);
        assert_eq!(runtime.allow_domain, preflight.allow_domain);
        assert_eq!(runtime.credentials, preflight.credentials);
        assert_eq!(runtime.custom_credentials, preflight.custom_credentials);
        assert_eq!(runtime.upstream_proxy, preflight.upstream_proxy);
        assert_eq!(runtime.upstream_bypass, preflight.upstream_bypass);
        assert_eq!(runtime.listen_ports, preflight.listen_ports);
        assert_eq!(runtime.open_url_origins, preflight.open_url_origins);
        assert_eq!(
            runtime.open_url_allow_localhost,
            preflight.open_url_allow_localhost
        );
        assert_eq!(
            runtime.allow_launch_services,
            preflight.allow_launch_services
        );
        assert_eq!(runtime.allow_gpu, preflight.allow_gpu);
        assert_eq!(
            runtime.bypass_protection_paths,
            preflight.bypass_protection_paths
        );
        assert_eq!(runtime.ignored_denial_paths, preflight.ignored_denial_paths);
        assert!(
            runtime
                .ignored_denial_paths
                .contains(&nono::try_canonicalize(
                    &workdir.path().join(".copilot/settings.json")
                ))
        );
        assert!(
            runtime
                .ignored_denial_paths
                .contains(&nono::try_canonicalize(&workdir.path().join("cli-ignore")))
        );
        assert_eq!(runtime.allowed_env_vars, preflight.allowed_env_vars);
        assert_eq!(runtime.denied_env_vars, preflight.denied_env_vars);
        assert_eq!(
            runtime.loaded_profile.as_ref().map(|profile| {
                (
                    profile.meta.name.clone(),
                    profile.extends.clone(),
                    profile.groups.include.clone(),
                    profile.workdir.access.clone(),
                    profile.filesystem.allow.clone(),
                )
            }),
            preflight.loaded_profile.as_ref().map(|profile| {
                (
                    profile.meta.name.clone(),
                    profile.extends.clone(),
                    profile.groups.include.clone(),
                    profile.workdir.access.clone(),
                    profile.filesystem.allow.clone(),
                )
            })
        );
    }

    #[test]
    fn environment_deny_only_does_not_activate_allow_filter() {
        // allow_vars absent (None) — no filter should be active
        let mut profile = profile::Profile::default();
        profile.environment = Some(profile::EnvironmentConfig {
            allow_vars: None,
            deny_vars: vec!["GH_TOKEN".to_string()],
            set_vars: Default::default(),
        });
        assert_eq!(
            profile
                .environment
                .as_ref()
                .and_then(|e| e.allow_vars.as_ref()),
            None,
            "absent allow_vars should produce no filter"
        );
    }

    #[test]
    fn environment_explicit_empty_allow_vars_blocks_all() {
        // allow_vars explicitly [] — filter active, nothing passes
        let mut profile = profile::Profile::default();
        profile.environment = Some(profile::EnvironmentConfig {
            allow_vars: Some(vec![]),
            deny_vars: vec![],
            set_vars: Default::default(),
        });
        assert_eq!(
            profile
                .environment
                .as_ref()
                .and_then(|e| e.allow_vars.as_ref()),
            Some(&vec![]),
            "explicit empty allow_vars should produce Some([]) (block all)"
        );
    }

    #[test]
    fn environment_set_vars_only_does_not_activate_allow_filter() {
        let mut profile = profile::Profile::default();
        let mut set_vars = std::collections::HashMap::new();
        set_vars.insert("MY_VAR".to_string(), "hello".to_string());
        profile.environment = Some(profile::EnvironmentConfig {
            allow_vars: None,
            deny_vars: vec![],
            set_vars,
        });
        assert_eq!(
            profile
                .environment
                .as_ref()
                .and_then(|e| e.allow_vars.as_ref()),
            None,
            "set_vars-only environment should not activate the allow filter"
        );
    }
}
