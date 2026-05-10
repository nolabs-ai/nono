use crate::cli::SandboxArgs;
use crate::{package, profile};
use sha2::{Digest, Sha256};
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
    pub(crate) allow_gpu: bool,
    pub(crate) allow_parent_of_protected: bool,
    pub(crate) bypass_protection_paths: Vec<PathBuf>,
    pub(crate) allowed_env_vars: Option<Vec<String>>,
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
fn verify_profile_packs(packs: &[String]) -> crate::Result<()> {
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

        let locked = lockfile.packages.get(pack_ref);
        if let Some(locked_pkg) = locked {
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
        }

        let bundle_path = install_dir.join(".nono-trust.bundle");
        if bundle_path.exists() {
            verify_stored_bundles(&install_dir, &bundle_path, pack_ref)?;
        }
    }

    Ok(())
}

/// Re-verify each artifact's Sigstore bundle from the stored trust bundle file.
fn verify_stored_bundles(
    install_dir: &Path,
    bundle_path: &Path,
    pack_ref: &str,
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

        let bundle_value = entry.get("bundle").ok_or_else(|| {
            nono::NonoError::PackageInstall(format!(
                "trust bundle entry missing 'bundle' field for '{}' in pack '{}'",
                artifact_name, pack_ref
            ))
        })?;

        let artifact_path = install_dir.join(artifact_name);
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

        nono::trust::verify_bundle_subject_name(&bundle, Path::new(artifact_name))?;
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
    }

    Ok(())
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
        verify_profile_packs(&profile.packs)?;

        if !profile.packs.is_empty() && !options.hook_output_silent {
            eprintln!("  Verified {} pack(s)", profile.packs.len());
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
        allowed_env_vars: loaded_profile.as_ref().and_then(|profile| {
            profile.environment.as_ref().map(|env_config| {
                if let Some(err) =
                    crate::exec_strategy::validate_allow_vars_pattern(&env_config.allow_vars)
                {
                    eprintln!("Warning: {}", err);
                }
                env_config.allow_vars.clone()
            })
        }),
        loaded_profile,
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
    use std::fs;
    use tempfile::tempdir;

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
                    "bypass_protection": ["$WORKDIR/.git"]
                }
            }"#,
        ) {
            panic!("failed to write profile: {err}");
        }

        let args = SandboxArgs {
            profile: Some(profile_path.to_string_lossy().into_owned()),
            bypass_protection: vec![cli_override],
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
}
