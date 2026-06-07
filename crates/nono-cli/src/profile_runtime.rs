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
    #[cfg(target_os = "linux")]
    pub(crate) af_unix_mediation: profile::LinuxAfUnixMediation,
    pub(crate) workdir_access: Option<profile::WorkdirAccess>,
    pub(crate) rollback_exclude_patterns: Vec<String>,
    pub(crate) rollback_exclude_globs: Vec<String>,
    pub(crate) network_profile: Option<String>,
    pub(crate) allow_domain: Vec<profile::AllowDomainEntry>,
    pub(crate) reject_domain: Vec<String>,
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
    pub(crate) ignored_denial_paths: Vec<PathBuf>,
    pub(crate) suppressed_system_service_operations: Vec<String>,
    pub(crate) allowed_env_vars: Option<Vec<String>>,
    pub(crate) denied_env_vars: Option<Vec<String>>,
    pub(crate) network_approval_mode: Option<String>,
    pub(crate) network_approval_timeout_secs: Option<u64>,
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

        verify_profile_packs(&packs_to_verify)?;

        if !packs_to_verify.is_empty() && !options.hook_output_silent {
            eprintln!("  Verified {} pack(s)", packs_to_verify.len());
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
        reject_domain: loaded_profile
            .as_ref()
            .map(|profile| profile.network.reject_domain.clone())
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
        network_approval_mode: loaded_profile
            .as_ref()
            .and_then(|profile| profile.network.approval_mode.clone()),
        network_approval_timeout_secs: loaded_profile
            .as_ref()
            .and_then(|profile| profile.network.approval_timeout_secs),
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

    fn with_config_env<F, R>(f: F) -> R
    where
        F: FnOnce(&Path) -> R,
    {
        let _guard = match crate::test_env::ENV_LOCK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let tmp = match tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("failed to create tempdir: {err}"),
        };
        let config_dir = match tmp.path().canonicalize() {
            Ok(path) => path,
            Err(err) => panic!("failed to canonicalize tempdir: {err}"),
        };
        let config_str = match config_dir.to_str() {
            Some(value) => value,
            None => panic!("tempdir path is not valid UTF-8"),
        };
        let _env = crate::test_env::EnvVarGuard::set_all(&[("XDG_CONFIG_HOME", config_str)]);
        f(&config_dir)
    }

    fn create_pack_dir(config_dir: &Path, namespace: &str, name: &str) -> PathBuf {
        let install_dir = config_dir
            .join("nono")
            .join("packages")
            .join(namespace)
            .join(name);
        if let Err(err) = fs::create_dir_all(&install_dir) {
            panic!("failed to create pack dir: {err}");
        }
        install_dir
    }

    fn write_lockfile_with_artifact(pack_ref: &str, artifact_name: &str, artifact_bytes: &[u8]) {
        let digest = Sha256::digest(artifact_bytes);
        let sha256 = digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();

        let mut artifacts = std::collections::BTreeMap::new();
        artifacts.insert(
            artifact_name.to_string(),
            package::LockedArtifact {
                sha256,
                artifact_type: package::ArtifactType::Profile,
            },
        );

        let mut packages = std::collections::BTreeMap::new();
        packages.insert(
            pack_ref.to_string(),
            package::LockedPackage {
                version: "1.0.0".to_string(),
                installed_at: "2026-01-01T00:00:00Z".to_string(),
                pinned: false,
                provenance: Some(package::PackageProvenance {
                    signer_identity: "https://github.com/acme/repo/.github/workflows/release.yml@refs/tags/v1.0.0"
                        .to_string(),
                    repository: "acme/repo".to_string(),
                    workflow: ".github/workflows/release.yml".to_string(),
                    git_ref: "refs/tags/v1.0.0".to_string(),
                    rekor_log_index: 1,
                    signed_at: "2026-01-01T00:00:00Z".to_string(),
                }),
                artifacts,
                wiring_record: Vec::new(),
            },
        );

        let lockfile = package::Lockfile {
            lockfile_version: package::LOCKFILE_VERSION,
            registry: "https://registry.example.test".to_string(),
            packages,
        };
        if let Err(err) = package::write_lockfile(&lockfile) {
            panic!("failed to write lockfile: {err}");
        }
    }

    #[test]
    fn verify_profile_packs_requires_lockfile_entry_for_installed_pack() {
        let result = with_config_env(|config_dir| {
            create_pack_dir(config_dir, "acme", "widget");
            verify_profile_packs(&["acme/widget".to_string()])
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

    #[test]
    fn verify_profile_packs_requires_trust_bundle_for_locked_pack() {
        let result = with_config_env(|config_dir| {
            let install_dir = create_pack_dir(config_dir, "acme", "widget");
            let artifact_bytes = br#"{"meta":{"name":"widget"}}"#;
            if let Err(err) = fs::write(install_dir.join("package.json"), artifact_bytes) {
                panic!("failed to write package artifact: {err}");
            }
            write_lockfile_with_artifact("acme/widget", "package.json", artifact_bytes);

            verify_profile_packs(&["acme/widget".to_string()])
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
}
