//! Pack command handlers.

use crate::cli::{
    ListArgs, OutdatedArgs, PinArgs, PullArgs, RemoveArgs, SearchArgs, UnpinArgs, UpdateArgs,
};
use crate::package::{
    self, ArtifactEntry, ArtifactType, LockedArtifact, LockedPackage, PackageManifest,
    PackageProvenance, PackageRef, PullResponse,
};
use crate::registry_client::{RegistryClient, resolve_registry_url};
use chrono::{DateTime, Local, Utc};
use nono::{NonoError, Result, SignerIdentity};
use semver::Version;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

pub fn run_pull(args: PullArgs) -> Result<()> {
    let package_ref = package::parse_package_ref(&args.package_ref)?;
    let registry_url = resolve_registry_url(args.registry.as_deref());
    let client = RegistryClient::new(registry_url.clone());

    let requested_version = package_ref.version.as_deref().unwrap_or("latest");
    let pull = client.fetch_pull_response(&package_ref, requested_version)?;
    validate_pull_response(&package_ref, &pull)?;

    let lockfile = package::read_lockfile()?;
    if let Some(existing) = lockfile.packages.get(&package_ref.key())
        && existing.version == pull.version
        && !args.force
    {
        eprintln!(
            "  {} is already at {} (use --force to reinstall)",
            package_ref.key(),
            pull.version
        );
        return Ok(());
    }

    let printer = crate::pull_ui::ProgressPrinter::new(&pull);
    printer.header(&package_ref);

    let downloads = download_and_verify_artifacts(&client, &package_ref, &pull, Some(&printer))?;
    let manifest = load_manifest(&downloads.artifacts)?;
    validate_manifest(&manifest)?;

    let signer_identity = signer_identity_uri(&downloads.signer_identity)?;
    enforce_signer_pinning(
        lockfile.packages.get(&package_ref.key()),
        &signer_identity,
        args.force,
    )?;

    // Re-pull semantics (security review fix): if this pack is
    // already installed, reverse its prior wiring records first so
    // the new install captures `prior_value` against the user's true
    // pre-install state — not against a previous pack-written value.
    // This also handles the case where the new manifest dropped
    // directives the old one had: their reversal happens here, since
    // the new install won't touch them.
    //
    // If reversal fails for any record, abort the re-pull (do not
    // proceed to apply the new directives). The lockfile entry stays
    // intact so the user can investigate.
    if let Some(prior_pkg) = lockfile.packages.get(&package_ref.key())
        && !prior_pkg.wiring_record.is_empty()
    {
        let failures = crate::wiring::reverse(&prior_pkg.wiring_record);
        if !failures.is_empty() {
            for f in &failures {
                eprintln!("    failed: {} — {}", f.record_summary, f.error);
            }
            return Err(NonoError::PackageInstall(format!(
                "re-pull of {} aborted — {} prior wiring directive(s) failed to reverse. \
                     Resolve the failures above (or `nono remove --force` first) before retrying.",
                package_ref.key(),
                failures.len()
            )));
        }
    }

    // Files this same pack wrote on a previous install — empty after
    // the reverse above succeeded (we tore down everything). Kept
    // around as a safety net: if reverse left anything behind, the
    // wiring interpreter can still verify it owns + matches before
    // overwriting.
    let pack_owned_files = pack_owned_write_file_paths(&lockfile, &package_ref);
    let install = install_package(
        &package_ref,
        &manifest,
        &downloads,
        args.init,
        args.force,
        &pack_owned_files,
    )?;
    update_lockfile(
        &package_ref,
        &registry_url,
        &pull,
        &signer_identity,
        &manifest,
        &downloads.artifacts,
        &install.wiring_record,
    )?;

    let install_dir = package::package_install_dir(&package_ref.namespace, &package_ref.name)?;
    crate::pull_ui::render_summary(
        &package_ref,
        &pull,
        &install_dir,
        install.installed_artifacts,
        install.copied_to_project,
    );

    // Direct-pull path: if the user just installed the canonical claude
    // pack (here, not via `migration::check_and_run`), also offer to
    // strip pre-0.43 inbuilt-hook leftovers. Idempotent — silent no-op
    // on a clean install. Mirrors the cleanup hook in `check_and_run`
    // so power users who skip `--profile always-further/claude` don't end up with
    // both legacy and pack hooks firing.
    if package_ref.namespace == "always-further" && package_ref.name == "claude" {
        crate::legacy_cleanup::check_and_offer_cleanup()?;
    }

    Ok(())
}

pub fn run_remove(args: RemoveArgs) -> Result<()> {
    let package_ref = package::parse_package_ref(&args.package_ref)?;

    let lockfile = package::read_lockfile()?;
    let locked_pkg = lockfile.packages.get(&package_ref.key());

    let install_dir = package::package_install_dir(&package_ref.namespace, &package_ref.name)?;
    let install_dir_existed = install_dir.exists();

    if locked_pkg.is_none() && !install_dir_existed {
        return Err(NonoError::PackageInstall(format!(
            "package {} is not installed",
            package_ref.key()
        )));
    }

    // Reverse the wiring directives the pack ran at install time.
    // Records live in the lockfile (`LockedPackage::wiring_record`)
    // so we don't need to re-evaluate the pack's manifest — works
    // even if the pack has been re-published or removed from the
    // registry between install and uninstall.
    //
    // Failure handling (security review fix): per-record failures
    // are surfaced rather than swallowed. Without `--force`, any
    // failure aborts the remove with the lockfile entry intact so
    // the user can investigate and retry. With `--force`, we log
    // the failures and proceed — the lockfile entry is still
    // dropped, leaving any orphaned wiring as the user's problem
    // (typically because the user already cleaned it up by hand).
    if let Some(pkg) = locked_pkg
        && !pkg.wiring_record.is_empty()
    {
        let failures = crate::wiring::reverse(&pkg.wiring_record);
        let total = pkg.wiring_record.len();
        let succeeded = total.saturating_sub(failures.len());
        eprintln!("  reversed {succeeded}/{total} wiring directive(s)",);
        if !failures.is_empty() {
            for f in &failures {
                eprintln!("    failed: {} — {}", f.record_summary, f.error);
            }
            if !args.force {
                return Err(NonoError::PackageInstall(format!(
                    "remove of {} aborted — {} wiring directive(s) failed to reverse. \
                         The lockfile entry has been preserved so you can retry. \
                         Inspect the failures above and either resolve them and re-run, \
                         or pass --force to drop the lockfile entry and accept any \
                         orphaned wiring.",
                    package_ref.key(),
                    failures.len()
                )));
            }
            eprintln!(
                "  --force: dropping lockfile entry despite {} failed reversal(s)",
                failures.len()
            );
        }
    }

    // Remove the package store directory.
    if install_dir.exists() {
        fs::remove_dir_all(&install_dir).map_err(NonoError::Io)?;
    }

    // Clean up empty namespace directory.
    if let Some(ns_dir) = install_dir.parent()
        && ns_dir.exists()
        && is_dir_empty(ns_dir)
    {
        let _ = fs::remove_dir(ns_dir);
    }

    package::remove_package_from_lockfile(&package_ref)?;

    eprintln!("Removed {}", package_ref.key());
    Ok(())
}

/// Collect the absolute paths and prior SHA-256 of `WriteFile`
/// destinations recorded against this exact pack in the lockfile.
/// The wiring interpreter uses both pieces to allow idempotent
/// re-pulls — only when the on-disk content still matches the
/// recorded hash (i.e. the user hasn't edited the file since we
/// wrote it). A user edit OR a path not in this map causes the
/// re-pull to refuse rather than silently clobber.
fn pack_owned_write_file_paths(
    lockfile: &package::Lockfile,
    package_ref: &PackageRef,
) -> HashMap<PathBuf, String> {
    let mut owned = HashMap::new();
    if let Some(pkg) = lockfile.packages.get(&package_ref.key()) {
        for record in &pkg.wiring_record {
            if let crate::wiring::WiringRecord::WriteFile { dest, sha256 } = record {
                owned.insert(PathBuf::from(dest), sha256.clone());
            }
        }
    }
    owned
}

fn is_dir_empty(path: &Path) -> bool {
    fs::read_dir(path)
        .map(|mut entries| entries.next().is_none())
        .unwrap_or(false)
}

pub fn run_update(args: UpdateArgs) -> Result<()> {
    let lockfile = package::read_lockfile()?;

    if lockfile.packages.is_empty() {
        eprintln!("No installed nono packs.");
        return Ok(());
    }

    let registry_url = resolve_registry_url(args.registry.as_deref());
    let client = RegistryClient::new(registry_url.clone());

    // Collect the keys to process: either one specific pack or all installed.
    let keys: Vec<String> = if let Some(ref pkg_ref_str) = args.package_ref {
        let pkg_ref = package::parse_package_ref(pkg_ref_str)?;
        if pkg_ref.version.is_some() {
            return Err(NonoError::PackageInstall(
                "nono update does not accept a version — use `nono pull <ns>/<name>@<version>` for exact installs".to_string(),
            ));
        }
        if !lockfile.packages.contains_key(&pkg_ref.key()) {
            return Err(NonoError::PackageInstall(format!(
                "{} is not installed",
                pkg_ref.key()
            )));
        }
        vec![pkg_ref.key()]
    } else {
        lockfile.packages.keys().cloned().collect()
    };

    let mut updated = 0usize;
    let mut skipped = 0usize;
    let mut failed = 0usize;

    for key in &keys {
        let pkg = match lockfile.packages.get(key) {
            Some(p) => p,
            None => continue,
        };

        let parts: Vec<&str> = key.splitn(2, '/').collect();
        if parts.len() != 2 {
            eprintln!("  warning: skipping malformed lockfile key '{key}'");
            continue;
        }
        let (namespace, name) = (parts[0], parts[1]);

        if pkg.pinned && !args.force {
            eprintln!(
                "  {key}@{} pinned — skipped (use --force to update pinned packs)",
                pkg.version
            );
            skipped = skipped.saturating_add(1);
            continue;
        }

        let pkg_ref = package::PackageRef {
            namespace: namespace.to_string(),
            name: name.to_string(),
            version: None,
        };

        let status = match client.fetch_package_status(&pkg_ref, Some(&pkg.version)) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("  warning: could not check status for {key}: {e}");
                failed = failed.saturating_add(1);
                continue;
            }
        };

        match status.installed_status.as_deref() {
            Some("current") => {
                eprintln!("  {key} {} — up to date", pkg.version);
                skipped = skipped.saturating_add(1);
            }
            Some("ahead") => {
                eprintln!("  {key} {} is ahead of registry — skipped", pkg.version);
                skipped = skipped.saturating_add(1);
            }
            Some("yanked") => {
                eprintln!(
                    "  {key}@{} has been yanked — run `nono pull {key}` to install the latest safe release",
                    pkg.version
                );
                failed = failed.saturating_add(1);
            }
            _ => {
                // "outdated" or "unknown" — attempt update.
                let latest = status.latest.as_deref().unwrap_or("latest");
                if args.dry_run {
                    eprintln!("  {key} {} → {latest} (dry run)", pkg.version);
                    updated = updated.saturating_add(1);
                } else {
                    if pkg.pinned {
                        eprintln!(
                            "  {key}@{} is pinned — updating anyway (--force)",
                            pkg.version
                        );
                    }
                    eprintln!("  updating {key} {} → {latest}", pkg.version);
                    match run_pull(PullArgs {
                        package_ref: key.clone(),
                        registry: args.registry.clone(),
                        force: args.force,
                        init: false,
                        help: None,
                    }) {
                        Ok(()) => {
                            updated = updated.saturating_add(1);
                        }
                        Err(e) => {
                            eprintln!("  failed to update {key}: {e}");
                            failed = failed.saturating_add(1);
                        }
                    }
                }
            }
        }
    }

    if args.dry_run {
        eprintln!("\n  dry run: {updated} would be updated, {skipped} skipped");
    } else {
        eprintln!("\n  {updated} updated, {skipped} skipped, {failed} failed");
    }

    if failed > 0 && !args.dry_run {
        Err(NonoError::PackageInstall(format!(
            "{failed} pack(s) failed to update"
        )))
    } else {
        Ok(())
    }
}

pub fn run_search(args: SearchArgs) -> Result<()> {
    let registry_url = resolve_registry_url(args.registry.as_deref());
    let client = RegistryClient::new(registry_url);
    let results = client.search_packages(&args.query)?;

    if args.json {
        let json = serde_json::to_string_pretty(&results).map_err(|e| {
            NonoError::ConfigParse(format!("failed to serialize search results: {e}"))
        })?;
        println!("{json}");
        return Ok(());
    }

    if results.is_empty() {
        println!("No nono packs found.");
        return Ok(());
    }

    for result in results {
        let version = result.latest_version.unwrap_or_else(|| "-".to_string());
        let description = result.description.unwrap_or_default();
        println!(
            "{}\t{}\t{}",
            format_args!("{}/{}", result.namespace, result.name),
            version,
            description
        );
    }

    Ok(())
}

pub fn run_list(args: ListArgs) -> Result<()> {
    let lockfile = package::read_lockfile()?;

    if args.installed {
        if args.json {
            let json = serde_json::to_string_pretty(&lockfile).map_err(|e| {
                NonoError::ConfigParse(format!("failed to serialize lockfile: {e}"))
            })?;
            println!("{json}");
            return Ok(());
        }

        if lockfile.packages.is_empty() {
            println!("No installed nono packs.");
            return Ok(());
        }

        for (name, pkg) in lockfile.packages {
            let installed_at = format_timestamp(&pkg.installed_at);
            println!("{name}\t{}\t{installed_at}", pkg.version);
        }
        return Ok(());
    }

    Err(NonoError::PackageInstall(
        "only `nono list --installed` is currently supported".to_string(),
    ))
}

pub fn run_pin(args: PinArgs) -> Result<()> {
    let package_ref = package::parse_package_ref(&args.package_ref)?;
    if package_ref.version.is_some() {
        return Err(NonoError::PackageInstall(
            "pin takes a pack name without a version — it pins the currently installed version"
                .to_string(),
        ));
    }

    let mut lockfile = package::read_lockfile()?;
    let pkg = lockfile
        .packages
        .get_mut(&package_ref.key())
        .ok_or_else(|| {
            NonoError::PackageInstall(format!("{} is not installed", package_ref.key()))
        })?;

    let pinned_version = pkg.version.clone();
    pkg.pinned = true;
    package::write_lockfile(&lockfile)?;

    eprintln!(
        "  pinned {}@{} — excluded from nono update",
        package_ref.key(),
        pinned_version
    );
    Ok(())
}

pub fn run_unpin(args: UnpinArgs) -> Result<()> {
    let package_ref = package::parse_package_ref(&args.package_ref)?;
    if package_ref.version.is_some() {
        return Err(NonoError::PackageInstall(
            "unpin takes a pack name without a version".to_string(),
        ));
    }

    let mut lockfile = package::read_lockfile()?;
    let pkg = lockfile
        .packages
        .get_mut(&package_ref.key())
        .ok_or_else(|| {
            NonoError::PackageInstall(format!("{} is not installed", package_ref.key()))
        })?;

    pkg.pinned = false;
    package::write_lockfile(&lockfile)?;

    eprintln!(
        "  unpinned {} — will be included in nono update",
        package_ref.key()
    );
    Ok(())
}

#[derive(serde::Serialize)]
struct OutdatedEntry {
    key: String,
    installed: String,
    latest: Option<String>,
    status: String,
    pinned: bool,
}

pub fn run_outdated(args: OutdatedArgs) -> Result<()> {
    let lockfile = package::read_lockfile()?;

    if lockfile.packages.is_empty() {
        if args.json {
            println!("[]");
        } else {
            println!("No installed nono packs.");
        }
        return Ok(());
    }

    let registry_url = resolve_registry_url(args.registry.as_deref());
    let client = RegistryClient::new(registry_url);

    let mut entries: Vec<OutdatedEntry> = Vec::new();

    for (key, pkg) in &lockfile.packages {
        let parts: Vec<&str> = key.splitn(2, '/').collect();
        let (namespace, name) = if parts.len() == 2 {
            (parts[0], parts[1])
        } else {
            eprintln!("  warning: skipping malformed lockfile key '{key}'");
            continue;
        };

        let pkg_ref = package::PackageRef {
            namespace: namespace.to_string(),
            name: name.to_string(),
            version: None,
        };

        match client.fetch_package_status(&pkg_ref, Some(&pkg.version)) {
            Ok(status) => {
                let status_str = status.installed_status.as_deref().unwrap_or("unknown");
                entries.push(OutdatedEntry {
                    key: key.clone(),
                    installed: pkg.version.clone(),
                    latest: status.latest.clone(),
                    status: status_str.to_string(),
                    pinned: pkg.pinned,
                });
            }
            Err(e) => {
                eprintln!("  warning: could not check status for {key}: {e}");
                entries.push(OutdatedEntry {
                    key: key.clone(),
                    installed: pkg.version.clone(),
                    latest: None,
                    status: "unknown".to_string(),
                    pinned: pkg.pinned,
                });
            }
        }
    }

    if args.json {
        let json = serde_json::to_string_pretty(&entries).map_err(|e| {
            NonoError::ConfigParse(format!("failed to serialize outdated results: {e}"))
        })?;
        println!("{json}");
        return Ok(());
    }

    let needs_attention = entries
        .iter()
        .any(|e| e.status != "current" && e.status != "unknown");

    if !needs_attention && entries.iter().all(|e| e.status == "current") {
        println!("All installed packs are up to date.");
        return Ok(());
    }

    println!("{:<40} {:<12} {:<12} STATUS", "PACK", "INSTALLED", "LATEST");
    for entry in &entries {
        let latest_display = entry.latest.as_deref().unwrap_or("-");
        let mut status_display = entry.status.clone();
        if entry.pinned {
            status_display.push_str(" (pinned)");
        }
        println!(
            "{:<40} {:<12} {:<12} {}",
            entry.key, entry.installed, latest_display, status_display
        );
    }

    Ok(())
}

struct DownloadedArtifact {
    filename: String,
    path: PathBuf,
    sha256_digest: String,
}

struct VerifiedDownloads {
    _tempdir: TempDir,
    bundle_json: String,
    signer_identity: SignerIdentity,
    artifacts: Vec<DownloadedArtifact>,
}

struct InstallSummary {
    installed_artifacts: usize,
    copied_to_project: usize,
    /// Records produced by the wiring interpreter, persisted into the
    /// lockfile so `nono remove` can reverse them.
    wiring_record: Vec<crate::wiring::WiringRecord>,
}

fn validate_pull_response(package_ref: &PackageRef, pull: &PullResponse) -> Result<()> {
    if pull.namespace != package_ref.namespace || pull.name != package_ref.name {
        return Err(NonoError::PackageVerification {
            package: package_ref.key(),
            reason: format!(
                "registry returned {} / {} for requested package {}",
                pull.namespace,
                pull.name,
                package_ref.key()
            ),
        });
    }

    if pull.artifacts.is_empty() {
        return Err(NonoError::PackageVerification {
            package: package_ref.key(),
            reason: "pull response did not include any artifacts".to_string(),
        });
    }

    let mut filenames = HashSet::with_capacity(pull.artifacts.len());
    for artifact in &pull.artifacts {
        validate_relative_path(&artifact.filename)?;
        if !filenames.insert(artifact.filename.as_str()) {
            return Err(NonoError::PackageVerification {
                package: package_ref.key(),
                reason: format!(
                    "pull response includes duplicate artifact '{}'",
                    artifact.filename
                ),
            });
        }
    }

    Ok(())
}

fn download_and_verify_artifacts(
    client: &RegistryClient,
    package_ref: &PackageRef,
    pull: &PullResponse,
    printer: Option<&crate::pull_ui::ProgressPrinter>,
) -> Result<VerifiedDownloads> {
    let trusted_root = nono::trust::load_production_trusted_root()?;
    let policy = nono::trust::VerificationPolicy::default();
    let bundle_path = Path::new(".nono-trust.bundle");
    let tempdir = TempDir::new().map_err(NonoError::Io)?;

    // Download the single multi-subject bundle for this version
    let bundle_json = client.download_bundle(&pull.bundle_url)?;
    let bundle = nono::trust::load_bundle_from_str(&bundle_json, bundle_path)?;

    // Extract all subjects from the bundle for digest matching
    let subjects = nono::trust::extract_all_subjects(&bundle, bundle_path)?;
    let subject_digests: std::collections::HashMap<&str, &str> = subjects
        .iter()
        .map(|(name, digest)| (digest.as_str(), name.as_str()))
        .collect();

    // Verify the bundle signature using the first subject's digest
    if let Some((_, first_digest)) = subjects.first() {
        nono::trust::verify_bundle_with_digest(
            first_digest,
            &bundle,
            &trusted_root,
            &policy,
            bundle_path,
        )?;
    } else {
        return Err(NonoError::PackageVerification {
            package: package_ref.key(),
            reason: "bundle contains no subjects".to_string(),
        });
    }

    let signer_identity = nono::trust::extract_signer_identity(&bundle, bundle_path)?;
    enforce_namespace_assertion(package_ref, &signer_identity)?;

    let mut downloads = Vec::with_capacity(pull.artifacts.len());

    for artifact in &pull.artifacts {
        let path = tempdir.path().join(&artifact.filename);
        let digest = client.download_artifact_to_path(&artifact.download_url, &path)?;
        if digest != artifact.sha256_digest {
            return Err(NonoError::PackageVerification {
                package: package_ref.key(),
                reason: format!(
                    "artifact {} digest mismatch: registry={}, local={}",
                    artifact.filename, artifact.sha256_digest, digest
                ),
            });
        }

        // Verify this artifact's digest is a subject in the bundle
        if !subject_digests.contains_key(digest.as_str()) {
            return Err(NonoError::PackageVerification {
                package: package_ref.key(),
                reason: format!(
                    "artifact {} digest not found in bundle subjects",
                    artifact.filename
                ),
            });
        }

        let bytes = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if let Some(p) = printer {
            p.finished(&artifact.filename, bytes);
        }

        downloads.push(DownloadedArtifact {
            filename: artifact.filename.clone(),
            path,
            sha256_digest: digest,
        });
    }

    Ok(VerifiedDownloads {
        _tempdir: tempdir,
        bundle_json,
        signer_identity,
        artifacts: downloads,
    })
}

fn load_manifest(downloads: &[DownloadedArtifact]) -> Result<PackageManifest> {
    let manifest = downloads
        .iter()
        .find(|artifact| artifact.filename == "package.json")
        .ok_or_else(|| NonoError::PackageInstall("package is missing package.json".to_string()))?;

    let bytes = fs::read(&manifest.path).map_err(NonoError::Io)?;
    serde_json::from_slice::<PackageManifest>(&bytes).map_err(|e| {
        NonoError::PackageInstall(format!("failed to parse package.json manifest: {e}"))
    })
}

fn validate_manifest(manifest: &PackageManifest) -> Result<()> {
    if !manifest.platforms.is_empty()
        && !manifest
            .platforms
            .iter()
            .any(|platform| platform == current_platform())
    {
        return Err(NonoError::PackageInstall(format!(
            "package does not support {}",
            current_platform()
        )));
    }

    if let Some(min_version) = &manifest.min_nono_version
        && compare_versions(env!("CARGO_PKG_VERSION"), min_version)?.is_lt()
    {
        return Err(NonoError::PackageInstall(format!(
            "package requires nono >= {}, current version is {}",
            min_version,
            env!("CARGO_PKG_VERSION")
        )));
    }

    Ok(())
}

fn install_package(
    package_ref: &PackageRef,
    manifest: &PackageManifest,
    downloads: &VerifiedDownloads,
    init: bool,
    force: bool,
    pack_owned_files: &HashMap<PathBuf, String>,
) -> Result<InstallSummary> {
    let staging_parent = package::package_store_dir()?
        .join(".staging")
        .join(&package_ref.namespace);
    fs::create_dir_all(&staging_parent).map_err(NonoError::Io)?;
    let tempdir = TempDir::new_in(&staging_parent).map_err(NonoError::Io)?;
    let staging_root = tempdir.path().join(&package_ref.name);
    fs::create_dir_all(&staging_root).map_err(NonoError::Io)?;

    let mut downloaded_by_name: HashMap<&str, &DownloadedArtifact> =
        HashMap::with_capacity(downloads.artifacts.len());
    for artifact in &downloads.artifacts {
        downloaded_by_name.insert(artifact.filename.as_str(), artifact);
    }

    validate_manifest_install_paths(manifest)?;
    write_supporting_artifacts(&staging_root, manifest, downloads)?;

    let mut copied_to_project = 0usize;
    for artifact in &manifest.artifacts {
        let downloaded = downloaded_by_name
            .get(artifact.path.as_str())
            .ok_or_else(|| {
                NonoError::PackageInstall(format!(
                    "manifest references missing artifact '{}'",
                    artifact.path
                ))
            })?;
        install_manifest_artifact(&staging_root, artifact, &downloaded.path)?;
        if init
            && artifact.artifact_type == ArtifactType::Instruction
            && artifact.placement.as_deref() == Some("project")
        {
            copy_instruction_to_project(artifact, &downloaded.path)?;
            copied_to_project = copied_to_project.saturating_add(1);
        }
    }

    let final_root = package::package_install_dir(&package_ref.namespace, &package_ref.name)?;
    if let Some(parent) = final_root.parent() {
        fs::create_dir_all(parent).map_err(NonoError::Io)?;
    }
    if final_root.exists() {
        fs::remove_dir_all(&final_root).map_err(NonoError::Io)?;
    }
    fs::rename(&staging_root, &final_root).map_err(NonoError::Io)?;
    tempdir.close().map_err(NonoError::Io)?;

    // Run the pack's declarative wiring directives. The CLI knows
    // nothing about specific agents (Claude Code, Codex, …); it just
    // executes the closed vocabulary the pack supplies as data. The
    // returned records go into the lockfile so `nono remove` can
    // reverse them deterministically.
    let wiring_record = if manifest.wiring.is_empty() {
        Vec::new()
    } else {
        let ctx = crate::wiring::WiringContext {
            pack_dir: final_root.clone(),
            namespace: package_ref.namespace.clone(),
            pack_name: package_ref.name.clone(),
        };
        let report = if force {
            crate::wiring::execute_with_options(
                &manifest.wiring,
                &ctx,
                pack_owned_files,
                crate::wiring::ExecuteOptions {
                    allow_unmanaged_identical_write_files: true,
                },
            )?
        } else {
            crate::wiring::execute(&manifest.wiring, &ctx, pack_owned_files)?
        };
        for conflict in &report.conflicts {
            eprintln!("  warning: {conflict}");
        }
        report.records
    };

    Ok(InstallSummary {
        installed_artifacts: manifest.artifacts.len(),
        copied_to_project,
        wiring_record,
    })
}

fn write_supporting_artifacts(
    staging_root: &Path,
    manifest: &PackageManifest,
    downloads: &VerifiedDownloads,
) -> Result<()> {
    for artifact in &downloads.artifacts {
        if artifact.filename == "package.json" {
            let path = staging_root.join("package.json");
            copy_path(&artifact.path, &path)?;
        }
    }

    let downloaded_by_name = downloads
        .artifacts
        .iter()
        .map(|artifact| (artifact.filename.as_str(), artifact))
        .collect::<HashMap<_, _>>();

    // Write per-artifact bundles into a single JSON array at the pack root
    let bundle =
        serde_json::from_str::<serde_json::Value>(&downloads.bundle_json).map_err(|e| {
            NonoError::PackageInstall(format!("failed to parse trust bundle from registry: {e}"))
        })?;
    let mut bundles: Vec<serde_json::Value> = Vec::new();
    if let Some(package_json) = downloaded_by_name.get("package.json") {
        bundles.push(serde_json::json!({
            "artifact": package_json.filename,
            "installed_path": "package.json",
            "digest": package_json.sha256_digest,
            "bundle": bundle.clone()
        }));
    }
    for artifact in &manifest.artifacts {
        let downloaded = downloaded_by_name
            .get(artifact.path.as_str())
            .ok_or_else(|| {
                NonoError::PackageInstall(format!(
                    "manifest references missing artifact '{}'",
                    artifact.path
                ))
            })?;
        let installed_path = installed_artifact_relative_path(artifact)?;
        bundles.push(serde_json::json!({
            "artifact": downloaded.filename,
            "installed_path": installed_path,
            "digest": downloaded.sha256_digest,
            "bundle": bundle.clone()
        }));
    }

    if !bundles.is_empty() {
        let bundle_path = staging_root.join(".nono-trust.bundle");
        let json = serde_json::to_string_pretty(&bundles).map_err(|e| {
            NonoError::PackageInstall(format!("failed to serialize trust bundle: {e}"))
        })?;
        fs::write(&bundle_path, json).map_err(NonoError::Io)?;
    }

    Ok(())
}

/// Install an artifact into the package staging directory based on its
/// declared type. All artifacts land inside the pack store; the wiring
/// interpreter (run after install) is responsible for any agent-facing
/// placement (symlinks, JSON merges, TOML blocks).
fn install_manifest_artifact(
    staging_root: &Path,
    artifact: &ArtifactEntry,
    source_path: &Path,
) -> Result<()> {
    let relative_path = installed_artifact_relative_path(artifact)?;
    let path = staging_root.join(&relative_path);
    match artifact.artifact_type {
        ArtifactType::Profile => {
            copy_path(source_path, &path)?;
            parse_json::<crate::profile::Profile>(&path)?;
        }
        ArtifactType::Instruction => {
            copy_path(source_path, &path)?;
        }
        ArtifactType::TrustPolicy => {
            copy_path(source_path, &path)?;
            let content = fs::read_to_string(&path).map_err(NonoError::Io)?;
            nono::trust::load_policy_from_str(&content)?;
        }
        ArtifactType::Groups => {
            let prefix = artifact.prefix.as_deref().ok_or_else(|| {
                NonoError::PackageInstall(format!(
                    "groups artifact '{}' is missing prefix",
                    artifact.path
                ))
            })?;
            copy_path(source_path, &path)?;
            let bytes = fs::read(&path).map_err(NonoError::Io)?;
            validate_groups(&bytes, prefix)?;
        }
        ArtifactType::Plugin => {
            copy_path(source_path, &path)?;
            if artifact.path.contains("/bin/") || artifact.path.ends_with(".sh") {
                ensure_executable(&path)?;
            }
        }
    }

    Ok(())
}

fn copy_instruction_to_project(artifact: &ArtifactEntry, source_path: &Path) -> Result<()> {
    let cwd = std::env::current_dir().map_err(NonoError::Io)?;
    let path = cwd.join(file_name(&artifact.path)?);
    if path.exists() {
        return Ok(());
    }
    copy_path(source_path, &path)
}

fn validate_groups(bytes: &[u8], prefix: &str) -> Result<()> {
    let groups: HashMap<String, crate::policy::Group> = serde_json::from_slice(bytes)
        .map_err(|e| NonoError::PackageInstall(format!("failed to parse groups.json: {e}")))?;
    let embedded = crate::policy::load_policy(crate::config::embedded::embedded_policy_json())?;

    for name in groups.keys() {
        if !name.starts_with(prefix) {
            return Err(NonoError::PackageInstall(format!(
                "group '{}' does not start with required prefix '{}'",
                name, prefix
            )));
        }
        if embedded.groups.contains_key(name) {
            return Err(NonoError::PackageInstall(format!(
                "group '{}' collides with an embedded policy group",
                name
            )));
        }
    }

    Ok(())
}

fn update_lockfile(
    package_ref: &PackageRef,
    registry_url: &str,
    pull: &PullResponse,
    signer_identity: &str,
    manifest: &PackageManifest,
    downloads: &[DownloadedArtifact],
    wiring_record: &[crate::wiring::WiringRecord],
) -> Result<()> {
    let mut lockfile = package::read_lockfile()?;
    lockfile.lockfile_version = package::LOCKFILE_VERSION;
    lockfile.registry = registry_url.to_string();

    let was_pinned = lockfile
        .packages
        .get(&package_ref.key())
        .map(|p| p.pinned)
        .unwrap_or(false);

    let downloaded_by_name = downloads
        .iter()
        .map(|artifact| (artifact.filename.as_str(), artifact))
        .collect::<HashMap<_, _>>();
    let mut artifacts = BTreeMap::new();
    for artifact in &manifest.artifacts {
        let downloaded = downloaded_by_name
            .get(artifact.path.as_str())
            .ok_or_else(|| {
                NonoError::PackageInstall(format!(
                    "manifest references missing artifact '{}'",
                    artifact.path
                ))
            })?;
        let installed_path = installed_artifact_relative_path(artifact)?;
        if artifacts
            .insert(
                installed_path.clone(),
                LockedArtifact {
                    sha256: downloaded.sha256_digest.clone(),
                    artifact_type: artifact.artifact_type.clone(),
                },
            )
            .is_some()
        {
            return Err(NonoError::PackageInstall(format!(
                "multiple artifacts install to the same path '{}' (conflict at '{}')",
                installed_path, artifact.path
            )));
        }
    }

    lockfile.packages.insert(
        package_ref.key(),
        LockedPackage {
            version: pull.version.clone(),
            installed_at: Utc::now().to_rfc3339(),
            pinned: was_pinned,
            provenance: Some(PackageProvenance {
                signer_identity: signer_identity.to_string(),
                repository: pull.provenance.repository.clone(),
                workflow: pull.provenance.workflow.clone(),
                git_ref: pull.provenance.git_ref.clone(),
                rekor_log_index: pull.provenance.rekor_log_index.unwrap_or_default() as u64,
                signed_at: pull
                    .provenance
                    .signed_at
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_else(|| Utc::now().to_rfc3339()),
            }),
            artifacts,
            wiring_record: wiring_record.to_vec(),
        },
    );

    package::write_lockfile(&lockfile)
}

fn validate_manifest_install_paths(manifest: &PackageManifest) -> Result<()> {
    let mut installed_paths = HashSet::with_capacity(manifest.artifacts.len());
    for artifact in &manifest.artifacts {
        let installed_path = installed_artifact_relative_path(artifact)?;
        if !installed_paths.insert(installed_path.clone()) {
            return Err(NonoError::PackageInstall(format!(
                "multiple artifacts install to the same path '{}' (conflict at '{}')",
                installed_path, artifact.path
            )));
        }
    }
    Ok(())
}

fn enforce_namespace_assertion(
    package_ref: &PackageRef,
    signer_identity: &SignerIdentity,
) -> Result<()> {
    match signer_identity {
        SignerIdentity::Keyless { repository, .. } => {
            let signer_namespace = repository.split('/').next().unwrap_or_default();
            if signer_namespace != package_ref.namespace {
                return Err(NonoError::PackageVerification {
                    package: package_ref.key(),
                    reason: format!(
                        "signer namespace '{}' does not match requested namespace '{}'",
                        signer_namespace, package_ref.namespace
                    ),
                });
            }
            Ok(())
        }
        SignerIdentity::Keyed { .. } => Err(NonoError::PackageVerification {
            package: package_ref.key(),
            reason: "registry packages must use keyless Sigstore signing".to_string(),
        }),
    }
}

fn enforce_signer_pinning(
    existing: Option<&LockedPackage>,
    signer_identity: &str,
    force: bool,
) -> Result<()> {
    if force {
        return Ok(());
    }

    if let Some(existing) = existing
        && let Some(provenance) = &existing.provenance
        && canonical_signer_identity(&provenance.signer_identity)
            != canonical_signer_identity(signer_identity)
    {
        return Err(NonoError::PackageVerification {
            package: provenance.repository.clone(),
            reason: format!(
                "signer identity changed from '{}' to '{}'",
                provenance.signer_identity, signer_identity
            ),
        });
    }

    Ok(())
}

/// Strip the per-release `@<git_ref>` suffix from a keyless signer identity
/// so version updates aren't misread as publisher changes. Pinning is meant
/// to detect a change in repo or workflow file, not the tag/branch that
/// triggered each release. Keyed identities (no `@`) pass through unchanged.
fn canonical_signer_identity(uri: &str) -> &str {
    uri.rsplit_once('@')
        .map(|(prefix, _)| prefix)
        .unwrap_or(uri)
}
fn signer_identity_uri(identity: &SignerIdentity) -> Result<String> {
    match identity {
        SignerIdentity::Keyless {
            repository,
            workflow,
            git_ref,
            ..
        } => Ok(format!(
            "https://github.com/{repository}/{workflow}@{git_ref}"
        )),
        SignerIdentity::Keyed { key_id } => Ok(format!("keyed:{key_id}")),
    }
}

fn parse_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let content = fs::read_to_string(path).map_err(NonoError::Io)?;
    serde_json::from_str(&content)
        .map_err(|e| NonoError::PackageInstall(format!("failed to parse {}: {e}", path.display())))
}

fn copy_path(source: &Path, dest: &Path) -> Result<()> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(NonoError::Io)?;
    }
    fs::copy(source, dest).map_err(NonoError::Io)?;
    Ok(())
}

fn ensure_executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path).map_err(NonoError::Io)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).map_err(NonoError::Io)?;
    }

    Ok(())
}

fn file_name(path: &str) -> Result<&str> {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| NonoError::PackageInstall(format!("invalid artifact path '{}'", path)))
}

fn installed_artifact_relative_path(artifact: &ArtifactEntry) -> Result<String> {
    let path = match artifact.artifact_type {
        ArtifactType::Profile => {
            let install_name = artifact.install_as.as_deref().ok_or_else(|| {
                NonoError::PackageInstall(format!(
                    "profile artifact '{}' is missing install_as",
                    artifact.path
                ))
            })?;
            validate_safe_name(install_name, "install_as")?;
            format!("profiles/{install_name}.json")
        }
        ArtifactType::Instruction => {
            validate_relative_path(&artifact.path)?;
            format!("instructions/{}", file_name(&artifact.path)?)
        }
        ArtifactType::TrustPolicy => "trust-policy.json".to_string(),
        ArtifactType::Groups => "groups.json".to_string(),
        ArtifactType::Plugin => {
            validate_relative_path(&artifact.path)?;
            artifact.path.clone()
        }
    };
    if path == "package.json" || path == ".nono-trust.bundle" {
        return Err(NonoError::PackageInstall(format!(
            "artifact '{}' attempts to overwrite reserved file '{}'",
            artifact.path, path
        )));
    }
    Ok(path)
}

fn validate_safe_name(name: &str, field: &str) -> Result<()> {
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name == "."
        || name == ".."
        || name.contains("..")
    {
        return Err(NonoError::PackageInstall(format!(
            "{field} contains unsafe path component: '{name}'"
        )));
    }
    Ok(())
}

fn validate_relative_path(path: &str) -> Result<()> {
    let p = Path::new(path);
    if p.is_absolute() {
        return Err(NonoError::PackageInstall(format!(
            "artifact path must be relative, got '{path}'"
        )));
    }
    for component in p.components() {
        match component {
            std::path::Component::ParentDir => {
                return Err(NonoError::PackageInstall(format!(
                    "artifact path contains '..': '{path}'"
                )));
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                return Err(NonoError::PackageInstall(format!(
                    "artifact path must be relative, got '{path}'"
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

fn current_platform() -> &'static str {
    crate::platform::current_os_name()
}

fn compare_versions(left: &str, right: &str) -> Result<Ordering> {
    let left = parse_version(left, "current nono version")?;
    let right = parse_version(right, "min_nono_version")?;
    Ok(left.cmp(&right))
}

fn parse_version(value: &str, field: &str) -> Result<Version> {
    let normalized = value.trim().strip_prefix('v').unwrap_or(value.trim());
    Version::parse(normalized)
        .map_err(|error| NonoError::PackageInstall(format!("invalid {field} '{value}': {error}")))
}

fn format_timestamp(value: &str) -> String {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| {
            dt.with_timezone(&Local)
                .format("%Y-%m-%d %H:%M")
                .to_string()
        })
        .unwrap_or_else(|_| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compare_versions_honors_prerelease_ordering() {
        let prerelease_vs_stable = compare_versions("1.0.0-alpha.1", "1.0.0")
            .unwrap_or_else(|err| panic!("version compare failed: {err}"));
        let stable_vs_prerelease = compare_versions("1.0.0", "1.0.0-alpha.1")
            .unwrap_or_else(|err| panic!("version compare failed: {err}"));

        assert_eq!(prerelease_vs_stable, Ordering::Less);
        assert_eq!(stable_vs_prerelease, Ordering::Greater);
    }
}
