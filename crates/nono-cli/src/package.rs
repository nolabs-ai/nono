//! Pack manifest, lockfile, and local store helpers.

use crate::profile;
use crate::wiring::{WiringDirective, WiringRecord};
use chrono::Utc;
use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

/// Bumped to 4 with the second-pass security-review changes:
/// WriteFile re-pulls now verify the on-disk hash before overwriting
/// (no clobber of user edits); re-pulls reverse the prior wiring
/// record set before applying the new one (so prior_value always
/// tracks the user's original, not a previous pack-written value);
/// JsonArrayAppend records the installed entry so reverse can leave
/// user-edited entries alone. Bumped to 3 with the first-pass review
/// (schema for prior values + parent tracking + failure surface).
/// Bumped to 2 with the move from agent-specific wiring code to
/// declarative directives. No back-compat — reading an older
/// lockfile fails the parse, the user re-pulls.
pub const LOCKFILE_VERSION: u32 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageRef {
    pub namespace: String,
    pub name: String,
    pub version: Option<String>,
}

impl PackageRef {
    #[must_use]
    pub fn key(&self) -> String {
        format!("{}/{}", self.namespace, self.name)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageManifest {
    pub schema_version: u32,
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub platforms: Vec<String>,
    #[serde(default)]
    pub min_nono_version: Option<String>,
    #[serde(default)]
    pub artifacts: Vec<ArtifactEntry>,
    /// Declarative install-time wiring. Executed by
    /// `crate::wiring::execute` after artifacts are staged into the
    /// pack store. Vocabulary is a closed set of agent-agnostic
    /// directives — see `wiring::WiringDirective` for the full list.
    /// Empty for packs that only ship a profile + files (no
    /// agent-specific install steps).
    #[serde(default)]
    pub wiring: Vec<WiringDirective>,
}

impl PackageManifest {
    /// True if this manifest declares at least one Profile artifact —
    /// i.e. the pack is usable with `--profile`.
    #[must_use]
    pub fn has_profile_artifact(&self) -> bool {
        self.artifacts
            .iter()
            .any(|a| a.artifact_type == ArtifactType::Profile)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactEntry {
    #[serde(rename = "type")]
    pub artifact_type: ArtifactType,
    pub path: String,
    #[serde(default)]
    pub install_as: Option<String>,
    #[serde(default)]
    pub placement: Option<String>,
    #[serde(default)]
    pub prefix: Option<String>,
    /// Additional names that resolve to this same artifact. Currently
    /// only meaningful for `Profile` artifacts: each alias is accepted
    /// by `--profile` and routes to the file installed under
    /// `install_as`. Lets a pack rename its canonical profile name
    /// (e.g. `claude-code` → `claude`) without breaking commands users
    /// already have in their shell history. The pack only stores the
    /// content once — aliases never produce extra files on disk.
    #[serde(default)]
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    Profile,
    Instruction,
    TrustPolicy,
    Groups,
    Plugin,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Lockfile {
    pub lockfile_version: u32,
    #[serde(default)]
    pub registry: String,
    #[serde(default)]
    pub packages: BTreeMap<String, LockedPackage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockedPackage {
    pub version: String,
    pub installed_at: String,
    #[serde(default)]
    pub pinned: bool,
    #[serde(default)]
    pub provenance: Option<PackageProvenance>,
    #[serde(default)]
    pub artifacts: BTreeMap<String, LockedArtifact>,
    /// What the wiring interpreter actually did at install time.
    /// `nono remove` replays this list in reverse to undo the
    /// install — the original directive list isn't re-evaluated, so
    /// removal works even if the pack has been re-published or
    /// removed from the registry between install and uninstall.
    #[serde(default)]
    pub wiring_record: Vec<WiringRecord>,
    /// True when the pack was installed via `nono sideload` rather than pulled
    /// from the registry. Sideloaded packs have no attestation, no bundle, and
    /// no registry provenance. They are skipped by `nono update` / `nono
    /// outdated` and their files are used as-is at runtime without signature
    /// verification.
    ///
    /// Defense-in-depth: `read_lockfile` hard-errors on any entry with
    /// `sideload: true` when the binary was compiled without the `sideload`
    /// feature, so production binaries never silently accept unverified packs.
    ///
    /// Omitted from JSON output when `false` to avoid bloating the lockfile for
    /// the common (registry-installed) case.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub sideload: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageProvenance {
    pub signer_identity: String,
    pub repository: String,
    pub workflow: String,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub rekor_log_index: u64,
    pub signed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockedArtifact {
    pub sha256: String,
    #[serde(rename = "type")]
    pub artifact_type: ArtifactType,
}

impl Default for LockedPackage {
    fn default() -> Self {
        Self {
            version: String::new(),
            installed_at: Utc::now().to_rfc3339(),
            pinned: false,
            provenance: None,
            artifacts: BTreeMap::new(),
            wiring_record: Vec::new(),
            sideload: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageSearchResult {
    pub namespace: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub latest_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageSearchResponse {
    pub packages: Vec<PackageSearchResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YankedErrorResponse {
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub yanked: bool,
    #[serde(default)]
    pub yank_reason: Option<String>,
    #[serde(default)]
    pub advisory: Option<PackageAdvisory>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageStatusResponse {
    pub schema_version: u32,
    #[serde(default)]
    pub latest: Option<String>,
    #[serde(default)]
    pub installed_status: Option<String>,
    #[serde(default)]
    pub yank_reason: Option<String>,
    #[serde(default)]
    pub advisory: Option<PackageAdvisory>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageAdvisory {
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
}

/// One pack that ships a given profile name (the `install_as` of a
/// profile artifact in its manifest). Returned by
/// `GET /api/v1/profiles/<name>/providers`. Used by the migration
/// prompt to discover which pack to offer when a user runs
/// `--profile <formerly-builtin-name>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileProvider {
    pub namespace: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    /// Short user-visible summary of what the pack installs. Renders
    /// in the migration prompt's "Installs" row.
    #[serde(default)]
    pub installs_summary: Option<String>,
}

impl ProfileProvider {
    #[must_use]
    pub fn pack_ref(&self) -> String {
        format!("{}/{}", self.namespace, self.name)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileProvidersResponse {
    pub providers: Vec<ProfileProvider>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullResponse {
    pub namespace: String,
    pub name: String,
    pub version: String,
    pub provenance: PullProvenance,
    pub artifacts: Vec<PullArtifact>,
    pub bundle_url: String,
    pub scan_passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullProvenance {
    pub signer_identity: String,
    pub repository: String,
    pub workflow: String,
    pub git_ref: String,
    #[serde(default)]
    pub rekor_log_index: Option<i64>,
    #[serde(default)]
    pub signed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullArtifact {
    pub filename: String,
    pub sha256_digest: String,
    pub size_bytes: i64,
    pub download_url: String,
}

pub fn parse_package_ref(input: &str) -> Result<PackageRef> {
    let (path_part, version) = match input.split_once('@') {
        Some((path, version)) if !version.is_empty() => (path, Some(version.to_string())),
        Some((_path, _)) => {
            return Err(NonoError::PackageInstall(format!(
                "invalid package reference '{input}': version must not be empty"
            )));
        }
        None => (input, None),
    };

    let mut parts = path_part.split('/');
    let namespace = parts.next().unwrap_or_default();
    let name = parts.next().unwrap_or_default();

    if namespace.is_empty() || name.is_empty() || parts.next().is_some() {
        return Err(NonoError::PackageInstall(format!(
            "invalid package reference '{input}': expected <namespace>/<name>[@<version>]"
        )));
    }

    validate_package_component("namespace", namespace)?;
    validate_package_component("name", name)?;

    Ok(PackageRef {
        namespace: namespace.to_string(),
        name: name.to_string(),
        version,
    })
}

fn validate_package_component(label: &str, value: &str) -> Result<()> {
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        Ok(())
    } else {
        Err(NonoError::PackageInstall(format!(
            "invalid package {label} '{value}': only alphanumeric, '-', '_' and '.' are allowed"
        )))
    }
}

pub fn nono_config_dir() -> Result<PathBuf> {
    Ok(profile::resolve_user_config_dir()?.join("nono"))
}

pub fn package_store_dir() -> Result<PathBuf> {
    Ok(nono_config_dir()?.join("packages"))
}

pub fn package_install_dir(namespace: &str, name: &str) -> Result<PathBuf> {
    Ok(package_store_dir()?.join(namespace).join(name))
}

pub fn package_groups_path(namespace: &str, name: &str) -> Result<PathBuf> {
    Ok(package_install_dir(namespace, name)?.join("groups.json"))
}

pub fn lockfile_path() -> Result<PathBuf> {
    Ok(package_store_dir()?.join("lockfile.json"))
}

pub fn read_lockfile() -> Result<Lockfile> {
    let path = lockfile_path()?;
    if !path.exists() {
        return Ok(Lockfile::default());
    }

    let content = fs::read_to_string(&path).map_err(|e| NonoError::ConfigRead {
        path: path.clone(),
        source: e,
    })?;

    let lockfile: Lockfile = serde_json::from_str(&content)
        .map_err(|e| NonoError::ConfigParse(format!("failed to parse {}: {e}", path.display())))?;

    // Defense-in-depth: reject sideloaded packs on production binaries.
    // A production binary compiled without `--features sideload` must never
    // silently accept packs that bypassed attestation and signature checks.
    #[cfg(not(feature = "sideload"))]
    {
        let sideloaded: Vec<&str> = lockfile
            .packages
            .iter()
            .filter(|(_, pkg)| pkg.sideload)
            .map(|(key, _)| key.as_str())
            .collect();
        if !sideloaded.is_empty() {
            let names = sideloaded.join(", ");
            return Err(NonoError::PackageInstall(format!(
                "lockfile contains sideloaded pack(s) [{names}]; remove with `nono remove <pack>`."
            )));
        }
    }

    Ok(lockfile)
}

pub fn write_lockfile(lockfile: &Lockfile) -> Result<()> {
    let path = lockfile_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(NonoError::Io)?;
    }

    let tmp_path = path.with_extension("json.tmp");
    let json = serde_json::to_string_pretty(lockfile)
        .map_err(|e| NonoError::ConfigParse(format!("failed to serialize lockfile: {e}")))?;
    fs::write(&tmp_path, format!("{json}\n")).map_err(NonoError::Io)?;
    fs::rename(&tmp_path, &path).map_err(NonoError::Io)?;
    Ok(())
}

pub fn remove_package_from_lockfile(package_ref: &PackageRef) -> Result<bool> {
    let mut lockfile = read_lockfile()?;
    let removed = lockfile.packages.remove(&package_ref.key()).is_some();
    if removed {
        if lockfile.lockfile_version == 0 {
            lockfile.lockfile_version = LOCKFILE_VERSION;
        }
        write_lockfile(&lockfile)?;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_package_ref_with_version() {
        let parsed = parse_package_ref("acme/claude-code@1.2.3").expect("parse");
        assert_eq!(parsed.namespace, "acme");
        assert_eq!(parsed.name, "claude-code");
        assert_eq!(parsed.version.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn rejects_invalid_package_ref() {
        let err = parse_package_ref("broken").expect_err("must fail");
        assert!(err.to_string().contains("expected <namespace>/<name>"));
    }
}
