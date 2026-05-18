//! Pack manifest, lockfile, and local store helpers.
//!
//! # Upstream registry-pack format awareness (v0.44.0, manual-replay of 24d8b924)
//!
//! In upstream nono v0.44.0 (commit `24d8b924`, "feat(profile, migration): move codex,
//! claude-code to registry pack"), the upstream project migrated the `claude-code` and
//! `claude-no-kc` profiles from `data/policy.json` builtins into a separate "registry
//! pack" distribution shape (`always-further/*`). That commit also introduced four
//! upstream-only files implementing a `wiring` abstraction (SHA-256-keyed install
//! records, `WriteFile` / `JsonMerge` / `JsonArrayAppend` directives, lockfile v3+v4
//! with strict overwrite policy):
//!   - `crates/nono-cli/src/wiring.rs`     (~1102 lines)
//!   - `crates/nono-cli/src/migration.rs`  (~337 lines)
//!   - `crates/nono-cli/src/pull_ui.rs`    (~260 lines)
//!   - `crates/nono-cli/src/legacy_cleanup.rs` (~573 lines, added by 5654b0f9)
//!
//! The fork does NOT carry that structural rewrite. Per Phase 33's DIVERGENCE-LEDGER.md
//! cluster C6 "fork-preserve" disposition and the upstream-sync-quick.md catalog entries
//! "Hooks subsystem ownership" + "validate_path_within retention", the fork retains:
//!   - `crates/nono-cli/src/hooks.rs` as the sole centralized hook installer (Phase 22-03 PKG-03)
//!   - `crates/nono-cli/data/policy.json` claude-code + codex builtins (Phase 18.1-03 dependency)
//!   - 9 `validate_path_within(...)` defense-in-depth callsites in `package_cmd.rs`
//!     (Phase 22-03 PKG-04 + Phase 26-01 PKGS-02)
//!   - Phase 18.1-03 Windows widening wiring (`cfg(target_os = "windows")` arms in `package_cmd.rs`)
//!   - `ArtifactType::Plugin` variant (Phase 26-01 PKGS-02)
//!
//! Plan 34-09 (Manual-replay: 24d8b924) acknowledges upstream's registry-pack shape but
//! does NOT port the structural rewrite. The fork's existing `ArtifactType`, `PackageManifest`,
//! `Lockfile`, and `ArtifactEntry` types are sufficient for Phase 34 needs; the upstream
//! `wiring.rs` abstraction is deferred to a future plan (post-Phase-34) if/when the fork
//! needs idempotent JSON-merge install records. See the Plan 34-09 SUMMARY for the full
//! per-commit disposition table and the catalog-driven preservation rationale.

use crate::profile;
use chrono::Utc;
use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const LOCKFILE_VERSION: u32 = 1;

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
    #[serde(default = "default_pack_type")]
    pub pack_type: PackType,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackType {
    Agent,
    Policy,
}

impl PackType {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Agent => "agent pack",
            Self::Policy => "policy pack",
        }
    }
}

fn default_pack_type() -> PackType {
    PackType::Agent
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactEntry {
    #[serde(rename = "type")]
    pub artifact_type: ArtifactType,
    pub path: String,
    #[serde(default)]
    pub install_as: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub install_dir: Option<String>,
    #[serde(default)]
    pub placement: Option<String>,
    #[serde(default)]
    pub merge_strategy: Option<String>,
    #[serde(default)]
    pub prefix: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    Profile,
    Hook,
    Instruction,
    TrustPolicy,
    Groups,
    Script,
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
    /// External path where this artifact was installed (outside the package store).
    /// Used by `nono remove` to clean up files placed via `install_dir`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed_path: Option<String>,
}

impl Default for LockedPackage {
    fn default() -> Self {
        Self {
            version: String::new(),
            installed_at: Utc::now().to_rfc3339(),
            pinned: false,
            provenance: None,
            artifacts: BTreeMap::new(),
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

/// Response from registry `/api/v1/packages/{ns}/{name}/status` endpoint.
/// Phase 36.5 D-36.5-C3 (package_status.rs companion port).
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
    pub namespace: String,
    pub name: String,
    /// One of: `"current"`, `"outdated"`, `"yanked"`, or `None` (unknown).
    #[serde(default)]
    pub installed_status: Option<String>,
    #[serde(default)]
    pub latest_version: Option<String>,
    #[serde(default)]
    pub yanked_reason: Option<String>,
    #[serde(default)]
    pub replacement_version: Option<String>,
    #[serde(default)]
    pub advisory: Option<PackageAdvisory>,
}

/// Security advisory attached to a `PackageStatusResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageAdvisory {
    /// Severity classification (e.g., `"high"`, `"medium"`, `"low"`).
    pub severity: String,
    /// Short operator-facing summary of the advisory.
    pub summary: String,
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

pub fn profiles_dir() -> Result<PathBuf> {
    Ok(nono_config_dir()?.join("profiles"))
}

/// Returns the cross-platform path to the profile-drafts directory
/// (sibling of `profiles/`). Resolves to `%APPDATA%\nono\profile-drafts\`
/// on Windows, `~/.config/nono/profile-drafts/` on Linux/macOS (honors
/// `XDG_CONFIG_HOME`). Reuses `nono_config_dir()` so no duplicate env-var
/// surface. Phase 36.5 D-36.5-B1.
///
/// Callers MUST validate the profile name with `profile::is_valid_profile_name`
/// before constructing per-name paths inside this directory.
#[must_use = "directory path should be used or stored"]
pub fn profile_drafts_dir() -> Result<PathBuf> {
    Ok(nono_config_dir()?.join("profile-drafts"))
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

    serde_json::from_str(&content)
        .map_err(|e| NonoError::ConfigParse(format!("failed to parse {}: {e}", path.display())))
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

pub fn profile_link_path(profile_name: &str) -> Result<PathBuf> {
    Ok(profiles_dir()?.join(format!("{profile_name}.json")))
}

pub fn is_profile_symlink_into_package_store(profile_name: &str) -> Option<PathBuf> {
    let link_path = profile_link_path(profile_name).ok()?;
    if !link_path.exists() {
        return None;
    }

    let target = fs::canonicalize(&link_path).ok()?;
    let store = fs::canonicalize(package_store_dir().ok()?).ok()?;
    if target.starts_with(&store) {
        target.parent().map(Path::to_path_buf)
    } else {
        None
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------------
    // profile_drafts_dir tests (Phase 36.5 D-36.5-B1)
    // ---------------------------------------------------------------------------

    #[test]
    fn profile_drafts_dir_resolves_under_config_dir() {
        let dir = profile_drafts_dir().expect("profile_drafts_dir must succeed");
        // The last component must be "profile-drafts"
        assert_eq!(
            dir.file_name().and_then(|n| n.to_str()),
            Some("profile-drafts"),
            "profile_drafts_dir must end in 'profile-drafts', got: {}",
            dir.display()
        );
        // The parent must be the nono config dir component
        let parent_name = dir
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str());
        assert_eq!(
            parent_name,
            Some("nono"),
            "profile-drafts parent must be 'nono', got: {:?}",
            parent_name
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn profile_drafts_dir_windows_appdata() {
        use crate::test_env::{lock_env, EnvVarGuard};
        let _lock = lock_env();
        let tmp = tempfile::TempDir::new().expect("create temp dir");
        let _guard = EnvVarGuard::set_all(&[("APPDATA", tmp.path().to_str().expect("utf8 path"))]);
        let dir = profile_drafts_dir().expect("profile_drafts_dir must succeed");
        // Canonicalize tmp.path() to handle Windows \\?\ prefix added by resolve_user_config_dir
        let canonical_tmp = tmp
            .path()
            .canonicalize()
            .unwrap_or_else(|_| tmp.path().to_path_buf());
        assert!(
            dir.starts_with(&canonical_tmp),
            "profile_drafts_dir must resolve under APPDATA tempdir (canonical: {}), got: {}",
            canonical_tmp.display(),
            dir.display()
        );
        assert_eq!(
            dir.file_name().and_then(|n| n.to_str()),
            Some("profile-drafts")
        );
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn profile_drafts_dir_unix_xdg_override() {
        use crate::test_env::{lock_env, EnvVarGuard};
        let _lock = lock_env();
        let tmp = tempfile::TempDir::new().expect("create temp dir");
        let _guard =
            EnvVarGuard::set_all(&[("XDG_CONFIG_HOME", tmp.path().to_str().expect("utf8 path"))]);
        let dir = profile_drafts_dir().expect("profile_drafts_dir must succeed");
        assert!(
            dir.starts_with(tmp.path()),
            "profile_drafts_dir must resolve under XDG_CONFIG_HOME tempdir, got: {}",
            dir.display()
        );
        assert_eq!(
            dir.file_name().and_then(|n| n.to_str()),
            Some("profile-drafts")
        );
    }

    // ---------------------------------------------------------------------------
    // Existing tests
    // ---------------------------------------------------------------------------

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

    #[test]
    fn artifact_type_plugin_round_trips() {
        // REQ-PKGS-03 truth #8: ArtifactType::Plugin serializes as "plugin"
        // (lowercase) and round-trips. The #[serde(rename_all = "snake_case")]
        // attribute handles the shape automatically.
        let json = serde_json::to_string(&ArtifactType::Plugin).expect("serialize");
        assert_eq!(json, "\"plugin\"");
        let parsed: ArtifactType = serde_json::from_str("\"plugin\"").expect("deserialize");
        assert_eq!(parsed, ArtifactType::Plugin);
    }

    #[test]
    fn artifact_type_unknown_fails_closed() {
        // REQ-PKGS-03 truth #9: Unknown artifact_type values fail-closed.
        // Schema-rejection on the JSON deserializer (NOT the filename-based
        // fallback at package_cmd.rs:967-972, which is a different code path
        // operating on filenames not on user-supplied JSON).
        let bad: std::result::Result<ArtifactType, _> = serde_json::from_str("\"made_up_variant\"");
        assert!(bad.is_err());
        let bad2: std::result::Result<ArtifactType, _> = serde_json::from_str("\"PLUGIN\"");
        assert!(bad2.is_err()); // case-sensitive — uppercase is not "plugin"
        let bad3: std::result::Result<ArtifactType, _> = serde_json::from_str("42");
        assert!(bad3.is_err()); // non-string fails
        let bad4: std::result::Result<ArtifactType, _> =
            serde_json::from_str("\"nonexistent-variant\"");
        assert!(bad4.is_err()); // hyphenated variant rejected (snake_case enforced)
    }

    // ---------------------------------------------------------------------------
    // PackageStatusResponse / PackageAdvisory tests (Phase 36.5 C3-02)
    // ---------------------------------------------------------------------------

    #[test]
    fn package_status_response_serde_roundtrip() {
        let status = PackageStatusResponse {
            namespace: "nono-official".into(),
            name: "claude".into(),
            installed_status: Some("yanked".into()),
            latest_version: Some("v1.2".into()),
            yanked_reason: Some("CVE-2026-1234".into()),
            replacement_version: Some("v1.3".into()),
            advisory: Some(PackageAdvisory {
                severity: "high".into(),
                summary: "Remote code execution via crafted profile".into(),
            }),
        };
        let json = serde_json::to_string(&status).expect("serialize");
        let parsed: PackageStatusResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.namespace, status.namespace);
        assert_eq!(parsed.name, status.name);
        assert_eq!(parsed.installed_status, status.installed_status);
        assert_eq!(parsed.latest_version, status.latest_version);
        assert_eq!(parsed.yanked_reason, status.yanked_reason);
        assert_eq!(parsed.replacement_version, status.replacement_version);
        let adv = parsed.advisory.expect("advisory must round-trip");
        assert_eq!(adv.severity, "high");
        assert_eq!(adv.summary, "Remote code execution via crafted profile");
    }

    #[test]
    fn package_status_response_partial_deserialize() {
        // Minimal JSON with all optional fields set to null
        let json = r#"{"namespace":"x","name":"y","installed_status":null,"latest_version":null,"yanked_reason":null,"replacement_version":null,"advisory":null}"#;
        let parsed: PackageStatusResponse = serde_json::from_str(json).expect("deserialize");
        assert_eq!(parsed.namespace, "x");
        assert_eq!(parsed.name, "y");
        assert!(parsed.installed_status.is_none());
        assert!(parsed.advisory.is_none());
    }
}
