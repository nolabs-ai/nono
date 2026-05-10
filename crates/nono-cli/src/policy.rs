//! Group-based policy resolver
//!
//! Parses `policy.json` and resolves named groups into `CapabilitySet` entries
//! and platform-specific rules using composable, platform-aware groups.

use crate::package;
use crate::profile;
use nono::{AccessMode, CapabilitySet, CapabilitySource, FsCapability, NonoError, Result};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

// ============================================================================
// JSON schema types
// ============================================================================

/// Root policy file structure
#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    #[allow(dead_code)]
    pub meta: PolicyMeta,
    pub groups: HashMap<String, Group>,
    /// Built-in profile definitions
    #[serde(default)]
    pub profiles: HashMap<String, ProfileDef>,
}

/// Policy metadata
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyMeta {
    #[allow(dead_code)]
    pub version: u64,
    #[allow(dead_code)]
    pub schema_version: String,
}

/// A named group of rules
#[derive(Debug, Clone, Deserialize)]
pub struct Group {
    #[allow(dead_code)]
    pub description: String,
    /// If set, this group only applies on the specified platform
    #[serde(default)]
    pub platform: Option<String>,
    /// If true, this group cannot be removed via group exclusions
    #[serde(default)]
    pub required: bool,
    /// Allow operations
    #[serde(default)]
    pub allow: Option<AllowOps>,
    /// Deny operations
    #[serde(default)]
    pub deny: Option<DenyOps>,
    /// macOS symlink path pairs (symlink -> real target)
    #[serde(default)]
    pub symlink_pairs: Option<HashMap<String, String>>,
}

/// Allow operations nested under `allow`
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AllowOps {
    /// Paths granted read access
    #[serde(default)]
    pub read: Vec<String>,
    /// Paths granted write-only access
    #[serde(default)]
    pub write: Vec<String>,
    /// Paths granted read+write access
    #[serde(default)]
    pub readwrite: Vec<String>,
}

/// Deny operations nested under `deny`
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DenyOps {
    /// Paths denied all content access (read+write; metadata still allowed)
    #[serde(default)]
    pub access: Vec<String>,
    /// Block file deletion globally
    #[serde(default)]
    pub unlink: bool,
    /// Override unlink denial for user-writable paths
    #[serde(default)]
    pub unlink_override_for_user_writable: bool,
    /// Commands to block
    #[serde(default)]
    pub commands: Vec<String>,
}

/// Profile definition as stored in `policy.json`.
///
/// Mirrors the canonical `profile::Profile` schema introduced by #594. All
/// embedded profiles in `policy.json` use canonical sections
/// (`groups.include`, `commands.allow/deny`, `filesystem.*`, narrow
/// `security`); legacy keys have been migrated out of the data file, so this
/// struct no longer carries the draining shim that earlier revisions used.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ProfileDef {
    #[serde(default)]
    pub extends: Option<String>,
    #[serde(default)]
    pub meta: profile::ProfileMeta,
    #[serde(default)]
    pub security: profile::SecurityConfig,
    #[serde(default)]
    pub groups: profile::GroupsConfig,
    #[serde(default)]
    pub commands: profile::CommandsConfig,
    #[serde(default)]
    pub filesystem: profile::FilesystemConfig,
    #[serde(default)]
    pub network: profile::NetworkConfig,
    /// ALIAS(canonical="env_credentials", introduced="v0.0.0", remove_by="indefinite", issue="#143")
    #[serde(default, alias = "secrets")]
    pub env_credentials: profile::SecretsConfig,
    #[serde(default)]
    pub workdir: profile::WorkdirConfig,
    #[serde(default)]
    pub hooks: profile::HooksConfig,
    /// ALIAS(canonical="rollback", introduced="v0.0.0", remove_by="indefinite", issue="#124")
    #[serde(default, alias = "undo")]
    pub rollback: profile::RollbackConfig,
    #[serde(default)]
    pub open_urls: Option<profile::OpenUrlConfig>,
    #[serde(default)]
    pub allow_launch_services: Option<bool>,
    #[serde(default)]
    pub allow_gpu: Option<bool>,
    #[serde(default)]
    pub interactive: bool,
    #[serde(default)]
    pub packs: Vec<String>,
    #[serde(default)]
    pub command_args: Vec<String>,
    #[serde(default)]
    pub unsafe_macos_seatbelt_rules: Vec<String>,
}

impl ProfileDef {
    /// Convert to a raw Profile without merging implicit default groups.
    ///
    /// Straight field-for-field copy; no legacy draining happens here because
    /// the embedded `policy.json` is already on the canonical #594 schema.
    pub fn to_raw_profile(&self) -> profile::Profile {
        profile::Profile {
            extends: self.extends.as_ref().map(|s| vec![s.clone()]),
            meta: self.meta.clone(),
            security: self.security.clone(),
            groups: self.groups.clone(),
            commands: self.commands.clone(),
            filesystem: self.filesystem.clone(),
            network: self.network.clone(),
            env_credentials: self.env_credentials.clone(),
            environment: None,
            workdir: self.workdir.clone(),
            hooks: self.hooks.clone(),
            rollback: self.rollback.clone(),
            open_urls: self.open_urls.clone(),
            allow_launch_services: self.allow_launch_services,
            allow_gpu: self.allow_gpu,
            allow_parent_of_protected: None,
            interactive: self.interactive,
            skipdirs: Vec::new(),
            packs: self.packs.clone(),
            command_args: self.command_args.clone(),
            unsafe_macos_seatbelt_rules: self.unsafe_macos_seatbelt_rules.clone(),
        }
    }
}

// ============================================================================
// Platform detection
// ============================================================================

/// Current platform identifier
pub(crate) fn current_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "unknown"
    }
}

/// Check if a group applies to the current platform
pub(crate) fn group_matches_platform(group: &Group) -> bool {
    match &group.platform {
        Some(platform) => platform == current_platform(),
        None => true, // No platform restriction = applies everywhere
    }
}

// ============================================================================
// Path expansion
// ============================================================================

/// Expand `~` to $HOME and `$TMPDIR` to the environment variable value.
///
/// Returns an error if HOME or TMPDIR are set to non-absolute paths.
pub(crate) fn expand_path(path_str: &str) -> Result<PathBuf> {
    use crate::config;

    let expanded = if let Some(rest) = path_str.strip_prefix("~/") {
        let home = config::validated_home()?;
        format!("{}/{}", home, rest)
    } else if path_str == "~" || path_str == "$HOME" {
        config::validated_home()?
    } else if let Some(rest) = path_str.strip_prefix("$HOME/") {
        let home = config::validated_home()?;
        format!("{}/{}", home, rest)
    } else if path_str == "$TMPDIR" {
        config::validated_tmpdir()?
    } else if let Some(rest) = path_str.strip_prefix("$TMPDIR/") {
        let tmpdir = config::validated_tmpdir()?;
        format!("{}/{}", tmpdir, rest)
    } else {
        path_str.to_string()
    };

    Ok(PathBuf::from(expanded))
}

/// Check whether a path resides inside the Nix store (`/nix/store`).
///
/// The Nix store is immutable by design — its contents are content-addressed
/// and read-only. On NixOS with home-manager, shell config files such as
/// `~/.zshrc` are often symlinks into `/nix/store/...`. Because these paths
/// cannot be modified at runtime, deny rules targeting them for secret
/// protection are unnecessary.
fn is_nix_store_path(path: &Path) -> bool {
    path.starts_with("/nix/store")
}

/// Decide whether a resolved (canonical) deny target should be skipped.
///
/// On Linux, symlink targets inside `/nix/store` are immutable and cannot
/// hold runtime secrets, so adding them to the deny list is both unnecessary
/// and harmful (causes Landlock deny-overlap errors when `/nix/store` is
/// allowed by the `nix_runtime` group). The original symlink path is still
/// denied, so the security posture is unchanged for non-Nix environments.
///
/// On macOS this always returns `false` — Seatbelt handles deny-within-allow
/// natively, and the canonical form is needed for correct kernel matching.
fn should_skip_resolved_deny_target(resolved: &Path) -> bool {
    cfg!(target_os = "linux") && is_nix_store_path(resolved)
}

/// Convert a PathBuf to a UTF-8 string, returning an error for non-UTF-8 paths.
///
/// Non-UTF-8 paths would produce incorrect Seatbelt rules via lossy conversion,
/// potentially targeting the wrong path in deny rules.
pub(crate) fn path_to_utf8(path: &Path) -> Result<&str> {
    path.to_str().ok_or_else(|| {
        NonoError::ConfigParse(format!("Path contains non-UTF-8 bytes: {}", path.display()))
    })
}

/// Escape a path for Seatbelt profile strings.
///
/// Paths are placed inside double-quoted S-expression strings where `\` and `"`
/// are the significant characters. Control characters are rejected (not stripped)
/// to match the library's escape_path behavior — silently stripping could cause
/// deny rules to target wrong paths.
pub(crate) fn escape_seatbelt_path(path: &str) -> Result<String> {
    let mut result = String::with_capacity(path.len());
    for c in path.chars() {
        if c.is_control() {
            return Err(NonoError::ConfigParse(format!(
                "Path contains control character: {:?}",
                path
            )));
        }
        match c {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            _ => result.push(c),
        }
    }
    Ok(result)
}

fn escape_seatbelt_regex_path(path: &str) -> Result<String> {
    let mut out = String::with_capacity(path.len() + 8);
    for c in path.chars() {
        if c.is_control() {
            return Err(NonoError::ConfigParse(format!(
                "Path contains control character: {:?}",
                path
            )));
        }
        match c {
            '.' | '+' | '*' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '^' | '$' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '"' => out.push_str("\\\""),
            _ => out.push(c),
        }
    }
    Ok(out)
}

// ============================================================================
// Group resolution
// ============================================================================

/// Load policy from JSON string
pub fn load_policy(json: &str) -> Result<Policy> {
    serde_json::from_str(json)
        .map_err(|e| NonoError::ConfigParse(format!("Failed to parse policy.json: {}", e)))
}

/// Result of resolving policy groups
pub struct ResolvedGroups {
    /// Names of groups that were resolved (platform-matching only)
    pub names: Vec<String>,
    /// Whether unlink overrides should be applied after all paths are finalized.
    /// This is deferred because the caller may add more writable paths (e.g., from
    /// the profile's [filesystem] section or CLI flags) after group resolution.
    pub needs_unlink_overrides: bool,
    /// Expanded deny.access paths for post-resolution validation.
    /// On macOS these also generate platform_rules; on Linux they're
    /// validation-only since Landlock has no deny semantics.
    pub deny_paths: Vec<PathBuf>,
}

/// Resolve a list of group names into capability set entries and platform rules.
///
/// For each group:
/// - `allow.read` paths become `FsCapability` with `AccessMode::Read`
/// - `allow.write` paths become `FsCapability` with `AccessMode::Write`
/// - `allow.readwrite` paths become `FsCapability` with `AccessMode::ReadWrite`
/// - `deny.access` paths become platform rules (deny read data + deny write)
/// - `deny.unlink` becomes a platform rule
/// - `deny.commands` are added to the blocked commands list
/// - `symlink_pairs` become platform rules for non-canonical paths
///
/// Groups with a `platform` field that doesn't match the current OS are skipped.
/// Non-existent allow paths are skipped with a warning.
/// Non-existent deny paths still generate rules (defensive).
///
/// **Important**: If `resolved.needs_unlink_overrides` is true, the caller MUST call
/// `apply_unlink_overrides(caps)` after all writable paths have been added to the
/// capability set (including profile [filesystem] and CLI overrides).
pub fn resolve_groups(
    policy: &Policy,
    group_names: &[String],
    caps: &mut CapabilitySet,
) -> Result<ResolvedGroups> {
    let mut resolved_groups = Vec::new();
    let mut needs_unlink_overrides = false;
    let mut deny_paths = Vec::new();

    for name in group_names {
        let group = policy
            .groups
            .get(name.as_str())
            .ok_or_else(|| NonoError::ConfigParse(format!("Unknown policy group: '{}'", name)))?;

        if !group_matches_platform(group) {
            debug!(
                "Skipping group '{}' (platform {:?} != {})",
                name,
                group.platform,
                current_platform()
            );
            continue;
        }

        if resolve_single_group(name, group, caps, &mut deny_paths)? {
            needs_unlink_overrides = true;
        }
        resolved_groups.push(name.clone());
    }

    Ok(ResolvedGroups {
        names: resolved_groups,
        needs_unlink_overrides,
        deny_paths,
    })
}

/// Resolve a single group into capability set entries.
/// Returns true if unlink overrides were requested (to be deferred).
fn resolve_single_group(
    group_name: &str,
    group: &Group,
    caps: &mut CapabilitySet,
    deny_paths: &mut Vec<PathBuf>,
) -> Result<bool> {
    let source = CapabilitySource::Group(group_name.to_string());
    let mut needs_unlink_overrides = false;

    // Process allow operations
    if let Some(allow) = &group.allow {
        for path_str in &allow.read {
            add_fs_capability(group_name, path_str, AccessMode::Read, &source, caps)?;
        }
        for path_str in &allow.write {
            add_fs_capability(group_name, path_str, AccessMode::Write, &source, caps)?;
        }
        for path_str in &allow.readwrite {
            add_fs_capability(group_name, path_str, AccessMode::ReadWrite, &source, caps)?;
        }
    }

    // Process deny operations
    if let Some(deny) = &group.deny {
        for path_str in &deny.access {
            add_deny_access_rules(path_str, caps, deny_paths)?;
        }

        // Seatbelt-only: global unlink denial. Landlock handles file/directory
        // deletion via AccessFs flags in access_to_landlock() (RemoveFile + RemoveDir).
        if deny.unlink && cfg!(target_os = "macos") {
            caps.add_platform_rule("(deny file-write-unlink)")?;
        }

        if deny.unlink_override_for_user_writable {
            // Deferred: caller must call apply_unlink_overrides() after all writable
            // paths are finalized (profile [filesystem] + CLI overrides).
            needs_unlink_overrides = true;
        }

        for cmd in &deny.commands {
            caps.add_blocked_command(cmd.clone());
        }
    }

    // Process symlink pairs (Seatbelt-only: macOS symlink → target path handling)
    if cfg!(target_os = "macos") {
        if let Some(pairs) = &group.symlink_pairs {
            for symlink in pairs.keys() {
                let expanded = expand_path(symlink)?;
                let escaped = escape_seatbelt_path(path_to_utf8(&expanded)?)?;
                caps.add_platform_rule(format!("(allow file-read* (subpath \"{}\"))", escaped))?;
            }
        }
    }

    Ok(needs_unlink_overrides)
}

fn canonicalize_for_comparison(path: &Path) -> PathBuf {
    match path.canonicalize() {
        Ok(canonical) => canonical,
        Err(_) => path.to_path_buf(),
    }
}

/// Skip implicit Linux temp-root grants that would cover HOME.
///
/// Landlock cannot enforce deny paths beneath an allowed parent. When HOME is
/// nested under `/tmp` or `$TMPDIR`, the broad system temp grants from
/// `system_write_linux` would silently disable default deny rules such as
/// `~/.aws` and `~/.bash_history`. In that environment, fail secure by dropping
/// the broad system grant and requiring explicit user/profile grants instead.
fn should_skip_group_allow_path(group_name: &str, path: &Path) -> Result<bool> {
    if !cfg!(target_os = "linux") || group_name != "system_write_linux" || !path.is_dir() {
        return Ok(false);
    }

    let home = PathBuf::from(crate::config::validated_home()?);
    let home_raw_overlaps = home.starts_with(path);
    let home_canonical = canonicalize_for_comparison(&home);
    let path_canonical = canonicalize_for_comparison(path);
    let home_canonical_overlaps = home_canonical.starts_with(&path_canonical);

    if !home_raw_overlaps && !home_canonical_overlaps {
        return Ok(false);
    }

    warn!(
        "Skipping Linux system temp grant '{}' from group '{}' because HOME '{}' is nested \
         inside it. Landlock cannot enforce deny rules beneath an allowed parent.",
        path.display(),
        group_name,
        home.display()
    );
    Ok(true)
}

/// Add a filesystem capability from a group path, handling expansion and existence checks
fn add_fs_capability(
    group_name: &str,
    path_str: &str,
    mode: AccessMode,
    source: &CapabilitySource,
    caps: &mut CapabilitySet,
) -> Result<()> {
    let path = expand_path(path_str)?;

    if !path.exists() {
        debug!(
            "Group path '{}' (expanded to '{}') does not exist, skipping",
            path_str,
            path.display()
        );
        return Ok(());
    }

    if should_skip_group_allow_path(group_name, &path)? {
        return Ok(());
    }

    if path.is_dir() {
        match FsCapability::new_dir(&path, mode) {
            Ok(mut cap) => {
                cap.source = source.clone();
                caps.add_fs(cap);
            }
            Err(e) => {
                debug!("Could not add group directory {}: {}", path_str, e);
            }
        }
    } else {
        // Accepts regular files, character devices (/dev/urandom, /dev/null, etc.),
        // symlinks, and other non-directory paths — matching FsCapability::new_file()
        // which rejects only directories.
        match FsCapability::new_file(&path, mode) {
            Ok(mut cap) => {
                cap.source = source.clone();
                caps.add_fs(cap);
            }
            Err(e) => {
                debug!("Could not add group file {}: {}", path_str, e);
            }
        }
    }

    Ok(())
}

/// Resolve symlinks in parent directories when the leaf path does not exist.
///
/// `path.canonicalize()` fails when the leaf is absent (e.g. a socket that
/// hasn't been created yet). This helper walks upward until it finds an
/// existing ancestor, canonicalizes it, then re-appends the non-existent
/// suffix components. Returns `Ok(None)` when no symlinks are found in
/// parents (resolved path equals the original).
///
/// Example on macOS:
/// - requested path: `/var/run/future.sock`
/// - `/future.sock` doesn't exist, but `/var/run` does
/// - `/var/run` canonicalizes to `/private/var/run`
/// - result: `Some("/private/var/run/future.sock")`
fn resolve_parent_symlinks(path: &Path) -> Result<Option<PathBuf>> {
    let mut suffix = Vec::new();
    let mut cur = path;

    loop {
        if cur.exists() {
            break;
        }
        let name = cur.file_name().ok_or_else(|| {
            NonoError::ConfigParse(format!(
                "cannot resolve parent symlinks for {}",
                path.display()
            ))
        })?;
        suffix.push(name.to_os_string());
        cur = cur.parent().ok_or_else(|| {
            NonoError::ConfigParse(format!(
                "cannot resolve parent symlinks for {}",
                path.display()
            ))
        })?;
    }

    let mut resolved = cur
        .canonicalize()
        .map_err(|e| NonoError::ConfigParse(format!("canonicalize {}: {}", cur.display(), e)))?;
    for part in suffix.iter().rev() {
        resolved.push(part);
    }

    Ok((resolved != path).then_some(resolved))
}

/// Add deny.access rules, collecting the expanded path for validation.
///
/// On macOS, generates Seatbelt platform rules:
/// - `(allow file-read-metadata ...)` — programs can stat/check existence
/// - `(deny file-read-data ...)` — deny reading content
/// - `(deny file-write* ...)` — deny writing
/// - `(deny network-outbound (path ...))` — blocks Unix socket connections
///
/// On Linux, deny paths are collected for overlap validation only —
/// Landlock has no deny semantics so platform rules would be ignored.
///
/// Uses `subpath` for directories, `literal` for files.
/// For non-existent paths, defaults to `subpath` (defensive).
///
/// Both the original and the kernel-resolved (canonical) path receive deny
/// rules so Seatbelt matches regardless of which form the kernel sees.
/// When the leaf does not yet exist (e.g. a future socket), parent symlinks
/// are resolved via `resolve_parent_symlinks` so the derived canonical path
/// is also covered.
pub(crate) fn add_deny_access_rules(
    path_str: &str,
    caps: &mut CapabilitySet,
    deny_paths: &mut Vec<PathBuf>,
) -> Result<()> {
    let path = expand_path(path_str)?;
    deny_paths.push(path.clone());

    // Canonicalize to resolve symlinks anywhere in the path (the deny target
    // itself, or any parent directory such as /var -> /private/var on macOS).
    // Seatbelt operates on kernel-resolved paths, so deny rules must use
    // the canonical form. We also keep the original to cover both forms.
    let canonical = path.canonicalize().ok();
    if let Some(ref canonical) = canonical {
        if *canonical != path {
            if should_skip_resolved_deny_target(canonical) {
                debug!(
                    "Skipping deny canonical path '{}' (Nix store immutable symlink target of '{}')",
                    canonical.display(),
                    path.display(),
                );
            } else {
                deny_paths.push(canonical.clone());
            }
        }
    }

    // When the full path doesn't exist yet (canonicalize failed), resolve
    // symlinks in parent directories so the derived canonical path is still
    // covered — important for sockets that are created after sandbox_init.
    let parent_resolved = if canonical.is_none() {
        match resolve_parent_symlinks(&path) {
            Ok(resolved) => resolved,
            Err(e) => {
                debug!(
                    "Skipping parent-symlink resolution for {}: {}",
                    path.display(),
                    e
                );
                None
            }
        }
    } else {
        None
    };
    if let Some(ref resolved) = parent_resolved {
        deny_paths.push(resolved.clone());
    }

    // Seatbelt deny rules only apply on macOS
    if cfg!(target_os = "macos") {
        // Helper: emit metadata-allow + read-deny + write-deny + network-deny for a single path
        let emit_deny_rules = |p: &Path, caps: &mut CapabilitySet| -> Result<()> {
            let escaped = escape_seatbelt_path(path_to_utf8(p)?)?;
            let filter = if p.exists() && p.is_file() {
                format!("literal \"{}\"", escaped)
            } else {
                format!("subpath \"{}\"", escaped)
            };
            caps.add_platform_rule(format!("(allow file-read-metadata ({}))", filter))?;
            caps.add_platform_rule(format!("(deny file-read-data ({}))", filter))?;
            caps.add_platform_rule(format!("(deny file-write* ({}))", filter))?;
            // SECURITY: connect(2) on a Unix domain socket is enforced by Seatbelt as
            // network-outbound, not as a file operation. File deny rules above have no
            // effect on socket connections. Emit an exact-path network-outbound deny so
            // that connecting to this path (e.g. a Docker daemon socket) is blocked even
            // if the socket is created after the sandbox is applied. This rule is
            // evaluated at syscall time, not at sandbox_init time, so it covers sockets
            // that do not yet exist. For non-socket paths the rule is a harmless no-op.
            // Use (path ...) not (subpath ...) — socket connections match on the exact
            // path, not a prefix. Both symlink and canonical paths are covered because
            // emit_deny_rules is called for each form by the caller.
            caps.add_platform_rule(format!("(deny network-outbound (path \"{}\"))", escaped))?;
            Ok(())
        };

        // Emit deny rules for the original path
        emit_deny_rules(&path, caps)?;

        // Emit deny rules for the canonical path too (covers parent symlinks on existing paths)
        if let Some(ref canonical) = canonical {
            if *canonical != path {
                if let Err(e) = emit_deny_rules(canonical, caps) {
                    warn!(
                        "Skipping canonical deny rules for {}: {}",
                        canonical.display(),
                        e
                    );
                }
            }
        }

        // Emit deny rules for the parent-resolved path (covers non-existent paths
        // whose parents contain symlinks, e.g. /var/run/future.sock -> /private/var/run/future.sock)
        if let Some(ref resolved) = parent_resolved {
            if let Err(e) = emit_deny_rules(resolved, caps) {
                warn!(
                    "Skipping parent-resolved deny rules for {}: {}",
                    resolved.display(),
                    e
                );
            }
        }
    }

    Ok(())
}

/// Add a narrow macOS exception for explicit keychain DB file grants.
///
/// This keeps broad keychain deny groups active while allowing only the exact
/// file capability intended by a profile or CLI flag, plus the backing
/// SQLite/WAL/SHM files the Security framework actually touches under
/// `~/Library/Keychains/<UUID>/...`.
pub fn apply_macos_keychain_db_exception(caps: &mut CapabilitySet) {
    if !cfg!(target_os = "macos") {
        return;
    }

    let user_keychain_dbs = std::env::var("HOME").ok().map(|home| {
        [
            Path::new(&home).join("Library/Keychains/login.keychain-db"),
            Path::new(&home).join("Library/Keychains/metadata.keychain-db"),
        ]
    });
    let system_keychain_dbs = [
        Path::new("/Library/Keychains/login.keychain-db").to_path_buf(),
        Path::new("/Library/Keychains/metadata.keychain-db").to_path_buf(),
    ];

    let is_keychain_db = |path: &Path| -> bool {
        if system_keychain_dbs
            .iter()
            .any(|candidate| path == candidate)
        {
            return true;
        }
        if let Some(ref user_keychain_dbs) = user_keychain_dbs {
            if user_keychain_dbs.iter().any(|candidate| path == candidate) {
                return true;
            }
        }
        false
    };

    let merge_access = |existing: &mut AccessMode, next: AccessMode| {
        *existing = match (*existing, next) {
            (AccessMode::ReadWrite, _) | (_, AccessMode::ReadWrite) => AccessMode::ReadWrite,
            (AccessMode::Read, AccessMode::Write) | (AccessMode::Write, AccessMode::Read) => {
                AccessMode::ReadWrite
            }
            (mode, _) => mode,
        };
    };

    let mut explicit_paths: HashMap<PathBuf, AccessMode> = HashMap::new();
    let mut keychain_roots: HashMap<PathBuf, AccessMode> = HashMap::new();

    for cap in caps.fs_capabilities().iter().filter(|cap| cap.is_file) {
        if !is_keychain_db(&cap.resolved) {
            continue;
        }

        explicit_paths
            .entry(cap.resolved.clone())
            .and_modify(|mode| merge_access(mode, cap.access))
            .or_insert(cap.access);

        if let Some(root) = cap.resolved.parent() {
            keychain_roots
                .entry(root.to_path_buf())
                .and_modify(|mode| merge_access(mode, cap.access))
                .or_insert(cap.access);
        }
    }

    let mut allow_rules = Vec::new();

    for (path, access) in explicit_paths {
        let path_str = match path_to_utf8(&path) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    "Skipping keychain DB exception for {}: {}",
                    path.display(),
                    e
                );
                continue;
            }
        };
        let escaped = match escape_seatbelt_path(path_str) {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    "Skipping keychain DB exception for {}: {}",
                    path.display(),
                    e
                );
                continue;
            }
        };
        let filter = format!("literal \"{}\"", escaped);
        // Emit specific ops (file-read-data, file-write-data) in addition to the
        // wildcards. In Apple's Seatbelt evaluator, a wildcard-op allow does not
        // override an earlier specific-op deny on an overlapping path (the broad
        // `deny_keychains_macos` group emits `(deny file-read-data (subpath ...))`).
        // Emitting the specific op with a literal path ensures the override wins.
        match access {
            AccessMode::Read => {
                allow_rules.push(format!("(allow file-read-data ({}))", filter));
                allow_rules.push(format!("(allow file-read* ({}))", filter));
            }
            AccessMode::Write => {
                allow_rules.push(format!("(allow file-write-data ({}))", filter));
                allow_rules.push(format!("(allow file-write* ({}))", filter));
            }
            AccessMode::ReadWrite => {
                allow_rules.push(format!("(allow file-read-data ({}))", filter));
                allow_rules.push(format!("(allow file-read* ({}))", filter));
                allow_rules.push(format!("(allow file-write-data ({}))", filter));
                allow_rules.push(format!("(allow file-write* ({}))", filter));
            }
        }
    }

    for (root, access) in keychain_roots {
        let root_str = match path_to_utf8(&root) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    "Skipping keychain runtime exception for {}: {}",
                    root.display(),
                    e
                );
                continue;
            }
        };
        let escaped_root = match escape_seatbelt_regex_path(root_str) {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    "Skipping keychain runtime exception for {}: {}",
                    root.display(),
                    e
                );
                continue;
            }
        };
        let filters = [
            format!(r#"regex #"^{}/\.fl[0-9A-Fa-f]+$""#, escaped_root),
            format!(
                r#"regex #"^{}/[^/]+/(?:[^/]+\.db(?:-(?:wal|shm))?|user\.kb)$""#,
                escaped_root
            ),
        ];

        // See comment above: emit specific ops alongside wildcards so they override
        // the specific-op denies from deny_keychains_macos.
        for filter in filters {
            match access {
                AccessMode::Read => {
                    allow_rules.push(format!("(allow file-read-data ({}))", filter));
                    allow_rules.push(format!("(allow file-read* ({}))", filter));
                }
                AccessMode::Write => {
                    allow_rules.push(format!("(allow file-write-data ({}))", filter));
                    allow_rules.push(format!("(allow file-write* ({}))", filter));
                }
                AccessMode::ReadWrite => {
                    allow_rules.push(format!("(allow file-read-data ({}))", filter));
                    allow_rules.push(format!("(allow file-read* ({}))", filter));
                    allow_rules.push(format!("(allow file-write-data ({}))", filter));
                    allow_rules.push(format!("(allow file-write* ({}))", filter));
                }
            }
        }
    }

    allow_rules.sort_unstable();

    for rule in allow_rules {
        if let Err(e) = caps.add_platform_rule(rule) {
            warn!("Failed to add keychain DB exception rule: {}", e);
        }
    }
}

/// Apply deny overrides for specific paths, punching targeted holes through deny groups.
///
/// For each override path:
/// 1. Expands `~`
/// 2. On macOS: emits Seatbelt allow rules more specific than the deny rules
/// 3. Removes the path from `deny_paths` so Linux `validate_deny_overlaps` passes
/// 4. Warns to stderr for each override applied (security relaxation must be visible)
///
/// The override path must also be explicitly granted via `--allow`, `--read`, or `--write`.
/// `--bypass-protection` only removes the deny; it does not implicitly grant access.
pub fn apply_deny_overrides(
    overrides: &[std::path::PathBuf],
    deny_paths: &mut Vec<PathBuf>,
    caps: &mut CapabilitySet,
) -> Result<()> {
    if overrides.is_empty() {
        return Ok(());
    }

    for override_path in overrides {
        // Expand ~ in the override path
        let path_str = override_path.to_str().ok_or_else(|| {
            NonoError::ConfigParse(format!(
                "Override path contains non-UTF-8 bytes: {}",
                override_path.display()
            ))
        })?;
        let expanded = expand_path(path_str)?;

        // Canonicalize if the path exists, otherwise use the expanded form
        let canonical = if expanded.exists() {
            expanded.canonicalize().map_err(|e| {
                NonoError::ConfigParse(format!(
                    "Failed to canonicalize override path {}: {}",
                    expanded.display(),
                    e
                ))
            })?
        } else {
            expanded.clone()
        };

        // Verify the override path is actually granted via explicit user intent
        // (CLI flags or profile filesystem/policy config), not just covered by a
        // system or group grant. Without this, a deny override under /tmp would
        // silently pass because system_write_macos grants /var/folders, creating
        // an unintended permission grant.
        //
        // Compute the union of access modes across ALL matching user-intent grants.
        // This runs before deduplicate() which merges complementary Read + Write
        // grants into ReadWrite, so we must aggregate here to avoid emitting
        // Seatbelt allow rules for only the first grant's access mode.
        let mut grant_has_read = false;
        let mut grant_has_write = false;
        for cap in caps.fs_capabilities() {
            if !cap.source.is_user_intent() {
                continue;
            }
            let covers = if cap.is_file {
                cap.resolved == canonical
            } else {
                canonical.starts_with(&cap.resolved)
            };
            if covers {
                match cap.access {
                    AccessMode::Read => grant_has_read = true,
                    AccessMode::Write => grant_has_write = true,
                    AccessMode::ReadWrite => {
                        grant_has_read = true;
                        grant_has_write = true;
                    }
                }
            }
        }
        if !grant_has_read && !grant_has_write {
            return Err(NonoError::SandboxInit(format!(
                "bypass_protection '{}' has no matching grant. \
                 Add a filesystem allow (--allow, --read, --write, or profile filesystem) \
                 for this path.",
                override_path.display(),
            )));
        }

        // Warn about the security relaxation
        info!(
            "bypass_protection relaxing deny rule for '{}'",
            canonical.display()
        );

        // On macOS: emit Seatbelt allow rules to punch through deny.
        // Only emit rules matching the effective access mode from the union
        // of all covering grants to preserve least-privilege.
        if cfg!(target_os = "macos") {
            // Emit allow rules for both the canonical path and the original
            // expanded path (if it differs, e.g. symlink). This mirrors
            // add_deny_access_rules which denies both the symlink and target.
            let mut override_paths = vec![canonical.clone()];
            if expanded != canonical {
                override_paths.push(expanded.clone());
            }

            for op in &override_paths {
                let path_utf8 = path_to_utf8(op)?;
                let escaped = escape_seatbelt_path(path_utf8)?;

                let filter = if op.exists() && op.is_file() {
                    format!("literal \"{}\"", escaped)
                } else {
                    format!("subpath \"{}\"", escaped)
                };

                if grant_has_read {
                    caps.add_platform_rule(format!("(allow file-read-data ({}))", filter))?;
                }
                if grant_has_write {
                    caps.add_platform_rule(format!("(allow file-write* ({}))", filter))?;
                }
            }
        }

        // Remove deny entries that the override covers (equal or child of the override path).
        // Check both the canonical and expanded (symlink) forms so that deny entries
        // recorded for either the symlink or its target are removed.
        // Do NOT remove broader deny entries when the override is a child — e.g.,
        // overriding ~/.aws must not remove a deny on the entire home directory.
        deny_paths.retain(|dp| !dp.starts_with(&canonical) && !dp.starts_with(&expanded));
    }

    Ok(())
}

/// Apply unlink override rules for all writable paths in the capability set.
///
/// This allows file deletion in paths that have Write or ReadWrite access,
/// counteracting a global `(deny file-write-unlink)` rule.
///
/// Seatbelt-only: Landlock handles file deletion via `AccessFs` flags in
/// `access_to_landlock()` and has no equivalent deny-then-allow mechanism.
///
/// **Must be called after all paths are finalized** (groups + profile + CLI overrides).
pub fn apply_unlink_overrides(caps: &mut CapabilitySet) {
    if cfg!(target_os = "linux") {
        return; // Unlink overrides are Seatbelt-specific
    }

    let mut unlink_rules = Vec::new();

    for cap in caps
        .fs_capabilities()
        .iter()
        .filter(|cap| matches!(cap.access, AccessMode::Write | AccessMode::ReadWrite))
    {
        for path in [&cap.original, &cap.resolved] {
            let path_str = match path_to_utf8(path) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("Skipping unlink override for {}: {}", path.display(), e);
                    continue;
                }
            };
            let escaped = match escape_seatbelt_path(path_str) {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!("Skipping unlink override for {}: {}", path.display(), e);
                    continue;
                }
            };
            let filter = if cap.is_file {
                format!("literal \"{}\"", escaped)
            } else {
                format!("subpath \"{}\"", escaped)
            };
            unlink_rules.push(format!("(allow file-write-unlink ({}))", filter));
        }
    }

    unlink_rules.sort_unstable();
    unlink_rules.dedup();

    for rule in unlink_rules {
        if let Err(e) = caps.add_platform_rule(rule) {
            tracing::warn!("Skipping unlink override rule: {}", e);
        }
    }
}

/// Resolve deny.access paths for a group list without mutating caller capabilities.
#[cfg(test)]
pub fn resolve_deny_paths_for_groups(
    policy: &Policy,
    group_names: &[String],
) -> Result<Vec<PathBuf>> {
    let mut tmp_caps = CapabilitySet::new();
    let resolved = resolve_groups(policy, group_names, &mut tmp_caps)?;
    Ok(resolved.deny_paths)
}

/// Check for deny paths that overlap with allowed paths on Linux.
///
/// Landlock is strictly allow-list and cannot deny a child of an allowed parent.
/// On Linux, overlap between `deny.access` and allowed parent paths is a hard error
/// because the deny rule would silently have no effect.
///
/// On macOS this is a no-op (Seatbelt handles deny-within-allow natively).
///
/// **Must be called after all paths are finalized** (groups + profile + CLI overrides + CWD).
pub fn validate_deny_overlaps(deny_paths: &[PathBuf], caps: &CapabilitySet) -> Result<()> {
    if cfg!(target_os = "macos") {
        return Ok(());
    }

    let mut fatal_conflicts = Vec::new();

    for deny_path in deny_paths {
        for cap in caps.fs_capabilities() {
            if cap.is_file {
                continue; // File caps can't cover a directory subtree
            }
            // Check if deny path is a child of an allowed directory
            if deny_path.starts_with(&cap.resolved) && *deny_path != cap.resolved {
                let conflict = format!(
                    "deny '{}' overlaps allowed parent '{}' (source: {})",
                    deny_path.display(),
                    cap.resolved.display(),
                    cap.source,
                );
                warn!(
                    "Landlock cannot enforce {}. This deny has no effect on Linux.",
                    conflict
                );
                fatal_conflicts.push(conflict);
            }
        }
    }

    if fatal_conflicts.is_empty() {
        return Ok(());
    }

    fatal_conflicts.sort();
    fatal_conflicts.dedup();

    let preview = fatal_conflicts
        .iter()
        .take(5)
        .map(|c| format!("- {}", c))
        .collect::<Vec<_>>()
        .join("\n");

    let remainder = fatal_conflicts.len().saturating_sub(5);
    let more = if remainder > 0 {
        format!("\n- ... and {} more conflict(s)", remainder)
    } else {
        String::new()
    };

    Err(NonoError::SandboxInit(format!(
        "Landlock deny-overlap is not enforceable on Linux. Refusing to start with conflicting policy.\n\
         Remove the broad allow path, remove the deny path, or restructure permissions.\n\
         Conflicts:\n{}{}",
        preview, more
    )))
}

/// Find user-granted paths that are blocked by deny rules.
///
/// Returns a list of `(deny_path, group_name)` pairs where the deny path overlaps
/// with an explicit user-intent grant (via `--allow`, `--read`, `--write`, or profile
/// `filesystem`). On macOS, these grants are silently ineffective because Seatbelt
/// deny rules override earlier allow rules for content access. The caller should
/// warn the user to use `--bypass-protection`.
///
/// The group name is `None` when the deny comes from a profile-level
/// `add_deny_access` rather than a named policy group.
///
/// This function is platform-independent (the overlap detection is pure logic),
/// but the caller should only emit warnings on macOS where the conflict is real.
pub fn find_denied_user_grants(
    deny_paths: &[PathBuf],
    caps: &CapabilitySet,
    policy: &Policy,
) -> Vec<(PathBuf, Option<String>)> {
    let mut conflicts = Vec::new();

    for deny_path in deny_paths {
        let has_user_grant = caps.fs_capabilities().iter().any(|cap| {
            if !cap.source.is_user_intent() {
                return false;
            }
            if cap.is_file {
                cap.resolved.starts_with(deny_path)
            } else {
                deny_path.starts_with(&cap.resolved)
            }
        });

        if !has_user_grant {
            continue;
        }

        let group_name = find_deny_group_for_path(policy, deny_path);
        conflicts.push((deny_path.clone(), group_name));
    }

    conflicts
}

/// Find which deny group blocks a given path by cross-referencing the policy.
fn find_deny_group_for_path(policy: &Policy, deny_path: &Path) -> Option<String> {
    for (name, group) in &policy.groups {
        if let Some(deny) = &group.deny {
            for path_str in &deny.access {
                if let Ok(expanded) = expand_path(path_str) {
                    if expanded == deny_path {
                        return Some(name.clone());
                    }
                    if let Ok(canonical) = expanded.canonicalize() {
                        if canonical == *deny_path {
                            return Some(name.clone());
                        }
                    }
                }
            }
        }
    }
    None
}

/// Get the list of all group names defined in the policy
#[cfg(test)]
pub fn list_groups(policy: &Policy) -> Vec<&str> {
    let mut names: Vec<&str> = policy.groups.keys().map(|s| s.as_str()).collect();
    names.sort();
    names
}

/// Get group description by name
#[cfg(test)]
pub fn group_description<'a>(policy: &'a Policy, name: &str) -> Option<&'a str> {
    policy.groups.get(name).map(|g| g.description.as_str())
}

// ============================================================================
// Query helpers: extract flat lists from policy groups
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensitivePathRule {
    pub expanded_path: String,
    pub group_name: String,
    pub description: String,
}

/// Get all sensitive (deny.access) paths from platform-matching policy groups.
///
/// Returns a list of expanded deny rules suitable for display in `nono why`.
/// Paths are expanded (~ -> $HOME, $TMPDIR -> value).
pub fn get_sensitive_paths(policy: &Policy) -> Result<Vec<SensitivePathRule>> {
    let mut result = Vec::new();

    for (group_name, group) in &policy.groups {
        if !group_matches_platform(group) {
            continue;
        }
        if let Some(deny) = &group.deny {
            for path_str in &deny.access {
                let expanded = expand_path(path_str)?;
                result.push(SensitivePathRule {
                    expanded_path: expanded.to_string_lossy().into_owned(),
                    group_name: group_name.clone(),
                    description: group.description.clone(),
                });

                // If the deny path is a symlink, also mark the resolved target
                // as sensitive. Without this, querying a symlinked path like
                // ~/.zshrc -> ~/dev/dotfiles/.zshrc would miss the deny.
                //
                // Exception: on Linux, skip resolved targets inside /nix/store.
                // NixOS home-manager creates symlinks from shell configs into the
                // immutable Nix store, and the sandbox correctly allows reading
                // those paths (see add_deny_access_rules). Marking the Nix store
                // target as sensitive would cause `nono why` to report a false
                // denial for paths the sandbox actually permits.
                if expanded.is_symlink() {
                    if let Ok(resolved) = expanded.canonicalize() {
                        if resolved != expanded && !should_skip_resolved_deny_target(&resolved) {
                            result.push(SensitivePathRule {
                                expanded_path: resolved.to_string_lossy().into_owned(),
                                group_name: group_name.clone(),
                                description: group.description.clone(),
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(result)
}

/// Get all dangerous (deny.commands) from platform-matching policy groups.
///
/// Returns a flat set of command names that should be blocked.
pub fn get_dangerous_commands(policy: &Policy) -> HashSet<String> {
    let mut result = HashSet::new();

    for group in policy.groups.values() {
        if !group_matches_platform(group) {
            continue;
        }
        if let Some(deny) = &group.deny {
            for cmd in &deny.commands {
                result.insert(cmd.clone());
            }
        }
    }

    result
}

/// Get all system read paths from allow.read groups for the current platform.
///
/// Collects `allow.read` entries from all platform-matching groups. Paths are
/// returned unexpanded (with `~` and `$TMPDIR` intact) for caller to expand.
/// Used by learn mode.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn get_system_read_paths(policy: &Policy) -> Vec<String> {
    let mut result = Vec::new();

    for group in policy.groups.values() {
        if !group_matches_platform(group) {
            continue;
        }
        if let Some(allow) = &group.allow {
            result.extend(allow.read.iter().cloned());
        }
    }

    result
}

/// Validate that a group exclusion list does not attempt to remove required groups.
///
/// Required groups have `required: true` in policy.json and cannot be excluded
/// by profiles or user configuration. Returns an error listing all violations.
pub fn validate_group_exclusions(policy: &Policy, excluded_groups: &[String]) -> Result<()> {
    let violations: Vec<&String> = excluded_groups
        .iter()
        .filter(|name| policy.groups.get(name.as_str()).is_some_and(|g| g.required))
        .collect();

    if violations.is_empty() {
        return Ok(());
    }

    let names = violations
        .iter()
        .map(|n| format!("'{}'", n))
        .collect::<Vec<_>>()
        .join(", ");

    Err(NonoError::ConfigParse(format!(
        "Cannot exclude required groups: {}",
        names
    )))
}

/// Get a built-in profile from embedded policy.json.
///
/// Returns `None` if the profile name is not defined in policy.json.
pub fn get_policy_profile(name: &str) -> Result<Option<profile::Profile>> {
    let policy = load_embedded_policy()?;
    match policy.profiles.get(name) {
        Some(def) => Ok(Some(crate::profile::resolve_and_finalize_profile(
            def.to_raw_profile(),
        )?)),
        None => Ok(None),
    }
}

/// List all built-in profile names from embedded policy.json.
pub fn list_policy_profiles() -> Result<Vec<String>> {
    let policy = load_embedded_policy()?;
    let mut names: Vec<String> = policy.profiles.keys().cloned().collect();
    names.sort();
    Ok(names)
}

/// Load the embedded policy and return the parsed Policy struct.
///
/// The policy JSON is embedded at compile time and never changes at runtime,
/// so we parse it once and cache the result. This avoids re-parsing ~23 KB of
/// JSON on every call (up to ~18 call sites per CLI invocation).
pub fn load_embedded_policy() -> Result<Policy> {
    static CACHED: std::sync::OnceLock<Policy> = std::sync::OnceLock::new();

    // The embedded JSON is baked in at build time — parse failure here means
    // a build-system bug, not a runtime condition.  We cache the successful
    // parse and clone on each call (cheap: Policy is a handful of HashMaps
    // whose keys and values are small strings).
    if let Some(policy) = CACHED.get() {
        return Ok(policy.clone());
    }

    let json = crate::config::embedded::embedded_policy_json();
    let mut policy = load_policy(json)?;
    load_package_groups(&mut policy)?;
    // Another thread may have raced us; that's fine — OnceLock keeps the
    // first value and our `policy` is simply dropped.
    let _ = CACHED.set(policy.clone());
    Ok(policy)
}

pub fn load_package_groups(policy: &mut Policy) -> Result<()> {
    // Tolerate missing config dir / lockfile — no packages installed means
    // no groups to load. This is the common case in tests and fresh installs.
    let lockfile = match package::read_lockfile() {
        Ok(lf) => lf,
        Err(_) => return Ok(()),
    };
    for package_key in lockfile.packages.keys() {
        let (namespace, name) = package_key.split_once('/').ok_or_else(|| {
            NonoError::PackageInstall(format!("invalid lockfile package key '{package_key}'"))
        })?;
        let groups_path = package::package_groups_path(namespace, name)?;
        if !groups_path.exists() {
            continue;
        }

        let content = std::fs::read_to_string(&groups_path).map_err(|e| NonoError::ConfigRead {
            path: groups_path.clone(),
            source: e,
        })?;

        let groups: HashMap<String, Group> = serde_json::from_str(&content).map_err(|e| {
            NonoError::ConfigParse(format!("failed to parse {}: {e}", groups_path.display()))
        })?;

        for (group_name, group) in groups {
            if policy.groups.contains_key(&group_name) {
                return Err(NonoError::PackageInstall(format!(
                    "package group '{}' collides with an existing policy group",
                    group_name
                )));
            }
            policy.groups.insert(group_name, group);
        }
    }

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_policy_json() -> &'static str {
        r#"{
            "meta": { "version": 2, "schema_version": "2.0" },
            "groups": {
                "test_read": {
                    "description": "Test read group",
                    "allow": { "read": ["/tmp"] }
                },
                "test_deny": {
                    "description": "Test deny group",
                    "deny": { "access": ["/nonexistent/test/path"] }
                },
                "test_commands": {
                    "description": "Test command blocking",
                    "deny": { "commands": ["rm", "dd"] }
                },
                "test_macos_only": {
                    "description": "macOS-only group",
                    "platform": "macos",
                    "allow": { "read": ["/tmp"] }
                },
                "test_linux_only": {
                    "description": "Linux-only group",
                    "platform": "linux",
                    "allow": { "read": ["/tmp"] }
                },
                "test_unlink": {
                    "description": "Unlink protection",
                    "deny": { "unlink": true }
                },
                "test_symlinks": {
                    "description": "Symlink test",
                    "symlink_pairs": { "/etc": "/private/etc" }
                },
                "test_required": {
                    "description": "Required deny group",
                    "required": true,
                    "deny": { "access": ["/nonexistent/required/path"] }
                }
            }
        }"#
    }

    #[test]
    fn test_load_policy() {
        let policy = load_policy(sample_policy_json());
        assert!(policy.is_ok());
        let policy = policy.expect("parse failed");
        assert_eq!(policy.meta.version, 2);
        assert_eq!(policy.groups.len(), 8);
    }

    #[test]
    fn test_load_embedded_policy() {
        let json = crate::config::embedded::embedded_policy_json();
        let policy = load_policy(json);
        assert!(policy.is_ok(), "Failed to parse embedded policy.json");
        let policy = policy.expect("parse failed");
        assert!(policy.meta.version >= 2);
        assert!(!policy.groups.is_empty());
    }

    #[test]
    fn test_embedded_claude_code_profile_was_removed() {
        // Removed in v0.43.0: claude-code now ships via the registry pack
        // `always-further/claude`. The platform GROUPS it referenced
        // (claude_code_macos / claude_code_linux) remain so the pack profile
        // can resolve them by name.
        let policy = load_embedded_policy().expect("embedded policy");
        assert!(
            !policy.profiles.contains_key("claude-code"),
            "claude-code profile must not be in the embedded policy.json"
        );
        assert!(policy.groups.contains_key("claude_code_macos"));
        assert!(policy.groups.contains_key("claude_code_linux"));
    }

    #[test]
    fn test_embedded_claude_code_platform_groups_have_expected_paths() {
        let policy = load_embedded_policy().expect("embedded policy");

        let claude_code_macos = policy
            .groups
            .get("claude_code_macos")
            .expect("claude_code_macos group missing");
        assert_eq!(claude_code_macos.platform.as_deref(), Some("macos"));
        let claude_code_macos_paths = &claude_code_macos
            .allow
            .as_ref()
            .expect("claude_code_macos allow missing")
            .readwrite;
        assert!(claude_code_macos
            .allow
            .as_ref()
            .expect("claude_code_macos allow missing")
            .read
            .contains(&"$HOME/.local/share/claude".to_string()));
        assert!(claude_code_macos
            .allow
            .as_ref()
            .expect("claude_code_macos allow missing")
            .read
            .contains(&"$HOME/Applications/Claude Code URL Handler.app".to_string()));
        assert!(claude_code_macos_paths.contains(&"$HOME/Library/Keychains".to_string()));
        assert!(claude_code_macos_paths
            .contains(&"$HOME/Library/Keychains/login.keychain-db".to_string()));
        assert!(claude_code_macos_paths
            .contains(&"$HOME/Library/Keychains/metadata.keychain-db".to_string()));

        let claude_code_linux = policy
            .groups
            .get("claude_code_linux")
            .expect("claude_code_linux group missing");
        assert_eq!(claude_code_linux.platform.as_deref(), Some("linux"));
        assert!(claude_code_linux
            .allow
            .as_ref()
            .expect("claude_code_linux allow missing")
            .read
            .contains(&"$HOME/.local/share/claude".to_string()));

        let vscode_macos = policy
            .groups
            .get("vscode_macos")
            .expect("vscode_macos group missing");
        assert_eq!(vscode_macos.platform.as_deref(), Some("macos"));
        let vscode_macos_paths = &vscode_macos
            .allow
            .as_ref()
            .expect("vscode_macos allow missing")
            .readwrite;
        assert!(vscode_macos_paths.contains(&"$HOME/.vscode".to_string()));
        assert!(vscode_macos_paths.contains(&"$HOME/Library/Application Support/Code".to_string()));

        let vscode_linux = policy
            .groups
            .get("vscode_linux")
            .expect("vscode_linux group missing");
        assert_eq!(vscode_linux.platform.as_deref(), Some("linux"));
        let vscode_linux_paths = &vscode_linux
            .allow
            .as_ref()
            .expect("vscode_linux allow missing")
            .readwrite;
        assert!(vscode_linux_paths.contains(&"$HOME/.vscode".to_string()));
        assert!(vscode_linux_paths.contains(&"$HOME/.config/Code".to_string()));
    }

    #[test]
    fn test_embedded_claude_code_platform_groups_filter_by_os() {
        let policy = load_embedded_policy().expect("embedded policy");
        let mut caps = CapabilitySet::new();
        let resolved = resolve_groups(
            &policy,
            &[
                "claude_code_macos".to_string(),
                "claude_code_linux".to_string(),
                "vscode_macos".to_string(),
                "vscode_linux".to_string(),
            ],
            &mut caps,
        )
        .expect("resolve failed");

        assert_eq!(resolved.names.len(), 2);

        if cfg!(target_os = "macos") {
            assert!(resolved.names.contains(&"claude_code_macos".to_string()));
            assert!(resolved.names.contains(&"vscode_macos".to_string()));
        } else {
            assert!(resolved.names.contains(&"claude_code_linux".to_string()));
            assert!(resolved.names.contains(&"vscode_linux".to_string()));
        }
    }

    #[test]
    fn test_resolve_read_group() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        let mut caps = CapabilitySet::new();
        let resolved = resolve_groups(&policy, &["test_read".to_string()], &mut caps);
        assert!(resolved.is_ok());
        // /tmp should exist on all platforms
        assert!(caps.has_fs());
    }

    #[test]
    fn test_resolve_deny_group() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        let mut caps = CapabilitySet::new();
        let resolved =
            resolve_groups(&policy, &["test_deny".to_string()], &mut caps).expect("resolve failed");

        // Deny paths should always be collected regardless of platform
        assert!(!resolved.deny_paths.is_empty());

        if cfg!(target_os = "macos") {
            // On macOS, should have platform rules for deny
            assert!(!caps.platform_rules().is_empty());
            let rules = caps.platform_rules().join("\n");
            assert!(rules.contains("deny file-read-data"));
            assert!(rules.contains("deny file-write*"));
            assert!(rules.contains("allow file-read-metadata"));
        } else {
            // On Linux, no platform rules (Landlock has no deny semantics)
            assert!(caps.platform_rules().is_empty());
        }
    }

    #[test]
    fn test_resolve_command_group() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        let mut caps = CapabilitySet::new();
        let resolved = resolve_groups(&policy, &["test_commands".to_string()], &mut caps);
        assert!(resolved.is_ok());
        assert!(caps.blocked_commands().contains(&"rm".to_string()));
        assert!(caps.blocked_commands().contains(&"dd".to_string()));
    }

    #[test]
    fn test_platform_filtering() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        let mut caps = CapabilitySet::new();

        // Resolve both platform groups - only the matching one should be active
        let resolved = resolve_groups(
            &policy,
            &["test_macos_only".to_string(), "test_linux_only".to_string()],
            &mut caps,
        )
        .expect("resolve failed");

        // Exactly one should have been resolved
        assert_eq!(resolved.names.len(), 1);

        if cfg!(target_os = "macos") {
            assert_eq!(resolved.names[0], "test_macos_only");
        } else {
            assert_eq!(resolved.names[0], "test_linux_only");
        }
    }

    #[test]
    fn test_unknown_group_error() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        let mut caps = CapabilitySet::new();
        let result = resolve_groups(&policy, &["nonexistent_group".to_string()], &mut caps);
        assert!(result.is_err());
    }

    #[test]
    fn test_unlink_protection() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        let mut caps = CapabilitySet::new();
        let resolved = resolve_groups(&policy, &["test_unlink".to_string()], &mut caps);
        assert!(resolved.is_ok());

        if cfg!(target_os = "macos") {
            assert!(caps
                .platform_rules()
                .iter()
                .any(|r| r.contains("deny file-write-unlink")));
        } else {
            // On Linux, unlink protection is Seatbelt-only
            assert!(!caps
                .platform_rules()
                .iter()
                .any(|r| r.contains("deny file-write-unlink")));
        }
    }

    #[test]
    fn test_symlink_pairs() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        let mut caps = CapabilitySet::new();
        let resolved = resolve_groups(&policy, &["test_symlinks".to_string()], &mut caps);
        assert!(resolved.is_ok());

        if cfg!(target_os = "macos") {
            assert!(caps.platform_rules().iter().any(|r| r.contains("/etc")));
        } else {
            // On Linux, symlink pairs are Seatbelt-only
            assert!(caps.platform_rules().is_empty());
        }
    }

    #[test]
    fn test_expand_path_tilde() {
        let path = expand_path("~/.ssh").expect("HOME must be valid");
        assert!(path.to_string_lossy().contains(".ssh"));
        assert!(!path.to_string_lossy().starts_with("~"));
    }

    #[test]
    fn test_expand_path_tmpdir() {
        let path = expand_path("$TMPDIR").expect("TMPDIR must be valid");
        assert!(!path.to_string_lossy().starts_with("$"));
    }

    #[test]
    fn test_expand_path_absolute() {
        let path = expand_path("/usr/bin").expect("absolute path needs no env");
        assert_eq!(path, PathBuf::from("/usr/bin"));
    }

    #[test]
    fn test_list_groups() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        let names = list_groups(&policy);
        assert!(names.contains(&"test_read"));
        assert!(names.contains(&"test_deny"));
    }

    #[test]
    fn test_group_description() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        assert_eq!(
            group_description(&policy, "test_read"),
            Some("Test read group")
        );
        assert_eq!(group_description(&policy, "nonexistent"), None);
    }

    #[test]
    fn test_deny_access_collects_path_and_generates_rules() {
        let mut caps = CapabilitySet::new();
        let mut deny_paths = Vec::new();
        add_deny_access_rules("/nonexistent/test/deny", &mut caps, &mut deny_paths)
            .expect("expand_path should succeed for absolute paths");

        // Deny path should always be collected regardless of platform
        assert_eq!(deny_paths.len(), 1);
        assert_eq!(deny_paths[0], PathBuf::from("/nonexistent/test/deny"));

        if cfg!(target_os = "macos") {
            // On macOS, Seatbelt platform rules should be generated
            let rules = caps.platform_rules();
            assert_eq!(rules.len(), 4);
            assert!(rules[0].contains("allow file-read-metadata"));
            assert!(rules[1].contains("deny file-read-data"));
            assert!(rules[2].contains("deny file-write*"));
            assert!(rules[3].contains("deny network-outbound"));
        } else {
            // On Linux, no platform rules generated (Landlock has no deny semantics)
            assert!(caps.platform_rules().is_empty());
        }
    }

    #[test]
    fn test_deny_access_includes_symlink_target() {
        // Create a temp dir with a file and a symlink to it
        let dir = tempfile::tempdir().expect("create tempdir");
        let target = dir.path().join("real_file");
        std::fs::write(&target, "secret").expect("write target");
        let link = dir.path().join("link_file");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");

        let mut caps = CapabilitySet::new();
        let mut deny_paths = Vec::new();
        let link_str = link.to_str().expect("valid utf8");
        add_deny_access_rules(link_str, &mut caps, &mut deny_paths)
            .expect("add deny rules for symlink");

        // Both the symlink path and resolved target should be in deny_paths
        let link_canonical = link.canonicalize().expect("canonicalize link");
        assert!(
            deny_paths.contains(&link),
            "deny_paths must contain the symlink path"
        );
        assert!(
            deny_paths.contains(&link_canonical),
            "deny_paths must contain the resolved target path"
        );

        if cfg!(target_os = "macos") {
            // Should have 8 rules: 4 for symlink path + 4 for resolved target
            let rules = caps.platform_rules();
            assert_eq!(rules.len(), 8, "expected 8 Seatbelt rules for symlink deny");
        }
    }

    #[test]
    fn test_deny_access_non_symlink_no_duplicate() {
        // A regular (non-symlink) file whose parents also resolve to the same
        // canonical path should produce one deny_paths entry. On macOS tempdir
        // lives under /var/folders (symlink to /private/var/folders), so the
        // canonical and original paths differ — that's two entries, which is
        // correct because Seatbelt needs both forms.
        let dir = tempfile::tempdir().expect("create tempdir");
        let file = dir.path().join("regular_file");
        std::fs::write(&file, "content").expect("write file");

        let canonical = file.canonicalize().expect("canonicalize");
        let parent_is_symlinked = canonical != file;

        let mut caps = CapabilitySet::new();
        let mut deny_paths = Vec::new();
        let file_str = file.to_str().expect("valid utf8");
        add_deny_access_rules(file_str, &mut caps, &mut deny_paths)
            .expect("add deny rules for regular file");

        let expected = if parent_is_symlinked { 2 } else { 1 };
        assert_eq!(
            deny_paths.len(),
            expected,
            "deny_paths entries: expected {} (parent symlinked: {}), got {:?}",
            expected,
            parent_is_symlinked,
            deny_paths
        );
    }

    #[test]
    fn test_resolve_parent_symlinks_nonexistent_leaf() {
        // Create a dir with a symlinked parent, then ask for a non-existent
        // child inside it. resolve_parent_symlinks should give back the
        // canonical form with the leaf appended.
        let dir = tempfile::tempdir().expect("create tempdir");

        // Build: dir/real_dir/  and  dir/link_dir -> real_dir
        let real_dir = dir.path().join("real_dir");
        std::fs::create_dir(&real_dir).expect("create real_dir");
        let link_dir = dir.path().join("link_dir");
        std::os::unix::fs::symlink(&real_dir, &link_dir).expect("create symlink");

        // The leaf (future.sock) does not exist yet
        let future = link_dir.join("future.sock");
        assert!(!future.exists(), "test precondition: leaf must not exist");

        let result = resolve_parent_symlinks(&future).expect("resolve_parent_symlinks");

        // The real_dir canonical path must be used as the parent
        let real_dir_canonical = real_dir.canonicalize().expect("canonicalize real_dir");
        let expected = real_dir_canonical.join("future.sock");

        // Only returns Some when the resolved path differs from the original
        if link_dir.canonicalize().ok().as_deref() != Some(&*real_dir_canonical)
            || link_dir != real_dir
        {
            assert_eq!(result, Some(expected));
        }
    }

    #[test]
    fn test_resolve_parent_symlinks_existing_path() {
        // When the full path already exists, resolve_parent_symlinks returns
        // None if it equals the original (no parent symlinks), or Some if
        // parent symlinks make it differ — consistent with canonicalize().
        let dir = tempfile::tempdir().expect("create tempdir");
        let file = dir.path().join("existing.txt");
        std::fs::write(&file, "content").expect("write file");

        let result = resolve_parent_symlinks(&file).expect("resolve_parent_symlinks");
        let canonical = file.canonicalize().expect("canonicalize");
        if canonical == file {
            assert_eq!(result, None, "no parent symlinks means None");
        } else {
            assert_eq!(
                result,
                Some(canonical),
                "parent symlinks means Some(canonical)"
            );
        }
    }

    #[test]
    fn test_deny_access_nonexistent_under_symlinked_parent() {
        // Simulate /var/run/future.sock on macOS: the leaf doesn't exist yet
        // but the parent directory contains a symlink. Both the original and
        // the parent-resolved path should appear in deny_paths, and on macOS
        // both should get Seatbelt rules (4 rules each = 8 total).
        let dir = tempfile::tempdir().expect("create tempdir");

        let real_dir = dir.path().join("real_run");
        std::fs::create_dir(&real_dir).expect("create real_run");
        let link_dir = dir.path().join("run");
        std::os::unix::fs::symlink(&real_dir, &link_dir).expect("create symlink");

        let socket_path = link_dir.join("daemon.sock");
        assert!(
            !socket_path.exists(),
            "test precondition: socket must not exist"
        );

        let mut caps = CapabilitySet::new();
        let mut deny_paths = Vec::new();
        let path_str = socket_path.to_str().expect("valid utf8");
        add_deny_access_rules(path_str, &mut caps, &mut deny_paths)
            .expect("add deny rules for non-existent socket under symlinked parent");

        let real_dir_canonical = real_dir.canonicalize().expect("canonicalize real_dir");
        let resolved_socket = real_dir_canonical.join("daemon.sock");

        let parent_is_symlinked = link_dir.canonicalize().ok().as_deref()
            != Some(&*real_dir_canonical)
            || link_dir != real_dir;

        if parent_is_symlinked && resolved_socket != socket_path {
            assert!(
                deny_paths.contains(&socket_path.to_path_buf()),
                "deny_paths must contain the original path"
            );
            assert!(
                deny_paths.contains(&resolved_socket),
                "deny_paths must contain the parent-resolved path; got {:?}",
                deny_paths
            );

            if cfg!(target_os = "macos") {
                let rules = caps.platform_rules();
                assert_eq!(
                    rules.len(),
                    8,
                    "expected 8 Seatbelt rules (4 original + 4 resolved); got: {:?}",
                    rules
                );
            }
        } else {
            // Parent was not actually a symlink (unlikely in this test but safe to handle)
            assert!(deny_paths.contains(&socket_path.to_path_buf()));
        }
    }

    #[test]
    fn test_sensitive_paths_includes_symlink_targets() {
        // Create a temp dir with a symlink
        let dir = tempfile::tempdir().expect("create tempdir");
        let target = dir.path().join("real_config");
        std::fs::write(&target, "secret").expect("write target");
        let link = dir.path().join("link_config");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");

        // Build a minimal policy with a deny group pointing at the symlink
        let link_str = link.to_str().expect("valid utf8");
        let json = format!(
            r#"{{
              "meta": {{ "version": 1, "schema_version": "1.0" }},
              "groups": {{
                "test_deny_symlink": {{
                  "description": "Test deny with symlink",
                  "deny": {{ "access": ["{}"] }}
                }}
              }}
            }}"#,
            link_str
        );
        let policy = load_policy(&json).expect("parse test policy");
        let sensitive = get_sensitive_paths(&policy).expect("get sensitive paths");

        let link_canonical = link.canonicalize().expect("canonicalize");
        let paths: Vec<&str> = sensitive
            .iter()
            .map(|rule| rule.expanded_path.as_str())
            .collect();
        assert!(
            paths.contains(&link_str),
            "sensitive paths must contain symlink path"
        );
        assert!(
            paths.contains(&link_canonical.to_str().expect("utf8")),
            "sensitive paths must contain resolved target"
        );
    }

    #[test]
    fn test_should_skip_resolved_deny_target() {
        // Directly exercise the shared predicate used by both
        // add_deny_access_rules and get_sensitive_paths.

        let nix_paths = [
            Path::new("/nix/store/abc123-home-manager-files/.zshrc"),
            Path::new("/nix/store/xyz789-zsh-5.9/share/zsh"),
            Path::new("/nix/store"),
        ];

        let non_nix_paths = [
            Path::new("/home/user/.zshrc"),
            Path::new("/nix/var/nix/profiles/default"),
            Path::new("/nix"),
            Path::new("/nix/stored-elsewhere"),
            Path::new("/tmp/nix/store/fake"),
        ];

        for p in &nix_paths {
            if cfg!(target_os = "linux") {
                assert!(
                    should_skip_resolved_deny_target(p),
                    "Linux must skip Nix store target: {}",
                    p.display()
                );
            } else {
                assert!(
                    !should_skip_resolved_deny_target(p),
                    "macOS must NOT skip Nix store target (Seatbelt needs it): {}",
                    p.display()
                );
            }
        }

        for p in &non_nix_paths {
            assert!(
                !should_skip_resolved_deny_target(p),
                "must never skip non-Nix-store path: {}",
                p.display()
            );
        }
    }

    #[test]
    fn test_sensitive_paths_nix_store_symlink_end_to_end() {
        // End-to-end: a symlinked deny target whose canonical form is NOT
        // in /nix/store is included. We cannot create real /nix/store files
        // in tests, but should_skip_resolved_deny_target (tested above)
        // covers the /nix/store branch directly. Here we verify that the
        // integration between get_sensitive_paths and the predicate works:
        // non-skipped symlink targets must appear in the result.
        let dir = tempfile::tempdir().expect("create tempdir");
        let target = dir.path().join("real_zshrc");
        std::fs::write(&target, "config").expect("write");
        let link = dir.path().join("linked_zshrc");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let link_str = link.to_str().expect("utf8");
        let json = format!(
            r#"{{
              "meta": {{ "version": 1, "schema_version": "1.0" }},
              "groups": {{
                "test_deny": {{
                  "description": "Test deny",
                  "deny": {{ "access": ["{}"] }}
                }}
              }}
            }}"#,
            link_str
        );
        let policy = load_policy(&json).expect("parse");
        let sensitive = get_sensitive_paths(&policy).expect("sensitive paths");
        let canonical = link.canonicalize().expect("canonicalize");
        let paths: Vec<&str> = sensitive.iter().map(|r| r.expanded_path.as_str()).collect();

        // The canonical target is not in /nix/store, so it must be included
        assert!(
            !should_skip_resolved_deny_target(&canonical),
            "precondition: tempdir canonical is not a nix store path"
        );
        assert!(
            paths.contains(&link_str),
            "sensitive paths must contain the symlink path"
        );
        assert!(
            paths.contains(&canonical.to_str().expect("utf8")),
            "non-nix canonical target must be in sensitive paths"
        );
    }

    #[test]
    fn test_escape_seatbelt_path() {
        assert_eq!(
            escape_seatbelt_path("/simple/path").expect("simple path"),
            "/simple/path"
        );
        assert_eq!(
            escape_seatbelt_path("/path with\\slash").expect("backslash"),
            "/path with\\\\slash"
        );
        assert_eq!(
            escape_seatbelt_path("/path\"quoted").expect("quote"),
            "/path\\\"quoted"
        );
    }

    #[test]
    fn test_escape_seatbelt_path_rejects_control_chars() {
        assert!(escape_seatbelt_path("/path\nwith\nnewlines").is_err());
        assert!(escape_seatbelt_path("/path\rwith\rreturns").is_err());
        assert!(escape_seatbelt_path("/path\0with\0nulls").is_err());
        assert!(escape_seatbelt_path("/path\twith\ttabs").is_err());
        assert!(escape_seatbelt_path("/path\x0bwith\x0cfeeds").is_err());
        assert!(escape_seatbelt_path("/path\x1bwith\x1bescape").is_err());
        assert!(escape_seatbelt_path("/path\x7fwith\x7fdel").is_err());
    }

    #[test]
    fn test_escape_seatbelt_path_injection_via_newline() {
        let malicious = "/tmp/evil\n(allow file-read* (subpath \"/\"))";
        // Control characters are now rejected outright
        assert!(escape_seatbelt_path(malicious).is_err());
    }

    #[test]
    fn test_escape_seatbelt_path_injection_via_quote() {
        let malicious = "/tmp/evil\")(allow file-read* (subpath \"/\"))(\"";
        let escaped = escape_seatbelt_path(malicious).expect("no control chars");
        let chars: Vec<char> = escaped.chars().collect();
        for (i, &c) in chars.iter().enumerate() {
            if c == '"' {
                assert!(
                    i > 0 && chars[i - 1] == '\\',
                    "unescaped quote at position {}",
                    i
                );
            }
        }
    }

    #[test]
    fn test_escape_seatbelt_regex_path() {
        assert_eq!(
            escape_seatbelt_regex_path("/simple/path").expect("simple path"),
            "/simple/path"
        );
        assert_eq!(
            escape_seatbelt_regex_path("/path.with+regex?(chars)").expect("regex chars"),
            "/path\\.with\\+regex\\?\\(chars\\)"
        );
        assert_eq!(
            escape_seatbelt_regex_path("/path\"quoted").expect("quote"),
            "/path\\\"quoted"
        );
    }

    #[test]
    fn test_escape_seatbelt_regex_path_rejects_control_chars() {
        assert!(escape_seatbelt_regex_path("/path\nwith\nnewlines").is_err());
        assert!(escape_seatbelt_regex_path("/path\rwith\rreturns").is_err());
        assert!(escape_seatbelt_regex_path("/path\0with\0nulls").is_err());
        assert!(escape_seatbelt_regex_path("/path\twith\ttabs").is_err());
        assert!(escape_seatbelt_regex_path("/path\x0bwith\x0cfeeds").is_err());
        assert!(escape_seatbelt_regex_path("/path\x1bwith\x1bescape").is_err());
        assert!(escape_seatbelt_regex_path("/path\x7fwith\x7fdel").is_err());
    }

    #[test]
    fn test_validate_deny_overlaps_detects_conflict() {
        use nono::FsCapability;

        let mut caps = CapabilitySet::new();
        // Allow /tmp (parent)
        let cap = FsCapability::new_dir(std::path::Path::new("/tmp"), AccessMode::Read)
            .expect("/tmp must exist");
        caps.add_fs(cap);

        // Deny /tmp/secret (child of allowed parent)
        let deny_paths = vec![PathBuf::from("/tmp/secret")];

        // On macOS: no-op (Seatbelt handles deny-within-allow natively)
        // On Linux: would warn, but we can't assert on warn!() easily
        // Instead, verify the detection logic directly
        if cfg!(target_os = "linux") {
            // Manually check the overlap detection logic
            let has_overlap = deny_paths.iter().any(|deny| {
                caps.fs_capabilities().iter().any(|cap| {
                    !cap.is_file && deny.starts_with(&cap.resolved) && *deny != cap.resolved
                })
            });
            assert!(
                has_overlap,
                "Should detect /tmp/secret overlapping with /tmp"
            );
        }

        // macOS: no-op, Linux: hard error
        if cfg!(target_os = "linux") {
            let err = validate_deny_overlaps(&deny_paths, &caps)
                .expect_err("Expected overlap to fail on Linux");
            assert!(
                err.to_string().contains("Landlock deny-overlap"),
                "Expected deny-overlap error message, got: {err}"
            );
        } else {
            validate_deny_overlaps(&deny_paths, &caps).expect("no-op on macOS");
        }
    }

    #[test]
    fn test_validate_deny_overlaps_no_false_positive() {
        use nono::FsCapability;

        let mut caps = CapabilitySet::new();
        // Allow /tmp
        let cap = FsCapability::new_dir(std::path::Path::new("/tmp"), AccessMode::Read)
            .expect("/tmp must exist");
        caps.add_fs(cap);

        // Deny /home/secret (NOT under /tmp — no overlap)
        let deny_paths = vec![PathBuf::from("/home/secret")];

        // Should not detect overlap
        let has_overlap = deny_paths.iter().any(|deny| {
            caps.fs_capabilities()
                .iter()
                .any(|cap| !cap.is_file && deny.starts_with(&cap.resolved) && *deny != cap.resolved)
        });
        assert!(
            !has_overlap,
            "Should not detect overlap for unrelated paths"
        );

        validate_deny_overlaps(&deny_paths, &caps).expect("No overlap should succeed");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_should_skip_system_write_linux_tmp_grant_when_home_is_nested() {
        // Use `keep()` so the temp dir is NOT auto-deleted. Tests that call
        // `tempdir()` concurrently (without the env lock) may create dirs
        // inside our temp_root while TMPDIR points to it. If we deleted it,
        // those dirs would vanish and cause flaky failures.  The OS reclaims
        // /tmp contents on its own schedule.
        let temp_root = tempfile::tempdir().expect("tmpdir").keep();
        let home = temp_root.join("home");
        std::fs::create_dir_all(&home).expect("create home");

        let _guard = match crate::test_env::ENV_LOCK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let original_tmpdir = std::env::var("TMPDIR").unwrap_or("/tmp".to_string());

        let _env = crate::test_env::EnvVarGuard::set_all(&[
            ("HOME", home.to_str().expect("home path")),
            ("TMPDIR", temp_root.to_str().expect("tmpdir path")),
        ]);

        let skip_tmp =
            should_skip_group_allow_path("system_write_linux", Path::new(&original_tmpdir))
                .expect("check original TMPDIR skip");
        let skip_tmpdir = should_skip_group_allow_path("system_write_linux", &temp_root)
            .expect("check new TMPDIR skip");

        assert!(
            skip_tmp,
            "original TMPDIR should be skipped when HOME is nested under it"
        );
        assert!(
            skip_tmpdir,
            "$TMPDIR should be skipped when HOME is nested under it"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_validate_deny_overlaps_group_overlap_is_fatal() {
        use nono::FsCapability;

        let mut caps = CapabilitySet::new();
        let mut cap = FsCapability::new_dir(std::path::Path::new("/tmp"), AccessMode::Read)
            .expect("/tmp must exist");
        cap.source = CapabilitySource::Group("user_tools".to_string());
        caps.add_fs(cap);

        let deny_paths = vec![PathBuf::from("/tmp/secret")];

        // Group-sourced overlaps must be fatal on Linux — Landlock cannot
        // enforce deny-within-allow, so silently ignoring the conflict
        // gives the user a false sense of security.
        // On macOS this is a no-op (Seatbelt handles deny-within-allow natively).
        let result = validate_deny_overlaps(&deny_paths, &caps);
        assert!(
            result.is_err(),
            "group-sourced deny overlap must be a hard error on Linux"
        );
    }

    #[test]
    fn test_all_groups_no_deny_within_allow_overlap() {
        // Invariant: across ALL Linux-applicable groups in the policy, no
        // deny.access path may be equal to or a child of any allow path.
        // Landlock is strictly allow-list: it cannot deny a path that falls
        // under an allowed subtree, and allowing + denying the same directory
        // means the allow wins. Both cases silently disable the deny.
        //
        // We check every group because profiles can
        // combine arbitrary groups, and validate_deny_overlaps rejects
        // overlaps at runtime. This test catches regressions in the
        // embedded policy at compile time.
        //
        // We filter to Linux-applicable groups (platform: None or "linux")
        // and check directly from parsed policy so this catches regressions
        // on all CI platforms (including macOS).
        let policy = load_embedded_policy().expect("embedded policy must load");

        let is_linux_applicable =
            |g: &Group| g.platform.is_none() || g.platform.as_deref() == Some("linux");

        let mut deny_paths: Vec<(String, PathBuf)> = Vec::new();
        let mut allow_paths: Vec<(String, PathBuf)> = Vec::new();

        for (name, group) in &policy.groups {
            if !is_linux_applicable(group) {
                continue;
            }

            if let Some(deny) = &group.deny {
                for p in &deny.access {
                    let expanded = expand_path(p).unwrap_or_else(|e| {
                        panic!("expand_path({p}) failed in group '{name}': {e}")
                    });
                    deny_paths.push((name.clone(), expanded));
                }
            }

            if let Some(allow) = &group.allow {
                for p in allow
                    .read
                    .iter()
                    .chain(&allow.write)
                    .chain(&allow.readwrite)
                {
                    let expanded = expand_path(p).unwrap_or_else(|e| {
                        panic!("expand_path({p}) failed in group '{name}': {e}")
                    });
                    if should_skip_group_allow_path(name, &expanded).unwrap_or_else(|e| {
                        panic!(
                            "should_skip_group_allow_path({}, {}) failed: {e}",
                            name,
                            expanded.display()
                        )
                    }) {
                        continue;
                    }
                    allow_paths.push((name.clone(), expanded));
                }
            }
        }

        for (deny_group, deny_path) in &deny_paths {
            for (allow_group, allow_path) in &allow_paths {
                // Landlock is purely additive: if a path is allowed, denying
                // that same path or any child has no effect. This covers both
                // child overlaps (deny starts_with allow) and exact matches.
                assert!(
                    !deny_path.starts_with(allow_path),
                    "Deny-within-allow overlap on Linux: deny '{}' (group: {}) \
                     is under or equal to allowed '{}' (group: {}). Landlock \
                     cannot enforce this. Narrow the allow path or move the \
                     deny into a separate explicit grant path.",
                    deny_path.display(),
                    deny_group,
                    allow_path.display(),
                    allow_group,
                );
            }
        }
    }

    #[test]
    fn test_resolve_deny_group_collects_deny_paths() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        let mut caps = CapabilitySet::new();
        let resolved =
            resolve_groups(&policy, &["test_deny".to_string()], &mut caps).expect("resolve failed");

        // deny_paths should be populated with the expanded deny.access paths
        assert_eq!(resolved.deny_paths.len(), 1);
        assert!(
            resolved.deny_paths[0]
                .to_string_lossy()
                .contains("nonexistent/test/path"),
            "Expected deny path to contain 'nonexistent/test/path', got: {}",
            resolved.deny_paths[0].display()
        );
    }

    #[test]
    fn test_validate_group_exclusions_allows_non_required() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        let result = validate_group_exclusions(&policy, &["test_read".to_string()]);
        assert!(result.is_ok(), "Non-required group should be removable");
    }

    #[test]
    fn test_validate_group_exclusions_rejects_required() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        let result = validate_group_exclusions(&policy, &["test_required".to_string()]);
        assert!(result.is_err(), "Required group must not be removable");
        let err = result.expect_err("expected error");
        assert!(
            err.to_string().contains("test_required"),
            "Error should name the group: {}",
            err
        );
    }

    #[test]
    fn test_validate_group_exclusions_ignores_unknown() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        let result = validate_group_exclusions(&policy, &["nonexistent_group".to_string()]);
        assert!(
            result.is_ok(),
            "Unknown groups should not trigger required check"
        );
    }

    #[test]
    fn test_profile_def_to_raw_profile_preserves_canonical_groups_exclude() {
        let def = ProfileDef {
            groups: profile::GroupsConfig {
                exclude: vec!["excluded".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        let raw = def.to_raw_profile();

        assert_eq!(raw.groups.exclude, vec!["excluded".to_string()]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_resolve_character_device_files() {
        // Character device files like /dev/urandom must be included in the
        // capability set. Rust's Path::is_file() returns false for device
        // files, so the resolver must not gate on is_file().
        let policy_json = r#"{
            "meta": { "version": 2, "schema_version": "2.0" },
            "groups": {
                "test_devices": {
                    "description": "Device files",
                    "platform": "linux",
                    "allow": { "read": ["/dev/urandom", "/dev/null", "/dev/zero"] }
                }
            }
        }"#;
        let policy = load_policy(policy_json).expect("parse failed");
        let mut caps = CapabilitySet::new();
        resolve_groups(&policy, &["test_devices".to_string()], &mut caps).expect("resolve failed");

        let resolved_paths: Vec<PathBuf> = caps
            .fs_capabilities()
            .iter()
            .map(|c| c.resolved.clone())
            .collect();

        for device in &["/dev/urandom", "/dev/null", "/dev/zero"] {
            assert!(
                resolved_paths.iter().any(|p| p == Path::new(device)),
                "{} must be included, got: {:?}",
                device,
                resolved_paths
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_embedded_policy_includes_device_files() {
        // The system_read_linux_core group lists /dev/urandom, /dev/null, etc.
        // Verify they survive policy resolution and end up in the capability set.
        let policy = load_embedded_policy().expect("embedded policy");
        let mut caps = CapabilitySet::new();
        resolve_groups(&policy, &["system_read_linux_core".to_string()], &mut caps)
            .expect("resolve failed");

        let resolved_paths: Vec<PathBuf> = caps
            .fs_capabilities()
            .iter()
            .map(|c| c.resolved.clone())
            .collect();

        for device in &["/dev/urandom", "/dev/null", "/dev/zero", "/dev/random"] {
            assert!(
                resolved_paths.iter().any(|p| p == Path::new(device)),
                "{} must be included in system_read_linux_core capabilities, got: {:?}",
                device,
                resolved_paths
            );
        }
    }

    #[test]
    fn test_embedded_policy_required_groups() {
        let policy = load_embedded_policy().expect("embedded policy");
        let required: Vec<&str> = policy
            .groups
            .iter()
            .filter(|(_, g)| g.required)
            .map(|(name, _)| name.as_str())
            .collect();
        assert!(
            required.contains(&"deny_credentials"),
            "deny_credentials must be required"
        );
        assert!(
            required.contains(&"deny_shell_configs"),
            "deny_shell_configs must be required"
        );
    }

    #[test]
    fn test_system_read_linux_core_does_not_grant_bare_etc_or_proc() {
        let policy = load_embedded_policy().expect("embedded policy must parse");
        let group = policy
            .groups
            .get("system_read_linux_core")
            .expect("system_read_linux_core group must exist");
        let read_paths = group
            .allow
            .as_ref()
            .map(|a| a.read.as_slice())
            .unwrap_or(&[]);

        assert!(
            !read_paths.iter().any(|p| p == "/etc"),
            "system_read_linux_core must not grant bare '/etc'; use specific paths instead. Found: {:?}",
            read_paths
        );
        assert!(
            !read_paths.iter().any(|p| p == "/proc"),
            "system_read_linux_core must not grant bare '/proc'; use specific paths instead. Found: {:?}",
            read_paths
        );
    }

    #[test]
    fn test_linux_core_excludes_runtime_state_sysfs_temp_and_nix() {
        let policy = load_embedded_policy().expect("embedded policy must parse");
        let group = policy
            .groups
            .get("system_read_linux_core")
            .expect("system_read_linux_core group must exist");
        let read_paths = group
            .allow
            .as_ref()
            .map(|a| a.read.as_slice())
            .unwrap_or(&[]);

        for disallowed in ["/run", "/var/run", "/sys", "/tmp", "/nix"] {
            assert!(
                !read_paths.iter().any(|p| p == disallowed),
                "system_read_linux_core must not include '{}'. Found: {:?}",
                disallowed,
                read_paths
            );
        }
    }

    #[test]
    fn test_linux_compat_groups_expose_expected_paths() {
        let policy = load_embedded_policy().expect("embedded policy must parse");

        let runtime = policy
            .groups
            .get("linux_runtime_state")
            .expect("linux_runtime_state group must exist");
        let runtime_paths = runtime
            .allow
            .as_ref()
            .map(|a| a.read.as_slice())
            .unwrap_or(&[]);
        assert!(runtime_paths.iter().any(|p| p == "/run"));
        assert!(runtime_paths.iter().any(|p| p == "/var/run"));

        let sysfs = policy
            .groups
            .get("linux_sysfs_read")
            .expect("linux_sysfs_read group must exist");
        let sysfs_paths = sysfs
            .allow
            .as_ref()
            .map(|a| a.read.as_slice())
            .unwrap_or(&[]);
        assert_eq!(sysfs_paths, ["/sys"]);

        let temp = policy
            .groups
            .get("linux_temp_read")
            .expect("linux_temp_read group must exist");
        let temp_paths = temp
            .allow
            .as_ref()
            .map(|a| a.read.as_slice())
            .unwrap_or(&[]);
        assert_eq!(temp_paths, ["/tmp"]);
    }

    #[test]
    fn test_default_user_groups_do_not_grant_local_state() {
        let policy = load_embedded_policy().expect("embedded policy must parse");

        let user_tools = policy
            .groups
            .get("user_tools")
            .expect("user_tools group must exist");
        let user_tools_allow = user_tools.allow.as_ref().expect("user_tools allow rules");
        assert!(
            !user_tools_allow.read.iter().any(|p| p == "~/.local/state"),
            "user_tools must not grant ~/.local/state"
        );
        assert!(
            !user_tools_allow
                .readwrite
                .iter()
                .any(|p| p == "~/.local/state"),
            "user_tools must not grant ~/.local/state"
        );

        let user_caches_linux = policy
            .groups
            .get("user_caches_linux")
            .expect("user_caches_linux group must exist");
        let user_caches_allow = user_caches_linux
            .allow
            .as_ref()
            .expect("user_caches_linux allow rules");
        assert!(
            !user_caches_allow.read.iter().any(|p| p == "~/.local/state"),
            "user_caches_linux must not grant ~/.local/state"
        );
        assert!(
            !user_caches_allow
                .readwrite
                .iter()
                .any(|p| p == "~/.local/state"),
            "user_caches_linux must not grant ~/.local/state"
        );
    }

    #[test]
    fn test_apply_deny_overrides_removes_from_deny_paths() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let denied = dir.path().join("denied");
        std::fs::create_dir_all(&denied).expect("mkdir denied");
        let other = dir.path().join("other");
        std::fs::create_dir_all(&other).expect("mkdir other");

        let denied_canonical = denied.canonicalize().expect("canonicalize denied");
        let other_canonical = other.canonicalize().expect("canonicalize other");

        let mut deny_paths = vec![denied_canonical.clone(), other_canonical.clone()];
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_dir(dir.path(), AccessMode::ReadWrite).expect("grant dir"));
        let overrides = vec![denied.clone()];

        apply_deny_overrides(&overrides, &mut deny_paths, &mut caps).expect("should succeed");

        assert_eq!(deny_paths.len(), 1);
        assert_eq!(deny_paths[0], other_canonical);
    }

    #[test]
    fn test_apply_deny_overrides_empty_is_noop() {
        let mut deny_paths = vec![PathBuf::from("/tmp/denied")];
        let mut caps = CapabilitySet::new();

        apply_deny_overrides(&[], &mut deny_paths, &mut caps)
            .expect("empty overrides should succeed");

        assert_eq!(deny_paths.len(), 1, "deny_paths should be unchanged");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_apply_deny_overrides_emits_seatbelt_rules() {
        let mut deny_paths = vec![PathBuf::from("/tmp")];
        let mut caps = CapabilitySet::new();
        // Add a grant covering the override path (required by validation)
        caps.add_fs(
            FsCapability::new_dir(Path::new("/tmp"), AccessMode::ReadWrite).expect("grant /tmp"),
        );
        let overrides = vec![PathBuf::from("/tmp")];

        apply_deny_overrides(&overrides, &mut deny_paths, &mut caps).expect("should succeed");

        let rules = caps.platform_rules().join("\n");
        assert!(
            rules.contains("allow file-read-data"),
            "should emit read allow rule, got: {}",
            rules
        );
        assert!(
            rules.contains("allow file-write*"),
            "should emit write allow rule, got: {}",
            rules
        );
        // /tmp is a directory, so should use subpath
        assert!(
            rules.contains("subpath"),
            "should use subpath for directory, got: {}",
            rules
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_apply_unlink_overrides_emits_literal_rule_for_writable_file_caps() {
        let mut caps = CapabilitySet::new();
        let file_path = PathBuf::from("/tmp/.claude.lock");
        caps.add_fs(FsCapability {
            original: file_path.clone(),
            resolved: file_path.clone(),
            access: AccessMode::ReadWrite,
            is_file: true,
            source: CapabilitySource::Profile,
        });

        apply_unlink_overrides(&mut caps);

        let escaped =
            escape_seatbelt_path(file_path.to_str().expect("utf8 path")).expect("escaped path");
        let rules = caps.platform_rules().join("\n");
        assert!(
            rules.contains(&format!(
                "(allow file-write-unlink (literal \"{}\"))",
                escaped
            )),
            "expected literal unlink override for writable file cap, got: {}",
            rules
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_apply_macos_keychain_db_exception_adds_login_db_allow_rule() {
        let mut caps = CapabilitySet::new();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/test".to_string());
        let login_db = PathBuf::from(home).join("Library/Keychains/login.keychain-db");
        caps.add_fs(FsCapability {
            original: login_db.clone(),
            resolved: login_db.clone(),
            access: AccessMode::ReadWrite,
            is_file: true,
            source: CapabilitySource::Profile,
        });

        apply_macos_keychain_db_exception(&mut caps);

        let rules = caps.platform_rules().join("\n");
        assert!(
            rules.contains(&format!(
                "(allow file-read* (literal \"{}\"))",
                escape_seatbelt_path(login_db.to_str().expect("utf8 path")).expect("escaped path")
            )),
            "expected login keychain DB exception rule, got: {}",
            rules
        );
        assert!(
            rules.contains(&format!(
                "(allow file-write* (literal \"{}\"))",
                escape_seatbelt_path(login_db.to_str().expect("utf8 path")).expect("escaped path")
            )),
            "expected login keychain DB write rule, got: {}",
            rules
        );
        // Specific-op rules must also be emitted so they override the specific-op
        // deny from deny_keychains_macos: (deny file-read-data (subpath "...Keychains")).
        // A file-read* wildcard allow does not override a file-read-data specific deny.
        assert!(
            rules.contains(&format!(
                "(allow file-read-data (literal \"{}\"))",
                escape_seatbelt_path(login_db.to_str().expect("utf8 path")).expect("escaped path")
            )),
            "expected login keychain DB file-read-data rule (to override specific deny), got: {}",
            rules
        );
        assert!(
            rules.contains(&format!(
                "(allow file-write-data (literal \"{}\"))",
                escape_seatbelt_path(login_db.to_str().expect("utf8 path")).expect("escaped path")
            )),
            "expected login keychain DB file-write-data rule (to override specific deny), got: {}",
            rules
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_apply_macos_keychain_db_exception_adds_metadata_db_allow_rule() {
        let mut caps = CapabilitySet::new();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/test".to_string());
        let metadata_db = PathBuf::from(home).join("Library/Keychains/metadata.keychain-db");
        caps.add_fs(FsCapability {
            original: metadata_db.clone(),
            resolved: metadata_db.clone(),
            access: AccessMode::ReadWrite,
            is_file: true,
            source: CapabilitySource::Profile,
        });

        apply_macos_keychain_db_exception(&mut caps);

        let rules = caps.platform_rules().join("\n");
        assert!(
            rules.contains(&format!(
                "(allow file-read* (literal \"{}\"))",
                escape_seatbelt_path(metadata_db.to_str().expect("utf8 path"))
                    .expect("escaped path")
            )),
            "expected metadata keychain DB exception rule, got: {}",
            rules
        );
        assert!(
            rules.contains(&format!(
                "(allow file-write* (literal \"{}\"))",
                escape_seatbelt_path(metadata_db.to_str().expect("utf8 path"))
                    .expect("escaped path")
            )),
            "expected metadata keychain DB write rule, got: {}",
            rules
        );
        assert!(
            rules.contains(&format!(
                "(allow file-read-data (literal \"{}\"))",
                escape_seatbelt_path(metadata_db.to_str().expect("utf8 path"))
                    .expect("escaped path")
            )),
            "expected metadata keychain DB file-read-data rule (to override specific deny), got: {}",
            rules
        );
        assert!(
            rules.contains(&format!(
                "(allow file-write-data (literal \"{}\"))",
                escape_seatbelt_path(metadata_db.to_str().expect("utf8 path"))
                    .expect("escaped path")
            )),
            "expected metadata keychain DB file-write-data rule (to override specific deny), got: {}",
            rules
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_apply_macos_keychain_db_exception_adds_runtime_keychain_rules() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let home = dir.path().join("home");
        let keychains = home.join("Library/Keychains");
        std::fs::create_dir_all(&keychains).expect("mkdir keychains");
        std::fs::write(keychains.join("login.keychain-db"), "").expect("write login db");
        std::fs::write(keychains.join("metadata.keychain-db"), "").expect("write metadata db");

        let _env = crate::test_env::EnvVarGuard::set_all(&[(
            "HOME",
            home.to_str().expect("home path utf8"),
        )]);

        let login_db = keychains.join("login.keychain-db");
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: login_db.clone(),
            resolved: login_db,
            access: AccessMode::ReadWrite,
            is_file: true,
            source: CapabilitySource::Profile,
        });

        apply_macos_keychain_db_exception(&mut caps);

        let escaped_root =
            escape_seatbelt_regex_path(keychains.to_str().expect("keychains path utf8"))
                .expect("escaped regex path");
        let rules = caps.platform_rules().join("\n");

        assert!(
            rules.contains(&format!(
                "(allow file-read* (regex #\"^{}/\\.fl[0-9A-Fa-f]+$\"))",
                escaped_root
            )),
            "expected root .fl keychain rule, got: {}",
            rules
        );
        assert!(
            rules.contains(&format!(
                "(allow file-write* (regex #\"^{}/\\.fl[0-9A-Fa-f]+$\"))",
                escaped_root
            )),
            "expected writable root .fl keychain rule, got: {}",
            rules
        );
        assert!(
            rules.contains(&format!(
                "(allow file-read* (regex #\"^{}/[^/]+/(?:[^/]+\\.db(?:-(?:wal|shm))?|user\\.kb)$\"))",
                escaped_root
            )),
            "expected runtime DB read rule, got: {}",
            rules
        );
        assert!(
            rules.contains(&format!(
                "(allow file-write* (regex #\"^{}/[^/]+/(?:[^/]+\\.db(?:-(?:wal|shm))?|user\\.kb)$\"))",
                escaped_root
            )),
            "expected runtime DB write rule, got: {}",
            rules
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_apply_deny_overrides_respects_read_only_grant() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let denied = dir.path().join("readonly");
        std::fs::create_dir_all(&denied).expect("mkdir");

        let denied_canonical = denied.canonicalize().expect("canonicalize");
        let mut deny_paths = vec![denied_canonical];
        let mut caps = CapabilitySet::new();
        // Grant read-only access
        caps.add_fs(FsCapability::new_dir(&denied, AccessMode::Read).expect("grant"));
        let overrides = vec![denied];

        apply_deny_overrides(&overrides, &mut deny_paths, &mut caps).expect("should succeed");

        let rules = caps.platform_rules().join("\n");
        assert!(
            rules.contains("allow file-read-data"),
            "should emit read rule for read-only grant, got: {}",
            rules
        );
        assert!(
            !rules.contains("allow file-write*"),
            "must NOT emit write rule for read-only grant, got: {}",
            rules
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_apply_deny_overrides_respects_write_only_grant() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let denied = dir.path().join("writeonly");
        std::fs::create_dir_all(&denied).expect("mkdir");

        let denied_canonical = denied.canonicalize().expect("canonicalize");
        let mut deny_paths = vec![denied_canonical];
        let mut caps = CapabilitySet::new();
        // Grant write-only access
        caps.add_fs(FsCapability::new_dir(&denied, AccessMode::Write).expect("grant"));
        let overrides = vec![denied];

        apply_deny_overrides(&overrides, &mut deny_paths, &mut caps).expect("should succeed");

        let rules = caps.platform_rules().join("\n");
        assert!(
            !rules.contains("allow file-read-data"),
            "must NOT emit read rule for write-only grant, got: {}",
            rules
        );
        assert!(
            rules.contains("allow file-write*"),
            "should emit write rule for write-only grant, got: {}",
            rules
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_apply_deny_overrides_merges_complementary_read_write_grants() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let denied = dir.path().join("merged_rw");
        std::fs::create_dir_all(&denied).expect("mkdir");

        let denied_canonical = denied.canonicalize().expect("canonicalize");
        let mut deny_paths = vec![denied_canonical];
        let mut caps = CapabilitySet::new();
        // Two separate grants: Read and Write (not yet deduplicated)
        caps.add_fs(FsCapability::new_dir(&denied, AccessMode::Read).expect("read grant"));
        caps.add_fs(FsCapability::new_dir(&denied, AccessMode::Write).expect("write grant"));
        let overrides = vec![denied];

        apply_deny_overrides(&overrides, &mut deny_paths, &mut caps).expect("should succeed");

        let rules = caps.platform_rules().join("\n");
        assert!(
            rules.contains("allow file-read-data"),
            "should emit read rule from merged Read+Write grants, got: {}",
            rules
        );
        assert!(
            rules.contains("allow file-write*"),
            "should emit write rule from merged Read+Write grants, got: {}",
            rules
        );
    }

    #[test]
    fn test_apply_deny_overrides_does_not_remove_broader_deny() {
        // Overriding a child path must NOT remove a broader parent deny.
        let dir = tempfile::tempdir().expect("tmpdir");
        let sub = dir.path().join("sub");
        std::fs::create_dir_all(&sub).expect("mkdir sub");

        let dir_canonical = dir.path().canonicalize().expect("canonicalize dir");
        let sub_canonical = sub.canonicalize().expect("canonicalize sub");

        let mut deny_paths = vec![dir_canonical.clone(), sub_canonical.clone()];
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_dir(&sub, AccessMode::ReadWrite).expect("grant sub"));
        let overrides = vec![sub.clone()];

        apply_deny_overrides(&overrides, &mut deny_paths, &mut caps).expect("should succeed");

        // sub should be removed, but parent dir must remain
        assert_eq!(deny_paths.len(), 1);
        assert_eq!(deny_paths[0], dir_canonical);
    }

    #[test]
    fn test_apply_deny_overrides_rejects_missing_grant() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let denied = dir.path().join("denied");
        std::fs::create_dir_all(&denied).expect("mkdir denied");

        let denied_canonical = denied.canonicalize().expect("canonicalize");
        let mut deny_paths = vec![denied_canonical];
        let mut caps = CapabilitySet::new();
        // No grant added — override should fail
        let overrides = vec![denied];

        let result = apply_deny_overrides(&overrides, &mut deny_paths, &mut caps);
        assert!(result.is_err());
        let err = result.expect_err("expected error");
        assert!(
            err.to_string().contains("no matching grant"),
            "error should mention missing grant, got: {}",
            err
        );
    }

    #[test]
    fn test_apply_deny_overrides_rejects_group_sourced_grant() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let denied = dir.path().join("group_granted");
        std::fs::create_dir_all(&denied).expect("mkdir");

        let denied_canonical = denied.canonicalize().expect("canonicalize");
        let mut deny_paths = vec![denied_canonical];
        let mut caps = CapabilitySet::new();
        // Add a group-sourced grant (not user intent)
        let mut cap = FsCapability::new_dir(dir.path(), AccessMode::ReadWrite).expect("grant");
        cap.source = CapabilitySource::Group("system_write".to_string());
        caps.add_fs(cap);
        let overrides = vec![denied];

        let result = apply_deny_overrides(&overrides, &mut deny_paths, &mut caps);
        assert!(result.is_err());
        let err = result.expect_err("expected error");
        assert!(
            err.to_string().contains("no matching grant"),
            "group grant should not satisfy bypass_protection, got: {}",
            err
        );
    }

    #[test]
    fn test_apply_deny_overrides_removes_symlink_and_target_deny_paths() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let target = dir.path().join("real_dir");
        std::fs::create_dir_all(&target).expect("mkdir target");
        let link = dir.path().join("link_dir");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let target_canonical = target.canonicalize().expect("canonicalize target");
        let link_expanded = link.clone();

        // add_deny_access_rules records both the symlink path and the resolved target
        let mut deny_paths = vec![link_expanded.clone(), target_canonical.clone()];
        let mut caps = CapabilitySet::new();
        // Grant via the target (which is what profile filesystem grants canonicalize to)
        caps.add_fs(FsCapability::new_dir(&target, AccessMode::ReadWrite).expect("grant"));
        // Override via the symlink path (what the user writes in their profile)
        let overrides = vec![link];

        apply_deny_overrides(&overrides, &mut deny_paths, &mut caps).expect("should succeed");

        assert!(
            deny_paths.is_empty(),
            "both symlink and target deny paths should be removed, remaining: {:?}",
            deny_paths
        );
    }

    #[test]
    fn test_deny_access_skips_nix_store_canonical_on_linux() {
        // Verify that add_deny_access_rules still includes canonical paths
        // for non-Nix-store symlinks (the skip logic only fires for
        // /nix/store targets, tested via should_skip_resolved_deny_target).
        let dir = tempfile::tempdir().expect("create tempdir");
        let target = dir.path().join("real_file");
        std::fs::write(&target, "content").expect("write target");
        let link = dir.path().join("link_file");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");

        let mut caps = CapabilitySet::new();
        let mut deny_paths = Vec::new();
        let link_str = link.to_str().expect("valid utf8");
        add_deny_access_rules(link_str, &mut caps, &mut deny_paths).expect("add deny rules");

        let link_canonical = link.canonicalize().expect("canonicalize");

        // Precondition: the canonical is not a nix store path
        assert!(
            !should_skip_resolved_deny_target(&link_canonical),
            "precondition: tempdir canonical is not a nix store path"
        );

        // Both the symlink and its canonical target should be in deny_paths
        assert!(
            deny_paths.contains(&link),
            "deny_paths must contain the symlink path"
        );
        assert!(
            deny_paths.contains(&link_canonical),
            "non-nix-store canonical should still be added to deny_paths"
        );
    }

    #[test]
    fn test_nix_runtime_group_includes_nix_store() {
        let json = crate::config::embedded::embedded_policy_json();
        let policy = load_policy(json).expect("parse policy.json");
        let group = policy
            .groups
            .get("nix_runtime")
            .expect("nix_runtime group must exist");
        let read_paths = &group
            .allow
            .as_ref()
            .expect("nix_runtime must have allow block")
            .read;
        assert!(
            read_paths.contains(&"/nix/store".to_string()),
            "nix_runtime group must include /nix/store for NixOS compatibility"
        );
    }

    #[test]
    fn test_find_denied_user_grants_detects_overlap() {
        let path = PathBuf::from("/nonexistent/test/secret");
        let policy = load_policy(
            r#"{"meta":{"version":2,"schema_version":"2.0"},"groups":{
                "deny_creds":{"description":"creds","deny":{"access":["/nonexistent/test/secret"]}}
            }}"#,
        )
        .expect("parse policy");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: path.clone(),
            resolved: path.clone(),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });

        let conflicts = find_denied_user_grants(&[path], &caps, &policy);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].1.as_deref(), Some("deny_creds"));
    }

    #[test]
    fn test_find_denied_user_grants_ignores_non_user_grants() {
        let path = PathBuf::from("/nonexistent/test/secret");
        let policy = load_policy(sample_policy_json()).expect("parse policy");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: path.clone(),
            resolved: path.clone(),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::Group("system".to_string()),
        });

        let conflicts = find_denied_user_grants(&[path], &caps, &policy);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn test_find_denied_user_grants_profile_deny_without_group() {
        let path = PathBuf::from("/nonexistent/test/profile_denied");
        let policy = load_policy(r#"{"meta":{"version":2,"schema_version":"2.0"},"groups":{}}"#)
            .expect("parse policy");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: path.clone(),
            resolved: path.clone(),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });

        let conflicts = find_denied_user_grants(&[path], &caps, &policy);
        assert_eq!(conflicts.len(), 1);
        assert!(conflicts[0].1.is_none());
    }
}
