//! CLI-specific extensions for CapabilitySet
//!
//! This module provides methods to construct a CapabilitySet from CLI arguments
//! or profiles. These are CLI-specific and not part of the core library.

use crate::cli::SandboxArgs;
use crate::policy;
use crate::profile::{expand_vars, Profile};
use crate::protected_paths::{self, ProtectedRoots};
use nono::{AccessMode, CapabilitySet, CapabilitySource, FsCapability, NonoError, Result};
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

/// Try to create a directory capability, warning and skipping on PathNotFound.
/// Propagates all other errors.
fn try_new_dir(path: &Path, access: AccessMode, label: &str) -> Result<Option<FsCapability>> {
    match FsCapability::new_dir(path, access) {
        Ok(cap) => Ok(Some(cap)),
        Err(NonoError::PathNotFound(_)) => {
            warn!("{}: {}", label, path.display());
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// Try to create a file capability, warning and skipping on PathNotFound.
/// Propagates all other errors.
fn try_new_file(path: &Path, access: AccessMode, label: &str) -> Result<Option<FsCapability>> {
    match FsCapability::new_file(path, access) {
        Ok(cap) => Ok(Some(cap)),
        Err(NonoError::PathNotFound(_)) => handle_missing_file_capability(path, access, label),
        Err(e) => Err(e),
    }
}

/// Create a profile capability for an exact path that is usually expected to be a file.
///
/// Some clients use lock directories at paths that historically held lock files
/// (for example `~/.claude.lock`). On macOS we can preserve exact-path semantics
/// for that directory by emitting a literal path rule instead of widening to a
/// recursive directory grant. On other platforms, fail closed.
fn try_new_profile_exact_path(
    path: &Path,
    access: AccessMode,
    label: &str,
    protected_roots: &ProtectedRoots,
) -> Result<Option<FsCapability>> {
    validate_requested_file(path, "Profile", protected_roots)?;
    match try_new_file(path, access, label) {
        Err(NonoError::ExpectedFile(_)) => {
            handle_exact_directory_path(path, access, protected_roots)
        }
        result => result,
    }
}

#[cfg(target_os = "macos")]
fn handle_exact_directory_path(
    path: &Path,
    access: AccessMode,
    protected_roots: &ProtectedRoots,
) -> Result<Option<FsCapability>> {
    validate_requested_dir(path, "Profile", protected_roots)?;
    let resolved = path.canonicalize().map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            NonoError::PathNotFound(path.to_path_buf())
        } else {
            NonoError::PathCanonicalization {
                path: path.to_path_buf(),
                source,
            }
        }
    })?;

    debug!(
        "Profile exact-file path resolved as directory; granting exact macOS literal path access: {}",
        path.display()
    );

    Ok(Some(FsCapability {
        original: path.to_path_buf(),
        resolved,
        access,
        // On macOS, `is_file = true` makes Seatbelt emit a literal path rule
        // rather than a recursive subpath rule. The target may still be a
        // directory; the important property is exact-path matching.
        is_file: true,
        source: CapabilitySource::Profile,
    }))
}

#[cfg(not(target_os = "macos"))]
fn handle_exact_directory_path(
    path: &Path,
    _access: AccessMode,
    _protected_roots: &ProtectedRoots,
) -> Result<Option<FsCapability>> {
    Err(NonoError::ExpectedFile(path.to_path_buf()))
}

#[cfg(target_os = "macos")]
fn handle_missing_file_capability(
    path: &Path,
    access: AccessMode,
    _label: &str,
) -> Result<Option<FsCapability>> {
    let cap = new_future_file_capability(path, access)?;
    debug!(
        "Granting future exact file capability on macOS for missing path: {}",
        path.display()
    );
    Ok(Some(cap))
}

#[cfg(not(target_os = "macos"))]
fn handle_missing_file_capability(
    path: &Path,
    _access: AccessMode,
    label: &str,
) -> Result<Option<FsCapability>> {
    warn!("{}: {}", label, path.display());
    Ok(None)
}

#[cfg(target_os = "macos")]
fn new_future_file_capability(path: &Path, access: AccessMode) -> Result<FsCapability> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_err(NonoError::Io)?.join(path)
    };

    Ok(FsCapability {
        original: path.to_path_buf(),
        resolved: resolve_missing_leaf_path(&absolute)?,
        access,
        is_file: true,
        source: CapabilitySource::User,
    })
}

#[cfg(target_os = "macos")]
fn resolve_missing_leaf_path(path: &Path) -> Result<PathBuf> {
    for ancestor in path.ancestors() {
        match ancestor.canonicalize() {
            Ok(mut canonical) => {
                if let Ok(relative) = path.strip_prefix(ancestor) {
                    canonical.push(relative);
                }
                return Ok(canonical);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(NonoError::PathCanonicalization {
                    path: path.to_path_buf(),
                    source: err,
                });
            }
        }
    }

    Err(NonoError::PathNotFound(path.to_path_buf()))
}

/// Add a platform rule to allow atomic-write temp files for a writable file.
///
/// Many tools (e.g. Claude Code) write atomically by creating a temp file
/// (`file.tmp.PID.TIMESTAMP`) then renaming it over the target. This function
/// adds a Seatbelt regex rule to permit creating/writing those temp files
/// alongside the allowed file.
#[cfg(target_os = "macos")]
fn add_atomic_write_rule(caps: &mut CapabilitySet, cap: &FsCapability) -> Result<()> {
    if !matches!(cap.access, AccessMode::Write | AccessMode::ReadWrite) {
        return Ok(());
    }

    fn add_rule_for_path(caps: &mut CapabilitySet, path: &Path) -> Result<()> {
        let path_str = path.to_str().ok_or_else(|| {
            NonoError::SandboxInit(format!(
                "non-UTF-8 path for atomic write rule: {}",
                path.display()
            ))
        })?;
        let escaped = regex_escape_path(path_str);
        let rule = format!(
            "(allow file-write* (regex #\"^{}\\.tmp\\.[0-9]+\\.[0-9]+$\"))",
            escaped
        );
        caps.add_platform_rule(&rule)
    }

    add_rule_for_path(caps, &cap.resolved)?;
    if cap.original != cap.resolved {
        add_rule_for_path(caps, &cap.original)?;
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn add_atomic_write_rule(_caps: &mut CapabilitySet, _cap: &FsCapability) -> Result<()> {
    Ok(())
}

/// Escape a filesystem path for use in a Seatbelt regex.
/// Only metacharacters that could appear in typical paths need escaping.
#[cfg(target_os = "macos")]
fn regex_escape_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len() + 8);
    for c in path.chars() {
        match c {
            '.' | '+' | '*' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '^' | '$' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

fn apply_profile_dir_allows(
    path_templates: &[String],
    access: AccessMode,
    workdir: &Path,
    protected_roots: &ProtectedRoots,
    caps: &mut CapabilitySet,
    label_prefix: &str,
) -> Result<()> {
    for path_template in path_templates {
        let path = expand_vars(path_template, workdir)?;
        validate_requested_dir(&path, "Profile", protected_roots)?;
        let label = format!(
            "{label_prefix} '{}' does not exist, skipping",
            path_template
        );
        if let Some(mut cap) = try_new_dir(&path, access, &label)? {
            cap.source = CapabilitySource::Profile;
            caps.add_fs(cap);
        }
    }
    Ok(())
}

fn validate_requested_dir(
    path: &Path,
    source: &str,
    protected_roots: &ProtectedRoots,
) -> Result<()> {
    if path.exists() && !path.is_dir() {
        return Err(NonoError::ConfigParse(format!(
            "{} path '{}' is not a directory. \
             Use --allow-file for single files.",
            source,
            path.display()
        )));
    }
    if !path.exists() && source == "CLI" {
        warn!("'{}' does not exist and will be ignored.", path.display());
    }
    protected_paths::validate_requested_path_against_protected_roots(
        path,
        false,
        source,
        protected_roots.as_paths(),
    )
}

fn validate_requested_file(
    path: &Path,
    source: &str,
    protected_roots: &ProtectedRoots,
) -> Result<()> {
    protected_paths::validate_requested_path_against_protected_roots(
        path,
        true,
        source,
        protected_roots.as_paths(),
    )
}

pub(crate) fn default_profile_groups() -> Result<Vec<String>> {
    let profile = crate::policy::get_policy_profile("default")?
        .ok_or_else(|| NonoError::ProfileNotFound("default".to_string()))?;
    Ok(profile.security.groups)
}

#[must_use]
pub(crate) fn retains_missing_exact_file_grants() -> bool {
    cfg!(target_os = "macos")
}

/// Result of building a CapabilitySet from CLI args or a profile.
///
/// `needs_unlink_overrides` defers `policy::apply_unlink_overrides()` until the
/// caller has added every writable path (including CWD).
///
/// `deny_paths` carries the resolved policy-deny set (groups + profile
/// `add_deny_access`) so the caller can re-run `validate_deny_overlaps` after
/// it adds further allow paths (e.g. `--allow-cwd`). Without this, a deny
/// configured by the profile can silently be neutralised on Linux when a later
/// allow path covers it — which Landlock cannot enforce.
#[derive(Debug)]
pub struct PreparedCaps {
    pub caps: CapabilitySet,
    pub needs_unlink_overrides: bool,
    pub deny_paths: Vec<PathBuf>,
}

/// Extension trait for CapabilitySet to add CLI-specific construction methods.
pub trait CapabilitySetExt {
    /// Create a capability set from CLI sandbox arguments.
    fn from_args(args: &SandboxArgs) -> Result<PreparedCaps>;

    /// Create a capability set from a profile with CLI overrides.
    fn from_profile(profile: &Profile, workdir: &Path, args: &SandboxArgs) -> Result<PreparedCaps>;
}

impl CapabilitySetExt for CapabilitySet {
    fn from_args(args: &SandboxArgs) -> Result<PreparedCaps> {
        let mut caps = CapabilitySet::new();
        let protected_roots = ProtectedRoots::from_defaults()?;

        // Resolve base policy groups (system paths, deny rules, dangerous commands)
        let loaded_policy = policy::load_embedded_policy()?;
        let default_groups = default_profile_groups()?;
        let mut resolved = policy::resolve_groups(&loaded_policy, &default_groups, &mut caps)?;

        // Directory permissions (canonicalize handles existence check atomically)
        for path in &args.allow {
            validate_requested_dir(path, "CLI", &protected_roots)?;
            if let Some(cap) =
                try_new_dir(path, AccessMode::ReadWrite, "Skipping non-existent path")?
            {
                caps.add_fs(cap);
            }
        }

        for path in &args.read {
            validate_requested_dir(path, "CLI", &protected_roots)?;
            if let Some(cap) = try_new_dir(path, AccessMode::Read, "Skipping non-existent path")? {
                caps.add_fs(cap);
            }
        }

        for path in &args.write {
            validate_requested_dir(path, "CLI", &protected_roots)?;
            if let Some(cap) = try_new_dir(path, AccessMode::Write, "Skipping non-existent path")? {
                caps.add_fs(cap);
            }
        }

        // Single file permissions
        for path in &args.allow_file {
            validate_requested_file(path, "CLI", &protected_roots)?;
            if let Some(cap) =
                try_new_file(path, AccessMode::ReadWrite, "Skipping non-existent file")?
            {
                caps.add_fs(cap);
            }
        }

        for path in &args.read_file {
            validate_requested_file(path, "CLI", &protected_roots)?;
            if let Some(cap) = try_new_file(path, AccessMode::Read, "Skipping non-existent file")? {
                caps.add_fs(cap);
            }
        }

        for path in &args.write_file {
            validate_requested_file(path, "CLI", &protected_roots)?;
            if let Some(cap) = try_new_file(path, AccessMode::Write, "Skipping non-existent file")?
            {
                caps.add_fs(cap);
            }
        }

        apply_cli_network_mode(&mut caps, args);

        // Localhost IPC ports
        for port in &args.allow_port {
            caps.add_localhost_port(*port);
        }

        // Outbound TCP connect port allowlist (Linux Landlock V4+ only)
        #[cfg(target_os = "macos")]
        if !args.allow_connect_port.is_empty() {
            return Err(NonoError::UnsupportedPlatform(
                "--allow-connect-port is not supported on macOS: Seatbelt cannot filter by TCP port. \
                 Use --allow-domain for host-level filtering, or ProxyOnly mode."
                    .to_string(),
            ));
        }
        #[cfg(not(target_os = "macos"))]
        for port in &args.allow_connect_port {
            caps.add_tcp_connect_port(*port);
        }

        // Command allow/block lists
        for cmd in &args.allow_command {
            caps.add_allowed_command(cmd.clone());
        }

        for cmd in &args.block_command {
            caps.add_blocked_command(cmd);
        }

        // --allow-gpu wiring (D-12 upstream parity port).
        //
        // On Windows the warning fires and the capability is deliberately
        // NOT added — proof that the Windows sandbox state is byte-identical
        // with and without the flag (D-21 invariant).
        args.warn_if_allow_gpu_unsupported_on_platform();
        #[cfg(not(target_os = "windows"))]
        if args.allow_gpu {
            caps.set_gpu(true);
        }

        finalize_caps(&mut caps, &mut resolved, &loaded_policy, args, &[])?;

        Ok(PreparedCaps {
            caps,
            needs_unlink_overrides: resolved.needs_unlink_overrides,
            deny_paths: resolved.deny_paths,
        })
    }

    fn from_profile(profile: &Profile, workdir: &Path, args: &SandboxArgs) -> Result<PreparedCaps> {
        let mut caps = CapabilitySet::new();
        let protected_roots = ProtectedRoots::from_defaults()?;

        // Resolve policy groups from the already-finalized profile.
        let loaded_policy = policy::load_embedded_policy()?;
        let groups = profile.security.groups.clone();
        let mut resolved = policy::resolve_groups(&loaded_policy, &groups, &mut caps)?;
        debug!("Resolved {} policy groups", resolved.names.len());

        // Process profile filesystem config (profile-specific paths on top of groups).
        // These are marked as CapabilitySource::Profile so they are displayed in
        // the banner but NOT tracked for rollback snapshots (only User-sourced paths
        // representing the project workspace are tracked).
        let fs = &profile.filesystem;

        // Directories with read+write access
        for path_template in &fs.allow {
            let path = expand_vars(path_template, workdir)?;
            validate_requested_dir(&path, "Profile", &protected_roots)?;
            let label = format!("Profile path '{}' does not exist, skipping", path_template);
            if let Some(mut cap) = try_new_dir(&path, AccessMode::ReadWrite, &label)? {
                cap.source = CapabilitySource::Profile;
                caps.add_fs(cap);
            }
        }

        // Read-only filesystem entries (directory or file)
        for path_template in &fs.read {
            let path = expand_vars(path_template, workdir)?;
            let label = format!("Profile path '{}' does not exist, skipping", path_template);

            let reads_file = std::fs::metadata(&path)
                .map(|metadata| !metadata.is_dir())
                .unwrap_or(false);

            let maybe_cap = if reads_file {
                validate_requested_file(&path, "Profile", &protected_roots)?;
                try_new_file(&path, AccessMode::Read, &label)?
            } else {
                validate_requested_dir(&path, "Profile", &protected_roots)?;
                try_new_dir(&path, AccessMode::Read, &label)?
            };

            if let Some(mut cap) = maybe_cap {
                cap.source = CapabilitySource::Profile;
                caps.add_fs(cap);
            }
        }

        // Directories with write-only access
        for path_template in &fs.write {
            let path = expand_vars(path_template, workdir)?;
            validate_requested_dir(&path, "Profile", &protected_roots)?;
            let label = format!("Profile path '{}' does not exist, skipping", path_template);
            if let Some(mut cap) = try_new_dir(&path, AccessMode::Write, &label)? {
                cap.source = CapabilitySource::Profile;
                caps.add_fs(cap);
            }
        }

        // Single files with read+write access
        for path_template in &fs.allow_file {
            let path = expand_vars(path_template, workdir)?;
            let label = format!("Profile file '{}' does not exist, skipping", path_template);
            if let Some(mut cap) =
                try_new_profile_exact_path(&path, AccessMode::ReadWrite, &label, &protected_roots)?
            {
                // Also allow atomic-write temp files (e.g. .claude.json.tmp.PID.TS).
                // Many tools write to a temp file then rename for crash safety.
                add_atomic_write_rule(&mut caps, &cap)?;
                cap.source = CapabilitySource::Profile;
                caps.add_fs(cap);
            }
        }

        // Single files with read-only access
        for path_template in &fs.read_file {
            let path = expand_vars(path_template, workdir)?;
            let label = format!("Profile file '{}' does not exist, skipping", path_template);
            if let Some(mut cap) =
                try_new_profile_exact_path(&path, AccessMode::Read, &label, &protected_roots)?
            {
                cap.source = CapabilitySource::Profile;
                caps.add_fs(cap);
            }
        }

        // Single files with write-only access
        for path_template in &fs.write_file {
            let path = expand_vars(path_template, workdir)?;
            let label = format!("Profile file '{}' does not exist, skipping", path_template);
            if let Some(mut cap) =
                try_new_profile_exact_path(&path, AccessMode::Write, &label, &protected_roots)?
            {
                add_atomic_write_rule(&mut caps, &cap)?;
                cap.source = CapabilitySource::Profile;
                caps.add_fs(cap);
            }
        }

        // Policy patch additions
        apply_profile_dir_allows(
            &profile.policy.add_allow_readwrite,
            AccessMode::ReadWrite,
            workdir,
            &protected_roots,
            &mut caps,
            "Profile policy path",
        )?;
        apply_profile_dir_allows(
            &profile.policy.add_allow_read,
            AccessMode::Read,
            workdir,
            &protected_roots,
            &mut caps,
            "Profile policy path",
        )?;
        apply_profile_dir_allows(
            &profile.policy.add_allow_write,
            AccessMode::Write,
            workdir,
            &protected_roots,
            &mut caps,
            "Profile policy path",
        )?;

        for path_template in &profile.policy.add_deny_access {
            let path = expand_vars(path_template, workdir)?;
            let path_str = path.to_str().ok_or_else(|| {
                NonoError::ConfigParse(format!(
                    "Profile policy deny path contains non-UTF-8 bytes: {}",
                    path.display()
                ))
            })?;
            policy::add_deny_access_rules(path_str, &mut caps, &mut resolved.deny_paths)?;
        }

        for cmd in &profile.policy.add_deny_commands {
            caps.add_blocked_command(cmd);
        }

        // Network blocking or proxy mode from profile
        if profile.network.block {
            caps.set_network_blocked(true);
        } else if profile.network.has_proxy_flags() {
            let bind_ports =
                crate::merge_dedup_ports(&profile.network.listen_port, &args.allow_bind);
            // Profile requests proxy mode; port 0 is a placeholder.
            // bind_ports come from profile listen_port plus CLI --listen-port.
            caps = caps.set_network_mode(nono::NetworkMode::ProxyOnly {
                port: 0,
                bind_ports,
            });
        }

        // Localhost IPC ports from profile
        for port in &profile.network.open_port {
            caps.add_localhost_port(*port);
        }

        // Outbound TCP connect port allowlist from profile (Linux Landlock V4+ only)
        #[cfg(target_os = "macos")]
        if !profile.network.connect_port.is_empty() {
            return Err(NonoError::UnsupportedPlatform(
                "profile `connect_port` is not supported on macOS: Seatbelt cannot filter by TCP \
                 port. Use `allow_domain` for host-level filtering, or ProxyOnly mode."
                    .to_string(),
            ));
        }
        #[cfg(not(target_os = "macos"))]
        for port in &profile.network.connect_port {
            caps.add_tcp_connect_port(*port);
        }

        // Apply allowed commands from profile
        for cmd in &profile.security.allowed_commands {
            caps.add_allowed_command(cmd.as_str());
        }

        // Plan 36-01b: canonical `commands.{allow,deny}` section per upstream
        // f0abd413 (v0.47.0). Wired here so that
        // `{"commands": {"deny": ["rm"]}}` profiles take effect at runtime
        // instead of silently no-opping. Fixes CR-01 (REVIEW.md): the
        // canonical section deserialised but was never read by
        // `CapabilitySet::from_profile`.
        for cmd in &profile.commands.allow {
            caps.add_allowed_command(cmd.clone());
        }
        for cmd in &profile.commands.deny {
            caps.add_blocked_command(cmd);
        }

        // Apply signal mode from profile (None defaults to Isolated)
        let mode = profile
            .security
            .signal_mode
            .map(nono::SignalMode::from)
            .unwrap_or_default();
        caps = caps.set_signal_mode(mode);

        // Apply process inspection mode from profile (None defaults to Isolated)
        let process_info_mode = profile
            .security
            .process_info_mode
            .map(nono::ProcessInfoMode::from)
            .unwrap_or_default();
        caps.set_process_info_mode_mut(process_info_mode);

        // Apply IPC mode from profile (None defaults to SharedMemoryOnly)
        let ipc_mode = profile
            .security
            .ipc_mode
            .map(nono::IpcMode::from)
            .unwrap_or_default();
        caps.set_ipc_mode_mut(ipc_mode);

        // Apply CLI overrides (CLI args take precedence)
        add_cli_overrides(&mut caps, args)?;

        // Expand profile-level bypass_protection paths for finalize_caps.
        // Existing override targets must fail closed in apply_deny_overrides
        // when they lack a matching user-intent grant. Non-existent paths are
        // skipped here to preserve platform-specific built-in profiles whose
        // grants are intentionally absent on other OSes.
        let mut profile_overrides = Vec::with_capacity(profile.policy.bypass_protection.len());
        for path_template in &profile.policy.bypass_protection {
            let path = expand_vars(path_template, workdir)?;
            if path.exists() {
                profile_overrides.push(path);
            }
        }

        finalize_caps(
            &mut caps,
            &mut resolved,
            &loaded_policy,
            args,
            &profile_overrides,
        )?;

        Ok(PreparedCaps {
            caps,
            needs_unlink_overrides: resolved.needs_unlink_overrides,
            deny_paths: resolved.deny_paths,
        })
    }
}

/// Shared finalization: deny overrides, overlap validation, keychain exception, dedup.
///
/// Called by both `from_args()` and `from_profile()` after all grants are added.
/// Caller must still call `apply_unlink_overrides()` after CWD and any other
/// writable paths are added, if `resolved.needs_unlink_overrides` is true.
fn finalize_caps(
    caps: &mut CapabilitySet,
    resolved: &mut policy::ResolvedGroups,
    loaded_policy: &policy::Policy,
    args: &SandboxArgs,
    profile_bypass_protection: &[PathBuf],
) -> Result<()> {
    // Apply profile-level deny overrides first, then CLI overrides.
    // Profile overrides come from `policy.bypass_protection` in the profile JSON.
    // CLI `--bypass-protection` flags are applied on top.
    policy::apply_deny_overrides(profile_bypass_protection, &mut resolved.deny_paths, caps)?;
    policy::apply_deny_overrides(&args.bypass_protection, &mut resolved.deny_paths, caps)?;

    // Remove exact file grants for the deny paths that remain after overrides.
    // This lets profile deny patches override inherited file capabilities while
    // preserving `--override-deny` validation against the original grant set.
    caps.remove_exact_file_caps_for_paths(&resolved.deny_paths);

    // Validate deny/allow overlaps (hard-fail on Linux where Landlock cannot enforce denies)
    policy::validate_deny_overlaps(&resolved.deny_paths, caps)?;

    // On macOS, warn when user-granted paths are silently blocked by deny rules.
    // Seatbelt deny rules override earlier allow rules for content access, so the
    // user's --allow/--read/--write has no effect without --override-deny.
    if cfg!(target_os = "macos") {
        for (path, group) in
            policy::find_denied_user_grants(&resolved.deny_paths, caps, loaded_policy)
        {
            let source = group.as_deref().unwrap_or("a deny rule");
            warn!(
                "'{}' is blocked by '{}'; use --override-deny {} to allow access",
                path.display(),
                source,
                path.display(),
            );
        }
    }

    // Keep broad keychain deny groups active, but allow explicit
    // keychain DB read grants (profile/CLI) on macOS.
    policy::apply_macos_keychain_db_exception(caps);

    // Deduplicate capabilities
    caps.deduplicate();

    Ok(())
}

fn apply_cli_network_mode(caps: &mut CapabilitySet, args: &SandboxArgs) {
    if args.block_net {
        caps.set_network_blocked(true);
    } else if args.allow_net {
        caps.set_network_mode_mut(nono::NetworkMode::AllowAll);
    } else if args.has_proxy_flags() {
        // Proxy mode: port 0 is a placeholder, updated when proxy starts.
        // bind_ports are passed through allow_bind CLI flag.
        caps.set_network_mode_mut(nono::NetworkMode::ProxyOnly {
            port: 0,
            bind_ports: args.allow_bind.clone(),
        });
    }
}

/// Apply CLI argument overrides on top of existing capabilities.
///
/// CLI directory args are always added, even if the path is already covered by
/// a profile or group capability. The subsequent `deduplicate()` call resolves
/// conflicts using source priority (User wins over Group/System) and merges
/// complementary access modes (Read + Write = ReadWrite).
fn add_cli_overrides(caps: &mut CapabilitySet, args: &SandboxArgs) -> Result<()> {
    let protected_roots = ProtectedRoots::from_defaults()?;

    // Additional directories from CLI
    for path in &args.allow {
        validate_requested_dir(path, "CLI", &protected_roots)?;
        if let Some(cap) = try_new_dir(path, AccessMode::ReadWrite, "Skipping non-existent path")? {
            caps.add_fs(cap);
        }
    }

    for path in &args.read {
        validate_requested_dir(path, "CLI", &protected_roots)?;
        if let Some(cap) = try_new_dir(path, AccessMode::Read, "Skipping non-existent path")? {
            caps.add_fs(cap);
        }
    }

    for path in &args.write {
        validate_requested_dir(path, "CLI", &protected_roots)?;
        if let Some(cap) = try_new_dir(path, AccessMode::Write, "Skipping non-existent path")? {
            caps.add_fs(cap);
        }
    }

    // Additional files from CLI
    for path in &args.allow_file {
        validate_requested_file(path, "CLI", &protected_roots)?;
        if let Some(cap) = try_new_file(path, AccessMode::ReadWrite, "Skipping non-existent file")?
        {
            caps.add_fs(cap);
        }
    }

    for path in &args.read_file {
        validate_requested_file(path, "CLI", &protected_roots)?;
        if let Some(cap) = try_new_file(path, AccessMode::Read, "Skipping non-existent file")? {
            caps.add_fs(cap);
        }
    }

    for path in &args.write_file {
        validate_requested_file(path, "CLI", &protected_roots)?;
        if let Some(cap) = try_new_file(path, AccessMode::Write, "Skipping non-existent file")? {
            caps.add_fs(cap);
        }
    }

    // CLI network flags override profile network settings.
    apply_cli_network_mode(caps, args);

    // Localhost IPC ports from CLI
    for port in &args.allow_port {
        caps.add_localhost_port(*port);
    }

    // Outbound TCP connect port allowlist from CLI (Linux Landlock V4+ only)
    #[cfg(target_os = "macos")]
    if !args.allow_connect_port.is_empty() {
        return Err(NonoError::UnsupportedPlatform(
            "--allow-connect-port is not supported on macOS: Seatbelt cannot filter by TCP port. \
             Use --allow-domain for host-level filtering, or ProxyOnly mode."
                .to_string(),
        ));
    }
    #[cfg(not(target_os = "macos"))]
    for port in &args.allow_connect_port {
        caps.add_tcp_connect_port(*port);
    }

    // Command allow/block from CLI
    for cmd in &args.allow_command {
        caps.add_allowed_command(cmd.clone());
    }

    for cmd in &args.block_command {
        caps.add_blocked_command(cmd);
    }

    // --allow-gpu CLI override (D-12 upstream parity port).
    //
    // On Windows, the warning fires and the capability is deliberately NOT
    // added — the Windows sandbox state is byte-identical with and without
    // the flag (D-21 invariant).
    args.warn_if_allow_gpu_unsupported_on_platform();
    #[cfg(not(target_os = "windows"))]
    if args.allow_gpu {
        caps.set_gpu(true);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn json_string(path: &Path) -> String {
        serde_json::to_string(&path.display().to_string()).expect("json path")
    }

    fn with_env_lock<T>(f: impl FnOnce() -> T) -> T {
        let _guard = match crate::test_env::ENV_LOCK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        f()
    }

    fn from_args_locked(args: &SandboxArgs) -> Result<(CapabilitySet, bool)> {
        with_env_lock(|| {
            CapabilitySet::from_args(args).map(|prepared| {
                let PreparedCaps {
                    caps,
                    needs_unlink_overrides,
                    ..
                } = prepared;
                (caps, needs_unlink_overrides)
            })
        })
    }

    fn from_profile_locked(
        profile: &crate::profile::Profile,
        workdir: &Path,
        args: &SandboxArgs,
    ) -> Result<(CapabilitySet, bool)> {
        with_env_lock(|| {
            CapabilitySet::from_profile(profile, workdir, args).map(|prepared| {
                let PreparedCaps {
                    caps,
                    needs_unlink_overrides,
                    ..
                } = prepared;
                (caps, needs_unlink_overrides)
            })
        })
    }

    fn sandbox_args() -> SandboxArgs {
        SandboxArgs::default()
    }

    #[test]
    fn test_from_args_basic() {
        let dir = tempdir().expect("Failed to create temp dir");

        let args = SandboxArgs {
            allow: vec![dir.path().to_path_buf()],
            ..sandbox_args()
        };

        let (caps, _) = from_args_locked(&args).expect("Failed to build caps");
        assert!(caps.has_fs());
        assert!(!caps.is_network_blocked());
    }

    #[test]
    fn test_from_args_network_blocked() {
        let args = SandboxArgs {
            block_net: true,
            ..sandbox_args()
        };

        let (caps, _) = from_args_locked(&args).expect("Failed to build caps");
        assert!(caps.is_network_blocked());
    }

    #[test]
    fn test_from_args_with_commands() {
        let args = SandboxArgs {
            bypass_protection: vec![],
            allow_command: vec!["rm".to_string()],
            block_command: vec!["custom".to_string()],
            ..sandbox_args()
        };

        let (caps, _) = from_args_locked(&args).expect("Failed to build caps");
        assert!(caps.allowed_commands().contains(&"rm".to_string()));
        assert!(caps.blocked_commands().contains(&"custom".to_string()));
    }

    #[test]
    fn test_from_args_rejects_protected_state_subtree() {
        with_env_lock(|| {
            let protected_subtree = ProtectedRoots::from_defaults()
                .expect("protected roots")
                .as_paths()
                .first()
                .expect("at least one protected root")
                .join("rollbacks");

            let args = SandboxArgs {
                allow: vec![protected_subtree],
                ..sandbox_args()
            };

            let err =
                CapabilitySet::from_args(&args).expect_err("must reject protected state path");
            assert!(
                err.to_string()
                    .contains("overlaps protected nono state root"),
                "unexpected error: {err}",
            );
        });
    }

    #[test]
    fn test_from_args_uses_default_profile_groups_for_runtime_policy() {
        with_env_lock(|| {
            let args = sandbox_args();
            let PreparedCaps { caps, .. } =
                CapabilitySet::from_args(&args).expect("build caps from args");

            let policy = crate::policy::load_embedded_policy().expect("load embedded policy");
            let default_groups = default_profile_groups().expect("get default profile groups");
            let deny_paths = crate::policy::resolve_deny_paths_for_groups(&policy, &default_groups)
                .expect("resolve deny paths");

            crate::policy::validate_deny_overlaps(&deny_paths, &caps)
                .expect("from_args caps should match default profile deny policy");
        });
    }

    // --allow-gpu wiring (D-12 upstream parity port).
    //
    // T-20-04-05 Windows-invariance regression guards:
    // On Windows, the CapabilitySet produced from `from_args` MUST have
    // `gpu() == false` regardless of the CLI flag. The enforcement layer
    // (CLI warning) lives in cli.rs; the capability bit is deliberately
    // NOT set so the Windows sandbox backend (sandbox/windows.rs) never
    // observes a GPU-related capability.

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_from_args_allow_gpu_sets_capability_on_unix() {
        let args = SandboxArgs {
            allow_gpu: true,
            ..sandbox_args()
        };

        let (caps, _) = from_args_locked(&args).expect("build caps with --allow-gpu");
        assert!(
            caps.gpu(),
            "on Linux/macOS, --allow-gpu must set CapabilitySet::gpu()"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_from_args_allow_gpu_is_noop_on_windows() {
        let args = SandboxArgs {
            allow_gpu: true,
            ..sandbox_args()
        };

        let (caps, _) = from_args_locked(&args).expect("build caps with --allow-gpu");
        assert!(
            !caps.gpu(),
            "D-21 invariant: on Windows --allow-gpu must NOT set CapabilitySet::gpu() \
             (the WFP + Job Object backend has no GPU primitive)"
        );
    }

    #[test]
    fn test_from_args_without_allow_gpu_never_sets_capability() {
        let args = SandboxArgs {
            allow_gpu: false,
            ..sandbox_args()
        };
        let (caps, _) = from_args_locked(&args).expect("build caps");
        assert!(
            !caps.gpu(),
            "T-20-04-01: without --allow-gpu the GPU bit must not be set"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_from_args_windows_sandbox_state_invariant_with_vs_without_allow_gpu() {
        // D-21 must-have proof: the Windows sandbox state (captured via
        // SandboxState::from_caps) is byte-identical with and without
        // --allow-gpu. The GPU bit lives outside SandboxState by design,
        // so even structurally no Windows sandbox capability changes.
        use nono::SandboxState;

        let args_on = SandboxArgs {
            allow_gpu: true,
            ..sandbox_args()
        };
        let args_off = SandboxArgs {
            allow_gpu: false,
            ..sandbox_args()
        };

        let (caps_on, _) = from_args_locked(&args_on).expect("build on");
        let (caps_off, _) = from_args_locked(&args_off).expect("build off");

        let state_on = SandboxState::from_caps(&caps_on)
            .to_json()
            .expect("serialize on");
        let state_off = SandboxState::from_caps(&caps_off)
            .to_json()
            .expect("serialize off");

        assert_eq!(
            state_on, state_off,
            "Windows sandbox state must be byte-identical with and without --allow-gpu"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_from_args_skips_linux_temp_root_when_home_is_nested() {
        // Use `keep()` so the temp dir is NOT auto-deleted. Tests that call
        // `tempdir()` concurrently (without the env lock) may create dirs
        // inside our temp_root while TMPDIR points to it. If we deleted it,
        // those dirs would vanish and cause flaky failures.
        let temp_root = tempdir().expect("tmpdir").keep();
        let home = temp_root.join("home");
        let allowed = temp_root.join("other");
        std::fs::create_dir_all(&home).expect("create home");
        std::fs::create_dir_all(&allowed).expect("create allowed dir");

        let _guard = match crate::test_env::ENV_LOCK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        let home_str = home.to_string_lossy().into_owned();
        let tmpdir_str = temp_root.to_string_lossy().into_owned();
        let _env = crate::test_env::EnvVarGuard::set_all(&[
            ("HOME", home_str.as_str()),
            ("TMPDIR", tmpdir_str.as_str()),
        ]);

        let args = SandboxArgs {
            allow: vec![allowed.clone()],
            ..sandbox_args()
        };

        let result = CapabilitySet::from_args(&args);

        let PreparedCaps { caps, .. } = result.expect(
            "from_args should succeed when HOME is nested under TMPDIR and the user grants a sibling path",
        );
        let allowed_canonical = allowed.canonicalize().expect("canonicalize allowed dir");
        assert!(
            caps.fs_capabilities()
                .iter()
                .any(|cap| !cap.is_file && cap.resolved == allowed_canonical),
            "explicit user grant under TMPDIR should still be present"
        );
    }

    #[test]
    fn test_from_profile_allowed_commands() {
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("rm-test.json");
        std::fs::write(
            &profile_path,
            r#"{
                "meta": { "name": "rm-test" },
                "filesystem": { "allow": ["/tmp"] },
                "security": { "allowed_commands": ["rm", "shred"] }
            }"#,
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let args = sandbox_args();

        let (caps, _) = from_profile_locked(&profile, workdir.path(), &args).expect("build caps");
        assert!(
            caps.allowed_commands().contains(&"rm".to_string()),
            "profile allowed_commands should include 'rm'"
        );
        assert!(
            caps.allowed_commands().contains(&"shred".to_string()),
            "profile allowed_commands should include 'shred'"
        );
    }

    /// CR-01 regression (REVIEW.md, Plan 36-01b): the canonical
    /// `commands.{allow,deny}` profile section must wire into
    /// `CapabilitySet::from_profile`. Before the fix, this profile
    /// section deserialised but was never read, silently no-opping
    /// security-relevant deny rules (fail-open).
    #[test]
    fn test_from_profile_commands_allow_deny_canonical_section() {
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("commands-canonical.json");
        std::fs::write(
            &profile_path,
            r#"{
                "meta": { "name": "commands-canonical" },
                "filesystem": { "allow": ["/tmp"] },
                "commands": {
                    "allow": ["git", "cargo"],
                    "deny": ["rm", "dd"]
                }
            }"#,
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let args = sandbox_args();

        let (caps, _) = from_profile_locked(&profile, workdir.path(), &args).expect("build caps");

        // Canonical `commands.allow` must appear in allowed_commands().
        assert!(
            caps.allowed_commands().contains(&"git".to_string()),
            "profile commands.allow should include 'git' (CR-01)"
        );
        assert!(
            caps.allowed_commands().contains(&"cargo".to_string()),
            "profile commands.allow should include 'cargo' (CR-01)"
        );

        // Canonical `commands.deny` must appear in blocked_commands().
        // This is the security-correctness invariant: a profile that says
        // "deny rm" must structurally deny `rm`, not silently allow it.
        assert!(
            caps.blocked_commands().contains(&"rm".to_string()),
            "profile commands.deny should include 'rm' (CR-01 fail-secure)"
        );
        assert!(
            caps.blocked_commands().contains(&"dd".to_string()),
            "profile commands.deny should include 'dd' (CR-01 fail-secure)"
        );
    }

    #[test]
    fn test_from_profile_filesystem_read_accepts_file_paths() {
        let dir = tempdir().expect("tmpdir");
        let read_file = dir.path().join("config.txt");
        std::fs::write(&read_file, "token=123").expect("write file");

        let profile_path = dir.path().join("read-file-profile.json");
        // Use json_string() to emit a properly-escaped JSON string literal
        // for the path. On Windows `read_file.display()` is a path like
        // `C:\Users\...\config.txt` whose backslashes form invalid JSON
        // escape sequences (`\U`, `\c`) when inlined into the raw string.
        std::fs::write(
            &profile_path,
            format!(
                r#"{{
                "meta": {{ "name": "read-file-profile" }},
                "filesystem": {{ "read": [{read}] }}
            }}"#,
                read = json_string(&read_file),
            ),
        )
        .expect("write profile");

        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");
        let workdir = tempdir().expect("workdir");
        let args = sandbox_args();

        let (caps, _) = from_profile_locked(&profile, workdir.path(), &args).expect("build caps");
        let resolved_file = read_file.canonicalize().expect("canonicalize file");

        assert!(
            caps.fs_capabilities().iter().any(|cap| {
                cap.is_file && cap.access == AccessMode::Read && cap.resolved == resolved_file
            }),
            "filesystem.read file entries should be granted as read-only file capabilities"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_from_profile_allow_file_keeps_missing_exact_file_on_macos() {
        let dir = tempdir().expect("tmpdir");
        let missing_file = dir.path().join("future.lock");
        let expected_resolved = dir.path().canonicalize().expect("canonicalize dir").join(
            missing_file
                .file_name()
                .expect("future file should have file name"),
        );

        let profile_path = dir.path().join("missing-file-profile.json");
        std::fs::write(
            &profile_path,
            format!(
                r#"{{
                "meta": {{ "name": "missing-file-profile" }},
                "filesystem": {{ "allow_file": ["{}"] }}
            }}"#,
                missing_file.display()
            ),
        )
        .expect("write profile");

        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");
        let workdir = tempdir().expect("workdir");
        let args = sandbox_args();

        let (caps, _) = from_profile_locked(&profile, workdir.path(), &args).expect("build caps");

        assert!(
            caps.fs_capabilities().iter().any(|cap| {
                cap.is_file
                    && cap.access == AccessMode::ReadWrite
                    && cap.original == missing_file
                    && cap.resolved == expected_resolved
            }),
            "macOS profiles should preserve explicit missing exact-file grants"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_from_args_allow_file_resolves_parent_symlinks_for_missing_file_on_macos() {
        let dir = tempdir().expect("tmpdir");
        let target_dir = dir.path().join("target");
        let link_dir = dir.path().join("link");
        std::fs::create_dir_all(&target_dir).expect("create target dir");
        std::os::unix::fs::symlink(&target_dir, &link_dir).expect("create symlink");

        let missing_file = link_dir.join("future.lock");
        let resolved_file = target_dir
            .canonicalize()
            .expect("canonicalize target dir")
            .join("future.lock");
        let args = SandboxArgs {
            allow_file: vec![missing_file.clone()],
            ..sandbox_args()
        };

        let (caps, _) = from_args_locked(&args).expect("build caps");

        assert!(
            caps.fs_capabilities().iter().any(|cap| {
                cap.is_file
                    && cap.access == AccessMode::ReadWrite
                    && cap.original == missing_file
                    && cap.resolved == resolved_file
            }),
            "macOS CLI exact-file grants should preserve original path and resolve parent symlinks"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_from_profile_allow_file_falls_back_to_exact_directory_when_present() {
        let dir = tempdir().expect("tmpdir");
        let lock_dir = dir.path().join("claude.lock");
        std::fs::create_dir_all(&lock_dir).expect("create lock dir");
        let resolved_dir = lock_dir.canonicalize().expect("canonicalize lock dir");
        let child = lock_dir.join("nested.txt");

        let profile_path = dir.path().join("lock-dir-profile.json");
        std::fs::write(
            &profile_path,
            format!(
                r#"{{
                "meta": {{ "name": "lock-dir-profile" }},
                "filesystem": {{ "allow_file": ["{}"] }}
            }}"#,
                lock_dir.display()
            ),
        )
        .expect("write profile");

        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");
        let workdir = tempdir().expect("workdir");
        let args = sandbox_args();

        let (caps, _) = from_profile_locked(&profile, workdir.path(), &args).expect("build caps");

        assert!(
            caps.fs_capabilities().iter().any(|cap| {
                cap.is_file
                    && cap.access == AccessMode::ReadWrite
                    && cap.original == lock_dir
                    && cap.resolved == resolved_dir
            }),
            "macOS profiles should preserve exact-path semantics when an allow_file entry resolves to a directory"
        );
        assert!(
            !caps.path_covered(&child),
            "exact-path fallback must not recursively cover descendants"
        );
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn test_from_profile_allow_file_rejects_directory_when_exact_dir_unsupported() {
        let dir = tempdir().expect("tmpdir");
        let lock_dir = dir.path().join("claude.lock");
        std::fs::create_dir_all(&lock_dir).expect("create lock dir");

        let profile_path = dir.path().join("lock-dir-profile.json");
        // Use json_string() to emit a properly-escaped JSON string literal
        // for the path. On Windows `lock_dir.display()` is a path like
        // `C:\Users\...\claude.lock` whose backslashes form invalid JSON
        // escape sequences when inlined into the raw string.
        std::fs::write(
            &profile_path,
            format!(
                r#"{{
                "meta": {{ "name": "lock-dir-profile" }},
                "filesystem": {{ "allow_file": [{lock}] }}
            }}"#,
                lock = json_string(&lock_dir),
            ),
        )
        .expect("write profile");

        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");
        let workdir = tempdir().expect("workdir");
        let args = sandbox_args();

        let err = from_profile_locked(&profile, workdir.path(), &args).expect_err("should fail");
        assert!(
            matches!(err, NonoError::ExpectedFile(ref p) if p == &lock_dir),
            "expected exact-file entries resolving to directories to fail closed, got: {err}"
        );
    }

    #[test]
    fn test_from_profile_policy_exclude_groups_removes_non_required_group() {
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("exclude-groups.json");
        std::fs::write(
            &profile_path,
            r#"{
                "meta": { "name": "exclude-groups" },
                "filesystem": { "allow": ["/tmp"] },
                "policy": {
                    "exclude_groups": ["dangerous_commands", "dangerous_commands_linux"]
                }
            }"#,
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let args = sandbox_args();

        let (caps, _) = from_profile_locked(&profile, workdir.path(), &args).expect("build caps");
        assert!(
            !caps.blocked_commands().contains(&"rm".to_string()),
            "excluded dangerous_commands should remove rm from blocked commands"
        );
        assert!(
            !caps.blocked_commands().contains(&"shred".to_string()),
            "excluded dangerous_commands_linux should remove shred from blocked commands"
        );
    }

    #[test]
    fn test_from_loaded_profile_extends_default_respects_excluded_blocked_commands() {
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("no-dangerous-commands.json");
        std::fs::write(
            &profile_path,
            r#"{
                "meta": { "name": "no-dangerous-commands", "version": "1.0.0" },
                "extends": "default",
                "policy": {
                    "exclude_groups": [
                        "dangerous_commands",
                        "dangerous_commands_linux",
                        "dangerous_commands_macos"
                    ]
                },
                "workdir": { "access": "readwrite" }
            }"#,
        )
        .expect("write profile");

        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");
        let workdir = tempdir().expect("workdir");
        let args = sandbox_args();
        let (caps, _) = from_profile_locked(&profile, workdir.path(), &args).expect("build caps");

        assert!(
            !caps.blocked_commands().contains(&"rm".to_string()),
            "excluded dangerous_commands should remove rm from blocked commands"
        );
        assert!(
            !caps.blocked_commands().contains(&"shred".to_string()),
            "excluded dangerous_commands_linux should remove shred from blocked commands"
        );
    }

    #[test]
    fn test_from_profile_policy_add_allow_paths_add_capabilities() {
        let dir = tempdir().expect("tmpdir");
        let read_dir = dir.path().join("read-dir");
        let write_dir = dir.path().join("write-dir");
        let rw_dir = dir.path().join("rw-dir");
        std::fs::create_dir_all(&read_dir).expect("mkdir read");
        std::fs::create_dir_all(&write_dir).expect("mkdir write");
        std::fs::create_dir_all(&rw_dir).expect("mkdir rw");

        let profile_path = dir.path().join("policy-adds.json");
        std::fs::write(
            &profile_path,
            format!(
                r#"{{
                    "meta": {{ "name": "policy-adds" }},
                    "policy": {{
                        "add_allow_read": [{read}],
                        "add_allow_write": [{write}],
                        "add_allow_readwrite": [{readwrite}]
                    }}
                }}"#,
                read = json_string(&read_dir),
                write = json_string(&write_dir),
                readwrite = json_string(&rw_dir),
            ),
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let args = sandbox_args();

        let (caps, _) = from_profile_locked(&profile, workdir.path(), &args).expect("build caps");

        let read_canonical = read_dir.canonicalize().expect("canonicalize read");
        let write_canonical = write_dir.canonicalize().expect("canonicalize write");
        let rw_canonical = rw_dir.canonicalize().expect("canonicalize rw");

        let read_cap = caps
            .fs_capabilities()
            .iter()
            .find(|c| c.resolved == read_canonical)
            .expect("read dir cap");
        let write_cap = caps
            .fs_capabilities()
            .iter()
            .find(|c| c.resolved == write_canonical)
            .expect("write dir cap");
        let rw_cap = caps
            .fs_capabilities()
            .iter()
            .find(|c| c.resolved == rw_canonical)
            .expect("rw dir cap");

        assert_eq!(read_cap.access, AccessMode::Read);
        assert_eq!(write_cap.access, AccessMode::Write);
        assert_eq!(rw_cap.access, AccessMode::ReadWrite);
    }

    /// Regression test for the `--allow-cwd` deny-bypass bug.
    ///
    /// A profile that denies `$WORKDIR/.ssh` must not be silently neutralised
    /// when the caller adds the workdir as an allow path *after* `from_profile`
    /// returns (which is what `--allow-cwd` does in `prepare_sandbox`). The
    /// fix exposes `PreparedCaps::deny_paths` so the caller can re-run
    /// `validate_deny_overlaps` against the full set of grants and fail closed
    /// on Linux.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_prepared_caps_deny_paths_catch_post_profile_cwd_overlap() {
        let dir = tempdir().expect("tmpdir");
        let workdir = dir.path().join("project");
        let denied = workdir.join(".ssh");
        std::fs::create_dir_all(&denied).expect("mkdir denied child");

        // Exclude `system_write_linux` (default group) — it grants write to
        // `/tmp`, which the test's tempdir lives under. Without the exclusion
        // the *initial* validate_deny_overlaps inside from_profile fires on
        // that group's `/tmp` allow vs our deny under `/tmp/.../.ssh`, before
        // we ever get to exercise the post-CWD validation that is the actual
        // subject of this regression.
        let profile_path = dir.path().join("post-cwd-deny.json");
        std::fs::write(
            &profile_path,
            format!(
                r#"{{
                    "meta": {{ "name": "post-cwd-deny" }},
                    "policy": {{
                        "exclude_groups": ["system_write_linux"],
                        "add_deny_access": ["{}"]
                    }}
                }}"#,
                denied.display()
            ),
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        with_env_lock(|| {
            // from_profile succeeds because CWD is not yet present in caps.
            let prepared = CapabilitySet::from_profile(&profile, &workdir, &sandbox_args())
                .expect("profile builds (no CWD allow yet)");

            assert!(
                prepared.deny_paths.iter().any(|p| p == &denied),
                "PreparedCaps::deny_paths must include profile add_deny_access entries; \
                 got {:?}",
                prepared.deny_paths,
            );

            // Simulate the --allow-cwd grant added by prepare_sandbox.
            let mut caps = prepared.caps;
            let cwd_canonical = workdir.canonicalize().expect("canonicalize workdir");
            let cap = nono::FsCapability::new_dir(cwd_canonical, AccessMode::ReadWrite)
                .expect("build cwd cap");
            caps.add_fs(cap);

            // Re-validating against the same deny set must now reject the
            // configuration: Landlock cannot enforce a deny under an allow.
            let err = crate::policy::validate_deny_overlaps(&prepared.deny_paths, &caps)
                .expect_err("post-CWD validation must fail on linux");
            assert!(
                err.to_string().contains("Landlock deny-overlap"),
                "unexpected error: {err}"
            );
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_from_profile_policy_add_deny_access_participates_in_overlap_validation() {
        let dir = tempdir().expect("tmpdir");
        let allowed = dir.path().join("allowed");
        let denied = allowed.join("child");
        std::fs::create_dir_all(&denied).expect("mkdir denied child");

        let profile_path = dir.path().join("policy-deny.json");
        std::fs::write(
            &profile_path,
            format!(
                r#"{{
                    "meta": {{ "name": "policy-deny" }},
                    "policy": {{
                        "add_allow_readwrite": ["{}"],
                        "add_deny_access": ["{}"]
                    }}
                }}"#,
                allowed.display(),
                denied.display()
            ),
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let args = sandbox_args();

        let err = from_profile_locked(&profile, workdir.path(), &args)
            .expect_err("profile deny overlap should fail on linux");
        assert!(
            err.to_string().contains("Landlock deny-overlap"),
            "unexpected error: {err}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_from_profile_policy_add_deny_access_tracks_symlink_target_for_overlap_validation() {
        let dir = tempdir().expect("tmpdir");
        let target_dir = dir.path().join("target");
        let denied_target = target_dir.join("child");
        std::fs::create_dir_all(&denied_target).expect("mkdir denied target");

        let symlink_dir = dir.path().join("symlinked");
        std::os::unix::fs::symlink(&denied_target, &symlink_dir).expect("create symlink");

        let profile_path = dir.path().join("policy-deny-symlink.json");
        std::fs::write(
            &profile_path,
            format!(
                r#"{{
                    "meta": {{ "name": "policy-deny-symlink" }},
                    "policy": {{
                        "add_allow_readwrite": ["{}"],
                        "add_deny_access": ["{}"]
                    }}
                }}"#,
                target_dir.display(),
                symlink_dir.display()
            ),
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let args = sandbox_args();

        let err = from_profile_locked(&profile, workdir.path(), &args)
            .expect_err("symlinked deny overlap should fail on linux");
        assert!(
            err.to_string().contains("Landlock deny-overlap"),
            "unexpected error: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_from_profile_policy_add_deny_access_removes_symlinked_file_grant() {
        let dir = tempdir().expect("tmpdir");
        let target = dir.path().join("real_gitconfig");
        std::fs::write(&target, "[user]\n").expect("write target");
        let target_canonical = target.canonicalize().expect("canonicalize target");
        let link = dir.path().join(".gitconfig");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");

        let profile_path = dir.path().join("policy-deny-file-symlink.json");
        std::fs::write(
            &profile_path,
            format!(
                r#"{{
                    "meta": {{ "name": "policy-deny-file-symlink" }},
                    "filesystem": {{
                        "read_file": ["{}"]
                    }},
                    "policy": {{
                        "exclude_groups": ["system_read_linux", "system_write_linux"],
                        "add_deny_access": ["{}"]
                    }}
                }}"#,
                target.display(),
                link.display()
            ),
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let args = sandbox_args();

        let (caps, _) = from_profile_locked(&profile, workdir.path(), &args).expect("build caps");

        assert!(
            !caps
                .fs_capabilities()
                .iter()
                .any(|cap| cap.is_file && cap.resolved == target_canonical),
            "deny patch should remove the inherited file grant for the symlink target"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_from_profile_policy_add_deny_access_respects_override_deny_for_symlinked_file() {
        let dir = tempdir().expect("tmpdir");
        let target = dir.path().join("real_gitconfig");
        std::fs::write(&target, "[user]\n").expect("write target");
        let target_canonical = target.canonicalize().expect("canonicalize target");
        let link = dir.path().join(".gitconfig");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");

        let profile_path = dir.path().join("policy-deny-file-symlink-override.json");
        std::fs::write(
            &profile_path,
            format!(
                r#"{{
                    "meta": {{ "name": "policy-deny-file-symlink-override" }},
                    "filesystem": {{
                        "read_file": ["{}"]
                    }},
                    "policy": {{
                        "exclude_groups": ["system_read_linux", "system_write_linux"],
                        "add_deny_access": ["{}"]
                    }}
                }}"#,
                target.display(),
                link.display()
            ),
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let mut args = sandbox_args();
        args.bypass_protection = vec![target.clone()];

        let (caps, _) = from_profile_locked(&profile, workdir.path(), &args).expect("build caps");

        assert!(
            caps.fs_capabilities()
                .iter()
                .any(|cap| cap.is_file && cap.resolved == target_canonical),
            "override should preserve the inherited file grant for the denied symlink target"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_from_profile_policy_override_deny_via_symlink_path() {
        let dir = tempdir().expect("tmpdir");
        let target = dir.path().join("real_gitconfig");
        std::fs::write(&target, "[user]\n").expect("write target");
        let target_canonical = target.canonicalize().expect("canonicalize target");
        let link = dir.path().join(".gitconfig");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");

        // Override via the symlink path (not the canonical target)
        let profile_path = dir.path().join("override-deny-symlink.json");
        std::fs::write(
            &profile_path,
            format!(
                r#"{{
                    "meta": {{ "name": "override-deny-symlink" }},
                    "filesystem": {{
                        "read_file": ["{target}"]
                    }},
                    "policy": {{
                        "add_deny_access": ["{link}"],
                        "bypass_protection": ["{link}"]
                    }}
                }}"#,
                target = target.display(),
                link = link.display()
            ),
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let args = sandbox_args();

        let (caps, _) = from_profile_locked(&profile, workdir.path(), &args).expect("build caps");

        assert!(
            caps.fs_capabilities()
                .iter()
                .any(|cap| cap.is_file && cap.resolved == target_canonical),
            "override via symlink path should preserve the file grant for the canonical target"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_from_profile_workdir_deny_env_extends_claude_code() {
        let workdir = tempdir().expect("workdir");
        std::fs::write(workdir.path().join(".env"), "SECRET=test").expect("write .env");

        let profile_path = workdir.path().join("deny-env.json");
        std::fs::write(
            &profile_path,
            r#"{
                "extends": "claude-code",
                "meta": { "name": "claude-code-deny-env" },
                "policy": {
                    "add_deny_access": ["$WORKDIR/.env"]
                }
            }"#,
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let args = sandbox_args();
        let (caps, _) = from_profile_locked(&profile, workdir.path(), &args).expect("build caps");

        let rules = caps.platform_rules().join("\n");
        // On macOS, tempdir is under /var/folders which is a symlink to /private/var/folders.
        // The deny rule must use the canonical path so it matches the kernel-resolved path
        // that Seatbelt sees at runtime.
        let env_path = workdir.path().join(".env");
        let env_canonical = env_path.canonicalize().expect("canonicalize .env");

        // Check: does the deny rule use the canonical path?
        let has_canonical_deny = rules.contains(&format!(
            "deny file-read-data (literal \"{}\")",
            env_canonical.display()
        ));
        // Check: does the deny rule use the original (possibly non-canonical) path?
        let has_original_deny = rules.contains(&format!(
            "deny file-read-data (literal \"{}\")",
            env_path.display()
        ));

        // The deny must cover the canonical path, otherwise Seatbelt won't enforce it
        assert!(
            has_canonical_deny,
            "deny rule must use canonical path {}.\n\
             Has original path deny: {}\n\
             Original path: {}\n\
             Canonical path: {}\n\
             All platform rules:\n{}",
            env_canonical.display(),
            has_original_deny,
            env_path.display(),
            env_canonical.display(),
            rules
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_from_profile_policy_add_deny_access_emits_seatbelt_rules() {
        let dir = tempdir().expect("tmpdir");
        let denied = dir.path().join("denied");
        std::fs::create_dir_all(&denied).expect("mkdir denied");

        let profile_path = dir.path().join("policy-deny-macos.json");
        std::fs::write(
            &profile_path,
            format!(
                r#"{{
                    "meta": {{ "name": "policy-deny-macos" }},
                    "policy": {{
                        "add_deny_access": ["{}"]
                    }}
                }}"#,
                denied.display()
            ),
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let args = sandbox_args();

        let (caps, _) = from_profile_locked(&profile, workdir.path(), &args).expect("build caps");

        let rules = caps.platform_rules().join("\n");
        assert!(
            rules.contains("deny file-read-data"),
            "expected macOS deny read rule, got:\n{}",
            rules
        );
        assert!(
            rules.contains("deny file-write*"),
            "expected macOS deny write rule, got:\n{}",
            rules
        );
    }

    #[test]
    fn test_from_profile_policy_override_deny_punches_through_deny_group() {
        let dir = tempdir().expect("tmpdir");
        let denied = dir.path().join("denied_dir");
        std::fs::create_dir_all(&denied).expect("mkdir denied");

        let profile_path = dir.path().join("override-deny-profile.json");
        std::fs::write(
            &profile_path,
            format!(
                r#"{{
                    "meta": {{ "name": "override-deny-test" }},
                    "policy": {{
                        "add_allow_readwrite": [{path}],
                        "add_deny_access": [{path}],
                        "bypass_protection": [{path}]
                    }}
                }}"#,
                path = json_string(&denied),
            ),
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let args = sandbox_args();

        let (caps, _) = from_profile_locked(&profile, workdir.path(), &args).expect("build caps");

        // The allow should survive because bypass_protection punches through the deny
        let canonical = denied.canonicalize().expect("canonicalize");
        assert!(
            caps.fs_capabilities()
                .iter()
                .any(|cap| !cap.is_file && cap.resolved == canonical),
            "bypass_protection should preserve the directory grant despite deny group"
        );
    }

    #[test]
    fn test_from_profile_policy_override_deny_requires_matching_grant() {
        // Override path is under temp dir which is covered by system groups,
        // but the grant check requires user-intent sources (User/Profile),
        // so group coverage is not sufficient.
        let dir = tempdir().expect("tmpdir");
        let denied = dir.path().join("denied_no_grant");
        std::fs::create_dir_all(&denied).expect("mkdir denied");

        let profile_path = dir.path().join("override-deny-no-grant.json");
        std::fs::write(
            &profile_path,
            format!(
                r#"{{
                    "meta": {{ "name": "override-deny-no-grant" }},
                    "policy": {{
                        "add_deny_access": [{path}],
                        "bypass_protection": [{path}]
                    }}
                }}"#,
                path = json_string(&denied),
            ),
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let args = sandbox_args();

        let err = from_profile_locked(&profile, workdir.path(), &args)
            .expect_err("bypass_protection without user-intent grant should fail");
        assert!(
            err.to_string().contains("no matching grant"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_profile_override_deny_requires_matching_grant() {
        // Upstream 5c301e8d adds this test at the same call-site as the
        // fork's existing test_from_profile_policy_override_deny_requires_matching_grant.
        // Both exercise the same fail-closed path; this one is preserved AS-IS
        // for upstream-provenance traceability (D-19) but routed through the
        // json_string helper so the JSON literal escapes Windows path separators.
        let dir = tempdir().expect("tmpdir");
        let denied = dir.path().join("denied_no_grant");
        std::fs::create_dir_all(&denied).expect("mkdir denied");

        let profile_path = dir.path().join("override-deny-no-grant.json");
        std::fs::write(
            &profile_path,
            format!(
                r#"{{
                    "meta": {{ "name": "override-deny-no-grant" }},
                    "policy": {{
                        "add_deny_access": [{path}],
                        "bypass_protection": [{path}]
                    }}
                }}"#,
                path = json_string(&denied),
            ),
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let args = sandbox_args();

        let err = from_profile_locked(&profile, workdir.path(), &args)
            .expect_err("profile bypass_protection without grant should fail");
        assert!(
            err.to_string().contains("no matching grant"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_from_profile_with_groups() {
        let profile = crate::profile::load_profile("claude-code")
            .expect("Failed to load claude-code profile");

        let workdir = tempdir().expect("Failed to create temp dir");
        let args = sandbox_args();

        let (mut caps, needs_unlink_overrides) =
            from_profile_locked(&profile, workdir.path(), &args).expect("Failed to build");

        // Simulate what main.rs does: apply unlink overrides after all paths finalized
        if needs_unlink_overrides {
            policy::apply_unlink_overrides(&mut caps);
        }

        // Groups should have populated filesystem capabilities
        assert!(caps.has_fs());

        if cfg!(target_os = "macos") {
            // On macOS: deny groups generate Seatbelt platform rules
            assert!(!caps.platform_rules().is_empty());

            let rules = caps.platform_rules().join("\n");
            assert!(rules.contains("deny file-read-data"));
            assert!(rules.contains("deny file-write*"));

            // Unlink protection should be present
            assert!(rules.contains("deny file-write-unlink"));

            // Unlink overrides must exist for writable paths (including ~/.claude from
            // the profile [filesystem] section, which is added AFTER group resolution).
            assert!(
                rules.contains("allow file-write-unlink"),
                "Expected unlink overrides for writable paths, got:\n{}",
                rules
            );
        }
        // On Linux: deny/unlink rules are not generated (Landlock has no deny semantics),
        // but deny_paths are collected for overlap validation.

        // Dangerous commands should be blocked (cross-platform)
        assert!(caps.blocked_commands().contains(&"rm".to_string()));
        assert!(caps.blocked_commands().contains(&"dd".to_string()));
    }

    #[test]
    fn test_cli_allow_upgrades_profile_read_path() {
        // Regression test: a profile sets a path as read-only, and --allow on
        // the CLI should upgrade it to ReadWrite. Previously, path_covered()
        // in add_cli_overrides() silently dropped the CLI entry because it
        // only checked path containment, not access mode.
        let dir = tempdir().expect("tmpdir");
        let target = dir.path().join("readonly_dir");
        std::fs::create_dir(&target).expect("create target dir");

        let profile_path = dir.path().join("test-profile.json");
        std::fs::write(
            &profile_path,
            format!(
                r#"{{
                    "meta": {{ "name": "test-upgrade" }},
                    "filesystem": {{ "read": [{path}] }}
                }}"#,
                path = json_string(&target),
            ),
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let args = SandboxArgs {
            allow: vec![target.clone()],
            ..sandbox_args()
        };

        let (caps, _) = from_profile_locked(&profile, workdir.path(), &args).expect("build caps");

        let canonical = target.canonicalize().expect("canonicalize target");
        let cap = caps
            .fs_capabilities()
            .iter()
            .find(|c| c.resolved == canonical)
            .expect("target path should be in capabilities");

        assert_eq!(
            cap.access,
            AccessMode::ReadWrite,
            "CLI --allow should upgrade profile read-only path to ReadWrite, got {:?}",
            cap.access,
        );
    }

    #[test]
    fn test_cli_write_merges_with_profile_read_path() {
        // Same regression but with --write instead of --allow.
        // Profile read + CLI write should merge to ReadWrite.
        let dir = tempdir().expect("tmpdir");
        let target = dir.path().join("readonly_dir");
        std::fs::create_dir(&target).expect("create target dir");

        let profile_path = dir.path().join("test-profile.json");
        std::fs::write(
            &profile_path,
            format!(
                r#"{{
                    "meta": {{ "name": "test-merge" }},
                    "filesystem": {{ "read": [{path}] }}
                }}"#,
                path = json_string(&target),
            ),
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let args = SandboxArgs {
            write: vec![target.clone()],
            ..sandbox_args()
        };

        let (caps, _) = from_profile_locked(&profile, workdir.path(), &args).expect("build caps");

        let canonical = target.canonicalize().expect("canonicalize target");
        let cap = caps
            .fs_capabilities()
            .iter()
            .find(|c| c.resolved == canonical)
            .expect("target path should be in capabilities");

        assert_eq!(
            cap.access,
            AccessMode::ReadWrite,
            "CLI --write + profile read should merge to ReadWrite, got {:?}",
            cap.access,
        );
    }

    #[test]
    fn test_from_profile_allow_net_overrides_proxy_mode() {
        let profile = crate::profile::load_profile("claude-code")
            .expect("Failed to load claude-code profile");
        let workdir = tempdir().expect("workdir");
        let args = SandboxArgs {
            allow_net: true,
            ..sandbox_args()
        };

        let (caps, _) = from_profile_locked(&profile, workdir.path(), &args).expect("build caps");

        assert_eq!(*caps.network_mode(), nono::NetworkMode::AllowAll);
    }

    #[test]
    fn test_from_profile_allow_net_overrides_blocked_network() {
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("blocked.json");
        std::fs::write(
            &profile_path,
            r#"{
                "meta": { "name": "blocked" },
                "filesystem": { "allow": ["/tmp"] },
                "network": { "block": true }
            }"#,
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let args = SandboxArgs {
            allow_net: true,
            ..sandbox_args()
        };

        let (caps, _) = from_profile_locked(&profile, workdir.path(), &args).expect("build caps");

        assert_eq!(*caps.network_mode(), nono::NetworkMode::AllowAll);
    }

    #[test]
    fn test_from_profile_process_info_mode_same_sandbox() {
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("pim-test.json");
        std::fs::write(
            &profile_path,
            r#"{
                "meta": { "name": "pim-test" },
                "filesystem": { "allow": ["/tmp"] },
                "security": { "process_info_mode": "allow_same_sandbox" }
            }"#,
        )
        .expect("write profile");
        let workdir = tempdir().expect("tmpdir");
        let args = sandbox_args();
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");
        let (caps, _) = from_profile_locked(&profile, workdir.path(), &args).expect("build caps");
        assert_eq!(
            caps.process_info_mode(),
            nono::ProcessInfoMode::AllowSameSandbox,
            "profile process_info_mode should propagate to CapabilitySet"
        );
    }

    #[test]
    fn test_from_profile_ipc_mode_full() {
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("ipc-test.json");
        std::fs::write(
            &profile_path,
            r#"{
                "meta": { "name": "ipc-test" },
                "filesystem": { "allow": ["/tmp"] },
                "security": { "ipc_mode": "full" }
            }"#,
        )
        .expect("write profile");
        let workdir = tempdir().expect("tmpdir");
        let args = sandbox_args();
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");
        let (caps, _) = from_profile_locked(&profile, workdir.path(), &args).expect("build caps");
        assert_eq!(
            caps.ipc_mode(),
            nono::IpcMode::Full,
            "profile ipc_mode should propagate to CapabilitySet"
        );
    }

    #[test]
    fn test_from_profile_ipc_mode_shared_memory_only() {
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("ipc-test-shm.json");
        std::fs::write(
            &profile_path,
            r#"{
                "meta": { "name": "ipc-test-shm" },
                "filesystem": { "allow": ["/tmp"] },
                "security": { "ipc_mode": "shared_memory_only" }
            }"#,
        )
        .expect("write profile");
        let workdir = tempdir().expect("tmpdir");
        let args = sandbox_args();
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");
        let (caps, _) = from_profile_locked(&profile, workdir.path(), &args).expect("build caps");
        assert_eq!(
            caps.ipc_mode(),
            nono::IpcMode::SharedMemoryOnly,
            "profile ipc_mode: shared_memory_only should propagate to CapabilitySet"
        );
    }

    #[test]
    fn test_from_profile_ipc_mode_default() {
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("ipc-test-default.json");
        std::fs::write(
            &profile_path,
            r#"{
                "meta": { "name": "ipc-test-default" },
                "filesystem": { "allow": ["/tmp"] },
                "security": {}
            }"#,
        )
        .expect("write profile");
        let workdir = tempdir().expect("tmpdir");
        let args = sandbox_args();
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");
        let (caps, _) = from_profile_locked(&profile, workdir.path(), &args).expect("build caps");
        assert_eq!(
            caps.ipc_mode(),
            nono::IpcMode::SharedMemoryOnly,
            "absent profile ipc_mode should default to SharedMemoryOnly"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_regex_escape_path_dots() {
        assert_eq!(
            regex_escape_path("/Users/me/.claude.json"),
            "/Users/me/\\.claude\\.json"
        );
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn test_from_args_allow_connect_port_populates_tcp_connect_ports() {
        let args = SandboxArgs {
            allow_connect_port: vec![443, 80, 5432],
            ..sandbox_args()
        };

        let (caps, _) = from_args_locked(&args).expect("build caps");
        assert_eq!(caps.tcp_connect_ports(), &[443, 80, 5432]);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_from_args_allow_connect_port_errors_on_macos() {
        let args = SandboxArgs {
            allow_connect_port: vec![443],
            ..sandbox_args()
        };
        let err = from_args_locked(&args).expect_err("should fail on macOS");
        assert!(
            err.to_string().contains("not supported on macOS"),
            "unexpected error: {err}"
        );
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn test_from_profile_connect_port_populates_tcp_connect_ports() {
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("connect-port-profile.json");
        std::fs::write(
            &profile_path,
            r#"{
                "meta": { "name": "connect-port-profile" },
                "network": { "connect_port": [443, 5432] }
            }"#,
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let args = sandbox_args();

        let (caps, _) = from_profile_locked(&profile, workdir.path(), &args).expect("build caps");
        assert_eq!(caps.tcp_connect_ports(), &[443, 5432]);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_from_profile_connect_port_errors_on_macos() {
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("connect-port-profile.json");
        std::fs::write(
            &profile_path,
            r#"{
                "meta": { "name": "connect-port-profile" },
                "network": { "connect_port": [443] }
            }"#,
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let args = sandbox_args();

        let err =
            from_profile_locked(&profile, workdir.path(), &args).expect_err("should fail on macOS");
        assert!(
            err.to_string().contains("not supported on macOS"),
            "unexpected error: {err}"
        );
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn test_cli_allow_connect_port_overrides_profile_connect_port() {
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("connect-port-override.json");
        std::fs::write(
            &profile_path,
            r#"{
                "meta": { "name": "connect-port-override" },
                "network": { "connect_port": [443] }
            }"#,
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let args = SandboxArgs {
            allow_connect_port: vec![5432],
            ..sandbox_args()
        };

        let (caps, _) = from_profile_locked(&profile, workdir.path(), &args).expect("build caps");
        // Both profile and CLI ports should be present
        let ports = caps.tcp_connect_ports();
        assert!(ports.contains(&443), "profile port 443 should be present");
        assert!(ports.contains(&5432), "CLI port 5432 should be present");
    }

    #[test]
    fn test_from_profile_allow_domain_does_not_open_raw_tcp_ports() {
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("allow-domain-no-raw-ports.json");
        std::fs::write(
            &profile_path,
            r#"{
                "meta": { "name": "allow-domain-no-raw-ports" },
                "filesystem": { "allow": ["/tmp"] },
                "network": {
                    "allow_domain": [
                        "api.example.com",
                        "nats.example.com:4222",
                        "postgres.example.com:5432"
                    ]
                }
            }"#,
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let args = sandbox_args();

        let (caps, _) = from_profile_locked(&profile, workdir.path(), &args).expect("build caps");

        assert!(
            caps.tcp_connect_ports().is_empty(),
            "allow_domain should not grant direct TCP ports in proxy mode, got: {:?}",
            caps.tcp_connect_ports()
        );
    }

    #[test]
    fn test_from_args_allow_proxy_does_not_open_raw_tcp_ports() {
        let args = SandboxArgs {
            allow_proxy: vec![
                "api.example.com".to_string(),
                "nats.example.com:4222".to_string(),
            ],
            ..sandbox_args()
        };

        let (caps, _) = from_args_locked(&args).expect("build caps");

        assert!(
            caps.tcp_connect_ports().is_empty(),
            "allow-domain should not grant direct TCP ports in proxy mode, got: {:?}",
            caps.tcp_connect_ports()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_regex_escape_path_no_metacharacters() {
        assert_eq!(regex_escape_path("/usr/local/bin"), "/usr/local/bin");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_regex_escape_path_special_chars() {
        assert_eq!(
            regex_escape_path("/path/with+parens(1)[2]"),
            "/path/with\\+parens\\(1\\)\\[2\\]"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_atomic_write_rule_adds_regex_for_writable_file() {
        let tmp = tempdir().expect("tempdir");
        let file_path = tmp.path().join("test.json");
        std::fs::write(&file_path, "{}").expect("write");
        let cap = FsCapability::new_file(&file_path, AccessMode::ReadWrite).expect("cap");
        let mut caps = CapabilitySet::new();
        add_atomic_write_rule(&mut caps, &cap).expect("add rule");
        let rules = caps.platform_rules().join("\n");
        assert!(
            rules.contains("file-write*"),
            "should contain file-write rule"
        );
        assert!(
            rules.contains(r"\.tmp\.[0-9]+\.[0-9]+"),
            "should contain temp file pattern, got: {}",
            rules
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_atomic_write_rule_skips_readonly_file() {
        let tmp = tempdir().expect("tempdir");
        let file_path = tmp.path().join("readonly.json");
        std::fs::write(&file_path, "{}").expect("write");
        let cap = FsCapability::new_file(&file_path, AccessMode::Read).expect("cap");
        let mut caps = CapabilitySet::new();
        add_atomic_write_rule(&mut caps, &cap).expect("add rule");
        assert!(
            caps.platform_rules().is_empty(),
            "read-only file should not get atomic write rule"
        );
    }
}
