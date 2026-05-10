//! CLI-specific extensions for CapabilitySet
//!
//! This module provides methods to construct a CapabilitySet from CLI arguments
//! or profiles. These are CLI-specific and not part of the core library.

use crate::cli::SandboxArgs;
use crate::policy;
use crate::profile::{expand_vars, Profile};
use crate::protected_paths::{self, ProtectedRoots};
use nono::{
    AccessMode, CapabilitySet, CapabilitySource, FsCapability, NonoError, Result,
    UnixSocketCapability, UnixSocketMode,
};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Try to create a directory capability, warning and skipping on PathNotFound.
/// Propagates all other errors.
fn try_new_dir(path: &Path, access: AccessMode, label: &str) -> Result<Option<FsCapability>> {
    match FsCapability::new_dir(path, access) {
        Ok(cap) => Ok(Some(cap)),
        Err(NonoError::PathNotFound(_)) => {
            info!("{}: {}", label, path.display());
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

/// Try to create a single-file AF_UNIX socket capability.
///
/// Both modes accept non-existent paths:
/// - `Connect`: via the library's NotFound warn-and-skip path (useful
///   for profile grants that only exist in some environments).
/// - `ConnectBind`: via the library's parent-canonicalise fallback.
///   `bind(2)` creates the socket file, so granting before the file
///   exists is the normal workflow; the caller must separately widen
///   the implied filesystem grant to the parent directory in that
///   case — see [`add_cli_unix_socket_caps`].
fn try_new_unix_socket_file(
    path: &Path,
    mode: UnixSocketMode,
    label: &str,
) -> Result<Option<UnixSocketCapability>> {
    match UnixSocketCapability::new_file(path, mode) {
        Ok(cap) => Ok(Some(cap)),
        Err(NonoError::PathNotFound(_)) => {
            info!("{}: {}", label, path.display());
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// Try to create a directory-scoped AF_UNIX socket capability.
fn try_new_unix_socket_dir(
    path: &Path,
    mode: UnixSocketMode,
    label: &str,
) -> Result<Option<UnixSocketCapability>> {
    match UnixSocketCapability::new_dir(path, mode) {
        Ok(cap) => Ok(Some(cap)),
        Err(NonoError::PathNotFound(_)) => {
            info!("{}: {}", label, path.display());
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// Apply all four `--allow-unix-socket*` flag groups to `caps`.
///
/// Each flag adds a [`UnixSocketCapability`] and auto-registers the
/// implied [`FsCapability`] (CLI-side sugar per #696). The socket-level
/// grant is non-recursive (enforced by `UnixSocketCapability::covers`);
/// the fs grant for directory forms is recursive by design — that's
/// Landlock's only expressible granularity.
fn add_cli_unix_socket_caps(
    caps: &mut CapabilitySet,
    args: &SandboxArgs,
    protected_roots: &ProtectedRoots,
    allow_parent_of_protected: bool,
) -> Result<()> {
    const LBL_SOCK_FILE: &str = "Skipping non-existent unix socket (connect grant)";
    const LBL_SOCK_FILE_BIND: &str = "Skipping non-existent unix socket (connect+bind grant)";
    const LBL_SOCK_DIR: &str = "Skipping non-existent unix socket directory (connect grant)";
    const LBL_SOCK_DIR_BIND: &str =
        "Skipping non-existent unix socket directory (connect+bind grant)";
    const LBL_FS_FILE_IMPLIED: &str = "Skipping implied fs grant for non-existent unix socket";
    const LBL_FS_DIR_IMPLIED: &str =
        "Skipping implied fs grant for non-existent unix socket directory";
    const LBL_FS_DIR_IMPLIED_BIND_PARENT: &str =
        "Skipping implied fs grant on parent of pending unix socket bind path";

    for path in &args.allow_unix_socket {
        validate_requested_file(path, "CLI", protected_roots, allow_parent_of_protected)?;
        let sock_cap = try_new_unix_socket_file(path, UnixSocketMode::Connect, LBL_SOCK_FILE)?;
        if let Some(cap) = sock_cap {
            caps.add_unix_socket(cap);
            // Only register the implied fs grant when the socket grant
            // itself was accepted — otherwise we'd silently add a
            // filesystem permission on a path the user is also asking
            // to connect to, without the corresponding unix-socket
            // grant (the two must stay coupled).
            if let Some(cap) = try_new_file(path, AccessMode::Read, LBL_FS_FILE_IMPLIED)? {
                caps.add_fs(cap);
            }
        }
    }

    for path in &args.allow_unix_socket_bind {
        validate_requested_file(path, "CLI", protected_roots, allow_parent_of_protected)?;

        // Dangling symlink guard: a symlink that exists on disk but
        // whose target doesn't is NOT the normal "future socket file"
        // case — `bind(2)` would punch through the symlink to create
        // at the target, which might be a different path than the
        // operator supplied. Reject loudly; users with a legitimate
        // dangling-symlink workflow can unlink the symlink first.
        //
        // `path.symlink_metadata().is_ok()` checks the link itself,
        // `path.exists()` follows it. The combination is: link exists
        // (symlink_metadata ok) but target doesn't (exists false).
        if path.symlink_metadata().is_ok() && !path.exists() {
            return Err(NonoError::SandboxInit(format!(
                "connect+bind unix socket grant rejects dangling symlink \
                 (bind would create at the symlink's target path, which is \
                 not what operators usually intend): {}",
                path.display()
            )));
        }

        let sock_cap =
            try_new_unix_socket_file(path, UnixSocketMode::ConnectBind, LBL_SOCK_FILE_BIND)?;
        if let Some(cap) = sock_cap {
            caps.add_unix_socket(cap);
            // Implied fs grant: ReadWrite. If the path exists, grant
            // file-scoped — narrow. If it doesn't, widen to the parent
            // directory because `bind(2)` needs write on the parent to
            // create the inode. Landlock/Seatbelt can't express a
            // per-file "create at this exact path" grant; operators
            // who want tighter scope should prefer
            // `--allow-unix-socket-dir-bind` with a scoped directory.
            if path.exists() {
                if let Some(cap) = try_new_file(path, AccessMode::ReadWrite, LBL_FS_FILE_IMPLIED)? {
                    caps.add_fs(cap);
                }
            } else if let Some(parent) = path.parent() {
                if let Some(cap) = try_new_dir(
                    parent,
                    AccessMode::ReadWrite,
                    LBL_FS_DIR_IMPLIED_BIND_PARENT,
                )? {
                    caps.add_fs(cap);
                }
            }
        }
    }

    for path in &args.allow_unix_socket_dir {
        validate_requested_dir(path, "CLI", protected_roots, allow_parent_of_protected)?;
        let sock_cap = try_new_unix_socket_dir(path, UnixSocketMode::Connect, LBL_SOCK_DIR)?;
        if let Some(cap) = sock_cap {
            caps.add_unix_socket(cap);
            if let Some(cap) = try_new_dir(path, AccessMode::Read, LBL_FS_DIR_IMPLIED)? {
                caps.add_fs(cap);
            }
        }
    }

    for path in &args.allow_unix_socket_dir_bind {
        validate_requested_dir(path, "CLI", protected_roots, allow_parent_of_protected)?;
        let sock_cap =
            try_new_unix_socket_dir(path, UnixSocketMode::ConnectBind, LBL_SOCK_DIR_BIND)?;
        if let Some(cap) = sock_cap {
            caps.add_unix_socket(cap);
            if let Some(cap) = try_new_dir(path, AccessMode::ReadWrite, LBL_FS_DIR_IMPLIED)? {
                caps.add_fs(cap);
            }
        }
    }

    Ok(())
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
    allow_parent_of_protected: bool,
) -> Result<Option<FsCapability>> {
    validate_requested_file(path, "Profile", protected_roots, allow_parent_of_protected)?;
    match try_new_file(path, access, label) {
        Err(NonoError::ExpectedFile(_)) => {
            handle_exact_directory_path(path, access, protected_roots, allow_parent_of_protected)
        }
        result => result,
    }
}

#[cfg(target_os = "macos")]
fn handle_exact_directory_path(
    path: &Path,
    access: AccessMode,
    protected_roots: &ProtectedRoots,
    allow_parent_of_protected: bool,
) -> Result<Option<FsCapability>> {
    validate_requested_dir(path, "Profile", protected_roots, allow_parent_of_protected)?;
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
    _allow_parent_of_protected: bool,
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
    info!("{}: {}", label, path.display());
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

fn validate_requested_dir(
    path: &Path,
    source: &str,
    protected_roots: &ProtectedRoots,
    allow_parent_of_protected: bool,
) -> Result<()> {
    protected_paths::validate_requested_path_against_protected_roots(
        path,
        false,
        source,
        protected_roots.as_paths(),
        allow_parent_of_protected,
    )
}

fn validate_requested_file(
    path: &Path,
    source: &str,
    protected_roots: &ProtectedRoots,
    allow_parent_of_protected: bool,
) -> Result<()> {
    protected_paths::validate_requested_path_against_protected_roots(
        path,
        true,
        source,
        protected_roots.as_paths(),
        allow_parent_of_protected,
    )
}

pub(crate) fn default_profile_groups() -> Result<Vec<String>> {
    let profile = crate::policy::get_policy_profile("default")?
        .ok_or_else(|| NonoError::ProfileNotFound("default".to_string()))?;
    Ok(profile.groups.include)
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
            validate_requested_dir(path, "CLI", &protected_roots, false)?;
            if let Some(cap) =
                try_new_dir(path, AccessMode::ReadWrite, "Skipping non-existent path")?
            {
                caps.add_fs(cap);
            }
        }

        for path in &args.read {
            validate_requested_dir(path, "CLI", &protected_roots, false)?;
            if let Some(cap) = try_new_dir(path, AccessMode::Read, "Skipping non-existent path")? {
                caps.add_fs(cap);
            }
        }

        for path in &args.write {
            validate_requested_dir(path, "CLI", &protected_roots, false)?;
            if let Some(cap) = try_new_dir(path, AccessMode::Write, "Skipping non-existent path")? {
                caps.add_fs(cap);
            }
        }

        // Single file permissions
        for path in &args.allow_file {
            validate_requested_file(path, "CLI", &protected_roots, false)?;
            if let Some(cap) =
                try_new_file(path, AccessMode::ReadWrite, "Skipping non-existent file")?
            {
                caps.add_fs(cap);
            }
        }

        for path in &args.read_file {
            validate_requested_file(path, "CLI", &protected_roots, false)?;
            if let Some(cap) = try_new_file(path, AccessMode::Read, "Skipping non-existent file")? {
                caps.add_fs(cap);
            }
        }

        for path in &args.write_file {
            validate_requested_file(path, "CLI", &protected_roots, false)?;
            if let Some(cap) = try_new_file(path, AccessMode::Write, "Skipping non-existent file")?
            {
                caps.add_fs(cap);
            }
        }

        // AF_UNIX socket capabilities (issue #685 / #696). See
        // add_cli_unix_socket_caps for the full flag handling + implied
        // fs-grant sugar.
        add_cli_unix_socket_caps(&mut caps, args, &protected_roots, false)?;

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

        finalize_caps(&mut caps, &mut resolved, &loaded_policy, args, &[])?;

        Ok(PreparedCaps {
            caps,
            needs_unlink_overrides: resolved.needs_unlink_overrides,
            deny_paths: resolved.deny_paths,
        })
    }

    #[allow(deprecated)] // reads profile.commands.{allow,deny} (deprecated v0.33.0)
    fn from_profile(profile: &Profile, workdir: &Path, args: &SandboxArgs) -> Result<PreparedCaps> {
        let mut caps = CapabilitySet::new();
        let protected_roots = ProtectedRoots::from_defaults()?;
        let allow_parent_of_protected = profile.allow_parent_of_protected.unwrap_or(false);

        // Resolve policy groups from the already-finalized profile.
        let loaded_policy = policy::load_embedded_policy()?;
        let groups = profile.groups.include.clone();
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
            validate_requested_dir(
                &path,
                "Profile",
                &protected_roots,
                allow_parent_of_protected,
            )?;
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
                validate_requested_file(
                    &path,
                    "Profile",
                    &protected_roots,
                    allow_parent_of_protected,
                )?;
                try_new_file(&path, AccessMode::Read, &label)?
            } else {
                validate_requested_dir(
                    &path,
                    "Profile",
                    &protected_roots,
                    allow_parent_of_protected,
                )?;
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
            validate_requested_dir(
                &path,
                "Profile",
                &protected_roots,
                allow_parent_of_protected,
            )?;
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
            if let Some(mut cap) = try_new_profile_exact_path(
                &path,
                AccessMode::ReadWrite,
                &label,
                &protected_roots,
                allow_parent_of_protected,
            )? {
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
            if let Some(mut cap) = try_new_profile_exact_path(
                &path,
                AccessMode::Read,
                &label,
                &protected_roots,
                allow_parent_of_protected,
            )? {
                cap.source = CapabilitySource::Profile;
                caps.add_fs(cap);
            }
        }

        // Single files with write-only access
        for path_template in &fs.write_file {
            let path = expand_vars(path_template, workdir)?;
            let label = format!("Profile file '{}' does not exist, skipping", path_template);
            if let Some(mut cap) = try_new_profile_exact_path(
                &path,
                AccessMode::Write,
                &label,
                &protected_roots,
                allow_parent_of_protected,
            )? {
                add_atomic_write_rule(&mut caps, &cap)?;
                cap.source = CapabilitySource::Profile;
                caps.add_fs(cap);
            }
        }

        // AF_UNIX socket capabilities from profile (issue #685 / #696).
        //
        // Mirrors the CLI-side sugar in from_args: each unix_socket*
        // field adds a UnixSocketCapability and auto-registers the
        // implied FsCapability with matching access mode. Source is
        // marked as Profile so `--dry-run -v` can show provenance.
        for path_template in &fs.unix_socket {
            let path = expand_vars(path_template, workdir)?;
            validate_requested_file(
                &path,
                "Profile",
                &protected_roots,
                allow_parent_of_protected,
            )?;
            let label = format!(
                "Profile unix socket '{}' does not exist, skipping",
                path_template
            );
            if let Some(mut cap) = try_new_unix_socket_file(&path, UnixSocketMode::Connect, &label)?
            {
                cap.source = CapabilitySource::Profile;
                caps.add_unix_socket(cap);
                // Implied fs grant only when the socket grant itself
                // was accepted — the two must stay coupled so we never
                // add an fs grant for a path with no matching socket
                // grant.
                if let Some(mut cap) = try_new_file(&path, AccessMode::Read, &label)? {
                    cap.source = CapabilitySource::Profile;
                    caps.add_fs(cap);
                }
            }
        }

        for path_template in &fs.unix_socket_bind {
            let path = expand_vars(path_template, workdir)?;
            validate_requested_file(
                &path,
                "Profile",
                &protected_roots,
                allow_parent_of_protected,
            )?;
            // Dangling-symlink guard — see add_cli_unix_socket_caps.
            if path.symlink_metadata().is_ok() && !path.exists() {
                return Err(NonoError::SandboxInit(format!(
                    "Profile unix_socket_bind rejects dangling symlink \
                     (bind would punch through to the link target): '{}'",
                    path_template
                )));
            }
            let label = format!(
                "Profile unix socket '{}' does not exist, skipping",
                path_template
            );
            if let Some(mut cap) =
                try_new_unix_socket_file(&path, UnixSocketMode::ConnectBind, &label)?
            {
                cap.source = CapabilitySource::Profile;
                caps.add_unix_socket(cap);
                // Implied fs grant. See add_cli_unix_socket_caps for the
                // parent-widening rationale.
                if path.exists() {
                    if let Some(mut cap) = try_new_file(&path, AccessMode::ReadWrite, &label)? {
                        cap.source = CapabilitySource::Profile;
                        caps.add_fs(cap);
                    }
                } else if let Some(parent) = path.parent() {
                    if let Some(mut cap) = try_new_dir(parent, AccessMode::ReadWrite, &label)? {
                        cap.source = CapabilitySource::Profile;
                        caps.add_fs(cap);
                    }
                }
            }
        }

        for path_template in &fs.unix_socket_dir {
            let path = expand_vars(path_template, workdir)?;
            validate_requested_dir(
                &path,
                "Profile",
                &protected_roots,
                allow_parent_of_protected,
            )?;
            let label = format!(
                "Profile unix socket dir '{}' does not exist, skipping",
                path_template
            );
            if let Some(mut cap) = try_new_unix_socket_dir(&path, UnixSocketMode::Connect, &label)?
            {
                cap.source = CapabilitySource::Profile;
                caps.add_unix_socket(cap);
                if let Some(mut cap) = try_new_dir(&path, AccessMode::Read, &label)? {
                    cap.source = CapabilitySource::Profile;
                    caps.add_fs(cap);
                }
            }
        }

        for path_template in &fs.unix_socket_dir_bind {
            let path = expand_vars(path_template, workdir)?;
            validate_requested_dir(
                &path,
                "Profile",
                &protected_roots,
                allow_parent_of_protected,
            )?;
            let label = format!(
                "Profile unix socket dir '{}' does not exist, skipping",
                path_template
            );
            if let Some(mut cap) =
                try_new_unix_socket_dir(&path, UnixSocketMode::ConnectBind, &label)?
            {
                cap.source = CapabilitySource::Profile;
                caps.add_unix_socket(cap);
                if let Some(mut cap) = try_new_dir(&path, AccessMode::ReadWrite, &label)? {
                    cap.source = CapabilitySource::Profile;
                    caps.add_fs(cap);
                }
            }
        }

        // Additional profile filesystem grants (canonical fields
        // `filesystem.deny` / `filesystem.bypass_protection` + historical
        // drain sources `filesystem.allow` / `.read` / `.write`). The core
        // allow/read/write entries are already applied above — these branches
        // apply the remaining deny and deny-command surfaces.
        for path_template in &profile.filesystem.deny {
            let path = expand_vars(path_template, workdir)?;
            let path_str = path.to_str().ok_or_else(|| {
                NonoError::ConfigParse(format!(
                    "Profile filesystem deny path contains non-UTF-8 bytes: {}",
                    path.display()
                ))
            })?;
            policy::add_deny_access_rules(path_str, &mut caps, &mut resolved.deny_paths)?;
        }

        for cmd in &profile.commands.deny {
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
        for cmd in &profile.commands.allow {
            caps.add_allowed_command(cmd.as_str());
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
        add_cli_overrides(&mut caps, args, allow_parent_of_protected)?;

        // Expand profile-level bypass_protection paths for finalize_caps.
        // Existing override targets must fail closed in apply_deny_overrides
        // when they lack a matching user-intent grant. Non-existent paths are
        // skipped here to preserve platform-specific built-in profiles whose
        // grants are intentionally absent on other OSes.
        //
        // Skipping is fail-safe (the deny stays in force) but it costs the
        // user the migration signal — a typo'd `bypass_protection` entry
        // would silently no-op with no feedback. Emit a `tracing::warn!`
        // so `nono -v ...` and the diagnostic footer surface the typo,
        // while keeping the security posture unchanged.
        let mut profile_overrides = Vec::with_capacity(profile.filesystem.bypass_protection.len());
        for path_template in &profile.filesystem.bypass_protection {
            let path = expand_vars(path_template, workdir)?;
            if path.exists() {
                profile_overrides.push(path);
            } else {
                tracing::warn!(
                    "filesystem.bypass_protection entry {path_template:?} expanded to \
                     {} which does not exist on this system; skipping. The deny rule \
                     remains in force. If you meant to bypass a deny on this path, \
                     check for typos or platform-specific path differences.",
                    path.display()
                );
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
    // Profile overrides come from `filesystem.bypass_protection` in the
    // profile JSON. CLI `--bypass-protection` flags are applied on top.
    policy::apply_deny_overrides(profile_bypass_protection, &mut resolved.deny_paths, caps)?;
    policy::apply_deny_overrides(&args.bypass_protection, &mut resolved.deny_paths, caps)?;

    // Remove exact file grants for the deny paths that remain after overrides.
    // This lets profile deny patches override inherited file capabilities while
    // preserving `--bypass-protection` validation against the original grant set.
    caps.remove_exact_file_caps_for_paths(&resolved.deny_paths);

    // Validate deny/allow overlaps (hard-fail on Linux where Landlock cannot enforce denies)
    policy::validate_deny_overlaps(&resolved.deny_paths, caps)?;

    // On macOS, warn when user-granted paths are silently blocked by deny rules.
    // Seatbelt deny rules override earlier allow rules for content access, so the
    // user's --allow/--read/--write has no effect without --bypass-protection.
    if cfg!(target_os = "macos") {
        for (path, group) in
            policy::find_denied_user_grants(&resolved.deny_paths, caps, loaded_policy)
        {
            let source = group.as_deref().unwrap_or("a deny rule");
            warn!(
                "'{}' is blocked by '{}'; use --bypass-protection {} to allow access",
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
fn add_cli_overrides(
    caps: &mut CapabilitySet,
    args: &SandboxArgs,
    allow_parent_of_protected: bool,
) -> Result<()> {
    let protected_roots = ProtectedRoots::from_defaults()?;

    // Additional directories from CLI
    for path in &args.allow {
        validate_requested_dir(path, "CLI", &protected_roots, allow_parent_of_protected)?;
        if let Some(cap) = try_new_dir(path, AccessMode::ReadWrite, "Skipping non-existent path")? {
            caps.add_fs(cap);
        }
    }

    for path in &args.read {
        validate_requested_dir(path, "CLI", &protected_roots, allow_parent_of_protected)?;
        if let Some(cap) = try_new_dir(path, AccessMode::Read, "Skipping non-existent path")? {
            caps.add_fs(cap);
        }
    }

    for path in &args.write {
        validate_requested_dir(path, "CLI", &protected_roots, allow_parent_of_protected)?;
        if let Some(cap) = try_new_dir(path, AccessMode::Write, "Skipping non-existent path")? {
            caps.add_fs(cap);
        }
    }

    // Additional files from CLI
    for path in &args.allow_file {
        validate_requested_file(path, "CLI", &protected_roots, allow_parent_of_protected)?;
        if let Some(cap) = try_new_file(path, AccessMode::ReadWrite, "Skipping non-existent file")?
        {
            caps.add_fs(cap);
        }
    }

    for path in &args.read_file {
        validate_requested_file(path, "CLI", &protected_roots, allow_parent_of_protected)?;
        if let Some(cap) = try_new_file(path, AccessMode::Read, "Skipping non-existent file")? {
            caps.add_fs(cap);
        }
    }

    for path in &args.write_file {
        validate_requested_file(path, "CLI", &protected_roots, allow_parent_of_protected)?;
        if let Some(cap) = try_new_file(path, AccessMode::Write, "Skipping non-existent file")? {
            caps.add_fs(cap);
        }
    }

    // AF_UNIX socket capabilities from CLI overrides.
    add_cli_unix_socket_caps(caps, args, &protected_roots, allow_parent_of_protected)?;

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

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

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
            let home = dirs::home_dir().expect("home");
            let protected_subtree = home.join(".nono").join("rollbacks");

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
                "commands": { "allow": ["rm", "shred"] }
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

    #[test]
    fn test_from_profile_filesystem_read_accepts_file_paths() {
        let dir = tempdir().expect("tmpdir");
        let read_file = dir.path().join("config.txt");
        std::fs::write(&read_file, "token=123").expect("write file");

        let profile_path = dir.path().join("read-file-profile.json");
        std::fs::write(
            &profile_path,
            format!(
                r#"{{
                "meta": {{ "name": "read-file-profile" }},
                "filesystem": {{ "read": ["{}"] }}
            }}"#,
                read_file.display()
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
                "groups": {
                    "exclude": ["dangerous_commands", "dangerous_commands_linux"]
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
                "groups": {
                    "exclude": [
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
                    "filesystem": {{
                        "read": ["{}"],
                        "write": ["{}"],
                        "allow": ["{}"]
                    }}
                }}"#,
                read_dir.display(),
                write_dir.display(),
                rw_dir.display()
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
                    "groups": {{
                        "exclude": ["system_write_linux"]
                    }},
                    "filesystem": {{
                        "deny": ["{}"]
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
                    "filesystem": {{
                        "allow": ["{}"],
                        "deny": ["{}"]
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
                    "filesystem": {{
                        "allow": ["{}"],
                        "deny": ["{}"]
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
                        "read_file": ["{}"],
                        "deny": ["{}"]
                    }},
                    "groups": {{
                        "exclude": ["system_read_linux", "system_write_linux"]
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

    #[test]
    fn test_from_profile_policy_add_deny_access_respects_bypass_protection_for_symlinked_file() {
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
                        "read_file": ["{}"],
                        "deny": ["{}"]
                    }},
                    "groups": {{
                        "exclude": ["system_read_linux", "system_write_linux"]
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

    #[test]
    fn test_from_profile_policy_bypass_protection_via_symlink_path() {
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
                        "read_file": ["{target}"],
                        "deny": ["{link}"],
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
    fn test_from_profile_workdir_deny_env_with_extends() {
        let workdir = tempdir().expect("workdir");
        std::fs::write(workdir.path().join(".env"), "SECRET=test").expect("write .env");

        // Synthetic profile that extends `default` (no fixed-path filesystem
        // grants) and applies a filesystem.deny for the workdir's .env.
        let profile_path = workdir.path().join("deny-env.json");
        std::fs::write(
            &profile_path,
            r#"{
                "extends": "default",
                "meta": { "name": "deny-env-test" },
                "workdir": { "access": "readwrite" },
                "filesystem": {
                    "deny": ["$WORKDIR/.env"]
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
                    "filesystem": {{
                        "deny": ["{}"]
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
    fn test_from_profile_policy_bypass_protection_punches_through_deny_group() {
        let dir = tempdir().expect("tmpdir");
        let denied = dir.path().join("denied_dir");
        std::fs::create_dir_all(&denied).expect("mkdir denied");

        let profile_path = dir.path().join("override-deny-profile.json");
        std::fs::write(
            &profile_path,
            format!(
                r#"{{
                    "meta": {{ "name": "override-deny-test" }},
                    "filesystem": {{
                        "allow": ["{path}"],
                        "deny": ["{path}"],
                        "bypass_protection": ["{path}"]
                    }}
                }}"#,
                path = denied.display()
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
    fn test_cli_bypass_protection_requires_matching_grant() {
        // Override path is under temp dir which is covered by system groups,
        // but the grant check requires user-intent sources (User/Profile),
        // so group coverage is not sufficient. Profile-level bypass_protection
        // entries may be skipped when their platform-specific grants do not
        // resolve on the current platform; CLI overrides should still fail.
        let dir = tempdir().expect("tmpdir");
        let denied = dir.path().join("denied_no_grant");
        std::fs::create_dir_all(&denied).expect("mkdir denied");

        let profile_path = dir.path().join("override-deny-no-grant.json");
        std::fs::write(
            &profile_path,
            format!(
                r#"{{
                    "meta": {{ "name": "override-deny-no-grant" }},
                    "filesystem": {{
                        "deny": ["{path}"]
                    }}
                }}"#,
                path = denied.display()
            ),
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let args = SandboxArgs {
            bypass_protection: vec![denied.clone()],
            ..sandbox_args()
        };

        let err = from_profile_locked(&profile, workdir.path(), &args)
            .expect_err("CLI bypass_protection without user-intent grant should fail");
        assert!(
            err.to_string().contains("no matching grant"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_profile_bypass_protection_requires_matching_grant() {
        let dir = tempdir().expect("tmpdir");
        let denied = dir.path().join("denied_no_grant");
        std::fs::create_dir_all(&denied).expect("mkdir denied");

        let profile_path = dir.path().join("override-deny-no-grant.json");
        std::fs::write(
            &profile_path,
            format!(
                r#"{{
                    "meta": {{ "name": "override-deny-no-grant" }},
                    "filesystem": {{
                        "deny": ["{path}"],
                        "bypass_protection": ["{path}"]
                    }}
                }}"#,
                path = denied.display()
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
        // Synthetic profile: extends `default` (so it inherits deny groups
        // and dangerous_commands) plus its own groups. We avoid depending on
        // a built-in's filesystem layout because the test process may not
        // have access to the paths that built-ins reference (e.g. ~/.codex).
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("groups-test.json");
        std::fs::write(
            &profile_path,
            r#"{
                "extends": "default",
                "meta": { "name": "groups-test" },
                "security": {
                    "groups": ["node_runtime", "rust_runtime", "unlink_protection"]
                }
            }"#,
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

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
                    "filesystem": {{ "read": ["{}"] }}
                }}"#,
                target.display()
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
                    "filesystem": {{ "read": ["{}"] }}
                }}"#,
                target.display()
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
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("allow-net-test.json");
        std::fs::write(
            &profile_path,
            r#"{
                "extends": "default",
                "meta": { "name": "allow-net-test" },
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

    // --- --allow-unix-socket* flag tests (issue #685 / #696) -----------------

    #[test]
    fn test_allow_unix_socket_adds_cap_and_implied_read_fs_grant() {
        let dir = tempdir().expect("tempdir");
        let sock = dir.path().join("a.sock");
        std::fs::write(&sock, b"").expect("create socket stub");

        let args = SandboxArgs {
            allow_unix_socket: vec![sock.clone()],
            ..sandbox_args()
        };

        let (caps, _) = from_args_locked(&args).expect("from_args");

        // One UnixSocketCapability with mode=Connect.
        let socks = caps.unix_socket_capabilities();
        assert_eq!(socks.len(), 1);
        assert_eq!(socks[0].mode, UnixSocketMode::Connect);
        assert!(!socks[0].is_directory);

        // Exactly one implied FsCapability at Read.
        let fs_matches: Vec<_> = caps
            .fs_capabilities()
            .iter()
            .filter(|c| c.is_file && c.resolved == sock.canonicalize().expect("canonicalize sock"))
            .collect();
        assert_eq!(fs_matches.len(), 1);
        assert_eq!(fs_matches[0].access, AccessMode::Read);
    }

    #[test]
    #[cfg(unix)]
    fn test_allow_unix_socket_bind_rejects_dangling_symlink() {
        // A dangling symlink is not a typical "future socket file" — bind(2)
        // follows the link and creates at the target, which is usually not
        // what the operator intended. Must reject loudly.
        let dir = tempdir().expect("tempdir");
        let link = dir.path().join("dangling.sock");
        let missing_target = dir.path().join("does-not-exist");
        std::os::unix::fs::symlink(&missing_target, &link).expect("create dangling symlink");

        let args = SandboxArgs {
            allow_unix_socket_bind: vec![link],
            ..sandbox_args()
        };

        let err = from_args_locked(&args)
            .expect_err("dangling symlink must be rejected by the bind guard");
        assert!(
            format!("{err}").contains("dangling symlink"),
            "error message should mention dangling symlink"
        );
    }

    #[test]
    fn test_allow_unix_socket_missing_skips_both_socket_and_fs_grants() {
        // On macOS, try_new_file's handle_missing_file_capability can
        // manufacture an exact-file FsCapability even when the path
        // doesn't exist. The unix-socket branch must NOT register that
        // fs grant when the socket grant itself was skipped — otherwise
        // the user gets a filesystem permission for a path they can't
        // `connect()` to anyway.
        let dir = tempdir().expect("tempdir");
        let missing = dir.path().join("never-exists.sock");

        let args = SandboxArgs {
            allow_unix_socket: vec![missing.clone()],
            ..sandbox_args()
        };

        let (caps, _) = from_args_locked(&args).expect("from_args");

        assert!(
            caps.unix_socket_capabilities().is_empty(),
            "no unix-socket grant for missing path"
        );
        assert!(
            !caps
                .fs_capabilities()
                .iter()
                .any(|c| c.original == missing || c.resolved == missing),
            "no implied fs grant when the socket grant was skipped"
        );
    }

    #[test]
    fn test_allow_unix_socket_bind_accepts_nonexistent_path_and_widens_fs_to_parent() {
        // The normal bind(2) workflow: grant is registered before the
        // socket file exists. The UnixSocketCapability is added
        // (ConnectBind, file-scoped, canonical parent + filename), and
        // the implied fs grant widens to ReadWrite on the parent
        // directory since the kernel needs write on the parent to
        // create the new inode.
        let dir = tempdir().expect("tempdir");
        let pending = dir.path().join("future.sock");
        assert!(!pending.exists(), "test precondition: path must not exist");

        let args = SandboxArgs {
            allow_unix_socket_bind: vec![pending.clone()],
            ..sandbox_args()
        };

        let (caps, _) = from_args_locked(&args).expect("from_args");

        let socks = caps.unix_socket_capabilities();
        assert_eq!(socks.len(), 1);
        assert_eq!(socks[0].mode, UnixSocketMode::ConnectBind);
        assert!(!socks[0].is_directory);

        // Implied fs grant should cover the parent dir with ReadWrite.
        let canonical_parent = dir.path().canonicalize().expect("canonicalize dir");
        let parent_grant = caps
            .fs_capabilities()
            .iter()
            .find(|c| !c.is_file && c.resolved == canonical_parent)
            .expect("implied parent-dir fs grant missing");
        assert_eq!(parent_grant.access, AccessMode::ReadWrite);
    }

    #[test]
    fn test_allow_unix_socket_bind_existing_grants_readwrite_fs() {
        let dir = tempdir().expect("tempdir");
        let sock = dir.path().join("b.sock");
        std::fs::write(&sock, b"").expect("create socket stub");

        let args = SandboxArgs {
            allow_unix_socket_bind: vec![sock.clone()],
            ..sandbox_args()
        };

        let (caps, _) = from_args_locked(&args).expect("from_args");

        let socks = caps.unix_socket_capabilities();
        assert_eq!(socks.len(), 1);
        assert_eq!(socks[0].mode, UnixSocketMode::ConnectBind);

        let fs_match = caps
            .fs_capabilities()
            .iter()
            .find(|c| c.is_file && c.resolved == sock.canonicalize().expect("canonicalize sock"))
            .expect("implied fs cap not found");
        assert_eq!(fs_match.access, AccessMode::ReadWrite);
    }

    #[test]
    fn test_allow_unix_socket_dir_bind_directory_grants_readwrite_fs() {
        // The tsx case (#685): runtime-generated socket filenames inside a
        // known directory.
        let dir = tempdir().expect("tempdir");

        let args = SandboxArgs {
            allow_unix_socket_dir_bind: vec![dir.path().to_path_buf()],
            ..sandbox_args()
        };

        let (caps, _) = from_args_locked(&args).expect("from_args");

        let socks = caps.unix_socket_capabilities();
        assert_eq!(socks.len(), 1);
        assert_eq!(socks[0].mode, UnixSocketMode::ConnectBind);
        assert!(socks[0].is_directory);

        let fs_match = caps
            .fs_capabilities()
            .iter()
            .find(|c| {
                !c.is_file && c.resolved == dir.path().canonicalize().expect("canonicalize dir")
            })
            .expect("implied fs dir cap not found");
        assert_eq!(fs_match.access, AccessMode::ReadWrite);
    }

    #[test]
    fn test_allow_unix_socket_dir_implies_read_fs_grant() {
        let dir = tempdir().expect("tempdir");

        let args = SandboxArgs {
            allow_unix_socket_dir: vec![dir.path().to_path_buf()],
            ..sandbox_args()
        };

        let (caps, _) = from_args_locked(&args).expect("from_args");

        let socks = caps.unix_socket_capabilities();
        assert_eq!(socks.len(), 1);
        assert_eq!(socks[0].mode, UnixSocketMode::Connect);
        assert!(socks[0].is_directory);

        let fs_match = caps
            .fs_capabilities()
            .iter()
            .find(|c| {
                !c.is_file && c.resolved == dir.path().canonicalize().expect("canonicalize dir")
            })
            .expect("implied fs dir cap not found");
        assert_eq!(fs_match.access, AccessMode::Read);
    }

    /// Build a minimal profile JSON with a single filesystem field set,
    /// then parse it into a [`crate::profile::Profile`].
    fn profile_with_fs_field(field: &str, value: &str) -> crate::profile::Profile {
        let json = format!(
            r#"{{
                "meta": {{ "name": "test-unix-socket" }},
                "security": {{ "groups": [] }},
                "filesystem": {{ "{field}": ["{value}"] }}
            }}"#
        );
        serde_json::from_str(&json).expect("parse profile")
    }

    #[test]
    fn test_profile_unix_socket_field_connect_file() {
        let dir = tempdir().expect("tempdir");
        let sock = dir.path().join("a.sock");
        std::fs::write(&sock, b"").expect("create socket stub");
        let profile = profile_with_fs_field("unix_socket", &sock.display().to_string());

        let (caps, _) =
            from_profile_locked(&profile, dir.path(), &sandbox_args()).expect("from_profile");

        let socks: Vec<_> = caps
            .unix_socket_capabilities()
            .iter()
            .filter(|c| c.source == CapabilitySource::Profile)
            .collect();
        assert_eq!(socks.len(), 1);
        assert_eq!(socks[0].mode, UnixSocketMode::Connect);
        assert!(!socks[0].is_directory);
    }

    #[test]
    fn test_profile_unix_socket_field_connect_bind_file() {
        let dir = tempdir().expect("tempdir");
        let sock = dir.path().join("b.sock");
        std::fs::write(&sock, b"").expect("create socket stub");
        let profile = profile_with_fs_field("unix_socket_bind", &sock.display().to_string());

        let (caps, _) =
            from_profile_locked(&profile, dir.path(), &sandbox_args()).expect("from_profile");

        let socks: Vec<_> = caps
            .unix_socket_capabilities()
            .iter()
            .filter(|c| c.source == CapabilitySource::Profile)
            .collect();
        assert_eq!(socks.len(), 1);
        assert_eq!(socks[0].mode, UnixSocketMode::ConnectBind);
        assert!(!socks[0].is_directory);
    }

    #[test]
    fn test_profile_unix_socket_field_connect_dir() {
        let dir = tempdir().expect("tempdir");
        let profile = profile_with_fs_field("unix_socket_dir", &dir.path().display().to_string());

        let (caps, _) =
            from_profile_locked(&profile, dir.path(), &sandbox_args()).expect("from_profile");

        let socks: Vec<_> = caps
            .unix_socket_capabilities()
            .iter()
            .filter(|c| c.source == CapabilitySource::Profile)
            .collect();
        assert_eq!(socks.len(), 1);
        assert_eq!(socks[0].mode, UnixSocketMode::Connect);
        assert!(socks[0].is_directory);
    }

    #[test]
    fn test_profile_unix_socket_field_connect_bind_dir() {
        // The tsx (#685) case, expressed via profile JSON.
        let dir = tempdir().expect("tempdir");
        let profile =
            profile_with_fs_field("unix_socket_dir_bind", &dir.path().display().to_string());

        let (caps, _) =
            from_profile_locked(&profile, dir.path(), &sandbox_args()).expect("from_profile");

        let socks: Vec<_> = caps
            .unix_socket_capabilities()
            .iter()
            .filter(|c| c.source == CapabilitySource::Profile)
            .collect();
        assert_eq!(socks.len(), 1);
        assert_eq!(socks[0].mode, UnixSocketMode::ConnectBind);
        assert!(socks[0].is_directory);
    }
}
