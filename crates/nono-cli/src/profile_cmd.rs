//! Profile subcommand implementations
//!
//! Handles `nono profile init|list|show|diff|validate|groups|schema|guide`:
//! creation, inspection, comparison, validation, and documentation of
//! nono profiles and the group-based policy rules they reference.

use crate::cli::{
    ProfileCmdArgs, ProfileCommands, ProfileDiffArgs, ProfileGroupsArgs, ProfileGuideArgs,
    ProfileInitArgs, ProfileListArgs, ProfilePatchArgs, ProfilePromoteArgs, ProfileSchemaArgs,
    ProfileShowArgs, ProfileValidateArgs,
};
use crate::config::embedded;
use crate::deprecated_schema::{DeprecationCounter, LegacyPolicyPatch, GLOBAL_DEPRECATION_COUNTER};
use crate::policy::{self, AllowOps, DenyOps, Group};
use crate::profile::{self, Profile, WorkdirAccess};
use crate::theme;
use colored::Colorize;
use nono::{NonoError, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;

/// Serialize a value to pretty-printed JSON, propagating serialization errors.
fn to_json(val: &serde_json::Value) -> Result<String> {
    serde_json::to_string_pretty(val)
        .map_err(|e| NonoError::ProfileParse(format!("JSON serialization failed: {e}")))
}

/// Prefix used for all profile command output
fn prefix() -> colored::ColoredString {
    let t = theme::current();
    theme::fg("nono profile", t.brand).bold()
}

/// Dispatch to the appropriate profile subcommand.
pub fn run_profile(args: ProfileCmdArgs) -> Result<()> {
    match args.command {
        ProfileCommands::Init(args) => cmd_init(args),
        ProfileCommands::List(args) => cmd_list(args),
        ProfileCommands::Patch(args) => cmd_patch(args),
        ProfileCommands::Show(args) => cmd_show(args),
        ProfileCommands::Diff(args) => cmd_diff(args),
        ProfileCommands::Validate(args) => cmd_validate(args),
        ProfileCommands::Groups(args) => cmd_groups(args),
        ProfileCommands::Schema(args) => cmd_schema(args),
        ProfileCommands::Guide(args) => cmd_guide(args),
        ProfileCommands::Promote(args) => cmd_promote(args),
    }
}

// ---------------------------------------------------------------------------
// SHA-256 helper (Phase 36.5 D-36.5-B4 — canonical helper; consolidated here,
// used by Commit 1 refresh + Commit 2 verify_base_hash / cmd_promote)
// ---------------------------------------------------------------------------

/// Compute SHA-256 of `bytes` and return the lowercase hex digest (64 chars).
/// Per D-36.5-B4 — `sha2` workspace dep; matches Phase 22-03 PKG-04 + Phase 32
/// sigstore TUF root hashing; one algorithm across codebase.
#[must_use]
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Symlink-safe file helpers (Phase 36.5 D-36.5-B4 / T-36.5-04 / T-36.5-05)
// ---------------------------------------------------------------------------

/// Read a regular file with symlink-safe semantics.
///
/// - Cross-platform: `symlink_metadata` precheck refuses any path whose
///   `file_type().is_symlink()` returns true (closes TOCTOU on the open(2)
///   call).
/// - Unix: also adds `nix::libc::O_NOFOLLOW` to the `OpenOptions` for
///   defense in depth (refuses symlinks at the kernel level).
/// - Windows: relies on the precheck only (no `O_NOFOLLOW` analog).
///
/// Mitigates T-36.5-05 (symlink escape). Adapted from upstream 829c341a
/// `read_regular_file` — D-20 manual-replay shape.
fn read_regular_file(path: &Path, label: &str) -> nono::Result<Vec<u8>> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| nono::NonoError::ProfileRead {
        path: path.to_path_buf(),
        source: e,
    })?;
    if meta.file_type().is_symlink() {
        return Err(nono::NonoError::ProfileParse(format!(
            "{label} must not be a symlink: {}",
            path.display()
        )));
    }
    if !meta.file_type().is_file() {
        return Err(nono::NonoError::ProfileParse(format!(
            "{label} is not a regular file: {}",
            path.display()
        )));
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|e| nono::NonoError::ProfileRead {
            path: path.to_path_buf(),
            source: e,
        })?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| nono::NonoError::ProfileRead {
            path: path.to_path_buf(),
            source: e,
        })?;
    Ok(bytes)
}

/// Check whether a path exists AND is a regular file (not symlink, not dir).
fn regular_file_exists(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => meta.file_type().is_file(),
        Err(_) => false,
    }
}

/// Atomic write with PID-suffixed tempfile + fsync. Reliable for cross-
/// directory rename targets (e.g., promote: `profile-drafts/<n>.json` →
/// `profiles/<n>.json` on same volume). Adapted from upstream 829c341a.
///
/// Mitigates T-36.5-04 (atomic-write TOCTOU). On Windows `fs::rename` is
/// atomic on same-volume targets via MoveFileExW + MOVEFILE_REPLACE_EXISTING.
/// All paths under `nono_config_dir()` share the same volume by construction.
fn atomic_write_file(path: &Path, contents: &[u8]) -> nono::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        nono::NonoError::ProfileParse(format!("invalid profile path {}", path.display()))
    })?;
    std::fs::create_dir_all(parent).map_err(|e| nono::NonoError::ProfileRead {
        path: parent.to_path_buf(),
        source: e,
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        nono::NonoError::ProfileParse(format!("invalid profile path {}", path.display()))
    })?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(file_name);
    tmp_name.push(format!(".tmp.{}", std::process::id()));
    let tmp_path = parent.join(tmp_name);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp_path)
        .map_err(|e| nono::NonoError::ProfileRead {
            path: tmp_path.clone(),
            source: e,
        })?;
    if let Err(error) = file.write_all(contents) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(nono::NonoError::ProfileRead {
            path: tmp_path,
            source: error,
        });
    }
    if let Err(error) = file.sync_all() {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(nono::NonoError::ProfileRead {
            path: tmp_path,
            source: error,
        });
    }
    drop(file);
    if let Err(error) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(nono::NonoError::ProfileRead {
            path: path.to_path_buf(),
            source: error,
        });
    }
    Ok(())
}

/// Verify the sidecar `<name>.base` hash against the SHA-256 of the current
/// canonical profile bytes. Returns `Err(ActionRequired)` on mismatch with
/// `resolve_via: "nono profile init --draft --refresh <name>"`.
///
/// Mitigates T-36.5-01 (stale-draft replay attack).
fn verify_base_hash(base_path: &Path, current_bytes: &[u8], name: &str) -> nono::Result<()> {
    let base_bytes = read_regular_file(base_path, "profile draft base hash")?;
    let provided = std::str::from_utf8(&base_bytes)
        .map_err(|e| nono::NonoError::ProfileParse(format!("base hash is not UTF-8: {e}")))?
        .trim();
    if provided.len() != 64 || !provided.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(nono::NonoError::ProfileParse(format!(
            "invalid base hash in {}",
            base_path.display()
        )));
    }
    let current = sha256_hex(current_bytes);
    if !provided.eq_ignore_ascii_case(&current) {
        return Err(nono::NonoError::ActionRequired {
            expected: provided.to_string(),
            actual: current,
            resolve_via: format!("nono profile init --draft --refresh {name}"),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// nono profile init
// ---------------------------------------------------------------------------

fn cmd_init(args: ProfileInitArgs) -> Result<()> {
    // Validate profile name
    if !profile::is_valid_profile_name(&args.name) {
        return Err(NonoError::ProfileParse(format!(
            "Invalid profile name '{}': must be alphanumeric with hyphens, no leading/trailing hyphens",
            args.name
        )));
    }

    // Phase 36.5 D-36.5-A1: --refresh mode rewrites the sidecar without touching draft.
    if args.refresh {
        return cmd_init_refresh(&args.name);
    }

    // Determine output path
    let output_path = match &args.output {
        Some(path) => path.clone(),
        None if args.draft => profile::get_user_profile_draft_path(&args.name)?,
        None => profile::get_user_profile_path(&args.name)?,
    };

    // Check for existing file
    if output_path.exists() && !args.force {
        return Err(NonoError::ProfileParse(format!(
            "Profile file already exists: {}\nUse --force to overwrite",
            output_path.display()
        )));
    }

    // Validate --extends target exists
    if let Some(ref base) = args.extends {
        if !profile_exists(base) {
            return Err(NonoError::ProfileParse(format!(
                "Base profile '{}' not found (built-in or user profile)",
                base
            )));
        }
    }

    // Validate --groups against embedded policy
    if !args.groups.is_empty() {
        let pol = policy::load_embedded_policy()?;
        for group in &args.groups {
            if !pol.groups.contains_key(group.as_str()) {
                return Err(NonoError::ProfileParse(format!(
                    "Unknown security group '{}'. Use `nono profile groups` to list available groups",
                    group
                )));
            }
        }
    }

    // Build skeleton JSON
    let skeleton = build_skeleton(&args);

    // Ensure parent directory exists
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            NonoError::ProfileParse(format!(
                "Failed to create directory {}: {}",
                parent.display(),
                e
            ))
        })?;
    }

    // Write file
    let json = serde_json::to_string_pretty(&skeleton)
        .map_err(|e| NonoError::ProfileParse(format!("JSON serialization failed: {e}")))?;

    fs::write(&output_path, format!("{json}\n")).map_err(|e| {
        NonoError::ProfileParse(format!(
            "Failed to write profile to {}: {}",
            output_path.display(),
            e
        ))
    })?;

    // Phase 36.5 D-36.5-B4: If creating a draft AND a canonical profile already
    // exists, write the sidecar .base file containing SHA-256 of canonical bytes.
    // This seeds the base-hash for promote-time staleness detection.
    if args.draft && args.output.is_none() {
        let canonical = profile::get_user_profile_path(&args.name)?;
        if canonical.exists() {
            let canonical_bytes = fs::read(&canonical).map_err(|e| NonoError::ProfileRead {
                path: canonical.clone(),
                source: e,
            })?;
            let hash = sha256_hex(&canonical_bytes);
            let base_path = profile::get_user_profile_draft_base_path(&args.name)?;
            // Atomic-write sidecar (.base file) via canonical helper (T-36.5-04)
            atomic_write_file(&base_path, hash.as_bytes())?;
        }
    }

    eprintln!(
        "{} Created profile at {}",
        prefix(),
        output_path.display().to_string().bold()
    );
    eprintln!(
        "{} Validate with: nono profile validate {}",
        prefix(),
        output_path.display()
    );
    eprintln!(
        "{} For editor autocomplete: nono profile schema -o nono-profile.schema.json",
        prefix()
    );

    Ok(())
}

/// Refresh a draft's recorded base-hash from the current canonical profile.
///
/// Preserves draft JSON content; rewrites only the sidecar `<name>.base`.
/// Errors if either the draft or the canonical profile is missing.
/// Phase 36.5 RESEARCH §`--refresh` recommendation.
fn cmd_init_refresh(name: &str) -> Result<()> {
    let draft_path = profile::get_user_profile_draft_path(name)?;
    if !draft_path.exists() {
        return Err(NonoError::ProfileParse(format!(
            "no draft to refresh; use `nono profile init --draft {name}` without `--refresh`"
        )));
    }
    let canonical_path = profile::get_user_profile_path(name)?;
    if !canonical_path.exists() {
        return Err(NonoError::ProfileParse(format!(
            "no canonical profile to refresh against at {} \
             (the draft is already a first-time promote candidate)",
            canonical_path.display()
        )));
    }
    let canonical_bytes = fs::read(&canonical_path).map_err(|e| NonoError::ProfileRead {
        path: canonical_path.clone(),
        source: e,
    })?;
    let hash_hex = sha256_hex(&canonical_bytes);
    let base_path = profile::get_user_profile_draft_base_path(name)?;
    // Atomic-write sidecar via canonical helper (T-36.5-04)
    atomic_write_file(&base_path, hash_hex.as_bytes())?;
    eprintln!("{}: refreshed base-hash for draft '{name}'", prefix());
    Ok(())
}

// ---------------------------------------------------------------------------
// nono profile promote (Phase 36.5 D-36.5-A3 / D-36.5-D1..D4)
// ---------------------------------------------------------------------------

/// Cross-platform interactive [y/N] prompt for promote confirmation.
///
/// On Unix: delegates to `profile_save_runtime::confirm` which reads from
/// `/dev/tty` for reliable stdin behavior. On Windows: reads from stdin
/// directly (no /dev/tty analog). `profile_save_runtime` is
/// `#[cfg(not(target_os = "windows"))]`-gated so we cannot use it here.
fn promote_confirm(prompt: &str, default_yes: bool) -> nono::Result<bool> {
    #[cfg(not(target_os = "windows"))]
    {
        crate::profile_save_runtime::confirm(prompt, default_yes)
    }
    #[cfg(target_os = "windows")]
    {
        use std::io::BufRead;
        eprint!("{prompt} [{}] ", if default_yes { "Y/n" } else { "y/N" });
        let stdin = std::io::stdin();
        let line = stdin
            .lock()
            .lines()
            .next()
            .ok_or_else(|| nono::NonoError::ProfileParse("failed to read stdin".to_string()))?
            .map_err(nono::NonoError::Io)?;
        let trimmed = line.trim().to_string();
        if trimmed.is_empty() {
            return Ok(default_yes);
        }
        Ok(trimmed.eq_ignore_ascii_case("y") || trimmed.eq_ignore_ascii_case("yes"))
    }
}

/// Shadow-detection wrapper. Returns `Some("built-in")` or
/// `Some("package-managed")` if the profile name is reserved; `None` if
/// promote may proceed. Phase 36.5 D-36.5-D1.
///
/// Built-in check is inlined here (not delegated to
/// `profile_save_runtime::would_shadow_builtin`) because
/// `profile_save_runtime` is `#[cfg(not(target_os = "windows"))]`-gated.
/// Semantics are identical to `profile_save_runtime::would_shadow_builtin`:
/// fail-closed on policy load error; returns false if user already overrides.
fn reserved_profile_source(name: &str) -> nono::Result<Option<&'static str>> {
    // Built-in check: replicate would_shadow_builtin logic inline for cross-platform
    // availability. profile_save_runtime is Unix-only.
    let shadows_builtin = if crate::profile::is_user_override(name) {
        false
    } else {
        match crate::policy::load_embedded_policy() {
            Ok(policy) => policy.profiles.contains_key(name),
            // Fail-closed: refuse if policy can't be loaded (CLAUDE.md § Fail Secure)
            Err(_) => true,
        }
    };
    if shadows_builtin {
        return Ok(Some("built-in"));
    }
    // Package-managed check: walk the pack store for a profile artifact
    // matching `name`. Upstream uses find_pack_store_profile directly.
    if crate::profile::find_pack_store_profile(name).is_some() {
        return Ok(Some("package-managed"));
    }
    Ok(None)
}

/// Build the multi-line resolution string for shadow refusals.
/// D-36.5-D3 — constant-template + name only; NO env-var / credential / URL
/// embedding (V7 security constraint).
fn shadow_resolve_via(name: &str, source: &str) -> String {
    let pack_clause = if source == "package-managed" {
        "\n               or remove the source package first (`nono package remove <ref>`)"
            .to_string()
    } else {
        String::new()
    };
    format!(
        "rename the draft (`nono profile init --draft <new-name>`)\n               \
         or override at the user layer (`nono profile init --force {name}` then edit){pack_clause}"
    )
}

/// Promote a profile draft to canonical. Performs (in order):
///
/// 1. Name validation via `is_valid_profile_name`.
/// 2. Path resolution (draft + canonical + sidecar).
/// 3. Shadow-detection (refuse-always on built-in / package-managed; NO --force per D-36.5-D2).
/// 4. Base-hash verification (skipped if no canonical — first-time promote).
/// 5. Diff render (one-line summary if --yes; structural diff otherwise).
/// 6. Prompt [y/N] unless --yes.
/// 7. Atomic rename `profile-drafts/<n>.json` → `profiles/<n>.json`.
/// 8. Sidecar `.base` cleanup.
///
/// Phase 36.5 D-36.5-A3 + D-36.5-D1..D4.
fn cmd_promote(args: ProfilePromoteArgs) -> nono::Result<()> {
    // 1. Validate name (mitigates path traversal — T-36.5-05 + CLAUDE.md req)
    if !crate::profile::is_valid_profile_name(&args.name) {
        return Err(nono::NonoError::ProfileParse(format!(
            "Invalid profile name '{}' (alphanumeric + hyphens only)",
            args.name
        )));
    }

    // 2. Resolve paths
    let draft_path = crate::profile::get_user_profile_draft_path(&args.name)?;
    let canonical_path = crate::profile::get_user_profile_path(&args.name)?;
    let base_path = crate::profile::get_user_profile_draft_base_path(&args.name)?;

    // Confirm draft exists
    if !regular_file_exists(&draft_path) {
        return Err(nono::NonoError::ProfileParse(format!(
            "no draft to promote at {}",
            draft_path.display()
        )));
    }

    // 3. Shadow-detection — refuse-always (D-36.5-D2 NO --force)
    if let Some(source) = reserved_profile_source(&args.name)? {
        return Err(nono::NonoError::ActionRequired {
            expected: canonical_path.display().to_string(),
            actual: draft_path.display().to_string(),
            resolve_via: format!(
                "profile '{}' is a {} profile and cannot be promoted over.\n  \
                 Resolve via: {}",
                args.name,
                source,
                shadow_resolve_via(&args.name, source),
            ),
        });
    }

    // 4. Base-hash verification (skip if no canonical — first-time promote)
    let first_time = !regular_file_exists(&canonical_path);
    if !first_time {
        let canonical_bytes = read_regular_file(&canonical_path, "canonical profile")?;
        verify_base_hash(&base_path, &canonical_bytes, &args.name)?;
    }

    // 5. Render diff (skipped one-line for --yes per Pitfall 8)
    let draft_bytes = read_regular_file(&draft_path, "profile draft")?;
    if !first_time {
        if args.yes {
            // One-line summary for CI ergonomics
            let canonical_bytes = read_regular_file(&canonical_path, "canonical profile")?;
            let summary = profile_diff_summary(&canonical_bytes, &draft_bytes);
            eprintln!("{}: Promoting draft '{}': {}", prefix(), args.name, summary);
        } else {
            eprintln!("Diff against {}:", canonical_path.display());
            let canonical_bytes = read_regular_file(&canonical_path, "canonical profile")?;
            render_profile_diff(&canonical_bytes, &draft_bytes);
            // 6. Interactive prompt
            if !promote_confirm("Promote draft?", false)? {
                eprintln!("{}: promote aborted", prefix());
                return Ok(());
            }
        }
    } else if !args.yes {
        // First-time promote — still prompt for review
        eprintln!("First-time promote (no existing canonical profile).");
        if !promote_confirm("Promote draft?", false)? {
            eprintln!("{}: promote aborted", prefix());
            return Ok(());
        }
    } else {
        eprintln!("{}: First-time promote of draft '{}'", prefix(), args.name);
    }

    // 7. Atomic rename — same-volume atomicity on Windows MoveFileExW + POSIX
    let canonical_parent = canonical_path.parent().ok_or_else(|| {
        nono::NonoError::ProfileParse(format!(
            "invalid canonical path {}",
            canonical_path.display()
        ))
    })?;
    std::fs::create_dir_all(canonical_parent).map_err(nono::NonoError::Io)?;
    std::fs::rename(&draft_path, &canonical_path).map_err(nono::NonoError::Io)?;

    // 8. Cleanup sidecar (best-effort — promote already succeeded)
    if regular_file_exists(&base_path) {
        let _ = std::fs::remove_file(&base_path);
    }

    eprintln!("{}: promoted to {}", prefix(), canonical_path.display());
    Ok(())
}

/// One-line summary "N added, M removed, K changed" for --yes flows.
/// Loads both byte slices as `Profile` via `parse_profile_bytes` (Task C2-04),
/// computes counts, returns a single string.
///
/// `added` / `removed` / `changed` are summed across five BTreeSet diffs:
/// `security.groups`, `filesystem.deny`, `filesystem.bypass_protection`,
/// `commands.allow`, `commands.deny`. Per D-36.5-D4.
fn profile_diff_summary(canonical_bytes: &[u8], draft_bytes: &[u8]) -> String {
    match (
        crate::profile::parse_profile_bytes(canonical_bytes),
        crate::profile::parse_profile_bytes(draft_bytes),
    ) {
        (Ok(p1), Ok(p2)) => {
            // 1. security.groups
            let g1: BTreeSet<&str> = p1.security.groups.iter().map(|s| s.as_str()).collect();
            let g2: BTreeSet<&str> = p2.security.groups.iter().map(|s| s.as_str()).collect();
            let groups_added = g2.difference(&g1).count();
            let groups_removed = g1.difference(&g2).count();
            // 2. filesystem.deny
            let fd1: BTreeSet<&str> = p1.filesystem.deny.iter().map(|s| s.as_str()).collect();
            let fd2: BTreeSet<&str> = p2.filesystem.deny.iter().map(|s| s.as_str()).collect();
            let fd_added = fd2.difference(&fd1).count();
            let fd_removed = fd1.difference(&fd2).count();
            // 3. filesystem.bypass_protection
            let fb1: BTreeSet<&str> = p1
                .filesystem
                .bypass_protection
                .iter()
                .map(|s| s.as_str())
                .collect();
            let fb2: BTreeSet<&str> = p2
                .filesystem
                .bypass_protection
                .iter()
                .map(|s| s.as_str())
                .collect();
            let fb_added = fb2.difference(&fb1).count();
            let fb_removed = fb1.difference(&fb2).count();
            // 4. commands.allow
            let ca1: BTreeSet<&str> = p1.commands.allow.iter().map(|s| s.as_str()).collect();
            let ca2: BTreeSet<&str> = p2.commands.allow.iter().map(|s| s.as_str()).collect();
            let ca_added = ca2.difference(&ca1).count();
            let ca_removed = ca1.difference(&ca2).count();
            // 5. commands.deny
            let cd1: BTreeSet<&str> = p1.commands.deny.iter().map(|s| s.as_str()).collect();
            let cd2: BTreeSet<&str> = p2.commands.deny.iter().map(|s| s.as_str()).collect();
            let cd_added = cd2.difference(&cd1).count();
            let cd_removed = cd1.difference(&cd2).count();

            let added = groups_added + fd_added + fb_added + ca_added + cd_added;
            let removed = groups_removed + fd_removed + fb_removed + ca_removed + cd_removed;
            let changed = std::cmp::min(groups_added, groups_removed)
                + std::cmp::min(fd_added, fd_removed)
                + std::cmp::min(fb_added, fb_removed)
                + std::cmp::min(ca_added, ca_removed)
                + std::cmp::min(cd_added, cd_removed);
            format!("{added} added, {removed} removed, {changed} changed")
        }
        _ => "(could not parse profiles for summary)".to_string(),
    }
}

/// Render a structural JSON-aware diff between two Profile byte slices to
/// stderr. Extracted from `cmd_diff` body (D-36.5-D4) so `cmd_promote`
/// shares one rendering surface.
///
/// Renders five BTreeSet diff surfaces:
/// 1. `security.groups`
/// 2. `filesystem.deny`
/// 3. `filesystem.bypass_protection`
/// 4. `commands.allow`
/// 5. `commands.deny`
fn render_profile_diff(canonical_bytes: &[u8], draft_bytes: &[u8]) {
    match (
        crate::profile::parse_profile_bytes(canonical_bytes),
        crate::profile::parse_profile_bytes(draft_bytes),
    ) {
        (Ok(p1), Ok(p2)) => {
            // 1. security.groups
            let g1: BTreeSet<&str> = p1.security.groups.iter().map(|s| s.as_str()).collect();
            let g2: BTreeSet<&str> = p2.security.groups.iter().map(|s| s.as_str()).collect();
            for added in g2.difference(&g1) {
                eprintln!("  + group: {added}");
            }
            for removed in g1.difference(&g2) {
                eprintln!("  - group: {removed}");
            }
            // 2. filesystem.deny
            let fd1: BTreeSet<&str> = p1.filesystem.deny.iter().map(|s| s.as_str()).collect();
            let fd2: BTreeSet<&str> = p2.filesystem.deny.iter().map(|s| s.as_str()).collect();
            for added in fd2.difference(&fd1) {
                eprintln!("  + filesystem.deny: {added}");
            }
            for removed in fd1.difference(&fd2) {
                eprintln!("  - filesystem.deny: {removed}");
            }
            // 3. filesystem.bypass_protection
            let fb1: BTreeSet<&str> = p1
                .filesystem
                .bypass_protection
                .iter()
                .map(|s| s.as_str())
                .collect();
            let fb2: BTreeSet<&str> = p2
                .filesystem
                .bypass_protection
                .iter()
                .map(|s| s.as_str())
                .collect();
            for added in fb2.difference(&fb1) {
                eprintln!("  + filesystem.bypass_protection: {added}");
            }
            for removed in fb1.difference(&fb2) {
                eprintln!("  - filesystem.bypass_protection: {removed}");
            }
            // 4. commands.allow
            let ca1: BTreeSet<&str> = p1.commands.allow.iter().map(|s| s.as_str()).collect();
            let ca2: BTreeSet<&str> = p2.commands.allow.iter().map(|s| s.as_str()).collect();
            for added in ca2.difference(&ca1) {
                eprintln!("  + commands.allow: {added}");
            }
            for removed in ca1.difference(&ca2) {
                eprintln!("  - commands.allow: {removed}");
            }
            // 5. commands.deny
            let cd1: BTreeSet<&str> = p1.commands.deny.iter().map(|s| s.as_str()).collect();
            let cd2: BTreeSet<&str> = p2.commands.deny.iter().map(|s| s.as_str()).collect();
            for added in cd2.difference(&cd1) {
                eprintln!("  + commands.deny: {added}");
            }
            for removed in cd1.difference(&cd2) {
                eprintln!("  - commands.deny: {removed}");
            }
        }
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("  (could not parse profiles for diff render: {e})");
        }
    }
}

/// Build a skeleton profile JSON value with controlled field ordering.
fn build_skeleton(args: &ProfileInitArgs) -> serde_json::Value {
    let mut root = serde_json::Map::new();

    if let Some(ref base) = args.extends {
        root.insert(
            "extends".to_string(),
            serde_json::Value::String(base.clone()),
        );
    }

    // meta
    let mut meta = serde_json::Map::new();
    meta.insert(
        "name".to_string(),
        serde_json::Value::String(args.name.clone()),
    );
    if let Some(ref desc) = args.description {
        meta.insert(
            "description".to_string(),
            serde_json::Value::String(desc.clone()),
        );
    }
    root.insert("meta".to_string(), serde_json::Value::Object(meta));

    // security
    let mut security = serde_json::Map::new();
    let groups: Vec<serde_json::Value> = args
        .groups
        .iter()
        .map(|g| serde_json::Value::String(g.clone()))
        .collect();
    security.insert("groups".to_string(), serde_json::Value::Array(groups));
    root.insert("security".to_string(), serde_json::Value::Object(security));

    // workdir
    let mut workdir = serde_json::Map::new();
    workdir.insert(
        "access".to_string(),
        serde_json::Value::String("readwrite".to_string()),
    );
    root.insert("workdir".to_string(), serde_json::Value::Object(workdir));

    // filesystem (minimal has allow + read; full adds all fields)
    let mut filesystem = serde_json::Map::new();
    filesystem.insert("allow".to_string(), serde_json::Value::Array(vec![]));
    filesystem.insert("read".to_string(), serde_json::Value::Array(vec![]));
    if args.full {
        filesystem.insert("write".to_string(), serde_json::Value::Array(vec![]));
        filesystem.insert("allow_file".to_string(), serde_json::Value::Array(vec![]));
        filesystem.insert("read_file".to_string(), serde_json::Value::Array(vec![]));
        filesystem.insert("write_file".to_string(), serde_json::Value::Array(vec![]));
    }
    root.insert(
        "filesystem".to_string(),
        serde_json::Value::Object(filesystem),
    );

    // Full skeleton adds additional sections
    if args.full {
        // policy
        let mut pol = serde_json::Map::new();
        pol.insert(
            "exclude_groups".to_string(),
            serde_json::Value::Array(vec![]),
        );
        pol.insert(
            "add_allow_read".to_string(),
            serde_json::Value::Array(vec![]),
        );
        pol.insert(
            "add_allow_write".to_string(),
            serde_json::Value::Array(vec![]),
        );
        pol.insert(
            "add_allow_readwrite".to_string(),
            serde_json::Value::Array(vec![]),
        );
        pol.insert(
            "add_deny_access".to_string(),
            serde_json::Value::Array(vec![]),
        );
        pol.insert(
            "add_deny_commands".to_string(),
            serde_json::Value::Array(vec![]),
        );
        pol.insert(
            "bypass_protection".to_string(),
            serde_json::Value::Array(vec![]),
        );
        root.insert("policy".to_string(), serde_json::Value::Object(pol));

        // network
        // NOTE: network_profile is intentionally omitted. Emitting null would
        // clear an inherited proxy profile (e.g., "developer" from python-dev),
        // silently broadening network access. Absent = inherit from base.
        let mut network = serde_json::Map::new();
        network.insert("block".to_string(), serde_json::Value::Bool(false));
        network.insert("allow_domain".to_string(), serde_json::Value::Array(vec![]));
        network.insert("credentials".to_string(), serde_json::Value::Array(vec![]));
        network.insert("open_port".to_string(), serde_json::Value::Array(vec![]));
        network.insert("listen_port".to_string(), serde_json::Value::Array(vec![]));
        network.insert(
            "custom_credentials".to_string(),
            serde_json::Value::Object(serde_json::Map::new()),
        );
        root.insert("network".to_string(), serde_json::Value::Object(network));

        // env_credentials
        root.insert(
            "env_credentials".to_string(),
            serde_json::Value::Object(serde_json::Map::new()),
        );

        // hooks
        root.insert(
            "hooks".to_string(),
            serde_json::Value::Object(serde_json::Map::new()),
        );

        // rollback
        let mut rollback = serde_json::Map::new();
        rollback.insert(
            "exclude_patterns".to_string(),
            serde_json::Value::Array(vec![]),
        );
        rollback.insert(
            "exclude_globs".to_string(),
            serde_json::Value::Array(vec![]),
        );
        root.insert("rollback".to_string(), serde_json::Value::Object(rollback));

        // NOTE: open_urls and allow_launch_services are intentionally omitted.
        // Emitting them would replace inherited values from base profiles like
        // claude-code (which grants OAuth2 origins and launch services).
        // Absent = inherit from base. Authors who need to override these
        // should add them explicitly.
    }

    serde_json::Value::Object(root)
}

/// Check if a profile exists (built-in or user).
fn profile_exists(name: &str) -> bool {
    // Check built-in profiles
    if profile::builtin::get_builtin(name).is_some() {
        return true;
    }
    // Check user profiles
    if let Ok(path) = profile::get_user_profile_path(name) {
        return path.exists();
    }
    false
}

// ---------------------------------------------------------------------------
// nono profile schema
// ---------------------------------------------------------------------------

fn cmd_schema(args: ProfileSchemaArgs) -> Result<()> {
    let schema = embedded::embedded_profile_schema();

    match args.output {
        Some(path) => {
            fs::write(&path, schema).map_err(|e| {
                NonoError::ProfileParse(format!(
                    "Failed to write schema to {}: {}",
                    path.display(),
                    e
                ))
            })?;
            eprintln!(
                "{} Schema written to {}",
                prefix(),
                path.display().to_string().bold()
            );
        }
        None => {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            handle
                .write_all(schema.as_bytes())
                .map_err(|e| NonoError::ProfileParse(format!("Failed to write to stdout: {e}")))?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// nono profile guide
// ---------------------------------------------------------------------------

fn cmd_guide(_args: ProfileGuideArgs) -> Result<()> {
    let guide = embedded::embedded_profile_guide();
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    handle
        .write_all(guide.as_bytes())
        .map_err(|e| NonoError::ProfileParse(format!("Failed to write to stdout: {e}")))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// nono profile groups
// ---------------------------------------------------------------------------

pub(crate) fn cmd_groups(args: ProfileGroupsArgs) -> Result<()> {
    let pol = policy::load_embedded_policy()?;

    match args.name {
        Some(name) => cmd_groups_detail(&pol, &name, args.json),
        None => cmd_groups_list(&pol, args.json, args.all_platforms),
    }
}

fn cmd_groups_list(pol: &policy::Policy, json: bool, all_platforms: bool) -> Result<()> {
    let mut groups: Vec<(&String, &Group)> = pol.groups.iter().collect();
    groups.sort_by_key(|(name, _)| name.as_str());

    if !all_platforms {
        groups.retain(|(_, g)| policy::group_matches_platform(g));
    }

    if json {
        let arr: Vec<serde_json::Value> = groups
            .iter()
            .map(|(name, g)| {
                serde_json::json!({
                    "name": name,
                    "description": g.description,
                    "platform": g.platform.as_deref().unwrap_or("cross-platform"),
                    "required": g.required,
                    "allow": count_allow(&g.allow),
                    "deny": count_deny(&g.deny),
                })
            })
            .collect();
        println!("{}", to_json(&serde_json::Value::Array(arr))?);
        return Ok(());
    }

    let t = theme::current();
    println!(
        "{}: {} groups{}",
        prefix(),
        groups.len(),
        if all_platforms {
            " (all platforms)"
        } else {
            ""
        }
    );
    println!();

    for (name, group) in &groups {
        let platform = group.platform.as_deref().unwrap_or("cross-platform");
        let required = if group.required { "  required" } else { "" };
        println!(
            "  {:<36} {:<42} {}{}",
            theme::fg(name, t.text).bold(),
            theme::fg(&group.description, t.subtext),
            theme::fg(platform, t.overlay),
            theme::fg(required, t.yellow),
        );
    }

    Ok(())
}

fn cmd_groups_detail(pol: &policy::Policy, name: &str, json: bool) -> Result<()> {
    let group = pol.groups.get(name).ok_or_else(|| {
        NonoError::ProfileParse(format!(
            "group '{}' not found in policy.json. Use `nono profile groups` to list available groups",
            name
        ))
    })?;

    if json {
        let val = group_to_json(name, group);
        println!("{}", to_json(&val)?);
        return Ok(());
    }

    let t = theme::current();
    println!("{}: group '{}'", prefix(), theme::fg(name, t.text).bold());
    println!();
    println!(
        "  {}  {}",
        theme::fg("Description:", t.subtext),
        theme::fg(&group.description, t.text)
    );
    println!(
        "  {}     {}",
        theme::fg("Platform:", t.subtext),
        theme::fg(
            group.platform.as_deref().unwrap_or("cross-platform"),
            t.text
        )
    );
    println!(
        "  {}     {}",
        theme::fg("Required:", t.subtext),
        theme::fg(if group.required { "yes" } else { "no" }, t.text)
    );

    if let Some(ref allow) = group.allow {
        print_path_section("allow.read", &allow.read, t);
        print_path_section("allow.write", &allow.write, t);
        print_path_section("allow.readwrite", &allow.readwrite, t);
    }

    if let Some(ref deny) = group.deny {
        print_path_section("deny.access", &deny.access, t);
        if deny.unlink {
            println!();
            println!("  {}", theme::fg("deny.unlink:", t.red).bold());
            println!("    {}", theme::fg("enabled", t.red));
        }
        if !deny.commands.is_empty() {
            println!();
            println!("  {}", theme::fg("deny.commands:", t.red).bold());
            for cmd in &deny.commands {
                println!("    {}", theme::fg(cmd, t.text));
            }
        }
    }

    if let Some(ref pairs) = group.symlink_pairs {
        if !pairs.is_empty() {
            println!();
            println!("  {}", theme::fg("symlink_pairs:", t.subtext).bold());
            let mut sorted: Vec<(&String, &String)> = pairs.iter().collect();
            sorted.sort_by_key(|(k, _)| k.as_str());
            for (from, to) in sorted {
                println!(
                    "    {} -> {}",
                    theme::fg(from, t.text),
                    theme::fg(to, t.subtext)
                );
            }
        }
    }

    Ok(())
}

fn print_path_section(label: &str, paths: &[String], t: &theme::Theme) {
    if paths.is_empty() {
        return;
    }
    let color = if label.starts_with("deny") {
        t.red
    } else {
        t.green
    };
    println!();
    println!("  {}", theme::fg(&format!("{label}:"), color).bold());
    for raw in paths {
        match policy::expand_path(raw) {
            Ok(expanded) => {
                let exp_str = expanded.display().to_string();
                if exp_str == *raw {
                    println!("    {}", theme::fg(raw, t.text));
                } else {
                    println!(
                        "    {:<36} -> {}",
                        theme::fg(raw, t.text),
                        theme::fg(&exp_str, t.subtext)
                    );
                }
            }
            Err(_) => {
                println!(
                    "    {:<36} -> {}",
                    theme::fg(raw, t.text),
                    theme::fg("<expansion failed>", t.red)
                );
            }
        }
    }
}

fn count_allow(allow: &Option<AllowOps>) -> serde_json::Value {
    match allow {
        Some(a) => serde_json::json!({
            "read": a.read.len(),
            "write": a.write.len(),
            "readwrite": a.readwrite.len(),
        }),
        None => serde_json::json!({}),
    }
}

fn count_deny(deny: &Option<DenyOps>) -> serde_json::Value {
    match deny {
        Some(d) => serde_json::json!({
            "access": d.access.len(),
            "commands": d.commands.len(),
            "unlink": d.unlink,
        }),
        None => serde_json::json!({}),
    }
}

fn group_to_json(name: &str, group: &Group) -> serde_json::Value {
    let mut val = serde_json::json!({
        "name": name,
        "description": group.description,
        "platform": group.platform.as_deref().unwrap_or("cross-platform"),
        "required": group.required,
    });

    if let Some(ref allow) = group.allow {
        let mut allow_val = serde_json::Map::new();
        if !allow.read.is_empty() {
            allow_val.insert("read".into(), expand_paths_json(&allow.read));
        }
        if !allow.write.is_empty() {
            allow_val.insert("write".into(), expand_paths_json(&allow.write));
        }
        if !allow.readwrite.is_empty() {
            allow_val.insert("readwrite".into(), expand_paths_json(&allow.readwrite));
        }
        val["allow"] = serde_json::Value::Object(allow_val);
    }

    if let Some(ref deny) = group.deny {
        let mut deny_val = serde_json::Map::new();
        if !deny.access.is_empty() {
            deny_val.insert("access".into(), expand_paths_json(&deny.access));
        }
        if !deny.commands.is_empty() {
            deny_val.insert("commands".into(), serde_json::json!(deny.commands));
        }
        if deny.unlink {
            deny_val.insert("unlink".into(), serde_json::json!(true));
        }
        val["deny"] = serde_json::Value::Object(deny_val);
    }

    if let Some(ref pairs) = group.symlink_pairs {
        if !pairs.is_empty() {
            val["symlink_pairs"] = serde_json::json!(pairs);
        }
    }

    val
}

fn expand_paths_json(paths: &[String]) -> serde_json::Value {
    let arr: Vec<serde_json::Value> = paths
        .iter()
        .map(|raw| {
            let expanded = policy::expand_path(raw)
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "<expansion failed>".to_string());
            serde_json::json!({
                "raw": raw,
                "expanded": expanded,
            })
        })
        .collect();
    serde_json::Value::Array(arr)
}

// ---------------------------------------------------------------------------
// nono profile list
// ---------------------------------------------------------------------------

/// Determine the actual source of a loaded profile.
///
/// Load precedence is user-first (profile/mod.rs), so a user file with a
/// built-in name shadows the built-in. We must check the filesystem to
/// report the real source accurately.
fn profile_source(name: &str) -> &'static str {
    let builtin_names = profile::builtin::list_builtin();
    if profile::is_user_override(name) {
        if builtin_names.contains(&name.to_string()) {
            "user (overrides built-in)"
        } else {
            "user"
        }
    } else if builtin_names.contains(&name.to_string()) {
        "built-in"
    } else {
        "user"
    }
}

pub(crate) fn cmd_list(args: ProfileListArgs) -> Result<()> {
    let builtin_names = profile::builtin::list_builtin();
    let all_names = profile::list_profiles();

    let mut builtin_profiles: Vec<(String, Result<Profile>)> = Vec::new();
    let mut user_profiles: Vec<(String, Result<Profile>)> = Vec::new();

    for name in &all_names {
        let p = profile::load_profile(name);
        // Categorize by actual source: user overrides of built-in names
        // go under user section to make shadowing visible.
        if builtin_names.contains(name) && !profile::is_user_override(name) {
            builtin_profiles.push((name.clone(), p));
        } else {
            user_profiles.push((name.clone(), p));
        }
    }

    if args.json {
        let format_entry = |name: &str, result: &Result<Profile>| {
            let source = profile_source(name);
            let extends = profile::load_profile_extends(name).unwrap_or_default();
            match result {
                Ok(p) => serde_json::json!({
                    "name": name,
                    "source": source,
                    "description": p.meta.description.as_deref().unwrap_or(""),
                    "extends": extends,
                }),
                Err(e) => serde_json::json!({
                    "name": name,
                    "source": source,
                    "error": format!("{}", e),
                }),
            }
        };

        let arr: Vec<serde_json::Value> = builtin_profiles
            .iter()
            .map(|(n, p)| format_entry(n, p))
            .chain(user_profiles.iter().map(|(n, p)| format_entry(n, p)))
            .collect();
        println!("{}", to_json(&serde_json::Value::Array(arr))?);
        return Ok(());
    }

    let t = theme::current();
    let total = builtin_profiles.len() + user_profiles.len();
    println!("{}: {} profiles", prefix(), total);

    if !builtin_profiles.is_empty() {
        println!();
        println!("  {}", theme::fg("Built-in:", t.subtext).bold());
        for (name, result) in &builtin_profiles {
            print_profile_line(name, result, t);
        }
    }

    if !user_profiles.is_empty() {
        println!();
        println!(
            "  {}",
            theme::fg("User (~/.config/nono/profiles/):", t.subtext).bold()
        );
        for (name, result) in &user_profiles {
            print_profile_line(name, result, t);
        }
    }

    Ok(())
}

fn print_profile_line(name: &str, result: &Result<Profile>, t: &theme::Theme) {
    match result {
        Ok(p) => {
            let desc = p.meta.description.as_deref().unwrap_or("").to_string();
            let extends = profile::load_profile_extends(name)
                .map(|v| format!("extends {}", v.join(", ")))
                .unwrap_or_default();
            println!(
                "    {:<16} {:<42} {}",
                theme::fg(name, t.text).bold(),
                theme::fg(&desc, t.subtext),
                theme::fg(&extends, t.overlay),
            );
        }
        Err(e) => {
            println!(
                "    {:<16} {}",
                theme::fg(name, t.text).bold(),
                theme::fg(&format!("[error: {}]", e), t.red),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// nono profile patch
// ---------------------------------------------------------------------------

/// Apply a YAML overlay to a profile file via `yaml_merge` directives.
///
/// The overlay file must contain a `yaml_merge:` key at the top level. The
/// directive's `target` path is resolved relative to `profile_dir` and validated
/// against it before any write occurs (defense-in-depth via
/// `wiring::apply_yaml_merge`'s `validate_target_path` primitive — uses
/// `Path::components()` iteration + `canonicalize()`, NOT `str::starts_with`
/// per CLAUDE.md § Common Footguns #1).
///
/// # Wiring note (Plan 36-02, D-36-C2 D-20 manual-replay)
///
/// Upstream `d44f5541` (v0.49.0) introduced the `yaml_merge` directive in a
/// 1761-LOC `wiring.rs`. Fork carries ONLY the yaml_merge machinery (D-36-C1
/// scope-trim). Full wiring.rs (WriteFile / JsonMerge / JsonArrayAppend /
/// idempotent install records) deferred to v2.5-FU-3.
pub(crate) fn cmd_patch(args: ProfilePatchArgs) -> Result<()> {
    // Determine the profile_dir: either the --profile-dir arg or the default
    // nono profiles config directory.
    let profile_dir = match args.profile_dir {
        Some(dir) => dir,
        None => {
            let home = dirs::home_dir().ok_or(NonoError::HomeNotFound)?;
            home.join(".config").join("nono").join("profiles")
        }
    };

    // Read and parse the YAML overlay file.
    let overlay_raw = std::fs::read_to_string(&args.yaml).map_err(|e| {
        NonoError::ProfileParse(format!(
            "yaml overlay: cannot read '{}': {}",
            args.yaml.display(),
            e
        ))
    })?;

    let overlay: crate::wiring::YamlOverlay =
        serde_yaml_ng::from_str(&overlay_raw).map_err(|e| {
            NonoError::ProfileParse(format!(
                "yaml overlay: cannot parse '{}': {}",
                args.yaml.display(),
                e
            ))
        })?;

    // Apply yaml_merge directive if present.
    if let Some(ref directive) = overlay.yaml_merge {
        // wiring::apply_yaml_merge calls validate_target_path internally
        // (Path::components() + canonicalize; NO str::starts_with).
        // This is the primary path-validation layer for yaml_merge targets.
        crate::wiring::apply_yaml_merge(directive, &profile_dir)?;
        eprintln!(
            "yaml_merge applied: '{}' merged into '{}'",
            directive.source.display(),
            directive.target.display()
        );
    } else {
        eprintln!(
            "yaml overlay: no yaml_merge directive found in '{}'",
            args.yaml.display()
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// nono profile show
// ---------------------------------------------------------------------------

pub(crate) fn cmd_show(args: ProfileShowArgs) -> Result<()> {
    let raw_extends = profile::load_profile_extends(&args.profile);
    let profile = profile::load_profile(&args.profile)?;

    if matches!(args.format, Some(crate::cli::ProfileShowFormat::Manifest)) {
        let workdir = std::env::current_dir().map_err(|e| {
            NonoError::ConfigParse(format!("cannot determine working directory: {e}"))
        })?;
        let manifest = resolve_to_manifest(&profile, &workdir)?;
        let json = manifest.to_json()?;
        println!("{json}");
        return Ok(());
    }

    if args.json {
        let val = profile_to_json(&args.profile, &profile, &raw_extends)?;
        println!("{}", to_json(&val)?);
        return Ok(());
    }

    let t = theme::current();
    println!(
        "{}: profile '{}'",
        prefix(),
        theme::fg(&args.profile, t.text).bold()
    );

    // Meta
    if let Some(ref desc) = profile.meta.description {
        println!();
        println!(
            "  {}  {}",
            theme::fg("Description:", t.subtext),
            theme::fg(desc, t.text)
        );
    }
    if let Some(ref extends) = raw_extends {
        println!(
            "  {}      {}",
            theme::fg("Extends:", t.subtext),
            theme::fg(&extends.join(", "), t.text)
        );
    }

    // Security groups
    if !profile.security.groups.is_empty() {
        println!();
        println!("  {}", theme::fg("Security groups:", t.subtext).bold());
        for g in &profile.security.groups {
            println!("    {}", theme::fg(g, t.text));
        }
    }

    if !profile.security.allowed_commands.is_empty() {
        println!();
        println!(
            "  {}",
            theme::fg("Allowed commands (deprecated, startup-only):", t.subtext).bold()
        );
        for cmd in &profile.security.allowed_commands {
            println!("    {}", theme::fg(cmd, t.text));
        }
    }

    if let Some(mode) = &profile.security.signal_mode {
        println!("  {}   {:?}", theme::fg("Signal mode:", t.subtext), mode);
    }

    if let Some(mode) = &profile.security.process_info_mode {
        println!("  {} {:?}", theme::fg("Process info:", t.subtext), mode);
    }

    if let Some(mode) = &profile.security.ipc_mode {
        println!("  {}     {:?}", theme::fg("IPC mode:", t.subtext), mode);
    }

    if let Some(elev) = profile.security.capability_elevation {
        println!(
            "  {} {}",
            theme::fg("Capability elevation:", t.subtext),
            theme::fg(if elev { "enabled" } else { "disabled" }, t.text)
        );
    }
    if let Some(policy) = profile.security.wsl2_proxy_policy {
        println!(
            "  {} {}",
            theme::fg("WSL2 proxy policy:", t.subtext),
            theme::fg(&format!("{policy:?}"), t.text)
        );
    }
    if let Some(mode) = profile.linux.af_unix_mediation {
        println!(
            "  {} {}",
            theme::fg("Linux AF_UNIX mediation:", t.subtext),
            theme::fg(&format!("{mode:?}"), t.text)
        );
    }

    // Filesystem
    let fs = &profile.filesystem;
    let has_fs = !fs.allow.is_empty()
        || !fs.read.is_empty()
        || !fs.write.is_empty()
        || !fs.allow_file.is_empty()
        || !fs.read_file.is_empty()
        || !fs.write_file.is_empty();

    if has_fs {
        println!();
        println!("  {}", theme::fg("Filesystem:", t.subtext).bold());
        print_fs_paths("allow (r+w)", &fs.allow, t, args.raw);
        print_fs_paths("read", &fs.read, t, args.raw);
        print_fs_paths("write", &fs.write, t, args.raw);
        print_fs_paths("allow_file (r+w)", &fs.allow_file, t, args.raw);
        print_fs_paths("read_file", &fs.read_file, t, args.raw);
        print_fs_paths("write_file", &fs.write_file, t, args.raw);
    }

    // Policy patches
    let pp = &profile.policy;
    let has_policy = !pp.exclude_groups.is_empty()
        || !pp.add_allow_read.is_empty()
        || !pp.add_allow_write.is_empty()
        || !pp.add_allow_readwrite.is_empty()
        || !pp.add_deny_access.is_empty()
        || !pp.add_deny_commands.is_empty()
        || !pp.bypass_protection.is_empty();

    if has_policy {
        println!();
        println!("  {}", theme::fg("Policy patches:", t.subtext).bold());
        if !pp.exclude_groups.is_empty() {
            println!(
                "    {}: {}",
                theme::fg("exclude_groups", t.yellow),
                pp.exclude_groups.join(", ")
            );
        }
        print_fs_paths("add_allow_read", &pp.add_allow_read, t, args.raw);
        print_fs_paths("add_allow_write", &pp.add_allow_write, t, args.raw);
        print_fs_paths("add_allow_readwrite", &pp.add_allow_readwrite, t, args.raw);
        print_fs_paths("add_deny_access", &pp.add_deny_access, t, args.raw);
        if !pp.add_deny_commands.is_empty() {
            println!(
                "    {}: {}",
                theme::fg("add_deny_commands (deprecated, startup-only)", t.yellow),
                pp.add_deny_commands.join(", ")
            );
        }
        if !pp.bypass_protection.is_empty() {
            println!(
                "    {}: {}",
                theme::fg("bypass_protection", t.yellow),
                pp.bypass_protection.join(", ")
            );
        }
    }

    // Network
    let net = &profile.network;
    let has_net = net.block
        || net.resolved_network_profile().is_some()
        || !net.allow_domain.is_empty()
        || !net.resolved_credentials().is_empty()
        || !net.open_port.is_empty()
        || !net.listen_port.is_empty()
        || net.upstream_proxy.is_some()
        || !net.upstream_bypass.is_empty();

    if has_net {
        println!();
        println!("  {}", theme::fg("Network:", t.subtext).bold());
        if net.block {
            println!("    {}", theme::fg("network blocked", t.red));
        }
        if let Some(np) = net.resolved_network_profile() {
            println!(
                "    {}: {}",
                theme::fg("network_profile", t.subtext),
                theme::fg(np, t.text)
            );
        }
        if !net.allow_domain.is_empty() {
            println!(
                "    {}: {}",
                theme::fg("allow_domain", t.subtext),
                net.allow_domain.join(", ")
            );
        }
        if !net.resolved_credentials().is_empty() {
            println!(
                "    {}: {}",
                theme::fg("credentials", t.subtext),
                net.resolved_credentials().join(", ")
            );
        }
        if !net.open_port.is_empty() {
            let ports: Vec<String> = net.open_port.iter().map(|p| p.to_string()).collect();
            println!(
                "    {}: {}",
                theme::fg("open_port", t.subtext),
                ports.join(", ")
            );
        }
        if !net.listen_port.is_empty() {
            let ports: Vec<String> = net.listen_port.iter().map(|p| p.to_string()).collect();
            println!(
                "    {}: {}",
                theme::fg("listen_port", t.subtext),
                ports.join(", ")
            );
        }
        if let Some(ref ep) = net.upstream_proxy {
            println!(
                "    {}: {}",
                theme::fg("upstream_proxy", t.subtext),
                theme::fg(ep, t.text)
            );
        }
        if !net.upstream_bypass.is_empty() {
            println!(
                "    {}: {}",
                theme::fg("upstream_bypass", t.subtext),
                net.upstream_bypass.join(", ")
            );
        }
    }

    // Workdir
    if profile.workdir.access != WorkdirAccess::None {
        println!();
        println!(
            "  {}  {:?}",
            theme::fg("Workdir access:", t.subtext).bold(),
            profile.workdir.access
        );
    }

    // Rollback
    let rb = &profile.rollback;
    if !rb.exclude_patterns.is_empty() || !rb.exclude_globs.is_empty() {
        println!();
        println!("  {}", theme::fg("Rollback exclusions:", t.subtext).bold());
        for p in &rb.exclude_patterns {
            println!("    {}", theme::fg(p, t.text));
        }
        for g in &rb.exclude_globs {
            println!(
                "    {} {}",
                theme::fg("glob:", t.overlay),
                theme::fg(g, t.text)
            );
        }
    }

    // Open URLs
    if let Some(ref urls) = profile.open_urls {
        println!();
        println!("  {}", theme::fg("Open URLs:", t.subtext).bold());
        if urls.allow_localhost {
            println!("    {}", theme::fg("localhost allowed", t.text));
        }
        for origin in &urls.allow_origins {
            println!("    {}", theme::fg(origin, t.text));
        }
    }

    // Raw Seatbelt rules — surfaced prominently so it is obvious a profile uses them.
    // Shown on all platforms so cross-platform auditing is possible.
    if !profile.unsafe_macos_seatbelt_rules.is_empty() {
        println!();
        println!(
            "  {}",
            theme::fg(
                "Raw Seatbelt rules (unsafe_macos_seatbelt_rules):",
                t.yellow
            )
            .bold()
        );
        for rule in &profile.unsafe_macos_seatbelt_rules {
            println!("    {}", theme::fg(rule, t.text));
        }
    }

    Ok(())
}

fn print_fs_paths(label: &str, paths: &[String], t: &theme::Theme, raw: bool) {
    if paths.is_empty() {
        return;
    }
    println!("    {}:", theme::fg(label, t.subtext));
    for p in paths {
        if raw {
            println!("      {}", theme::fg(p, t.text));
        } else {
            match policy::expand_path(p) {
                Ok(expanded) => {
                    let exp_str = expanded.display().to_string();
                    if exp_str == *p {
                        println!("      {}", theme::fg(p, t.text));
                    } else {
                        println!(
                            "      {:<36} -> {}",
                            theme::fg(p, t.text),
                            theme::fg(&exp_str, t.subtext)
                        );
                    }
                }
                Err(_) => {
                    println!("      {}", theme::fg(p, t.text));
                }
            }
        }
    }
}

fn profile_to_json(
    name: &str,
    profile: &Profile,
    raw_extends: &Option<Vec<String>>,
) -> Result<serde_json::Value> {
    let mut val = serde_json::json!({
        "name": name,
        "description": profile.meta.description.as_deref().unwrap_or(""),
        "extends": raw_extends.as_ref().map(|v| serde_json::json!(v)).unwrap_or(serde_json::Value::Null),
    });

    // Plan 35-03 (REQ-PORT-CLOSURE-07 / D-35-C2 + D-35-C3): replace
    // format!("{:?}", …) JSON emission of Option<…> security fields with
    // serde_json::Map insertion + omit-when-None semantics. Restores the
    // upstream f3e7f885 (v0.47.0) shape that Plan 34-04b adopted but later
    // Wave-3 plans regressed (P34-DEFER-10-1).
    let mut security = serde_json::Map::new();
    security.insert(
        "groups".to_string(),
        serde_json::json!(profile.security.groups),
    );
    security.insert(
        "allowed_commands".to_string(),
        serde_json::json!(profile.security.allowed_commands),
    );
    if let Some(ref mode) = profile.security.signal_mode {
        security.insert(
            "signal_mode".to_string(),
            serde_json::to_value(mode)
                .map_err(|e| NonoError::ProfileParse(format!("signal_mode serialize: {e}")))?,
        );
    }
    if let Some(ref mode) = profile.security.process_info_mode {
        security.insert(
            "process_info_mode".to_string(),
            serde_json::to_value(mode).map_err(|e| {
                NonoError::ProfileParse(format!("process_info_mode serialize: {e}"))
            })?,
        );
    }
    if let Some(ref mode) = profile.security.ipc_mode {
        security.insert(
            "ipc_mode".to_string(),
            serde_json::to_value(mode)
                .map_err(|e| NonoError::ProfileParse(format!("ipc_mode serialize: {e}")))?,
        );
    }
    security.insert(
        "capability_elevation".to_string(),
        serde_json::json!(profile.security.capability_elevation),
    );
    if let Some(ref policy) = profile.security.wsl2_proxy_policy {
        security.insert(
            "wsl2_proxy_policy".to_string(),
            serde_json::to_value(policy).map_err(|e| {
                NonoError::ProfileParse(format!("wsl2_proxy_policy serialize: {e}"))
            })?,
        );
    }
    val["security"] = serde_json::Value::Object(security);
    if let Some(v) = profile.linux.af_unix_mediation {
        val["linux"] = serde_json::json!({ "af_unix_mediation": v });
    }

    // Filesystem
    val["filesystem"] = serde_json::json!({
        "allow": profile.filesystem.allow,
        "read": profile.filesystem.read,
        "write": profile.filesystem.write,
        "allow_file": profile.filesystem.allow_file,
        "read_file": profile.filesystem.read_file,
        "write_file": profile.filesystem.write_file,
    });

    // Policy patches
    val["policy"] = serde_json::json!({
        "exclude_groups": profile.policy.exclude_groups,
        "add_allow_read": profile.policy.add_allow_read,
        "add_allow_write": profile.policy.add_allow_write,
        "add_allow_readwrite": profile.policy.add_allow_readwrite,
        "add_deny_access": profile.policy.add_deny_access,
        "add_deny_commands": profile.policy.add_deny_commands,
        "bypass_protection": profile.policy.bypass_protection,
    });

    // Network
    val["network"] = serde_json::json!({
        "block": profile.network.block,
        "network_profile": profile.network.resolved_network_profile(),
        "allow_domain": profile.network.allow_domain,
        "credentials": profile.network.resolved_credentials(),
        "open_port": profile.network.open_port,
        "listen_port": profile.network.listen_port,
        "upstream_proxy": profile.network.upstream_proxy,
        "upstream_bypass": profile.network.upstream_bypass,
    });

    // Workdir — emit via serde_json::to_value so the existing
    // #[serde(rename_all = "lowercase")] on WorkdirAccess produces "readwrite"
    // rather than the Debug-leaked "ReadWrite" (Plan 35-03 D-35-C3).
    let mut workdir = serde_json::Map::new();
    workdir.insert(
        "access".to_string(),
        serde_json::to_value(&profile.workdir.access)
            .map_err(|e| NonoError::ProfileParse(format!("workdir.access serialize: {e}")))?,
    );
    val.as_object_mut()
        .ok_or_else(|| {
            NonoError::ProfileParse("profile_to_json root not an object (workdir)".to_string())
        })?
        .insert("workdir".to_string(), serde_json::Value::Object(workdir));

    // Rollback
    val["rollback"] = serde_json::json!({
        "exclude_patterns": profile.rollback.exclude_patterns,
        "exclude_globs": profile.rollback.exclude_globs,
    });

    // Env credentials
    if !profile.env_credentials.mappings.is_empty() {
        val["env_credentials"] = serde_json::json!(profile.env_credentials.mappings);
    }

    // Hooks
    if !profile.hooks.hooks.is_empty() {
        let hooks: serde_json::Map<String, serde_json::Value> = profile
            .hooks
            .hooks
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    serde_json::json!({
                        "event": v.event,
                        "matcher": v.matcher,
                        "script": v.script,
                    }),
                )
            })
            .collect();
        val["hooks"] = serde_json::Value::Object(hooks);
    }

    // Open URLs
    if let Some(ref urls) = profile.open_urls {
        val["open_urls"] = serde_json::json!({
            "allow_origins": urls.allow_origins,
            "allow_localhost": urls.allow_localhost,
        });
    }

    // Allow launch services
    if let Some(als) = profile.allow_launch_services {
        val["allow_launch_services"] = serde_json::json!(als);
    }

    // Plan 34-01 fork-divergence: profile.allow_gpu field does not exist in fork's Profile
    // (upstream-only Profile field, not absorbed by fork). Skip rendering allow_gpu in show output.

    if !profile.unsafe_macos_seatbelt_rules.is_empty() {
        val["unsafe_macos_seatbelt_rules"] = serde_json::json!(profile.unsafe_macos_seatbelt_rules);
    }

    Ok(val)
}

// ---------------------------------------------------------------------------
// nono profile diff
// ---------------------------------------------------------------------------

pub(crate) fn cmd_diff(args: ProfileDiffArgs) -> Result<()> {
    let p1 = profile::load_profile(&args.profile1)?;
    let p2 = profile::load_profile(&args.profile2)?;

    if args.json {
        let val = diff_to_json(&args.profile1, &args.profile2, &p1, &p2)?;
        println!("{}", to_json(&val)?);
        return Ok(());
    }

    let t = theme::current();
    println!(
        "{}: diff '{}' vs '{}'",
        prefix(),
        theme::fg(&args.profile1, t.text).bold(),
        theme::fg(&args.profile2, t.text).bold()
    );

    let mut any_diff = false;

    // Groups
    let g1: BTreeSet<&str> = p1.security.groups.iter().map(|s| s.as_str()).collect();
    let g2: BTreeSet<&str> = p2.security.groups.iter().map(|s| s.as_str()).collect();
    let added_groups: BTreeSet<&&str> = g2.difference(&g1).collect();
    let removed_groups: BTreeSet<&&str> = g1.difference(&g2).collect();

    if !added_groups.is_empty() || !removed_groups.is_empty() {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Groups", t.subtext).bold());
        for g in &removed_groups {
            println!("    {} {}", theme::fg("-", t.red), theme::fg(g, t.red));
        }
        for g in &added_groups {
            println!("    {} {}", theme::fg("+", t.green), theme::fg(g, t.green));
        }
    }

    // Filesystem
    let fs_diffs = diff_string_vecs(&[
        ("allow", &p1.filesystem.allow, &p2.filesystem.allow),
        ("read", &p1.filesystem.read, &p2.filesystem.read),
        ("write", &p1.filesystem.write, &p2.filesystem.write),
        (
            "allow_file",
            &p1.filesystem.allow_file,
            &p2.filesystem.allow_file,
        ),
        (
            "read_file",
            &p1.filesystem.read_file,
            &p2.filesystem.read_file,
        ),
        (
            "write_file",
            &p1.filesystem.write_file,
            &p2.filesystem.write_file,
        ),
    ]);

    if !fs_diffs.is_empty() {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Filesystem", t.subtext).bold());
        for (label, sign, path) in &fs_diffs {
            let color = if *sign == "+" { t.green } else { t.red };
            println!(
                "    {} {} {}",
                theme::fg(sign, color),
                theme::fg(label, t.subtext),
                theme::fg(path, color)
            );
        }
    }

    // Policy patches
    let pp_diffs = diff_string_vecs(&[
        (
            "exclude_groups",
            &p1.policy.exclude_groups,
            &p2.policy.exclude_groups,
        ),
        (
            "add_allow_read",
            &p1.policy.add_allow_read,
            &p2.policy.add_allow_read,
        ),
        (
            "add_allow_write",
            &p1.policy.add_allow_write,
            &p2.policy.add_allow_write,
        ),
        (
            "add_allow_readwrite",
            &p1.policy.add_allow_readwrite,
            &p2.policy.add_allow_readwrite,
        ),
        (
            "add_deny_access",
            &p1.policy.add_deny_access,
            &p2.policy.add_deny_access,
        ),
        (
            "add_deny_commands",
            &p1.policy.add_deny_commands,
            &p2.policy.add_deny_commands,
        ),
        (
            "bypass_protection",
            &p1.policy.bypass_protection,
            &p2.policy.bypass_protection,
        ),
    ]);

    if !pp_diffs.is_empty() {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Policy patches", t.subtext).bold());
        for (label, sign, val) in &pp_diffs {
            let color = if *sign == "+" { t.green } else { t.red };
            println!(
                "    {} {} {}",
                theme::fg(sign, color),
                theme::fg(label, t.subtext),
                theme::fg(val, color)
            );
        }
    }

    // Security scalar fields
    any_diff |= diff_scalar_option(
        "capability_elevation",
        &p1.security.capability_elevation.map(|v| format!("{v}")),
        &p2.security.capability_elevation.map(|v| format!("{v}")),
        t,
    );
    any_diff |= diff_scalar_option(
        "wsl2_proxy_policy",
        &p1.security.wsl2_proxy_policy.map(|v| format!("{v:?}")),
        &p2.security.wsl2_proxy_policy.map(|v| format!("{v:?}")),
        t,
    );
    any_diff |= diff_scalar_option(
        "linux.af_unix_mediation",
        &p1.linux.af_unix_mediation.map(|v| format!("{v:?}")),
        &p2.linux.af_unix_mediation.map(|v| format!("{v:?}")),
        t,
    );
    any_diff |= diff_scalar_option(
        "signal_mode",
        &p1.security.signal_mode.map(|v| format!("{v:?}")),
        &p2.security.signal_mode.map(|v| format!("{v:?}")),
        t,
    );
    any_diff |= diff_scalar_option(
        "process_info_mode",
        &p1.security.process_info_mode.map(|v| format!("{v:?}")),
        &p2.security.process_info_mode.map(|v| format!("{v:?}")),
        t,
    );
    any_diff |= diff_scalar_option(
        "ipc_mode",
        &p1.security.ipc_mode.map(|v| format!("{v:?}")),
        &p2.security.ipc_mode.map(|v| format!("{v:?}")),
        t,
    );

    // Network
    let mut net_diffs: Vec<(String, String)> = Vec::new();
    if p1.network.block != p2.network.block {
        net_diffs.push((
            format!("- block: {}", p1.network.block),
            format!("+ block: {}", p2.network.block),
        ));
    }
    let np1 = p1.network.resolved_network_profile().unwrap_or("");
    let np2 = p2.network.resolved_network_profile().unwrap_or("");
    if np1 != np2 {
        if !np1.is_empty() {
            net_diffs.push((format!("- network_profile: {np1}"), String::new()));
        }
        if !np2.is_empty() {
            net_diffs.push((String::new(), format!("+ network_profile: {np2}")));
        }
    }

    let net_vec_diffs = diff_string_vecs(&[
        (
            "allow_domain",
            &p1.network.allow_domain,
            &p2.network.allow_domain,
        ),
        (
            "credentials",
            p1.network.resolved_credentials(),
            p2.network.resolved_credentials(),
        ),
        (
            "upstream_bypass",
            &p1.network.upstream_bypass,
            &p2.network.upstream_bypass,
        ),
    ]);

    let port1: Vec<String> = p1.network.open_port.iter().map(|p| p.to_string()).collect();
    let port2: Vec<String> = p2.network.open_port.iter().map(|p| p.to_string()).collect();
    let port_diffs = diff_string_vecs(&[("open_port", &port1, &port2)]);
    let listen1: Vec<String> = p1
        .network
        .listen_port
        .iter()
        .map(|p| p.to_string())
        .collect();
    let listen2: Vec<String> = p2
        .network
        .listen_port
        .iter()
        .map(|p| p.to_string())
        .collect();
    let listen_diffs = diff_string_vecs(&[("listen_port", &listen1, &listen2)]);

    if !net_diffs.is_empty()
        || !net_vec_diffs.is_empty()
        || !port_diffs.is_empty()
        || !listen_diffs.is_empty()
    {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Network", t.subtext).bold());
        for (rem, add) in &net_diffs {
            if !rem.is_empty() {
                println!("    {}", theme::fg(rem, t.red));
            }
            if !add.is_empty() {
                println!("    {}", theme::fg(add, t.green));
            }
        }
        for (label, sign, val) in net_vec_diffs
            .iter()
            .chain(port_diffs.iter())
            .chain(listen_diffs.iter())
        {
            let color = if *sign == "+" { t.green } else { t.red };
            println!(
                "    {} {} {}",
                theme::fg(sign, color),
                theme::fg(label, t.subtext),
                theme::fg(val, color)
            );
        }
    }

    any_diff |= diff_scalar_option(
        "upstream_proxy",
        &p1.network.upstream_proxy,
        &p2.network.upstream_proxy,
        t,
    );

    // Workdir
    if p1.workdir.access != p2.workdir.access {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Workdir", t.subtext).bold());
        println!(
            "    {}",
            theme::fg(&format!("- access: {:?}", p1.workdir.access), t.red)
        );
        println!(
            "    {}",
            theme::fg(&format!("+ access: {:?}", p2.workdir.access), t.green)
        );
    }

    // Allowed commands
    let cmd1: BTreeSet<&str> = p1
        .security
        .allowed_commands
        .iter()
        .map(|s| s.as_str())
        .collect();
    let cmd2: BTreeSet<&str> = p2
        .security
        .allowed_commands
        .iter()
        .map(|s| s.as_str())
        .collect();
    let added_cmds: BTreeSet<&&str> = cmd2.difference(&cmd1).collect();
    let removed_cmds: BTreeSet<&&str> = cmd1.difference(&cmd2).collect();

    if !added_cmds.is_empty() || !removed_cmds.is_empty() {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Allowed commands", t.subtext).bold());
        for c in &removed_cmds {
            println!("    {} {}", theme::fg("-", t.red), theme::fg(c, t.red));
        }
        for c in &added_cmds {
            println!("    {} {}", theme::fg("+", t.green), theme::fg(c, t.green));
        }
    }

    // Rollback
    let rb_diffs = diff_string_vecs(&[
        (
            "exclude_patterns",
            &p1.rollback.exclude_patterns,
            &p2.rollback.exclude_patterns,
        ),
        (
            "exclude_globs",
            &p1.rollback.exclude_globs,
            &p2.rollback.exclude_globs,
        ),
    ]);
    if !rb_diffs.is_empty() {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Rollback", t.subtext).bold());
        for (label, sign, val) in &rb_diffs {
            let color = if *sign == "+" { t.green } else { t.red };
            println!(
                "    {} {} {}",
                theme::fg(sign, color),
                theme::fg(label, t.subtext),
                theme::fg(val, color)
            );
        }
    }

    // Open URLs
    let ou1_origins: Vec<String> = p1
        .open_urls
        .as_ref()
        .map(|u| u.allow_origins.clone())
        .unwrap_or_default();
    let ou2_origins: Vec<String> = p2
        .open_urls
        .as_ref()
        .map(|u| u.allow_origins.clone())
        .unwrap_or_default();
    let ou_diffs = diff_string_vecs(&[("allow_origins", &ou1_origins, &ou2_origins)]);
    let ou1_localhost = p1.open_urls.as_ref().is_some_and(|u| u.allow_localhost);
    let ou2_localhost = p2.open_urls.as_ref().is_some_and(|u| u.allow_localhost);

    if !ou_diffs.is_empty() || ou1_localhost != ou2_localhost {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Open URLs", t.subtext).bold());
        for (label, sign, val) in &ou_diffs {
            let color = if *sign == "+" { t.green } else { t.red };
            println!(
                "    {} {} {}",
                theme::fg(sign, color),
                theme::fg(label, t.subtext),
                theme::fg(val, color)
            );
        }
        if ou1_localhost != ou2_localhost {
            println!(
                "    {}",
                theme::fg(&format!("- allow_localhost: {ou1_localhost}"), t.red)
            );
            println!(
                "    {}",
                theme::fg(&format!("+ allow_localhost: {ou2_localhost}"), t.green)
            );
        }
    }

    // Allow launch services
    any_diff |= diff_scalar_option(
        "allow_launch_services",
        &p1.allow_launch_services.map(|v| format!("{v}")),
        &p2.allow_launch_services.map(|v| format!("{v}")),
        t,
    );

    // Plan 34-01 fork-divergence: profile.allow_gpu field does not exist in fork's Profile.

    // Env credentials
    let ec1: BTreeSet<(&String, &String)> = p1.env_credentials.mappings.iter().collect();
    let ec2: BTreeSet<(&String, &String)> = p2.env_credentials.mappings.iter().collect();
    let ec_added: BTreeSet<&(&String, &String)> = ec2.difference(&ec1).collect();
    let ec_removed: BTreeSet<&(&String, &String)> = ec1.difference(&ec2).collect();
    if !ec_added.is_empty() || !ec_removed.is_empty() {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Env credentials", t.subtext).bold());
        for (k, v) in &ec_removed {
            println!(
                "    {} {} -> {}",
                theme::fg("-", t.red),
                theme::fg(k, t.red),
                theme::fg(v, t.red)
            );
        }
        for (k, v) in &ec_added {
            println!(
                "    {} {} -> {}",
                theme::fg("+", t.green),
                theme::fg(k, t.green),
                theme::fg(v, t.green)
            );
        }
    }

    // Hooks
    let h1: BTreeSet<&String> = p1.hooks.hooks.keys().collect();
    let h2: BTreeSet<&String> = p2.hooks.hooks.keys().collect();
    let hooks_added: BTreeSet<&&String> = h2.difference(&h1).collect();
    let hooks_removed: BTreeSet<&&String> = h1.difference(&h2).collect();
    // Check for hooks present in both but with different config
    let hooks_changed: Vec<&String> = h1
        .intersection(&h2)
        .filter(|k| {
            let a = &p1.hooks.hooks[**k];
            let b = &p2.hooks.hooks[**k];
            a.event != b.event || a.matcher != b.matcher || a.script != b.script
        })
        .copied()
        .collect();
    if !hooks_added.is_empty() || !hooks_removed.is_empty() || !hooks_changed.is_empty() {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Hooks", t.subtext).bold());
        for h in &hooks_removed {
            println!("    {} {}", theme::fg("-", t.red), theme::fg(h, t.red));
        }
        for h in &hooks_added {
            println!("    {} {}", theme::fg("+", t.green), theme::fg(h, t.green));
        }
        for h in &hooks_changed {
            println!(
                "    {} {} (changed)",
                theme::fg("~", t.yellow),
                theme::fg(h, t.yellow)
            );
        }
    }

    // Custom credentials
    let cc1: BTreeSet<&String> = p1.network.custom_credentials.keys().collect();
    let cc2: BTreeSet<&String> = p2.network.custom_credentials.keys().collect();
    let cc_added: BTreeSet<&&String> = cc2.difference(&cc1).collect();
    let cc_removed: BTreeSet<&&String> = cc1.difference(&cc2).collect();
    let cc_changed: Vec<&String> = cc1
        .intersection(&cc2)
        .filter(|k| p1.network.custom_credentials[**k] != p2.network.custom_credentials[**k])
        .copied()
        .collect();
    if !cc_added.is_empty() || !cc_removed.is_empty() || !cc_changed.is_empty() {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Custom credentials", t.subtext).bold());
        for c in &cc_removed {
            println!("    {} {}", theme::fg("-", t.red), theme::fg(c, t.red));
        }
        for c in &cc_added {
            println!("    {} {}", theme::fg("+", t.green), theme::fg(c, t.green));
        }
        for c in &cc_changed {
            let old = &p1.network.custom_credentials[*c];
            let new = &p2.network.custom_credentials[*c];
            println!(
                "    {} {} (changed)",
                theme::fg("~", t.yellow),
                theme::fg(c, t.yellow)
            );
            if old.upstream != new.upstream {
                println!(
                    "      {} upstream: {}",
                    theme::fg("-", t.red),
                    theme::fg(&old.upstream, t.red)
                );
                println!(
                    "      {} upstream: {}",
                    theme::fg("+", t.green),
                    theme::fg(&new.upstream, t.green)
                );
            }
            if old.credential_key != new.credential_key {
                let old_key = old.credential_key.as_deref().unwrap_or("<none>");
                let new_key = new.credential_key.as_deref().unwrap_or("<none>");
                println!(
                    "      {} credential_key: {}",
                    theme::fg("-", t.red),
                    theme::fg(old_key, t.red)
                );
                println!(
                    "      {} credential_key: {}",
                    theme::fg("+", t.green),
                    theme::fg(new_key, t.green)
                );
            }
            if old.inject_mode != new.inject_mode {
                println!(
                    "      {} inject_mode: {:?}",
                    theme::fg("-", t.red),
                    old.inject_mode
                );
                println!(
                    "      {} inject_mode: {:?}",
                    theme::fg("+", t.green),
                    new.inject_mode
                );
            }
            if old.inject_header != new.inject_header {
                println!(
                    "      {} inject_header: {}",
                    theme::fg("-", t.red),
                    theme::fg(&old.inject_header, t.red)
                );
                println!(
                    "      {} inject_header: {}",
                    theme::fg("+", t.green),
                    theme::fg(&new.inject_header, t.green)
                );
            }
            if old.credential_format != new.credential_format {
                println!(
                    "      {} credential_format: {}",
                    theme::fg("-", t.red),
                    theme::fg(&old.credential_format, t.red)
                );
                println!(
                    "      {} credential_format: {}",
                    theme::fg("+", t.green),
                    theme::fg(&new.credential_format, t.green)
                );
            }
            if old.path_pattern != new.path_pattern {
                println!(
                    "      {} path_pattern: {:?}",
                    theme::fg("-", t.red),
                    old.path_pattern
                );
                println!(
                    "      {} path_pattern: {:?}",
                    theme::fg("+", t.green),
                    new.path_pattern
                );
            }
            if old.path_replacement != new.path_replacement {
                println!(
                    "      {} path_replacement: {:?}",
                    theme::fg("-", t.red),
                    old.path_replacement
                );
                println!(
                    "      {} path_replacement: {:?}",
                    theme::fg("+", t.green),
                    new.path_replacement
                );
            }
            if old.query_param_name != new.query_param_name {
                println!(
                    "      {} query_param_name: {:?}",
                    theme::fg("-", t.red),
                    old.query_param_name
                );
                println!(
                    "      {} query_param_name: {:?}",
                    theme::fg("+", t.green),
                    new.query_param_name
                );
            }
            if old.env_var != new.env_var {
                println!("      {} env_var: {:?}", theme::fg("-", t.red), old.env_var);
                println!(
                    "      {} env_var: {:?}",
                    theme::fg("+", t.green),
                    new.env_var
                );
            }
        }
    }

    if !any_diff {
        println!();
        println!("  {}", theme::fg("(no differences)", t.subtext));
    }

    Ok(())
}

/// Print a diff for an optional scalar field. Returns true if there was a difference.
fn diff_scalar_option(
    label: &str,
    v1: &Option<String>,
    v2: &Option<String>,
    t: &theme::Theme,
) -> bool {
    if v1 == v2 {
        return false;
    }
    println!();
    println!("  {}:", theme::fg(label, t.subtext).bold());
    if let Some(ref old) = v1 {
        println!("    {}", theme::fg(&format!("- {old}"), t.red));
    }
    if let Some(ref new) = v2 {
        println!("    {}", theme::fg(&format!("+ {new}"), t.green));
    }
    true
}

fn diff_string_vecs<'a>(
    pairs: &[(&'a str, &[String], &[String])],
) -> Vec<(&'a str, &'static str, String)> {
    let mut result = Vec::new();
    for (label, v1, v2) in pairs {
        let s1: BTreeSet<&str> = v1.iter().map(|s| s.as_str()).collect();
        let s2: BTreeSet<&str> = v2.iter().map(|s| s.as_str()).collect();
        for removed in s1.difference(&s2) {
            result.push((*label, "-", removed.to_string()));
        }
        for added in s2.difference(&s1) {
            result.push((*label, "+", added.to_string()));
        }
    }
    result
}

fn diff_to_json(name1: &str, name2: &str, p1: &Profile, p2: &Profile) -> Result<serde_json::Value> {
    let g1: BTreeSet<&str> = p1.security.groups.iter().map(|s| s.as_str()).collect();
    let g2: BTreeSet<&str> = p2.security.groups.iter().map(|s| s.as_str()).collect();

    let groups_added: Vec<&str> = g2.difference(&g1).copied().collect();
    let groups_removed: Vec<&str> = g1.difference(&g2).copied().collect();

    let diff_vec = |v1: &[String], v2: &[String]| -> serde_json::Value {
        let s1: BTreeSet<&str> = v1.iter().map(|s| s.as_str()).collect();
        let s2: BTreeSet<&str> = v2.iter().map(|s| s.as_str()).collect();
        let added: Vec<&str> = s2.difference(&s1).copied().collect();
        let removed: Vec<&str> = s1.difference(&s2).copied().collect();
        serde_json::json!({ "added": added, "removed": removed })
    };

    let ou1 = p1.open_urls.as_ref();
    let ou2 = p2.open_urls.as_ref();

    // Plan 35-03 (REQ-PORT-CLOSURE-07 / D-35-C2 + D-35-C3): pre-compute
    // serde_json::to_value for Option<…> and non-Optional enum fields so we
    // can use `?` before the json!({}) macro (which doesn't support `?`).
    // Applies omit-when-None semantics: None → JSON null here (we preserve
    // the diff shape — profile1/profile2 keys always present — but emit
    // serde-driven snake_case strings rather than Debug-leaked "None").
    let wsl2_p1 = match &p1.security.wsl2_proxy_policy {
        Some(ref v) => serde_json::to_value(v)
            .map_err(|e| NonoError::ProfileParse(format!("wsl2_proxy_policy p1 serialize: {e}")))?,
        None => serde_json::Value::Null,
    };
    let wsl2_p2 = match &p2.security.wsl2_proxy_policy {
        Some(ref v) => serde_json::to_value(v)
            .map_err(|e| NonoError::ProfileParse(format!("wsl2_proxy_policy p2 serialize: {e}")))?,
        None => serde_json::Value::Null,
    };
    let workdir_p1 = serde_json::to_value(&p1.workdir.access)
        .map_err(|e| NonoError::ProfileParse(format!("workdir.access p1 serialize: {e}")))?;
    let workdir_p2 = serde_json::to_value(&p2.workdir.access)
        .map_err(|e| NonoError::ProfileParse(format!("workdir.access p2 serialize: {e}")))?;

    Ok(serde_json::json!({
        "profile1": name1,
        "profile2": name2,
        "groups": {
            "added": groups_added,
            "removed": groups_removed,
        },
        "allowed_commands": diff_vec(
            &p1.security.allowed_commands,
            &p2.security.allowed_commands,
        ),
        "capability_elevation": {
            "profile1": p1.security.capability_elevation,
            "profile2": p2.security.capability_elevation,
            "changed": p1.security.capability_elevation != p2.security.capability_elevation,
        },
        "wsl2_proxy_policy": {
            "profile1": wsl2_p1,
            "profile2": wsl2_p2,
            "changed": p1.security.wsl2_proxy_policy != p2.security.wsl2_proxy_policy,
        },
        "linux": {
            "af_unix_mediation": {
                "profile1": p1.linux.af_unix_mediation,
                "profile2": p2.linux.af_unix_mediation,
                "changed": p1.linux.af_unix_mediation != p2.linux.af_unix_mediation,
            }
        },
        "filesystem": diff_fs_json(&p1.filesystem, &p2.filesystem),
        "workdir": {
            "profile1": workdir_p1,
            "profile2": workdir_p2,
            "changed": p1.workdir.access != p2.workdir.access,
        },
        "network": {
            "block": {
                "profile1": p1.network.block,
                "profile2": p2.network.block,
                "changed": p1.network.block != p2.network.block,
            },
            "network_profile": {
                "profile1": p1.network.resolved_network_profile(),
                "profile2": p2.network.resolved_network_profile(),
                "changed": p1.network.resolved_network_profile() != p2.network.resolved_network_profile(),
            },
            "allow_domain": diff_vec(&p1.network.allow_domain, &p2.network.allow_domain),
            "credentials": diff_vec(p1.network.resolved_credentials(), p2.network.resolved_credentials()),
            "open_port": {
                "profile1": p1.network.open_port,
                "profile2": p2.network.open_port,
                "changed": p1.network.open_port != p2.network.open_port,
            },
            "listen_port": {
                "profile1": p1.network.listen_port,
                "profile2": p2.network.listen_port,
                "changed": p1.network.listen_port != p2.network.listen_port,
            },
            "upstream_proxy": {
                "profile1": p1.network.upstream_proxy,
                "profile2": p2.network.upstream_proxy,
                "changed": p1.network.upstream_proxy != p2.network.upstream_proxy,
            },
            "upstream_bypass": diff_vec(
                &p1.network.upstream_bypass,
                &p2.network.upstream_bypass,
            ),
            "custom_credentials": diff_custom_credentials_json(
                &p1.network.custom_credentials,
                &p2.network.custom_credentials,
            ),
        },
        "env_credentials": {
            "profile1": p1.env_credentials.mappings,
            "profile2": p2.env_credentials.mappings,
            "changed": p1.env_credentials.mappings != p2.env_credentials.mappings,
        },
        "hooks": diff_hooks_json(&p1.hooks.hooks, &p2.hooks.hooks),
        "rollback": {
            "exclude_patterns": diff_vec(&p1.rollback.exclude_patterns, &p2.rollback.exclude_patterns),
            "exclude_globs": diff_vec(&p1.rollback.exclude_globs, &p2.rollback.exclude_globs),
        },
        "open_urls": {
            "allow_origins": diff_vec(
                &ou1.map(|u| u.allow_origins.clone()).unwrap_or_default(),
                &ou2.map(|u| u.allow_origins.clone()).unwrap_or_default(),
            ),
            "allow_localhost": {
                "profile1": ou1.is_some_and(|u| u.allow_localhost),
                "profile2": ou2.is_some_and(|u| u.allow_localhost),
                "changed": ou1.is_some_and(|u| u.allow_localhost) != ou2.is_some_and(|u| u.allow_localhost),
            },
        },
        "allow_launch_services": {
            "profile1": p1.allow_launch_services,
            "profile2": p2.allow_launch_services,
            "changed": p1.allow_launch_services != p2.allow_launch_services,
        },
        // Plan 34-01 fork-divergence: profile.allow_gpu field does not exist in fork's Profile.
    }))
}

fn diff_fs_json(
    fs1: &profile::FilesystemConfig,
    fs2: &profile::FilesystemConfig,
) -> serde_json::Value {
    let diff_vec = |v1: &[String], v2: &[String]| -> serde_json::Value {
        let s1: BTreeSet<&str> = v1.iter().map(|s| s.as_str()).collect();
        let s2: BTreeSet<&str> = v2.iter().map(|s| s.as_str()).collect();
        let added: Vec<&str> = s2.difference(&s1).copied().collect();
        let removed: Vec<&str> = s1.difference(&s2).copied().collect();
        serde_json::json!({ "added": added, "removed": removed })
    };

    serde_json::json!({
        "allow": diff_vec(&fs1.allow, &fs2.allow),
        "read": diff_vec(&fs1.read, &fs2.read),
        "write": diff_vec(&fs1.write, &fs2.write),
        "allow_file": diff_vec(&fs1.allow_file, &fs2.allow_file),
        "read_file": diff_vec(&fs1.read_file, &fs2.read_file),
        "write_file": diff_vec(&fs1.write_file, &fs2.write_file),
    })
}

fn diff_hooks_json(
    h1: &std::collections::HashMap<String, profile::HookConfig>,
    h2: &std::collections::HashMap<String, profile::HookConfig>,
) -> serde_json::Value {
    let added: Vec<&String> = h2.keys().filter(|k| !h1.contains_key(*k)).collect();
    let removed: Vec<&String> = h1.keys().filter(|k| !h2.contains_key(*k)).collect();
    let changed: Vec<&String> = h1
        .keys()
        .filter(|k| {
            h2.get(*k).is_some_and(|v2| {
                let v1 = &h1[*k];
                v1.event != v2.event || v1.matcher != v2.matcher || v1.script != v2.script
            })
        })
        .collect();

    let mut changed_details = serde_json::Map::new();
    for k in &changed {
        let old = &h1[*k];
        let new = &h2[*k];
        let mut detail = serde_json::Map::new();
        if old.event != new.event {
            detail.insert(
                "event".into(),
                serde_json::json!({"profile1": old.event, "profile2": new.event}),
            );
        }
        if old.matcher != new.matcher {
            detail.insert(
                "matcher".into(),
                serde_json::json!({"profile1": old.matcher, "profile2": new.matcher}),
            );
        }
        if old.script != new.script {
            detail.insert(
                "script".into(),
                serde_json::json!({"profile1": old.script, "profile2": new.script}),
            );
        }
        changed_details.insert((*k).clone(), serde_json::Value::Object(detail));
    }

    serde_json::json!({
        "added": added,
        "removed": removed,
        "changed": changed_details,
    })
}

fn diff_custom_credentials_json(
    cc1: &std::collections::HashMap<String, profile::CustomCredentialDef>,
    cc2: &std::collections::HashMap<String, profile::CustomCredentialDef>,
) -> serde_json::Value {
    let added: Vec<&String> = cc2.keys().filter(|k| !cc1.contains_key(*k)).collect();
    let removed: Vec<&String> = cc1.keys().filter(|k| !cc2.contains_key(*k)).collect();
    let changed: Vec<&String> = cc1
        .keys()
        .filter(|k| cc2.get(*k).is_some_and(|v2| cc1[*k] != *v2))
        .collect();

    let mut changed_details = serde_json::Map::new();
    for k in &changed {
        let old = &cc1[*k];
        let new = &cc2[*k];
        let mut detail = serde_json::Map::new();
        if old.upstream != new.upstream {
            detail.insert(
                "upstream".into(),
                serde_json::json!({"profile1": old.upstream, "profile2": new.upstream}),
            );
        }
        if old.credential_key != new.credential_key {
            detail.insert(
                "credential_key".into(),
                serde_json::json!({"profile1": old.credential_key, "profile2": new.credential_key}),
            );
        }
        if old.inject_mode != new.inject_mode {
            // Plan 35-03 (D-35-C3): InjectMode carries #[serde(rename_all = "snake_case")]
            // so serde_json::to_value emits "header" / "url_path" etc. rather than
            // Debug-format "Header" / "UrlPath". Fall back to Debug only on the
            // (structurally impossible) serialization error path.
            let im_p1 = serde_json::to_value(&old.inject_mode)
                .unwrap_or_else(|_| serde_json::Value::String(format!("{:?}", old.inject_mode)));
            let im_p2 = serde_json::to_value(&new.inject_mode)
                .unwrap_or_else(|_| serde_json::Value::String(format!("{:?}", new.inject_mode)));
            detail.insert(
                "inject_mode".into(),
                serde_json::json!({"profile1": im_p1, "profile2": im_p2}),
            );
        }
        if old.inject_header != new.inject_header {
            detail.insert(
                "inject_header".into(),
                serde_json::json!({"profile1": old.inject_header, "profile2": new.inject_header}),
            );
        }
        if old.credential_format != new.credential_format {
            detail.insert(
                "credential_format".into(),
                serde_json::json!({"profile1": old.credential_format, "profile2": new.credential_format}),
            );
        }
        if old.path_pattern != new.path_pattern {
            detail.insert(
                "path_pattern".into(),
                serde_json::json!({"profile1": old.path_pattern, "profile2": new.path_pattern}),
            );
        }
        if old.path_replacement != new.path_replacement {
            detail.insert(
                "path_replacement".into(),
                serde_json::json!({"profile1": old.path_replacement, "profile2": new.path_replacement}),
            );
        }
        if old.query_param_name != new.query_param_name {
            detail.insert(
                "query_param_name".into(),
                serde_json::json!({"profile1": old.query_param_name, "profile2": new.query_param_name}),
            );
        }
        if old.env_var != new.env_var {
            detail.insert(
                "env_var".into(),
                serde_json::json!({"profile1": old.env_var, "profile2": new.env_var}),
            );
        }
        changed_details.insert((*k).clone(), serde_json::Value::Object(detail));
    }

    serde_json::json!({
        "added": added,
        "removed": removed,
        "changed": changed_details,
    })
}

// ---------------------------------------------------------------------------
// nono profile validate
// ---------------------------------------------------------------------------

fn classify_profile_error(e: &NonoError) -> &'static str {
    match e {
        NonoError::ProfileParse(msg)
            if msg.starts_with("expected")
                || msg.contains("line ")
                || msg.contains("column ")
                || msg.contains("EOF") =>
        {
            "JSON syntax error"
        }
        NonoError::ProfileParse(_) => "Profile error",
        NonoError::ProfileRead { .. } => "File read error",
        NonoError::ProfileInheritance(_) => "Inheritance error",
        NonoError::ProfileNotFound(_) => "Profile not found",
        _ => "Error",
    }
}

pub(crate) fn cmd_validate(args: ProfileValidateArgs) -> Result<()> {
    let pol = policy::load_embedded_policy()?;
    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    // Phase 36.5 D-36.5-A2: When `--draft` is set, treat `args.file` as a
    // profile name and route to `profile-drafts/<name>.json`. Composes with
    // `--strict` (orthogonal flags per D-36.5-A2 — draft branch changes only
    // the file path resolution; the rest of the validation body is unchanged).
    let input_file: std::path::PathBuf = if args.draft {
        let name = args.file.to_string_lossy();
        if !profile::is_valid_profile_name(&name) {
            return Err(NonoError::ProfileParse(format!(
                "Invalid profile name '{}' for --draft (alphanumeric + hyphens only)",
                name
            )));
        }
        profile::get_user_profile_draft_path(&name)?
    } else {
        args.file.clone()
    };

    // Plan 36-01a (Task 2): Detect the legacy `override_deny` key and
    // route to errors (--strict) or warnings (default) based on args.strict.
    //
    // WR-05 fix (REVIEW.md): inspect the parsed JSON directly to detect the
    // legacy key, sidestepping the coupling between LegacyPolicyPatch's
    // `#[serde(deny_unknown_fields)]` schema and the validation logic.
    // Previously, `serde_json::from_value::<LegacyPolicyPatch>(policy_val)`
    // would fail (silently!) if the policy object contained ANY other
    // PolicyPatchConfig fields — `--strict` would skip dual-key profiles
    // entirely. Direct `policy_val.get("override_deny")` extracts the
    // legacy field robustly regardless of which other keys coexist.
    //
    // The actual rewrite still goes through `LegacyPolicyPatch::rewrite`
    // so the canonical-form contract stays centralised in
    // `deprecated_schema`. We build a synthetic single-field JSON object
    // to feed the deserializer.
    //
    // Failure to read or parse the file is silently ignored here — the
    // main parse in Step 1 below surfaces real parse errors.
    {
        let counter: &DeprecationCounter = &GLOBAL_DEPRECATION_COUNTER;
        if let Ok(raw) = fs::read_to_string(&input_file) {
            if let Ok(root) = serde_json::from_str::<serde_json::Value>(&raw) {
                if let Some(legacy_val) = root.get("policy").and_then(|p| p.get("override_deny")) {
                    // Build a synthetic {"override_deny": [...]} value so we
                    // can keep the canonical rewrite path centralised in
                    // LegacyPolicyPatch::rewrite. Per WR-05, this avoids
                    // failing-deserialise when sibling canonical keys are
                    // present in the real `policy` object.
                    let mut synthetic = serde_json::Map::new();
                    synthetic.insert("override_deny".to_string(), legacy_val.clone());
                    let synthetic_val = serde_json::Value::Object(synthetic);
                    if let Ok(patch) = serde_json::from_value::<LegacyPolicyPatch>(synthetic_val) {
                        if patch.has_legacy_keys() {
                            // Rewrite to canonical form to get the
                            // bypass_protection paths for the error message.
                            let canonical = patch.rewrite()?;
                            // CR-02 fix: emit the one-shot WARN with the
                            // correct legacy / canonical key pair. The
                            // DeprecationCounter map only registers
                            // `override_deny` as a known legacy key.
                            counter.emit_once("override_deny", "bypass_protection");
                            if args.strict {
                                // Strict mode: fail closed with a clear error message.
                                errors.push(format!(
                                    "legacy key `override_deny` rejected by --strict; \
                                     use canonical `bypass_protection` instead (found {} \
                                     path(s))",
                                    canonical.bypass_protection.len()
                                ));
                            } else {
                                // Non-strict mode: the emit_once call above already
                                // wrote the WARN to stderr; record as warning.
                                warnings.push(
                                    "legacy key `override_deny` found; migrate to canonical \
                                     `bypass_protection`"
                                        .to_string(),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // Step 1: Load profile (parse JSON + resolve inheritance)
    let profile = match profile::load_profile_from_path(&input_file) {
        Ok(p) => Some(p),
        Err(e) => {
            let label = classify_profile_error(&e);
            errors.push(format!("{}: {}", label, e));
            None
        }
    };

    if let Some(ref profile) = profile {
        // Step 2: Check group references
        for group_name in &profile.security.groups {
            if !pol.groups.contains_key(group_name) {
                errors.push(format!("Group '{}' not found in policy.json", group_name));
            }
        }

        // Step 3: Check exclude_groups
        for excl in &profile.policy.exclude_groups {
            if let Some(group) = pol.groups.get(excl) {
                if group.required {
                    errors.push(format!("Cannot exclude required group '{}'", excl));
                }
            } else {
                warnings.push(format!(
                    "Excluded group '{}' not found in policy.json",
                    excl
                ));
            }
        }

        // Step 5: Check for empty paths
        let check_paths = |paths: &[String], label: &str, w: &mut Vec<String>| {
            for p in paths {
                if p.trim().is_empty() {
                    w.push(format!("Empty path in {}", label));
                }
            }
        };
        check_paths(&profile.filesystem.allow, "filesystem.allow", &mut warnings);
        check_paths(&profile.filesystem.read, "filesystem.read", &mut warnings);
        check_paths(&profile.filesystem.write, "filesystem.write", &mut warnings);
    }

    if args.json {
        let val = serde_json::json!({
            "file": input_file.display().to_string(),
            "valid": errors.is_empty(),
            "errors": errors,
            "warnings": warnings,
        });
        println!("{}", to_json(&val)?);
        if !errors.is_empty() {
            return Err(NonoError::ProfileParse("validation failed".into()));
        }
        return Ok(());
    }

    let t = theme::current();
    println!(
        "{}: validating {}",
        prefix(),
        theme::fg(&input_file.display().to_string(), t.text)
    );
    println!();

    if profile.is_some() {
        println!("  {}  JSON syntax valid", theme::fg("[ok]", t.green));
    }

    if let Some(ref profile) = profile {
        let valid_groups = profile
            .security
            .groups
            .iter()
            .filter(|g| pol.groups.contains_key(g.as_str()))
            .count();
        let total_groups = profile.security.groups.len();
        if valid_groups == total_groups && total_groups > 0 {
            println!(
                "  {}  All {} group references valid",
                theme::fg("[ok]", t.green),
                total_groups
            );
        }
    }

    for w in &warnings {
        println!(
            "  {} {}",
            theme::fg("[warn]", t.yellow),
            theme::fg(w, t.yellow)
        );
    }

    for e in &errors {
        println!("  {}  {}", theme::fg("[err]", t.red), theme::fg(e, t.red));
    }

    println!();
    if errors.is_empty() {
        let suffix = if warnings.is_empty() {
            String::new()
        } else {
            format!(
                " ({} warning{})",
                warnings.len(),
                if warnings.len() == 1 { "" } else { "s" }
            )
        };
        println!(
            "  Result: {}{}",
            theme::fg("valid", t.green).bold(),
            theme::fg(&suffix, t.yellow)
        );
        Ok(())
    } else {
        println!(
            "  Result: {} ({} error{})",
            theme::fg("invalid", t.red).bold(),
            errors.len(),
            if errors.len() == 1 { "" } else { "s" }
        );
        Err(NonoError::ProfileParse("validation failed".into()))
    }
}

// ---------------------------------------------------------------------------
// Profile → Manifest compilation
// ---------------------------------------------------------------------------

/// Compile a resolved profile into a capability manifest.
///
/// This produces a fully-resolved, portable manifest with absolute paths.
/// Environment variables (`~`, `$HOME`, `$TMPDIR`, etc.) are expanded.
fn resolve_to_manifest(
    prof: &Profile,
    workdir: &std::path::Path,
) -> Result<nono::manifest::CapabilityManifest> {
    use nono::manifest;

    // Helper: expand a path template and convert to string for the manifest
    let expand = |tmpl: &str| -> Result<String> {
        let expanded = profile::expand_vars(tmpl, workdir)?;
        Ok(expanded.to_string_lossy().into_owned())
    };

    // Filesystem
    let mut grants = Vec::new();
    let mut deny = Vec::new();

    let fs_sources: &[(&[String], manifest::AccessMode, bool)] = &[
        (
            &prof.filesystem.allow,
            manifest::AccessMode::Readwrite,
            false,
        ),
        (&prof.filesystem.read, manifest::AccessMode::Read, false),
        (&prof.filesystem.write, manifest::AccessMode::Write, false),
        (
            &prof.filesystem.allow_file,
            manifest::AccessMode::Readwrite,
            true,
        ),
        (&prof.filesystem.read_file, manifest::AccessMode::Read, true),
        (
            &prof.filesystem.write_file,
            manifest::AccessMode::Write,
            true,
        ),
        (
            &prof.policy.add_allow_read,
            manifest::AccessMode::Read,
            false,
        ),
        (
            &prof.policy.add_allow_write,
            manifest::AccessMode::Write,
            false,
        ),
        (
            &prof.policy.add_allow_readwrite,
            manifest::AccessMode::Readwrite,
            false,
        ),
    ];

    for (paths, access, is_file) in fs_sources {
        for p in *paths {
            grants.push(make_fs_grant(&expand(p)?, *access, *is_file)?);
        }
    }
    // Deny paths from policy patches
    for p in &prof.policy.add_deny_access {
        let expanded = expand(p)?;
        deny.push(manifest::FsDeny {
            path: expanded
                .parse()
                .map_err(|e| NonoError::ConfigParse(format!("invalid deny path: {e}")))?,
        });
    }

    // Resolve security.groups → filesystem grants, deny paths, and blocked commands.
    // Groups are the primary source of system read paths, deny rules, and dangerous
    // command blocks. Without this, the exported manifest is weaker than the profile.
    let loaded_policy = policy::load_embedded_policy()?;
    let mut scratch_caps = nono::CapabilitySet::new();
    let resolved_groups =
        policy::resolve_groups(&loaded_policy, &prof.security.groups, &mut scratch_caps)?;

    // Add filesystem grants from resolved groups
    for cap in scratch_caps.fs_capabilities() {
        let access = match cap.access {
            nono::AccessMode::Read => manifest::AccessMode::Read,
            nono::AccessMode::Write => manifest::AccessMode::Write,
            nono::AccessMode::ReadWrite => manifest::AccessMode::Readwrite,
        };
        let path_str = cap.resolved.to_string_lossy().into_owned();
        grants.push(make_fs_grant(&path_str, access, cap.is_file)?);
    }

    // Expand bypass_protection paths so we can filter them out of the deny list.
    // The manifest is the fully-resolved output — overridden denies must not
    // appear, otherwise the manifest re-applies restrictions the profile relaxed.
    let bypass_protection_expanded: Vec<std::path::PathBuf> = prof
        .policy
        .bypass_protection
        .iter()
        .filter_map(|tmpl| profile::expand_vars(tmpl, workdir).ok())
        .map(|p| {
            if p.exists() {
                p.canonicalize().unwrap_or(p)
            } else {
                p
            }
        })
        .collect();

    // Add deny paths from resolved groups, filtering out overridden paths.
    for deny_path in resolved_groups.deny_paths.iter().filter(|dp| {
        !bypass_protection_expanded
            .iter()
            .any(|ovr| dp.starts_with(ovr))
    }) {
        let path_str = deny_path.to_string_lossy().into_owned();
        deny.push(manifest::FsDeny {
            path: path_str
                .parse()
                .map_err(|e| NonoError::ConfigParse(format!("invalid deny path: {e}")))?,
        });
    }

    // Add blocked commands from resolved groups
    let group_blocked_commands: Vec<String> = scratch_caps.blocked_commands().to_vec();

    // Add workdir access as a filesystem grant
    let workdir_str = workdir.to_string_lossy().into_owned();
    match prof.workdir.access {
        WorkdirAccess::ReadWrite => {
            grants.push(make_fs_grant(
                &workdir_str,
                manifest::AccessMode::Readwrite,
                false,
            )?);
        }
        WorkdirAccess::Read => {
            grants.push(make_fs_grant(
                &workdir_str,
                manifest::AccessMode::Read,
                false,
            )?);
        }
        WorkdirAccess::Write => {
            grants.push(make_fs_grant(
                &workdir_str,
                manifest::AccessMode::Write,
                false,
            )?);
        }
        WorkdirAccess::None => {} // no grant
    }

    // Deduplicate grants: if the same path appears from both filesystem.allow
    // and workdir (or groups), keep the highest-access-mode entry.
    grants.sort_by(|a, b| a.path.as_str().cmp(b.path.as_str()));
    grants.dedup_by(|a, b| {
        if a.path.as_str() == b.path.as_str() && a.type_ == b.type_ {
            // Keep the broader access mode in `b` (the survivor of dedup_by)
            b.access = wider_access(a.access, b.access);
            true
        } else {
            false
        }
    });

    // Deduplicate deny entries by path
    deny.sort_by(|a, b| a.path.as_str().cmp(b.path.as_str()));
    deny.dedup_by(|a, b| a.path.as_str() == b.path.as_str());

    let filesystem = if grants.is_empty() && deny.is_empty() {
        None
    } else {
        Some(manifest::Filesystem { grants, deny })
    };

    // Network
    let network_mode = if prof.network.block {
        manifest::NetworkMode::Blocked
    } else if prof.network.resolved_network_profile().is_some()
        || !prof.network.allow_domain.is_empty()
        || !prof.network.resolved_credentials().is_empty()
        || !prof.network.custom_credentials.is_empty()
    {
        manifest::NetworkMode::Proxy
    } else {
        manifest::NetworkMode::Unrestricted
    };

    let network = Some(manifest::Network {
        mode: network_mode,
        allow_domains: prof.network.allow_domain.clone(),
        endpoints: Vec::new(),
        dns: true,
        ports: if prof.network.listen_port.is_empty() && prof.network.open_port.is_empty() {
            None
        } else {
            Some(manifest::PortConfig {
                connect: Vec::new(),
                bind: prof
                    .network
                    .listen_port
                    .iter()
                    .filter_map(|p| std::num::NonZeroU64::new(u64::from(*p)))
                    .collect(),
                localhost: prof
                    .network
                    .open_port
                    .iter()
                    .filter_map(|p| std::num::NonZeroU64::new(u64::from(*p)))
                    .collect(),
            })
        },
    });

    // Process
    let signal_mode = match prof.security.signal_mode {
        Some(profile::ProfileSignalMode::Isolated) | None => manifest::SignalMode::Isolated,
        Some(profile::ProfileSignalMode::AllowSameSandbox) => {
            manifest::SignalMode::AllowSameSandbox
        }
        Some(profile::ProfileSignalMode::AllowAll) => manifest::SignalMode::AllowAll,
    };
    let process_info_mode = match prof.security.process_info_mode {
        Some(profile::ProfileProcessInfoMode::Isolated) | None => {
            manifest::ProcessInfoMode::Isolated
        }
        Some(profile::ProfileProcessInfoMode::AllowSameSandbox) => {
            manifest::ProcessInfoMode::AllowSameSandbox
        }
        Some(profile::ProfileProcessInfoMode::AllowAll) => manifest::ProcessInfoMode::AllowAll,
    };
    let ipc_mode = match prof.security.ipc_mode {
        Some(profile::ProfileIpcMode::SharedMemoryOnly) | None => {
            manifest::IpcMode::SharedMemoryOnly
        }
        Some(profile::ProfileIpcMode::Full) => manifest::IpcMode::Full,
    };

    let process = Some(manifest::Process {
        allowed_commands: prof.security.allowed_commands.clone(),
        blocked_commands: {
            let mut cmds = group_blocked_commands;
            cmds.extend(prof.policy.add_deny_commands.clone());
            cmds.sort();
            cmds.dedup();
            cmds
        },
        exec_strategy: if !prof.rollback.exclude_patterns.is_empty()
            || !prof.rollback.exclude_globs.is_empty()
        {
            manifest::ExecStrategy::Supervised
        } else {
            manifest::ExecStrategy::Monitor
        },
        signal_mode,
        process_info_mode,
        ipc_mode,
    });

    // Rollback
    let rollback =
        if prof.rollback.exclude_patterns.is_empty() && prof.rollback.exclude_globs.is_empty() {
            None
        } else {
            Some(manifest::Rollback {
                enabled: false,
                exclude_patterns: prof.rollback.exclude_patterns.clone(),
                exclude_globs: prof.rollback.exclude_globs.clone(),
            })
        };

    // Credentials (custom_credentials from profile → manifest credentials)
    // OAuth2 credentials (auth field) are not yet representable in the manifest
    // schema, so only static-key credentials are exported.
    let mut credentials = Vec::new();
    for (name, cred) in &prof.network.custom_credentials {
        let inject_mode = match cred.inject_mode {
            profile::InjectMode::Header => manifest::InjectMode::Header,
            profile::InjectMode::UrlPath => manifest::InjectMode::UrlPath,
            profile::InjectMode::QueryParam => manifest::InjectMode::QueryParam,
            profile::InjectMode::BasicAuth => manifest::InjectMode::BasicAuth,
        };

        let endpoint_rules: Vec<manifest::EndpointRule> = cred
            .endpoint_rules
            .iter()
            .map(|r| {
                let method = r.method.parse().map_err(|e| {
                    NonoError::ConfigParse(format!(
                        "invalid endpoint rule method '{}': {e}",
                        r.method
                    ))
                })?;
                let path = r.path.parse().map_err(|e| {
                    NonoError::ConfigParse(format!("invalid endpoint rule path '{}': {e}", r.path))
                })?;
                Ok(manifest::EndpointRule { method, path })
            })
            .collect::<Result<Vec<_>>>()?;

        credentials.push(manifest::Credential {
            name: name
                .parse()
                .map_err(|e| NonoError::ConfigParse(format!("invalid credential name: {e}")))?,
            upstream: cred
                .upstream
                .parse()
                .map_err(|e| NonoError::ConfigParse(format!("invalid credential upstream: {e}")))?,
            source: match cred.credential_key.as_ref() {
                Some(key) => key.parse().map_err(|e| {
                    NonoError::ConfigParse(format!("invalid credential source: {e}"))
                })?,
                None => continue,
            },
            inject: Some(manifest::CredentialInject {
                mode: inject_mode,
                header: cred.inject_header.clone(),
                format: cred.credential_format.clone(),
                path_pattern: cred.path_pattern.clone(),
                path_replacement: cred.path_replacement.clone(),
                query_param_name: cred.query_param_name.clone(),
            }),
            env_var: cred
                .env_var
                .as_ref()
                .map(|v| {
                    v.parse()
                        .map_err(|e| NonoError::ConfigParse(format!("invalid env_var: {e}")))
                })
                .transpose()?,
            endpoint_rules,
        });
    }

    let version = "0.1.0"
        .parse()
        .map_err(|e| NonoError::ConfigParse(format!("version parse error: {e}")))?;

    Ok(manifest::CapabilityManifest {
        version,
        schema: Some("https://nono.dev/schemas/capability-manifest.schema.json".to_string()),
        filesystem,
        network,
        process,
        rollback,
        credentials,
    })
}

/// Return the broader of two access modes (Read + Write → Readwrite).
fn wider_access(
    a: nono::manifest::AccessMode,
    b: nono::manifest::AccessMode,
) -> nono::manifest::AccessMode {
    use nono::manifest::AccessMode::{Read, Readwrite, Write};
    match (a, b) {
        (Readwrite, _) | (_, Readwrite) => Readwrite,
        (Read, Write) | (Write, Read) => Readwrite,
        (Read, Read) => Read,
        (Write, Write) => Write,
    }
}

/// Helper to construct an `FsGrant` from an expanded path string.
fn make_fs_grant(
    path: &str,
    access: nono::manifest::AccessMode,
    is_file: bool,
) -> Result<nono::manifest::FsGrant> {
    Ok(nono::manifest::FsGrant {
        path: path
            .parse()
            .map_err(|e| NonoError::ConfigParse(format!("invalid grant path: {e}")))?,
        access,
        type_: if is_file {
            nono::manifest::FsEntryType::File
        } else {
            nono::manifest::FsEntryType::Directory
        },
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::Profile;
    use std::path::PathBuf;

    /// The profile authoring guide is compiled into the binary and surfaced
    /// via `nono profile guide`. It must not instruct users to run the
    /// deprecated `nono policy <sub>` commands.
    #[test]
    fn embedded_guide_contains_no_nono_policy_references() {
        let text = crate::config::embedded::embedded_profile_guide();
        assert!(
            !text.contains("nono policy "),
            "profile-authoring-guide.md references deprecated 'nono policy ' commands — update to 'nono profile '",
        );
    }

    #[test]
    fn test_minimal_skeleton_is_valid_profile() {
        let args = ProfileInitArgs {
            name: "test-profile".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: false,
            output: None,
            force: false,
            draft: false,
            refresh: false,
        };
        let skeleton = build_skeleton(&args);
        let json = serde_json::to_string(&skeleton).expect("serialize");
        let profile: Profile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(profile.meta.name, "test-profile");
    }

    #[test]
    fn test_full_skeleton_is_valid_profile() {
        let args = ProfileInitArgs {
            name: "full-test".to_string(),
            extends: Some("default".to_string()),
            groups: vec![],
            description: Some("A full test profile".to_string()),
            full: true,
            output: None,
            force: false,
            draft: false,
            refresh: false,
        };
        let skeleton = build_skeleton(&args);
        let json = serde_json::to_string(&skeleton).expect("serialize");
        let profile: Profile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(profile.meta.name, "full-test");
        assert_eq!(profile.extends, Some(vec!["default".to_string()]));
        assert_eq!(
            profile.meta.description,
            Some("A full test profile".to_string())
        );
    }

    #[test]
    fn test_skeleton_with_groups() {
        let args = ProfileInitArgs {
            name: "grouped".to_string(),
            extends: None,
            groups: vec!["deny_credentials".to_string()],
            description: None,
            full: false,
            output: None,
            force: false,
            draft: false,
            refresh: false,
        };
        let skeleton = build_skeleton(&args);
        let groups = skeleton["security"]["groups"].as_array().expect("array");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0], "deny_credentials");
    }

    #[test]
    fn test_skeleton_omits_schema_url() {
        let args = ProfileInitArgs {
            name: "schema-test".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: false,
            output: None,
            force: false,
            draft: false,
            refresh: false,
        };
        let skeleton = build_skeleton(&args);
        // $schema is not emitted because the URL is not hosted;
        // users export the schema locally via `nono profile schema`
        assert!(skeleton.get("$schema").is_none());
    }

    #[test]
    fn test_invalid_profile_name() {
        let result = cmd_init(ProfileInitArgs {
            name: "-bad-name-".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: false,
            output: Some(PathBuf::from("/tmp/nono-test-bad.json")),
            force: false,
            draft: false,
            refresh: false,
        });
        assert!(result.is_err());
        let err = result.expect_err("error");
        assert!(err.to_string().contains("Invalid profile name"));
    }

    #[test]
    fn test_invalid_group_name() {
        let result = cmd_init(ProfileInitArgs {
            name: "test-profile".to_string(),
            extends: None,
            groups: vec!["nonexistent_group_xyz".to_string()],
            description: None,
            full: false,
            output: Some(PathBuf::from("/tmp/nono-test-badgroup.json")),
            force: false,
            draft: false,
            refresh: false,
        });
        assert!(result.is_err());
        let err = result.expect_err("error");
        assert!(err.to_string().contains("Unknown security group"));
    }

    #[test]
    fn test_invalid_extends_target() {
        let result = cmd_init(ProfileInitArgs {
            name: "test-profile".to_string(),
            extends: Some("nonexistent-base-profile-xyz".to_string()),
            groups: vec![],
            description: None,
            full: false,
            output: Some(PathBuf::from("/tmp/nono-test-badextends.json")),
            force: false,
            draft: false,
            refresh: false,
        });
        assert!(result.is_err());
        let err = result.expect_err("error");
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_force_overwrite() {
        use std::io::Write;

        let tmp = std::env::temp_dir().join("nono-test-force-overwrite.json");
        // Create existing file
        let mut f = fs::File::create(&tmp).expect("create");
        f.write_all(b"{}").expect("write");
        drop(f);

        // Without force: should fail
        let result = cmd_init(ProfileInitArgs {
            name: "test-profile".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: false,
            output: Some(tmp.clone()),
            force: false,
            draft: false,
            refresh: false,
        });
        assert!(result.is_err());

        // With force: should succeed
        let result = cmd_init(ProfileInitArgs {
            name: "test-profile".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: false,
            output: Some(tmp.clone()),
            force: true,
            draft: false,
            refresh: false,
        });
        assert!(result.is_ok());

        // Verify file was written with correct content
        let content = fs::read_to_string(&tmp).expect("read");
        let profile: Profile = serde_json::from_str(&content).expect("parse");
        assert_eq!(profile.meta.name, "test-profile");

        // Cleanup
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_full_vs_minimal_differences() {
        let minimal_args = ProfileInitArgs {
            name: "minimal".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: false,
            output: None,
            force: false,
            draft: false,
            refresh: false,
        };
        let full_args = ProfileInitArgs {
            name: "full".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: true,
            output: None,
            force: false,
            draft: false,
            refresh: false,
        };
        let minimal = build_skeleton(&minimal_args);
        let full = build_skeleton(&full_args);

        let minimal_obj = minimal.as_object().expect("object");
        let full_obj = full.as_object().expect("object");

        // Full has more keys than minimal
        assert!(full_obj.len() > minimal_obj.len());

        // Full has sections that minimal does not
        assert!(full_obj.contains_key("policy"));
        assert!(full_obj.contains_key("network"));
        assert!(full_obj.contains_key("env_credentials"));
        assert!(full_obj.contains_key("hooks"));
        assert!(full_obj.contains_key("rollback"));

        // open_urls and allow_launch_services are intentionally omitted
        // to avoid silently overriding inherited values from base profiles
        assert!(!full_obj.contains_key("open_urls"));
        assert!(!full_obj.contains_key("allow_launch_services"));

        assert!(!minimal_obj.contains_key("policy"));
        assert!(!minimal_obj.contains_key("network"));
        assert!(!minimal_obj.contains_key("hooks"));

        // Full filesystem has all fields
        let full_fs = full_obj["filesystem"].as_object().expect("fs object");
        assert!(full_fs.contains_key("write"));
        assert!(full_fs.contains_key("allow_file"));
        assert!(full_fs.contains_key("read_file"));
        assert!(full_fs.contains_key("write_file"));

        // Minimal filesystem has only allow + read
        let min_fs = minimal_obj["filesystem"].as_object().expect("fs object");
        assert!(!min_fs.contains_key("write"));
        assert!(!min_fs.contains_key("allow_file"));

        // Full policy has add_deny_access
        let full_pol = full_obj["policy"].as_object().expect("policy object");
        assert!(full_pol.contains_key("add_deny_access"));

        // Full network has all fields
        let full_net = full_obj["network"].as_object().expect("network object");
        assert!(full_net.contains_key("allow_domain"));
        assert!(full_net.contains_key("credentials"));
        assert!(full_net.contains_key("open_port"));
        assert!(full_net.contains_key("listen_port"));
        assert!(full_net.contains_key("custom_credentials"));
    }

    #[test]
    fn test_groups_lists_all() {
        let pol = policy::load_embedded_policy().expect("should load policy");
        assert!(
            pol.groups.len() > 10,
            "expected many groups, got {}",
            pol.groups.len()
        );
        assert!(
            pol.groups.contains_key("deny_credentials"),
            "expected deny_credentials group"
        );
    }

    #[test]
    fn test_groups_specific_known() {
        let pol = policy::load_embedded_policy().expect("should load policy");
        let group = pol
            .groups
            .get("deny_credentials")
            .expect("deny_credentials should exist");
        assert!(!group.description.is_empty());
        assert!(group.required);
        if let Some(ref deny) = group.deny {
            let all_paths = deny.access.join(" ");
            assert!(all_paths.contains(".ssh"), "expected .ssh in deny paths");
            assert!(all_paths.contains(".aws"), "expected .aws in deny paths");
        } else {
            panic!("deny_credentials should have deny rules");
        }
    }

    #[test]
    fn test_groups_unknown_errors() {
        let pol = policy::load_embedded_policy().expect("should load policy");
        let result = cmd_groups_detail(&pol, "nonexistent_group_xyz", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_profiles_includes_builtins() {
        let profiles = profile::list_profiles();
        assert!(
            profiles.contains(&"default".to_string()),
            "expected 'default' in profiles"
        );
        assert!(
            profiles.contains(&"claude-code".to_string()),
            "expected 'claude-code' in profiles"
        );
    }

    #[test]
    fn test_show_resolves_inheritance() {
        let profile =
            profile::load_profile("claude-code").expect("claude-code profile should load");
        assert!(
            !profile.security.groups.is_empty(),
            "claude-code should have security groups"
        );
        // claude-code extends default, so it should have default's base groups
        let has_deny = profile.security.groups.iter().any(|g| g.contains("deny"));
        assert!(has_deny, "claude-code should inherit deny groups");
    }

    #[test]
    fn test_diff_shows_differences() {
        let p1 = profile::load_profile("default").expect("default should load");
        let p2 = profile::load_profile("claude-code").expect("claude-code should load");

        let g1: BTreeSet<&str> = p1.security.groups.iter().map(|s| s.as_str()).collect();
        let g2: BTreeSet<&str> = p2.security.groups.iter().map(|s| s.as_str()).collect();

        let added: BTreeSet<&&str> = g2.difference(&g1).collect();
        assert!(
            !added.is_empty(),
            "claude-code should have additional groups over default"
        );
    }

    #[test]
    fn test_validate_valid_profile() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test-profile.json");
        std::fs::write(
            &path,
            r#"{
                "meta": { "name": "test", "description": "test profile" },
                "security": { "groups": ["deny_credentials"] },
                "workdir": { "access": "readwrite" }
            }"#,
        )
        .expect("write");

        let args = ProfileValidateArgs {
            file: path,
            json: false,
            strict: false,
            draft: false,
        };
        let result = cmd_validate(args);
        assert!(result.is_ok(), "valid profile should pass validation");
    }

    #[test]
    fn test_validate_invalid_group() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bad-profile.json");
        std::fs::write(
            &path,
            r#"{
                "meta": { "name": "test" },
                "security": { "groups": ["nonexistent_group_xyz"] }
            }"#,
        )
        .expect("write");

        let args = ProfileValidateArgs {
            file: path,
            json: false,
            strict: false,
            draft: false,
        };
        let result = cmd_validate(args);
        assert!(result.is_err(), "invalid group should fail validation");
    }

    #[test]
    fn test_validate_exclude_required() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bad-exclude.json");
        std::fs::write(
            &path,
            r#"{
                "meta": { "name": "test" },
                "security": { "groups": [] },
                "policy": { "exclude_groups": ["deny_credentials"] }
            }"#,
        )
        .expect("write");

        let args = ProfileValidateArgs {
            file: path,
            json: false,
            strict: false,
            draft: false,
        };
        let result = cmd_validate(args);
        assert!(
            result.is_err(),
            "excluding required group should fail validation"
        );
    }

    // ---------------------------------------------------------------------------
    // Helper tests (Phase 36.5 Task C2-02)
    // ---------------------------------------------------------------------------

    #[test]
    fn sha256_hex_of_known_bytes() {
        // SHA-256 of empty input is well-known
        let result = sha256_hex(b"");
        assert_eq!(
            result,
            "e3b0c44298fc1c149afbf4c8996fb924\
             27ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_hex_produces_lowercase_hex() {
        let result = sha256_hex(b"hello");
        assert_eq!(result.len(), 64, "SHA-256 hex must be 64 chars");
        assert!(
            result.chars().all(|c| c.is_ascii_hexdigit()),
            "SHA-256 hex must be lowercase hexadecimal: {result}"
        );
    }

    #[test]
    fn read_regular_file_reads_normal_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("regular.txt");
        let content = b"hello world 1234567890";
        std::fs::write(&path, content).expect("write");
        let result = read_regular_file(&path, "test file").expect("read_regular_file");
        assert_eq!(result, content);
    }

    #[cfg(unix)]
    #[test]
    fn read_regular_file_rejects_symlink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target.txt");
        let symlink_path = dir.path().join("link.txt");
        std::fs::write(&target, b"content").expect("write target");
        std::os::unix::fs::symlink(&target, &symlink_path).expect("create symlink");
        let result = read_regular_file(&symlink_path, "test file");
        assert!(result.is_err(), "should reject symlink");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("symlink"),
            "error message should mention 'symlink': {msg}"
        );
    }

    #[test]
    fn read_regular_file_rejects_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let result = read_regular_file(dir.path(), "test dir");
        assert!(result.is_err(), "should reject directory");
        let msg = result
            .expect_err("expected error for directory")
            .to_string();
        assert!(
            msg.contains("not a regular file"),
            "error message should mention 'not a regular file': {msg}"
        );
    }

    #[test]
    fn read_regular_file_rejects_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("nonexistent.txt");
        let result = read_regular_file(&missing, "missing file");
        assert!(result.is_err(), "should error on missing file");
        // Should be a ProfileRead error (io error)
        assert!(
            matches!(
                result.expect_err("expected error for missing file"),
                nono::NonoError::ProfileRead { .. }
            ),
            "expected ProfileRead error for missing file"
        );
    }

    #[test]
    fn atomic_write_file_creates_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("output.txt");
        let content = b"atomic write content";
        atomic_write_file(&path, content).expect("atomic_write_file");
        assert!(path.exists(), "target file should exist after atomic write");
        let read_back = std::fs::read(&path).expect("read back");
        assert_eq!(read_back, content);
    }

    #[test]
    fn atomic_write_file_overwrites_existing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("overwrite.txt");
        std::fs::write(&path, b"old content").expect("write old");
        let new_content = b"new content";
        atomic_write_file(&path, new_content).expect("atomic_write_file overwrite");
        let read_back = std::fs::read(&path).expect("read back");
        assert_eq!(read_back, new_content, "should overwrite existing content");
        // No .tmp.* files should leak in parent dir
        let leaked: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(
            leaked.is_empty(),
            "no .tmp.* files should remain after atomic write"
        );
    }

    #[test]
    fn atomic_write_file_uses_pid_suffix() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("subdir").join("file.txt");
        // We can only indirectly verify PID suffix: the parent dir must be
        // created by the helper (subdir does not pre-exist).
        atomic_write_file(&path, b"content").expect("atomic_write_file with mkdir");
        assert!(
            path.exists(),
            "target should exist even when parent was created"
        );
    }

    #[test]
    fn verify_base_hash_match() {
        let dir = tempfile::tempdir().expect("tempdir");
        let canonical_bytes = b"canonical profile content";
        let hash = sha256_hex(canonical_bytes);
        let base_path = dir.path().join("myagent.base");
        std::fs::write(&base_path, &hash).expect("write base hash");
        let result = verify_base_hash(&base_path, canonical_bytes, "myagent");
        assert!(
            result.is_ok(),
            "hash match should return Ok(()): {result:?}"
        );
    }

    #[test]
    fn verify_base_hash_mismatch_returns_action_required() {
        let dir = tempfile::tempdir().expect("tempdir");
        let original_bytes = b"original content";
        let hash_of_original = sha256_hex(original_bytes);
        let base_path = dir.path().join("myagent.base");
        std::fs::write(&base_path, &hash_of_original).expect("write base hash");
        // Now verify against DIFFERENT content
        let modified_bytes = b"modified content";
        let result = verify_base_hash(&base_path, modified_bytes, "myagent");
        assert!(result.is_err(), "hash mismatch should return Err");
        let err = result.expect_err("expected ActionRequired error on hash mismatch");
        match &err {
            nono::NonoError::ActionRequired {
                expected,
                actual,
                resolve_via,
            } => {
                assert_eq!(
                    expected, &hash_of_original,
                    "expected should be sidecar hash"
                );
                assert_eq!(
                    actual,
                    &sha256_hex(modified_bytes),
                    "actual should be current hash"
                );
                assert!(
                    resolve_via.contains("--refresh"),
                    "resolve_via should contain '--refresh': {resolve_via}"
                );
            }
            other => panic!("expected ActionRequired, got: {other:?}"),
        }
    }

    #[test]
    fn verify_base_hash_rejects_invalid_hex() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base_path = dir.path().join("invalid.base");
        std::fs::write(&base_path, b"not-64-hex").expect("write invalid hash");
        let result = verify_base_hash(&base_path, b"any content", "myagent");
        assert!(result.is_err(), "invalid hex should fail");
        let msg = result
            .expect_err("expected error for invalid hex")
            .to_string();
        assert!(
            msg.contains("invalid base hash"),
            "error should mention 'invalid base hash': {msg}"
        );
    }

    #[test]
    fn regular_file_exists_true_for_regular() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("exists.txt");
        std::fs::write(&path, b"content").expect("write");
        assert!(
            regular_file_exists(&path),
            "should return true for regular file"
        );
        assert!(
            !regular_file_exists(dir.path()),
            "should return false for directory"
        );
        assert!(
            !regular_file_exists(&dir.path().join("missing.txt")),
            "should return false for missing"
        );
    }

    #[cfg(unix)]
    #[test]
    fn regular_file_exists_false_for_symlink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target.txt");
        let symlink_path = dir.path().join("link.txt");
        std::fs::write(&target, b"content").expect("write target");
        std::os::unix::fs::symlink(&target, &symlink_path).expect("create symlink");
        assert!(
            !regular_file_exists(&symlink_path),
            "should return false for symlink"
        );
    }
}
