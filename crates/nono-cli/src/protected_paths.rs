//! Protection for nono's own state paths.
//!
//! These checks enforce a hard fail if initial sandbox capabilities overlap
//! with internal CLI state roots (currently `~/.nono`).

use nono::{try_canonicalize, CapabilitySet, NonoError, Result};
use std::path::{Path, PathBuf};

/// Resolved internal state roots that must not be accessible by the sandboxed child.
///
/// This is intentionally modeled as a list so configured/custom roots can be
/// added later without changing call sites.
pub struct ProtectedRoots {
    roots: Vec<PathBuf>,
}

impl ProtectedRoots {
    /// Build protected roots from current defaults.
    ///
    /// Today this protects the full `~/.nono` subtree.
    pub fn from_defaults() -> Result<Self> {
        let home = dirs::home_dir().ok_or(NonoError::HomeNotFound)?;
        let state_root = try_canonicalize(&home.join(".nono"));
        Ok(Self {
            roots: vec![state_root],
        })
    }

    /// Return a slice of protected root paths.
    pub fn as_paths(&self) -> &[PathBuf] {
        &self.roots
    }
}

/// Validate that no filesystem capability overlaps any protected root.
///
/// Overlap rules:
/// - Any file capability inside a protected root is rejected.
/// - Any directory capability inside a protected root is rejected.
/// - Any directory capability that is a parent of a protected root is rejected
///   (e.g. granting `~` would cover `~/.nono`).
pub fn validate_caps_against_protected_roots(
    caps: &CapabilitySet,
    protected_roots: &[PathBuf],
    allow_parent_of_protected: bool,
) -> Result<()> {
    // Pre-canonicalize once so the per-capability loop doesn't repeat the work.
    let resolved_roots: Vec<PathBuf> = protected_roots
        .iter()
        .map(|p| try_canonicalize(p))
        .collect();
    for cap in caps.fs_capabilities() {
        validate_requested_path_against_protected_roots(
            &cap.resolved,
            cap.is_file,
            &cap.source.to_string(),
            &resolved_roots,
            allow_parent_of_protected,
        )?;
    }

    Ok(())
}

/// Validate an intended grant path before capability construction.
///
/// This catches protected-root overlaps even when requested paths don't exist
/// yet and are later skipped during capability creation.
///
/// On macOS, `parent_of_protected` is allowed because Seatbelt can express
/// deny-within-allow via rule specificity. The caller must emit deny rules
/// for the protected roots via [`emit_protected_root_deny_rules`].
/// On Linux, `parent_of_protected` remains a hard error because Landlock
/// is strictly allow-list and cannot express deny-within-allow.
pub fn validate_requested_path_against_protected_roots(
    path: &Path,
    is_file: bool,
    source: &str,
    protected_roots: &[PathBuf],
    allow_parent_of_protected: bool,
) -> Result<()> {
    let requested_path = try_canonicalize(path);

    for protected_root in protected_roots {
        let resolved_root = try_canonicalize(protected_root);
        let inside_protected = requested_path.starts_with(&resolved_root);
        let parent_of_protected = !is_file && resolved_root.starts_with(&requested_path);

        // inside_protected is always a hard error on all platforms
        if inside_protected {
            return Err(NonoError::SandboxInit(format!(
                "Refusing to grant '{}' (source: {}) because it overlaps protected nono state root '{}'.",
                requested_path.display(),
                source,
                resolved_root.display(),
            )));
        }

        // parent_of_protected: on macOS with opt-in, Seatbelt deny rules protect the root;
        // on Linux, Landlock cannot express deny-within-allow so we must reject.
        if parent_of_protected && !(cfg!(target_os = "macos") && allow_parent_of_protected) {
            return Err(NonoError::SandboxInit(format!(
                "Refusing to grant '{}' (source: {}) because it overlaps protected nono state root '{}'.",
                requested_path.display(),
                source,
                resolved_root.display(),
            )));
        }
    }

    Ok(())
}

/// Return the protected root overlapped by a requested path, if any.
///
/// On macOS, only `inside_protected` is flagged because Seatbelt deny rules
/// protect the root from parent grants. On Linux, both `inside_protected` and
/// `parent_of_protected` are flagged.
///
/// Unlike [`validate_requested_path_against_protected_roots`], this function
/// does **not** take an `allow_parent_of_protected` flag. It is called by the
/// supervisor at runtime, after Seatbelt deny rules have already been emitted,
/// so the unconditional macOS relaxation is safe here. The pre-flight
/// validation (which does respect the opt-in flag) has already rejected the
/// grant if the profile did not opt in.
#[must_use]
pub fn overlapping_protected_root(
    path: &Path,
    is_file: bool,
    protected_roots: &[PathBuf],
) -> Option<PathBuf> {
    let requested_path = try_canonicalize(path);

    for protected_root in protected_roots {
        let resolved_root = try_canonicalize(protected_root);
        let inside_protected = requested_path.starts_with(&resolved_root);
        if inside_protected {
            return Some(resolved_root);
        }

        let parent_of_protected = !is_file && resolved_root.starts_with(&requested_path);
        if parent_of_protected && !cfg!(target_os = "macos") {
            return Some(resolved_root);
        }
    }

    None
}

/// Emit Seatbelt deny rules for all protected roots.
///
/// On macOS, this adds `(deny file-read-data ...)` and `(deny file-write* ...)`
/// platform rules for each protected root, preventing the sandboxed child from
/// accessing `~/.nono` even when a parent directory is granted.
///
/// On non-macOS, this is a no-op — Landlock does not support deny-within-allow,
/// so the pre-flight validation rejects parent grants instead.
pub(crate) fn emit_protected_root_deny_rules(
    protected_roots: &[PathBuf],
    caps: &mut CapabilitySet,
) -> Result<()> {
    if !cfg!(target_os = "macos") {
        return Ok(());
    }

    for root in protected_roots {
        let resolved = try_canonicalize(root);
        emit_deny_rules_for_path(&resolved, caps)?;

        // Also emit for the canonical path if it differs (important on macOS
        // where paths like /var resolve to /private/var).
        if let Ok(canonical) = resolved.canonicalize() {
            if canonical != resolved {
                emit_deny_rules_for_path(&canonical, caps)?;
            }
        }
    }

    Ok(())
}

/// Emit Seatbelt deny rules for a single path.
#[cfg(target_os = "macos")]
fn emit_deny_rules_for_path(path: &Path, caps: &mut CapabilitySet) -> Result<()> {
    let escaped = crate::policy::escape_seatbelt_path(crate::policy::path_to_utf8(path)?)?;
    let filter = format!("subpath \"{}\"", escaped);
    caps.add_platform_rule(format!("(allow file-read-metadata ({}))", filter))?;
    caps.add_platform_rule(format!("(deny file-read-data ({}))", filter))?;
    caps.add_platform_rule(format!("(deny file-write* ({}))", filter))?;
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn emit_deny_rules_for_path(_path: &Path, _caps: &mut CapabilitySet) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nono::{AccessMode, CapabilitySet, FsCapability};
    use tempfile::TempDir;

    #[test]
    fn parent_directory_capability_blocked_without_opt_in() {
        let tmp = TempDir::new().expect("tmpdir");
        let parent = tmp.path().to_path_buf();
        let protected = parent.join(".nono");

        let mut caps = CapabilitySet::new();
        let cap = FsCapability::new_dir(&parent, AccessMode::ReadWrite).expect("dir cap");
        caps.add_fs(cap);

        // Without opt-in, parent grant is always rejected
        let err =
            validate_caps_against_protected_roots(&caps, &[protected], false).expect_err("blocked");
        assert!(
            err.to_string()
                .contains("overlaps protected nono state root"),
            "unexpected error: {err}",
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parent_directory_capability_allowed_with_opt_in_on_macos() {
        let tmp = TempDir::new().expect("tmpdir");
        let parent = tmp.path().to_path_buf();
        let protected = parent.join(".nono");

        let mut caps = CapabilitySet::new();
        let cap = FsCapability::new_dir(&parent, AccessMode::ReadWrite).expect("dir cap");
        caps.add_fs(cap);

        // With opt-in on macOS, parent grant is allowed (Seatbelt deny rules protect the root)
        validate_caps_against_protected_roots(&caps, &[protected], true)
            .expect("allowed on macOS with opt-in");
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn parent_directory_capability_blocked_even_with_opt_in_on_linux() {
        let tmp = TempDir::new().expect("tmpdir");
        let parent = tmp.path().to_path_buf();
        let protected = parent.join(".nono");

        let mut caps = CapabilitySet::new();
        let cap = FsCapability::new_dir(&parent, AccessMode::ReadWrite).expect("dir cap");
        caps.add_fs(cap);

        // On Linux, parent grant is always rejected even with opt-in
        // (Landlock cannot express deny-within-allow)
        let err = validate_caps_against_protected_roots(&caps, &[protected], true)
            .expect_err("blocked on Linux even with opt-in");
        assert!(
            err.to_string()
                .contains("overlaps protected nono state root"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn inside_protected_root_always_blocked() {
        let tmp = TempDir::new().expect("tmpdir");
        let protected = tmp.path().join(".nono");
        std::fs::create_dir_all(&protected).expect("mkdir");
        let inside = protected.join("state.db");
        std::fs::write(&inside, b"").expect("create file");

        // File inside protected root — blocked on all platforms
        let err = validate_requested_path_against_protected_roots(
            &inside,
            true,
            "test",
            std::slice::from_ref(&protected),
            false,
        )
        .expect_err("blocked");
        assert!(
            err.to_string()
                .contains("overlaps protected nono state root"),
            "unexpected error: {err}",
        );

        // Directory inside protected root — blocked on all platforms
        let subdir = protected.join("rollbacks");
        std::fs::create_dir_all(&subdir).expect("mkdir");
        let err = validate_requested_path_against_protected_roots(
            &subdir,
            false,
            "test",
            std::slice::from_ref(&protected),
            false,
        )
        .expect_err("blocked");
        assert!(
            err.to_string()
                .contains("overlaps protected nono state root"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn blocks_child_directory_capability() {
        let tmp = TempDir::new().expect("tmpdir");
        let protected = tmp.path().join(".nono");
        let child = protected.join("rollbacks");
        std::fs::create_dir_all(&child).expect("mkdir");

        let mut caps = CapabilitySet::new();
        let cap = FsCapability::new_dir(&child, AccessMode::ReadWrite).expect("dir cap");
        caps.add_fs(cap);

        validate_caps_against_protected_roots(&caps, &[protected], false).expect_err("blocked");
    }

    #[test]
    fn allows_unrelated_capability() {
        let tmp = TempDir::new().expect("tmpdir");
        let protected = tmp.path().join(".nono");
        let workspace = tmp.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("mkdir");

        let mut caps = CapabilitySet::new();
        let cap = FsCapability::new_dir(&workspace, AccessMode::ReadWrite).expect("dir cap");
        caps.add_fs(cap);

        validate_caps_against_protected_roots(&caps, &[protected], false).expect("allowed");
    }

    #[test]
    fn requested_path_blocks_nonexistent_child_under_protected_root() {
        let tmp = TempDir::new().expect("tmpdir");
        let protected = tmp.path().join(".nono");
        std::fs::create_dir_all(&protected).expect("mkdir");
        let child = protected.join("rollbacks").join("future-session");

        let err = validate_requested_path_against_protected_roots(
            &child,
            false,
            "CLI",
            &[protected],
            false,
        )
        .expect_err("blocked");
        assert!(
            err.to_string()
                .contains("overlaps protected nono state root"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn overlapping_protected_root_reports_match() {
        let tmp = TempDir::new().expect("tmpdir");
        let protected = tmp.path().join(".nono");
        std::fs::create_dir_all(&protected).expect("mkdir");
        let child = protected.join("rollbacks");

        // inside_protected is always reported
        let overlap = overlapping_protected_root(&child, false, std::slice::from_ref(&protected));
        let expected = std::fs::canonicalize(&protected).unwrap_or(protected);

        assert_eq!(overlap, Some(expected));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn overlapping_protected_root_parent_not_flagged_on_macos() {
        let tmp = TempDir::new().expect("tmpdir");
        let parent = tmp.path().to_path_buf();
        let protected = parent.join(".nono");

        let overlap = overlapping_protected_root(&parent, false, std::slice::from_ref(&protected));
        // macOS: parent-of-protected is not flagged (Seatbelt deny rules handle it)
        assert_eq!(overlap, None, "parent should not be flagged on macOS");
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn overlapping_protected_root_parent_flagged_on_linux() {
        let tmp = TempDir::new().expect("tmpdir");
        let parent = tmp.path().to_path_buf();
        let protected = parent.join(".nono");

        let overlap = overlapping_protected_root(&parent, false, std::slice::from_ref(&protected));
        // Linux: parent-of-protected is flagged
        assert!(overlap.is_some(), "parent should be flagged on Linux");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn emit_protected_root_deny_rules_adds_platform_rules() {
        let tmp = TempDir::new().expect("tmpdir");
        let protected = tmp.path().join(".nono");
        std::fs::create_dir_all(&protected).expect("mkdir");

        let mut caps = CapabilitySet::new();
        emit_protected_root_deny_rules(&[protected], &mut caps).expect("emit rules");

        let rules = caps.platform_rules();
        assert!(!rules.is_empty(), "should have platform rules");
        let joined = rules.join("\n");
        assert!(
            joined.contains("deny file-read-data"),
            "should deny reads: {joined}"
        );
        assert!(
            joined.contains("deny file-write*"),
            "should deny writes: {joined}"
        );
        assert!(
            joined.contains("allow file-read-metadata"),
            "should allow metadata: {joined}"
        );
    }
}
