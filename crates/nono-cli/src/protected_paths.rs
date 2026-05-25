//! Protection for nono's own state paths.
//!
//! These checks enforce a hard fail if initial sandbox capabilities overlap
//! with internal CLI state roots.

use nono::{CapabilitySet, NonoError, Result};
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
    /// On Windows, protect both the current OS state root and the historical
    /// preview-era `~/.nono` subtree so older local state remains fail-closed.
    pub fn from_defaults() -> Result<Self> {
        #[cfg(target_os = "windows")]
        {
            let mut roots = Vec::new();

            if let Some(state_root) = crate::config::user_state_dir() {
                roots.push(resolve_path(&state_root));
            }

            roots.push(resolve_path(&crate::config::legacy_windows_state_dir()?));
            sort_and_dedup_roots(&mut roots);

            if roots.is_empty() {
                return Err(NonoError::HomeNotFound);
            }

            Ok(Self { roots })
        }

        #[cfg(not(target_os = "windows"))]
        {
            let home = crate::config::nono_home_dir()?;
            let state_root = resolve_path(&home.join(".nono"));
            Ok(Self {
                roots: vec![state_root],
            })
        }
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
) -> Result<()> {
    // Fork divergence (upstream ee70922d): roots are already resolved at
    // construction time via ProtectedRoots::from_defaults → resolve_path
    // (which handles Windows verbatim-prefix normalization), so the
    // upstream's pre-canonicalize-once pattern is unnecessary here. The
    // fork's `resolve_path` is the Plan 22 Windows long-path defense.
    for cap in caps.fs_capabilities() {
        validate_requested_path_against_protected_roots(
            &cap.resolved,
            cap.is_file,
            &cap.source.to_string(),
            protected_roots,
            false,
        )?;
    }

    Ok(())
}

/// Validate an intended grant path before capability construction.
///
/// This catches protected-root overlaps even when requested paths don't exist
/// yet and are later skipped during capability creation.
pub fn validate_requested_path_against_protected_roots(
    path: &Path,
    is_file: bool,
    source: &str,
    protected_roots: &[PathBuf],
    allow_parent_of_protected: bool,
) -> Result<()> {
    // Fork divergence: retain resolve_path (Windows `\\?\` verbatim-prefix
    // normalization) — semantically equivalent to nono::try_canonicalize on
    // non-Windows; superset on Windows for safe component-wise comparison.
    //
    // Perf (upstream be384ee4): protected_roots are already resolved at
    // construction time via ProtectedRoots::from_defaults → resolve_path,
    // so iterate them directly instead of re-resolving per call. Fork's
    // path_starts_with handles component-wise comparison safely on Windows.
    let requested_path = resolve_path(path);

    for protected_root in protected_roots {
        let inside_protected = path_starts_with(&requested_path, protected_root);
        let parent_of_protected = !is_file && path_starts_with(protected_root, &requested_path);
        // Being inside a protected root is always an error.
        // Being a parent of a protected root is only blocked when the caller
        // has not explicitly opted in (e.g., unix socket directory grants
        // on directories that happen to contain a protected root).
        if inside_protected || (parent_of_protected && !allow_parent_of_protected) {
            return Err(NonoError::SandboxInit(format!(
                "Refusing to grant '{}' (source: {}) because it overlaps protected nono state root '{}'.",
                requested_path.display(),
                source,
                protected_root.display(),
            )));
        }
    }

    Ok(())
}

/// Return the protected root overlapped by a requested path, if any.
#[must_use]
#[cfg(not(target_os = "windows"))]
pub fn overlapping_protected_root(
    path: &Path,
    is_file: bool,
    protected_roots: &[PathBuf],
) -> Option<PathBuf> {
    // Fork divergence: retain resolve_path (Windows `\\?\` verbatim-prefix
    // normalization) — semantically equivalent to nono::try_canonicalize on
    // non-Windows; superset on Windows for safe component-wise comparison.
    //
    // Perf (upstream be384ee4): protected_roots are already resolved at
    // construction time, so iterate them directly.
    let requested_path = resolve_path(path);

    for protected_root in protected_roots {
        let inside_protected = path_starts_with(&requested_path, protected_root);
        let parent_of_protected = !is_file && path_starts_with(protected_root, &requested_path);
        if inside_protected || parent_of_protected {
            return Some(protected_root.clone());
        }
    }

    None
}

/// Resolve path by canonicalizing the full path, or canonicalizing the longest
/// existing ancestor and appending remaining components.
///
/// Fork divergence (Plan 22 + Windows long-path handling): retains
/// `normalize_for_compare` to strip Windows `\\?\` and `\\??\\` verbatim
/// prefixes for safe component-wise comparison. Functionally equivalent to
/// upstream's `nono::try_canonicalize` (introduced by `bb3f512d`) on
/// non-Windows targets; superset on Windows.
fn resolve_path(path: &Path) -> PathBuf {
    if let Ok(canonical) = path.canonicalize() {
        return normalize_for_compare(&canonical);
    }

    let mut remaining = Vec::new();
    let mut current = path.to_path_buf();
    loop {
        if let Ok(canonical) = current.canonicalize() {
            let mut result = normalize_for_compare(&canonical);
            for component in remaining.iter().rev() {
                result = result.join(component);
            }
            return normalize_for_compare(&result);
        }

        match current.file_name() {
            Some(name) => {
                remaining.push(name.to_os_string());
                if !current.pop() {
                    break;
                }
            }
            None => break,
        }
    }

    normalize_for_compare(path)
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn sort_and_dedup_roots(roots: &mut Vec<PathBuf>) {
    roots.sort();
    roots.dedup_by(|left, right| paths_equal(left, right));
}

#[cfg(target_os = "windows")]
fn normalize_for_compare(path: &Path) -> PathBuf {
    let raw = path.as_os_str().to_string_lossy();
    let without_verbatim = raw
        .replace("\\\\?\\UNC\\", r"\\")
        .replace("\\\\?\\", "")
        .replace("\\??\\", "");
    PathBuf::from(without_verbatim)
}

#[cfg(not(target_os = "windows"))]
fn normalize_for_compare(path: &Path) -> PathBuf {
    path.to_path_buf()
}

/// Emit Seatbelt deny rules for all protected roots.
///
/// On macOS, this adds `(deny file-read-data ...)` and `(deny file-write* ...)`
/// platform rules for each protected root, preventing the sandboxed child from
/// accessing `~/.nono` even when a parent directory is granted.
///
/// Upstream-only as of Plan 34-04: the fork does not yet wire callers
/// (`proxy_runtime`, `sandbox_prepare`, `sandbox/macos`). Marked `dead_code`
/// allow because the surface is preserved for future macOS plans that will
/// adopt the caller side.
#[cfg(target_os = "macos")]
#[allow(dead_code)]
pub(crate) fn emit_protected_root_deny_rules(
    protected_roots: &[PathBuf],
    caps: &mut CapabilitySet,
) -> Result<()> {
    for root in protected_roots {
        let resolved = nono::try_canonicalize(root);
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
#[allow(dead_code)]
fn emit_deny_rules_for_path(path: &Path, caps: &mut CapabilitySet) -> Result<()> {
    let escaped = crate::policy::escape_seatbelt_path(crate::policy::path_to_utf8(path)?)?;
    let filter = format!("subpath \"{}\"", escaped);
    caps.add_platform_rule(format!("(allow file-read-metadata ({}))", filter))?;
    caps.add_platform_rule(format!("(deny file-read-data ({}))", filter))?;
    caps.add_platform_rule(format!("(deny file-write* ({}))", filter))?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn path_starts_with(path: &Path, prefix: &Path) -> bool {
    let mut path_components = path.components();
    let mut prefix_components = prefix.components();

    loop {
        match (path_components.next(), prefix_components.next()) {
            (_, None) => return true,
            (None, Some(_)) => return false,
            (Some(left), Some(right)) => {
                let left = left.as_os_str().to_string_lossy();
                let right = right.as_os_str().to_string_lossy();
                if !left.eq_ignore_ascii_case(&right) {
                    return false;
                }
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn path_starts_with(path: &Path, prefix: &Path) -> bool {
    path.starts_with(prefix)
}

#[cfg(target_os = "windows")]
fn paths_equal(left: &Path, right: &Path) -> bool {
    path_starts_with(left, right) && path_starts_with(right, left)
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
#[cfg(not(target_os = "windows"))]
fn paths_equal(left: &Path, right: &Path) -> bool {
    left == right
}

#[cfg(test)]
mod tests {
    use super::*;
    use nono::{AccessMode, CapabilitySet, FsCapability};
    use tempfile::TempDir;

    #[test]
    fn blocks_parent_directory_capability() {
        let tmp = TempDir::new().expect("tmpdir");
        // Canonicalize to resolve platform symlinks (e.g. macOS /var -> /private/var)
        // so that the protected root path matches the resolved capability path.
        let parent = tmp.path().canonicalize().expect("canonical tmpdir");
        let protected = parent.join(".nono");

        let mut caps = CapabilitySet::new();
        let cap = FsCapability::new_dir(&parent, AccessMode::ReadWrite).expect("dir cap");
        caps.add_fs(cap);

        let err = validate_caps_against_protected_roots(&caps, &[protected]).expect_err("blocked");
        assert!(
            err.to_string()
                .contains("overlaps protected nono state root"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn blocks_child_directory_capability() {
        let tmp = TempDir::new().expect("tmpdir");
        let canonical_tmp = tmp.path().canonicalize().expect("canonical tmpdir");
        let protected = canonical_tmp.join(".nono");
        let child = protected.join("rollbacks");
        std::fs::create_dir_all(&child).expect("mkdir");

        let mut caps = CapabilitySet::new();
        let cap = FsCapability::new_dir(&child, AccessMode::ReadWrite).expect("dir cap");
        caps.add_fs(cap);

        validate_caps_against_protected_roots(&caps, &[protected]).expect_err("blocked");
    }

    #[test]
    fn allows_unrelated_capability() {
        let tmp = TempDir::new().expect("tmpdir");
        let canonical_tmp = tmp.path().canonicalize().expect("canonical tmpdir");
        let protected = canonical_tmp.join(".nono");
        let workspace = canonical_tmp.join("workspace");
        std::fs::create_dir_all(&workspace).expect("mkdir");

        let mut caps = CapabilitySet::new();
        let cap = FsCapability::new_dir(&workspace, AccessMode::ReadWrite).expect("dir cap");
        caps.add_fs(cap);

        validate_caps_against_protected_roots(&caps, &[protected]).expect("allowed");
    }

    #[test]
    fn requested_path_blocks_nonexistent_child_under_protected_root() {
        let tmp = TempDir::new().expect("tmpdir");
        let canonical_tmp = tmp.path().canonicalize().expect("canonical tmpdir");
        let protected = canonical_tmp.join(".nono");
        std::fs::create_dir_all(&protected).expect("mkdir");
        let child = protected.join("rollbacks").join("future-session");

        let err =
            validate_requested_path_against_protected_roots(&child, false, "CLI", &[protected], false)
                .expect_err("blocked");
        assert!(
            err.to_string()
                .contains("overlaps protected nono state root"),
            "unexpected error: {err}",
        );
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn overlapping_protected_root_reports_match() {
        let tmp = TempDir::new().expect("tmpdir");
        let canonical_tmp = tmp.path().canonicalize().expect("canonical tmpdir");
        let protected = canonical_tmp.join(".nono");
        std::fs::create_dir_all(&protected).expect("mkdir");
        let child = protected.join("rollbacks");

        let overlap = overlapping_protected_root(&child, false, std::slice::from_ref(&protected));
        let expected = std::fs::canonicalize(&protected).unwrap_or(protected);

        assert_eq!(overlap, Some(expected));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn protected_roots_include_current_windows_state_dir() {
        let roots = ProtectedRoots::from_defaults().expect("protected roots");
        let expected = resolve_path(
            &crate::config::user_state_dir().expect("windows user state dir should exist"),
        );
        assert!(
            roots
                .as_paths()
                .iter()
                .any(|root| paths_equal(root, &expected)),
            "protected roots should include current Windows state dir, got: {:?}",
            roots.as_paths()
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_protected_path_check_handles_verbatim_prefix_and_case_insensitive_drive_letters() {
        let tmp = TempDir::new().expect("tmpdir");
        let protected = tmp.path().join("StateRoot");
        std::fs::create_dir_all(protected.join("rollbacks")).expect("mkdir");

        let canonical = protected
            .join("rollbacks")
            .canonicalize()
            .expect("canonical");
        let raw = canonical.display().to_string();
        let verbatim = PathBuf::from(format!(r"\\?\{}", raw.to_ascii_uppercase()));
        let normalized_requested = resolve_path(&verbatim);
        let normalized_protected = resolve_path(&protected);

        assert!(
            path_starts_with(&normalized_requested, &normalized_protected),
            "normalized requested path should stay inside protected root:\nrequested={}\nprotected={}",
            normalized_requested.display(),
            normalized_protected.display()
        );
    }
}
