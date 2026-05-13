//! Write-protection rules for verified files (macOS Seatbelt)
//!
//! After the pre-exec trust scan verifies files, this module injects
//! literal `(deny file-write-data ...)` rules into the Seatbelt profile
//! for each verified file. This makes verified files structurally immutable
//! at the kernel level — the agent cannot tamper with them even though the
//! parent directory has write access granted.
//!
//! # Design
//!
//! The trust policy's `includes` patterns define which files are scanned
//! and verified. The pre-exec scan resolves every matching file to an
//! absolute path with a concrete verification outcome. Only files that
//! pass verification reach this module, and they receive literal write-deny
//! rules keyed to their exact paths.
//!
//! No regex deny-read rules are used. The pre-exec scan gates execution
//! (aborting if any file fails verification), and the supervisor's
//! `TrustInterceptor` handles runtime verification of files opened
//! mid-session.

use nono::CapabilitySet;
use nono::Result;
#[cfg(target_os = "macos")]
use std::path::Path;

/// Write-protect verified files in the Seatbelt profile.
///
/// For each verified file path, adds a
/// `(deny file-write-data (literal ...))` rule to prevent modification.
///
/// On macOS, handles symlinks by emitting rules for both the original
/// path and the canonical path when they differ (e.g., `/tmp/` vs
/// `/private/tmp/`).
///
/// This function is a no-op on non-macOS platforms.
///
/// # Errors
///
/// Returns an error if `add_platform_rule` rejects a generated rule.
#[cfg(target_os = "macos")]
pub fn write_protect_verified_files(
    caps: &mut CapabilitySet,
    verified_paths: &[std::path::PathBuf],
) -> Result<()> {
    for path in verified_paths {
        add_literal_write_deny(caps, path)?;
    }

    Ok(())
}

/// No-op on non-macOS platforms.
#[cfg(not(target_os = "macos"))]
pub fn write_protect_verified_files(
    _caps: &mut CapabilitySet,
    _verified_paths: &[std::path::PathBuf],
) -> Result<()> {
    Ok(())
}

/// Add a `(deny file-write-data (literal ...))` rule for a verified file.
///
/// This prevents modification of signed files even when the parent
/// directory has write access granted. The deny rule takes precedence over
/// directory-level `(allow file-write* (subpath ...))` rules.
///
/// On macOS, handles symlinks by emitting rules for both the original path
/// and the canonical path when they differ.
#[cfg(target_os = "macos")]
fn add_literal_write_deny(caps: &mut CapabilitySet, path: &Path) -> Result<()> {
    let path_str = path.display().to_string();
    validate_seatbelt_path(&path_str)?;

    let deny_rule = format!("(deny file-write-data (literal \"{path_str}\"))");
    caps.add_platform_rule(deny_rule)?;

    // Handle macOS symlinks: emit rule for canonical path too
    if let Ok(canonical) = std::fs::canonicalize(path)
        && canonical != path
    {
        let canonical_str = canonical.display().to_string();
        validate_seatbelt_path(&canonical_str)?;
        let canonical_rule = format!("(deny file-write-data (literal \"{canonical_str}\"))");
        caps.add_platform_rule(canonical_rule)?;
    }

    Ok(())
}

/// Reject paths containing characters that would break out of Seatbelt string literals.
///
/// On macOS/HFS+, `"` is legal in filenames but would terminate a Seatbelt `(literal "...")`
/// string, allowing injection of arbitrary sandbox rules. `\` could be used for escape
/// sequence injection. Both are rejected.
#[cfg(target_os = "macos")]
fn validate_seatbelt_path(path_str: &str) -> Result<()> {
    if path_str.contains('"') || path_str.contains('\\') {
        return Err(nono::NonoError::ConfigParse(format!(
            "path contains characters not permitted in Seatbelt rules: {path_str}"
        )));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn write_protect_with_no_paths_is_noop() {
        let mut caps = CapabilitySet::new();
        write_protect_verified_files(&mut caps, &[]).unwrap();
        assert!(caps.platform_rules().is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn write_protect_adds_deny_write_rule() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("SKILLS.md");
        std::fs::write(&file, "content").unwrap();

        let mut caps = CapabilitySet::new();
        write_protect_verified_files(&mut caps, std::slice::from_ref(&file)).unwrap();

        let rules = caps.platform_rules();
        assert!(!rules.is_empty());
        // Should have a write-deny rule for the file
        assert!(
            rules
                .iter()
                .any(|r| r.contains("deny file-write-data")
                    && r.contains(&file.display().to_string()))
        );
        // Should NOT have any read-deny rules
        assert!(!rules.iter().any(|r| r.contains("deny file-read-data")));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn write_protect_rejects_path_with_quote() {
        let mut caps = CapabilitySet::new();
        let bad_path =
            std::path::PathBuf::from("/tmp/SKILLS\") (allow file-write* (subpath \"/\")) ;.md");
        let result = write_protect_verified_files(&mut caps, &[bad_path]);
        assert!(result.is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn write_protect_rejects_path_with_backslash() {
        let mut caps = CapabilitySet::new();
        let bad_path = std::path::PathBuf::from("/tmp/SKILLS\\.md");
        let result = write_protect_verified_files(&mut caps, &[bad_path]);
        assert!(result.is_err());
    }
}
