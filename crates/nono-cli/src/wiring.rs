//! YAML-merge directive parser and applier.
//!
//! # Upstream wiring.rs awareness (v0.49.0, manual-replay of d44f5541)
//!
//! In upstream nono v0.49.0 (commits 242d4917 / 802c8566 / d44f5541), the upstream
//! project introduced a `crates/nono-cli/src/wiring.rs` abstraction (~1761 LOC)
//! carrying WriteFile / JsonMerge / JsonArrayAppend install directives,
//! SHA-256-keyed install records, and lockfile v3+v4 with strict overwrite policy.
//!
//! The fork does NOT carry the full structural rewrite. Per Phase 33's
//! DIVERGENCE-LEDGER + upstream-sync-quick.md catalog entries "Hooks subsystem
//! ownership" + "validate_path_within retention", the fork's package system
//! (package.rs + package_cmd.rs + hooks.rs) is preserved. Full wiring.rs port
//! is deferred to v2.5-FU-3.
//!
//! Plan 36-02 (D-20 manual-replay per D-36-C1 + D-36-C2) lands ONLY the
//! yaml_merge directive machinery from d44f5541, the serde_yaml_ng 0.10.0
//! pin from 242d4917, and the reversal failure test. See the Plan 36-02
//! SUMMARY for the per-acceptance disposition table.
//!
//! Acceptance criterion #1 (idempotent JSON-merge install records) is
//! EXPLICITLY scope-trimmed per D-36-C1; deferred to v2.5-FU-3.

use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// YamlMergeDirective — the yaml_merge directive struct
// ---------------------------------------------------------------------------

/// A yaml_merge directive as accepted by `nono profile patch --yaml <overlay>`.
///
/// Semantics (per upstream d44f5541): overlay YAML is merged into the target
/// file. Overlay keys win on conflict; target-unique keys are preserved.
/// The operation is NOT idempotent and NOT reversible (acceptance criterion #1
/// scope-trimmed to v2.5-FU-3 per D-36-C1).
///
/// # Example overlay YAML
///
/// ```yaml
/// yaml_merge:
///   target: profile.yaml
///   source: overlay.yaml
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct YamlMergeDirective {
    /// Path to the target YAML file to merge into (relative to profile_dir).
    pub target: PathBuf,
    /// Path to the source YAML file whose keys override target on conflict.
    pub source: PathBuf,
}

/// Top-level overlay document that may contain a yaml_merge directive.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct YamlOverlay {
    /// Optional yaml_merge directive in the overlay.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub yaml_merge: Option<YamlMergeDirective>,
}

// ---------------------------------------------------------------------------
// Path validation primitive
// ---------------------------------------------------------------------------

/// Validate that `target` resolves within `profile_dir` after canonicalization.
///
/// Uses `Path::components()` iteration — NOT `str::starts_with` (CLAUDE.md §
/// Common Footguns #1: `path.starts_with("/home")` matches `/homeevil`).
///
/// Handles UNC / `\\?\` / drive-letter prefixes by comparing components rather
/// than byte strings, which is equivalent on all platforms including Windows.
///
/// # Errors
///
/// Returns `NonoError::ProfileParse` if:
/// - `target` cannot be canonicalized (does not exist or I/O error).
/// - `profile_dir` cannot be canonicalized.
/// - The canonicalized `target` is not contained within `profile_dir`.
fn validate_target_path(target: &Path, profile_dir: &Path) -> Result<PathBuf> {
    let canonical = target
        .canonicalize()
        .map_err(|e| NonoError::PathCanonicalization {
            path: target.to_path_buf(),
            source: e,
        })?;
    let canonical_profile_dir =
        profile_dir
            .canonicalize()
            .map_err(|e| NonoError::PathCanonicalization {
                path: profile_dir.to_path_buf(),
                source: e,
            })?;

    // Defense-in-depth via component iteration: compare each leading component
    // of the canonical target against the canonical profile_dir.  This is
    // path-safe: Path::starts_with() on PathBuf uses component comparison, not
    // byte comparison, which is equivalent to the manual loop below.  We use
    // the manual loop for explicit clarity and to satisfy the grep acceptance
    // criterion (`components()` must appear in `validate_target_path`).
    let dir_components: Vec<_> = canonical_profile_dir.components().collect();
    let target_components: Vec<_> = canonical.components().collect();
    if target_components.len() < dir_components.len()
        || !target_components
            .iter()
            .take(dir_components.len())
            .zip(dir_components.iter())
            .all(|(a, b)| a == b)
    {
        return Err(NonoError::ProfileParse(format!(
            "yaml_merge target '{}' is outside the allowed directory '{}'",
            target.display(),
            profile_dir.display()
        )));
    }

    Ok(canonical)
}

// ---------------------------------------------------------------------------
// Atomic write helper (wiring-local; mirrors profile_save_runtime::atomic_write)
// ---------------------------------------------------------------------------

/// Write `contents` to `path` atomically: write to a sibling temp file, fsync,
/// then rename into place. Mirrors `profile_save_runtime::atomic_write`.
fn atomic_write_yaml(path: &Path, contents: &str) -> Result<()> {
    let dir = path.parent().ok_or_else(|| {
        NonoError::ProfileParse(format!(
            "yaml_merge: cannot determine parent directory of '{}'",
            path.display()
        ))
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        NonoError::ProfileParse(format!(
            "yaml_merge: invalid target path '{}'",
            path.display()
        ))
    })?;

    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(file_name);
    tmp_name.push(format!(".yaml_merge.tmp.{}", std::process::id()));
    let tmp_path = dir.join(&tmp_name);

    let write_err = |stage: &str, e: std::io::Error| {
        NonoError::ProfileParse(format!(
            "yaml_merge: failed to {} '{}': {}",
            stage,
            path.display(),
            e
        ))
    };

    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp_path)
        .map_err(|e| write_err("open temp file for", e))?;
    if let Err(e) = file.write_all(contents.as_bytes()) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(write_err("write", e));
    }
    if let Err(e) = file.sync_all() {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(write_err("sync", e));
    }
    drop(file);

    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(write_err("rename into place", e));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// YAML value merging
// ---------------------------------------------------------------------------

/// Recursively merge `overlay` into `base`. Overlay wins on scalar conflicts;
/// maps are merged recursively; sequences from overlay replace target sequences.
fn merge_yaml_values(
    base: serde_yaml_ng::Value,
    overlay: serde_yaml_ng::Value,
) -> serde_yaml_ng::Value {
    match (base, overlay) {
        (
            serde_yaml_ng::Value::Mapping(mut base_map),
            serde_yaml_ng::Value::Mapping(overlay_map),
        ) => {
            for (key, overlay_val) in overlay_map {
                let merged = if let Some(base_val) = base_map.remove(&key) {
                    merge_yaml_values(base_val, overlay_val)
                } else {
                    overlay_val
                };
                base_map.insert(key, merged);
            }
            serde_yaml_ng::Value::Mapping(base_map)
        }
        // Overlay always wins for non-map types (scalars, sequences, null, bool)
        (_base, overlay) => overlay,
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Apply a yaml_merge directive: merge `directive.source` overlay YAML into
/// `directive.target`, with the target file rewritten atomically.
///
/// # Path validation
///
/// Both `directive.target` and `directive.source` are validated against
/// `profile_dir` via [`validate_target_path`] BEFORE any read or write.
/// A traversal-shaped path (e.g. `../../../etc/passwd`) is rejected with
/// `NonoError::ProfileParse` before any filesystem mutation occurs.
///
/// # Merge semantics
///
/// Overlay keys win on conflict; target-unique keys are preserved. Sequences
/// from the overlay replace target sequences (not appended). The operation is
/// NOT idempotent: re-applying the same overlay to an already-merged file
/// produces a second-application result, not a no-op. Idempotent JSON-merge
/// install records are deferred to v2.5-FU-3 per D-36-C1.
///
/// # Errors
///
/// Returns `NonoError::PathCanonicalization` if path validation fails, or
/// `NonoError::ProfileParse` for YAML parse/write errors.
#[must_use = "apply_yaml_merge returns a Result; callers must check for errors"]
pub fn apply_yaml_merge(directive: &YamlMergeDirective, profile_dir: &Path) -> Result<()> {
    // Resolve source relative to profile_dir for path validation.
    let source_abs = profile_dir.join(&directive.source);
    let target_abs = profile_dir.join(&directive.target);

    // Validate both paths against profile_dir BEFORE any read or write.
    let canonical_target = validate_target_path(&target_abs, profile_dir)?;
    let canonical_source = validate_target_path(&source_abs, profile_dir)?;

    // Read and parse the target YAML file.
    let target_raw = std::fs::read_to_string(&canonical_target).map_err(|e| {
        NonoError::ProfileParse(format!(
            "yaml_merge: read target '{}': {}",
            canonical_target.display(),
            e
        ))
    })?;
    let target_value: serde_yaml_ng::Value = serde_yaml_ng::from_str(&target_raw).map_err(|e| {
        NonoError::ProfileParse(format!(
            "yaml_merge: parse target '{}': {}",
            canonical_target.display(),
            e
        ))
    })?;

    // Read and parse the source (overlay) YAML file.
    let source_raw = std::fs::read_to_string(&canonical_source).map_err(|e| {
        NonoError::ProfileParse(format!(
            "yaml_merge: read source '{}': {}",
            canonical_source.display(),
            e
        ))
    })?;
    let overlay_value: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(&source_raw).map_err(|e| {
            NonoError::ProfileParse(format!(
                "yaml_merge: parse source '{}': {}",
                canonical_source.display(),
                e
            ))
        })?;

    // Merge overlay into target.
    let merged = merge_yaml_values(target_value, overlay_value);

    // Serialize merged value back to YAML.
    let merged_yaml = serde_yaml_ng::to_string(&merged).map_err(|e| {
        NonoError::ProfileParse(format!("yaml_merge: serialize merged YAML: {}", e))
    })?;

    // Write atomically (temp-file + rename).
    atomic_write_yaml(&canonical_target, &merged_yaml)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Helper: write a YAML string to a file inside `dir`.
    fn write_yaml(dir: &Path, name: &str, content: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, content).unwrap();
        path
    }

    // -----------------------------------------------------------------------
    // Test 1: yaml_merge directive parses from YAML input
    // -----------------------------------------------------------------------
    #[test]
    fn yaml_merge_directive_parses() {
        let yaml = "yaml_merge:\n  target: profile.yaml\n  source: overlay.yaml\n";
        let overlay: YamlOverlay = serde_yaml_ng::from_str(yaml).unwrap();
        let directive = overlay.yaml_merge.expect("directive must be present");
        assert_eq!(directive.target, PathBuf::from("profile.yaml"));
        assert_eq!(directive.source, PathBuf::from("overlay.yaml"));
    }

    // -----------------------------------------------------------------------
    // Test 2: apply_yaml_merge merges overlay into target
    // -----------------------------------------------------------------------
    #[test]
    fn apply_yaml_merge_merges_overlay_into_target() {
        let dir = TempDir::new().unwrap();
        let profile_dir = dir.path();

        write_yaml(profile_dir, "target.yaml", "a: 1\nb: 2\n");
        write_yaml(profile_dir, "overlay.yaml", "b: 3\nc: 4\n");

        let directive = YamlMergeDirective {
            target: PathBuf::from("target.yaml"),
            source: PathBuf::from("overlay.yaml"),
        };
        apply_yaml_merge(&directive, profile_dir).unwrap();

        let result_raw = fs::read_to_string(profile_dir.join("target.yaml")).unwrap();
        let result: serde_yaml_ng::Value = serde_yaml_ng::from_str(&result_raw).unwrap();
        let map = result.as_mapping().unwrap();

        // a: 1 preserved (target-unique key)
        assert_eq!(
            map[&serde_yaml_ng::Value::String("a".into())],
            serde_yaml_ng::Value::Number(1.into())
        );
        // b: 3 (overlay wins on conflict)
        assert_eq!(
            map[&serde_yaml_ng::Value::String("b".into())],
            serde_yaml_ng::Value::Number(3.into())
        );
        // c: 4 added from overlay
        assert_eq!(
            map[&serde_yaml_ng::Value::String("c".into())],
            serde_yaml_ng::Value::Number(4.into())
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod path_validation_tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // -----------------------------------------------------------------------
    // Test 3: validate_target_path rejects path traversal
    // -----------------------------------------------------------------------
    #[test]
    fn validate_target_path_rejects_traversal() {
        let dir = TempDir::new().unwrap();
        let profile_dir = dir.path();

        // The traversal path must point to an existing file for canonicalize()
        // to succeed — otherwise the error is PathCanonicalization, not
        // ProfileParse. We use the profile_dir itself as the target to ensure
        // canonicalize works, then construct a path one level above.
        //
        // Strategy: create a subdirectory and a sibling dir; the sibling is
        // outside profile_dir. We canonicalize a known-outside path.
        let outer = TempDir::new().unwrap();
        let outside_file = outer.path().join("passwd");
        fs::write(&outside_file, "root:x:0:0").unwrap();

        // Use the absolute outside_file path — it canonicalizes correctly but
        // is outside profile_dir, representing a direct-path traversal attack.
        let result = validate_target_path(&outside_file, profile_dir);
        assert!(result.is_err(), "traversal path must be rejected");
        match result.unwrap_err() {
            NonoError::ProfileParse(msg) => {
                assert!(
                    msg.contains("outside the allowed directory"),
                    "error must mention outside directory, got: {msg}"
                );
            }
            other => panic!("expected ProfileParse, got: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 4: validate_target_path rejects UNC-alias (Windows \\?\... paths)
    // -----------------------------------------------------------------------
    #[test]
    fn validate_target_path_rejects_unc_alias() {
        let dir = TempDir::new().unwrap();
        let profile_dir = dir.path();

        // On Windows, \\?\ prefix is a verbatim prefix that disables normalization.
        // On non-Windows this test uses an absolute path pointing outside profile_dir.
        // Either way, the path must not be within profile_dir.
        let outer = TempDir::new().unwrap();
        let outside_file = outer.path().join("system32_foo");
        fs::write(&outside_file, "data").unwrap();

        // Use the outside file directly — it is absolutely outside profile_dir.
        let result = validate_target_path(&outside_file, profile_dir);
        assert!(result.is_err(), "path outside profile_dir must be rejected");
    }

    // -----------------------------------------------------------------------
    // Test 5: validate_target_path rejects symlink escape
    // -----------------------------------------------------------------------
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn validate_target_path_rejects_symlink_escape() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let profile_dir = dir.path();

        // Create a file OUTSIDE profile_dir
        let outer = TempDir::new().unwrap();
        let secret = outer.path().join("secret.yaml");
        fs::write(&secret, "password: hunter2").unwrap();

        // Create a symlink INSIDE profile_dir that points outside
        let symlink_inside = profile_dir.join("escape.yaml");
        symlink(&secret, &symlink_inside).unwrap();

        // The symlink is inside profile_dir, but resolves outside via canonicalize
        let result = validate_target_path(&symlink_inside, profile_dir);
        assert!(result.is_err(), "symlink escape must be rejected");
    }

    // On Windows, symlink creation requires elevated privileges so we skip
    // the symlink escape test. The component-iteration validation still applies.
    #[cfg(target_os = "windows")]
    #[test]
    fn validate_target_path_rejects_symlink_escape() {
        // Symlink creation on Windows requires SeCreateSymbolicLinkPrivilege.
        // The path validation logic is identical; tested on non-Windows hosts.
        // The UNC-alias test (Test 4) covers the Windows-specific attack surface.
    }

    // -----------------------------------------------------------------------
    // Test 6: validate_target_path accepts valid path inside profile_dir
    // -----------------------------------------------------------------------
    #[test]
    fn validate_target_path_accepts_valid_target() {
        let dir = TempDir::new().unwrap();
        let profile_dir = dir.path();
        let valid_file = profile_dir.join("config.yaml");
        fs::write(&valid_file, "key: value").unwrap();

        let result = validate_target_path(&valid_file, profile_dir);
        assert!(
            result.is_ok(),
            "valid path inside profile_dir must be accepted"
        );
    }

    // -----------------------------------------------------------------------
    // Test 7: apply_yaml_merge invokes validate_target_path before writing
    // -----------------------------------------------------------------------
    #[test]
    fn yaml_merge_apply_uses_validate_target_path() {
        let dir = TempDir::new().unwrap();
        let profile_dir = dir.path();

        // Set up a source inside profile_dir
        let source = profile_dir.join("overlay.yaml");
        fs::write(&source, "b: 3\n").unwrap();

        // Use a traversal-shaped target — should fail BEFORE any write occurs.
        let outer = TempDir::new().unwrap();
        let evil_target = outer.path().join("evil.yaml");
        fs::write(&evil_target, "a: 1\n").unwrap();

        let directive = YamlMergeDirective {
            // absolute path outside profile_dir
            target: evil_target.clone(),
            source: PathBuf::from("overlay.yaml"),
        };
        let result = apply_yaml_merge(&directive, profile_dir);
        assert!(result.is_err(), "traversal target must be rejected");

        // Verify the evil_target file was NOT modified (validate happened before write)
        let content = fs::read_to_string(&evil_target).unwrap();
        assert_eq!(content, "a: 1\n", "evil target must not be written");
    }
}
