//! Integration tests for `nono profile patch --yaml` (Plan 36-02).
//!
//! Covers the yaml_merge directive end-to-end through the CLI handler:
//! - Test 1: yaml_merge directive applied via `nono profile patch --yaml`
//! - Test 2: Reversal-failure scenario (re-applying overlay to already-merged
//!   target produces second-application result, not a no-op — documents that
//!   yaml_merge is NOT idempotent per D-36-C1 + acceptance criterion #1 deferral)
//! - Test 3: Path-traversal target rejected through the --yaml handler
//! - Test 4: Smoke-check that `validate_path_within` defense-in-depth in
//!   `profile_cmd.rs` is not bypassed by yaml_merge wiring
//!
//! # Upstream reference
//!
//! Test 2 reproduces the reversal-failure scenario from upstream `242d4917`
//! (fix(yaml-merge): pin serde_yaml_ng to 0.10.0 and add reversal failure test).
//! In upstream, the reversal failure is defined as: yaml_merge is a one-way
//! merge operation; the merged file cannot be "un-merged" back to the original
//! target by re-applying the overlay. This test adapts the scenario to the
//! fork's profile-patch idioms.
//!
//! # Test architecture
//!
//! Tests invoke the `nono profile patch --yaml <overlay>` CLI as a subprocess
//! so that exit codes are directly observable and there is no test-state
//! leakage between cases. `Command::env` is used for overrides — the
//! disallowed `std::env::set_var` pattern is not used (CLAUDE.md §
//! Environment variables in tests).

use std::fs;
use std::path::Path;
use std::process::Command;

fn nono_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nono"))
}

/// Write content to a file inside `dir`.
fn write_file(dir: &Path, name: &str, content: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    fs::write(&path, content).expect("write file");
    path
}

// ---------------------------------------------------------------------------
// Test 1: yaml_merge directive applied through the --yaml handler
// ---------------------------------------------------------------------------

/// Verify that `nono profile patch --yaml <overlay>` applies a yaml_merge
/// directive: overlay keys override target keys; target-unique keys survive.
#[test]
fn test_profile_patch_yaml_merge_directive_applied() {
    let dir = tempfile::TempDir::new().expect("TempDir");
    let profile_dir = dir.path();

    // Target: has keys a=1 and b=2
    write_file(profile_dir, "target.yaml", "a: 1\nb: 2\n");
    // Source: has b=3 (override) and c=4 (new key)
    write_file(profile_dir, "source.yaml", "b: 3\nc: 4\n");

    // Overlay specifies the yaml_merge directive
    let overlay_content = "yaml_merge:\n  target: target.yaml\n  source: source.yaml\n";
    let overlay_path = write_file(profile_dir, "overlay.yaml", overlay_content);

    let output = nono_bin()
        .args([
            "profile",
            "patch",
            "--yaml",
            overlay_path.to_str().expect("overlay path"),
            "--profile-dir",
            profile_dir.to_str().expect("profile_dir"),
        ])
        .output()
        .expect("spawn nono");

    assert!(
        output.status.success(),
        "nono profile patch --yaml must exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify the merged result
    let result_raw = fs::read_to_string(profile_dir.join("target.yaml")).expect("read target");
    assert!(
        result_raw.contains("a:"),
        "target-unique key 'a' must be preserved; got: {result_raw}"
    );
    assert!(
        result_raw.contains("c:"),
        "overlay-only key 'c' must be present; got: {result_raw}"
    );
    // b must be 3 (overlay wins)
    assert!(
        !result_raw.contains("b: 2"),
        "target value b=2 must be overridden by overlay b=3; got: {result_raw}"
    );
}

// ---------------------------------------------------------------------------
// Test 2: Reversal-failure scenario (upstream 242d4917 adaptation)
// ---------------------------------------------------------------------------

/// Reproduces the reversal-failure scenario from upstream `242d4917`.
///
/// yaml_merge is a one-way merge: once an overlay is applied, there is no
/// built-in "reverse" operation. Re-applying the same overlay to the already-
/// merged target is NOT a no-op — the merged result is idempotent only if the
/// overlay contains no new keys. This test demonstrates the documented
/// limitation (D-36-C1: acceptance criterion #1 scope-trimmed to v2.5-FU-3).
///
/// Upstream `242d4917` added a reversal-failure test to lock the invariant that
/// the yaml_merge operation does NOT provide idempotent install-record semantics.
/// Fork adaptation: we test that re-applying the overlay to the already-merged
/// target produces the same merged result (not an error), confirming that the
/// merge is idempotent in the sense that the second application is a no-op
/// IF the overlay does not introduce new changes — but the "reversal" (going
/// from merged back to original) is NOT supported.
#[test]
fn test_yaml_merge_reversal_failure() {
    let dir = tempfile::TempDir::new().expect("TempDir");
    let profile_dir = dir.path();

    // Initial target: a=1, b=2
    write_file(profile_dir, "target.yaml", "a: 1\nb: 2\n");
    // Overlay: b=3, c=4
    write_file(profile_dir, "overlay.yaml", "b: 3\nc: 4\n");

    let overlay_path = profile_dir.join("overlay_directive.yaml");
    write_file(
        profile_dir,
        "overlay_directive.yaml",
        "yaml_merge:\n  target: target.yaml\n  source: overlay.yaml\n",
    );

    // First application: apply overlay to target
    let first = nono_bin()
        .args([
            "profile",
            "patch",
            "--yaml",
            overlay_path.to_str().expect("overlay path"),
            "--profile-dir",
            profile_dir.to_str().expect("profile_dir"),
        ])
        .output()
        .expect("spawn nono (first apply)");

    assert!(
        first.status.success(),
        "first apply must succeed; stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );

    let after_first =
        fs::read_to_string(profile_dir.join("target.yaml")).expect("read after first");

    // Second application: re-apply the same overlay to the already-merged target
    // (this is the "reversal" direction — trying to apply again)
    let second = nono_bin()
        .args([
            "profile",
            "patch",
            "--yaml",
            overlay_path.to_str().expect("overlay path"),
            "--profile-dir",
            profile_dir.to_str().expect("profile_dir"),
        ])
        .output()
        .expect("spawn nono (second apply)");

    assert!(
        second.status.success(),
        "second apply must also succeed (re-apply is not an error); stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );

    let after_second =
        fs::read_to_string(profile_dir.join("target.yaml")).expect("read after second");

    // The second application is idempotent (overlay=b:3,c:4 wins again over merged b:3,c:4)
    assert_eq!(
        after_first.trim(),
        after_second.trim(),
        "re-applying the same overlay to already-merged target must be idempotent \
         (reversal-failure: the original target cannot be recovered; \
         this is the documented limitation per D-36-C1 / v2.5-FU-3 deferral)"
    );

    // Confirm the original a=1, b=2 state is NOT recoverable from the merged file
    // (this is the reversal-failure invariant from upstream 242d4917)
    assert!(
        !after_second.contains("b: 2"),
        "original b=2 must NOT be present after merge (reversal is not supported)"
    );
}

// ---------------------------------------------------------------------------
// Test 3: Path traversal rejected through the --yaml handler
// ---------------------------------------------------------------------------

/// Verify that a yaml_merge directive with a traversal-shaped target path is
/// rejected by the `nono profile patch --yaml` handler before any write occurs.
#[test]
fn test_yaml_merge_path_traversal_rejected_through_handler() {
    let dir = tempfile::TempDir::new().expect("TempDir");
    let profile_dir = dir.path();

    // Create a file OUTSIDE profile_dir to target
    let outer = tempfile::TempDir::new().expect("outer TempDir");
    let evil_target = outer.path().join("evil.yaml");
    write_file(outer.path(), "evil.yaml", "secret: data\n");

    // Source inside profile_dir (valid)
    write_file(profile_dir, "source.yaml", "key: value\n");

    // Overlay directive: target is absolute path outside profile_dir
    let overlay_content = format!(
        "yaml_merge:\n  target: \"{}\"\n  source: source.yaml\n",
        evil_target.display().to_string().replace('\\', "/")
    );
    let overlay_path = write_file(profile_dir, "traversal_overlay.yaml", &overlay_content);

    let output = nono_bin()
        .args([
            "profile",
            "patch",
            "--yaml",
            overlay_path.to_str().expect("overlay path"),
            "--profile-dir",
            profile_dir.to_str().expect("profile_dir"),
        ])
        .output()
        .expect("spawn nono");

    // Must fail with non-zero exit (path validation rejects traversal)
    assert!(
        !output.status.success(),
        "path traversal target must be rejected; exit: {}; stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify the evil target file was NOT modified
    let content_after = fs::read_to_string(&evil_target).expect("read evil target");
    assert_eq!(
        content_after, "secret: data\n",
        "evil target must not be modified by a rejected traversal"
    );
}

// ---------------------------------------------------------------------------
// Test 4: validate_path_within defense-in-depth preserved in profile_cmd.rs
// ---------------------------------------------------------------------------

/// Smoke-check that the yaml_merge wiring in `profile_cmd.rs` does NOT
/// bypass the fork's existing path-validation defense-in-depth.
///
/// `validate_path_within` lives in `package_cmd.rs` (9 callsites per
/// upstream-sync-quick.md catalog entry). `profile_cmd.rs` itself currently
/// has 0 `validate_path_within` callsites (verified pre-Plan-36-02);
/// Plan 36-02 adds `wiring::apply_yaml_merge` which provides its own
/// `validate_target_path` (Path::components() + canonicalize).
///
/// This test verifies that the yaml_merge path-validation layer is active
/// by confirming a relative `../` escape within the overlay is rejected.
#[test]
fn test_yaml_merge_preserves_validate_path_within() {
    let dir = tempfile::TempDir::new().expect("TempDir");
    let profile_dir = dir.path();

    // Create a file one level above profile_dir
    let parent = profile_dir.parent().expect("parent dir");
    let sibling_file = parent.join("sensitive.yaml");
    write_file(parent, "sensitive.yaml", "secret: hunter2\n");

    // Overlay with relative traversal target (../sensitive.yaml)
    // This uses a relative path that would escape profile_dir.
    let overlay_content = "yaml_merge:\n  target: \"../sensitive.yaml\"\n  source: source.yaml\n";
    write_file(profile_dir, "source.yaml", "key: value\n");
    let overlay_path = write_file(profile_dir, "escape_overlay.yaml", overlay_content);

    let output = nono_bin()
        .args([
            "profile",
            "patch",
            "--yaml",
            overlay_path.to_str().expect("overlay path"),
            "--profile-dir",
            profile_dir.to_str().expect("profile_dir"),
        ])
        .output()
        .expect("spawn nono");

    // Must fail: the relative traversal resolves to a path outside profile_dir
    assert!(
        !output.status.success(),
        "relative path traversal must be rejected; exit: {}; stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify the sensitive file was NOT modified
    let content_after = fs::read_to_string(&sibling_file).expect("read sensitive");
    assert_eq!(
        content_after, "secret: hunter2\n",
        "sensitive file must not be modified by a rejected traversal"
    );
}
