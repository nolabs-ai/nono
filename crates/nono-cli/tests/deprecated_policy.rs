//! Integration tests for the deprecated `nono policy` alias tree.
//!
//! Confirms that every deprecated form:
//!   1. Still runs.
//!   2. Prints a deprecation warning to stderr.
//!   3. Produces identical stdout to the canonical `nono profile` form.

use std::process::Command;

fn nono_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nono"))
}

fn run(args: &[&str]) -> (bool, Vec<u8>, Vec<u8>) {
    let out = nono_bin().args(args).output().expect("failed to run nono");
    (out.status.success(), out.stdout, out.stderr)
}

fn assert_deprecation_warning(stderr: &[u8], old_sub: &str, new_sub: &str) {
    let s = String::from_utf8_lossy(stderr);
    let expected = format!(
        "warning: 'nono policy {old_sub}' is deprecated and will be removed in a future release; use 'nono profile {new_sub}'"
    );
    assert!(
        s.contains(&expected),
        "expected deprecation warning '{expected}' in stderr, got:\n{s}"
    );
}

#[test]
fn policy_groups_alias_prints_warning_and_matches_profile_groups() {
    let (ok_old, stdout_old, stderr_old) = run(&["policy", "groups", "--all-platforms"]);
    let (ok_new, stdout_new, _) = run(&["profile", "groups", "--all-platforms"]);
    assert!(ok_old && ok_new, "both forms should exit 0");
    assert_deprecation_warning(&stderr_old, "groups", "groups");
    assert_eq!(
        stdout_old, stdout_new,
        "stdout diverged between 'nono policy groups' and 'nono profile groups'"
    );
}

#[test]
fn policy_profiles_alias_maps_to_profile_list() {
    let (ok_old, stdout_old, stderr_old) = run(&["policy", "profiles"]);
    let (ok_new, stdout_new, _) = run(&["profile", "list"]);
    assert!(ok_old && ok_new);
    assert_deprecation_warning(&stderr_old, "profiles", "list");
    assert_eq!(
        stdout_old, stdout_new,
        "'nono policy profiles' stdout should match 'nono profile list'"
    );
}

#[test]
fn policy_show_alias() {
    let (ok_old, stdout_old, stderr_old) = run(&["policy", "show", "default", "--json"]);
    let (ok_new, stdout_new, _) = run(&["profile", "show", "default", "--json"]);
    assert!(ok_old && ok_new);
    assert_deprecation_warning(&stderr_old, "show", "show");
    assert_eq!(stdout_old, stdout_new);
}

#[test]
fn policy_diff_alias() {
    // Both profiles must be embedded so the test doesn't depend on a
    // registry pack being installed. `claude-code` was used here
    // before it was moved to the nolabs-ai/claude pack.
    let (ok_old, stdout_old, stderr_old) =
        run(&["policy", "diff", "default", "node-dev", "--json"]);
    let (ok_new, stdout_new, _) = run(&["profile", "diff", "default", "node-dev", "--json"]);
    assert!(ok_old && ok_new);
    assert_deprecation_warning(&stderr_old, "diff", "diff");
    assert_eq!(stdout_old, stdout_new);
}

#[test]
fn policy_validate_alias() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("valid-profile.json");
    std::fs::write(
        &path,
        r#"{
            "meta": { "name": "test", "description": "test profile" },
            "security": { "groups": ["deny_credentials"] },
            "workdir": { "access": "readwrite" }
        }"#,
    )
    .expect("write");

    let (ok_old, stdout_old, stderr_old) =
        run(&["policy", "validate", path.to_str().expect("path")]);
    let (ok_new, stdout_new, _) = run(&["profile", "validate", path.to_str().expect("path")]);
    assert!(
        ok_old,
        "deprecated form should succeed, stderr:\n{}",
        String::from_utf8_lossy(&stderr_old)
    );
    assert!(ok_new);
    assert_deprecation_warning(&stderr_old, "validate", "validate");
    assert_eq!(stdout_old, stdout_new);
}

#[test]
fn policy_help_top_level_labels_deprecated() {
    let (ok, stdout, _) = run(&["policy", "--help"]);
    assert!(ok, "--help should exit 0");
    let s = String::from_utf8_lossy(&stdout);
    assert!(
        s.contains("deprecated"),
        "'nono policy --help' should label the command as deprecated, got:\n{s}"
    );
}
