//! Integration tests for the legacy profile schema drain.
//!
//! Shell out to the built `nono` binary and validate that every deprecated
//! JSON profile key:
//!   1. Parses successfully through `profile show --json` and `profile validate`.
//!   2. Emits exactly one `warning: deprecated key 'X' — use 'Y' instead`
//!      line on stderr per legacy key per file (the design's "one warning
//!      per legacy key per file" contract — see
//!      `docs/plans/2026-04-24-issue-594-phase-2-schema-design.md`).
//!   3. Drains into the canonical section so the resolved state is
//!      byte-equal to a profile authored in the new schema.
//!
//! Tests use the fixtures under `tests/fixtures/legacy_profiles/`.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_nono")
}

fn show_json(path: &str) -> (std::process::ExitStatus, String, String) {
    let out = Command::new(bin())
        .args(["profile", "show", "--json", path])
        .output()
        .expect("run nono");
    (
        out.status,
        String::from_utf8(out.stdout).expect("utf8"),
        String::from_utf8(out.stderr).expect("utf8"),
    )
}

fn validate(path: &str, extra: &[&str]) -> (std::process::ExitStatus, String, String) {
    let mut args: Vec<&str> = vec!["profile", "validate"];
    args.extend(extra);
    args.push(path);
    let out = Command::new(bin()).args(&args).output().expect("run nono");
    (
        out.status,
        String::from_utf8(out.stdout).expect("utf8"),
        String::from_utf8(out.stderr).expect("utf8"),
    )
}

fn count_warnings(stderr: &str) -> usize {
    stderr.matches("warning: deprecated key").count()
}

// ---------------------------------------------------------------------------
// Byte-equal semantic equivalence + warning-count contract on `profile show`
// ---------------------------------------------------------------------------

#[test]
fn legacy_all_keys_shows_byte_equal_canonical_equivalent() {
    let (s1, stdout1, stderr1) = show_json("tests/fixtures/legacy_profiles/legacy_all_keys.json");
    let (s2, stdout2, stderr2) =
        show_json("tests/fixtures/legacy_profiles/canonical_equivalent_of_all_keys.json");
    assert!(s1.success(), "legacy show failed");
    assert!(s2.success(), "canonical show failed");
    assert_eq!(
        stdout1, stdout2,
        "resolved state differs between legacy and canonical fixtures"
    );

    // Critical contract: the design promises "one warning per legacy key
    // per file". Before #594 fix, `cmd_show` parsed the profile twice
    // (load_profile_extends + load_profile) so each legacy key yielded
    // two stderr lines. WarningSuppressionGuard around the preview parse
    // makes the count exactly 9.
    let n = count_warnings(&stderr1);
    assert_eq!(
        n, 9,
        "expected 9 deprecation warnings on `profile show` for legacy_all_keys.json, got {n}. \
         Regression in cmd_show double-parse fix? stderr: {stderr1}"
    );

    // Canonical fixture must emit zero deprecation warnings.
    let n2 = count_warnings(&stderr2);
    assert_eq!(
        n2, 0,
        "canonical fixture must emit zero deprecation warnings, got {n2}. stderr: {stderr2}"
    );
}

#[test]
fn legacy_all_keys_validate_succeeds_and_emits_nine_warnings() {
    let (status, _stdout, stderr) =
        validate("tests/fixtures/legacy_profiles/legacy_all_keys.json", &[]);
    assert!(status.success(), "validate failed; stderr: {stderr}");
    let n = count_warnings(&stderr);
    assert_eq!(
        n, 9,
        "expected 9 deprecation warnings, got {n}. stderr: {stderr}"
    );
}

#[test]
fn test_validate_prints_summary_of_deprecated_keys() {
    let (status, _stdout, stderr) =
        validate("tests/fixtures/legacy_profiles/legacy_all_keys.json", &[]);
    assert!(status.success(), "validate failed; stderr: {stderr}");
    assert!(
        stderr.contains("found 9 deprecated keys"),
        "expected summary 'found 9 deprecated keys' on stderr; stderr: {stderr}"
    );
    assert!(
        stderr.contains("nono profile guide"),
        "expected summary to reference 'nono profile guide'; stderr: {stderr}"
    );
    let n = count_warnings(&stderr);
    assert_eq!(
        n, 9,
        "expected 9 per-key deprecation warnings alongside summary, got {n}. stderr: {stderr}"
    );
}

#[test]
fn test_validate_strict_upgrades_warnings_to_errors() {
    let (status, _stdout, stderr) = validate(
        "tests/fixtures/legacy_profiles/legacy_all_keys.json",
        &["--strict"],
    );
    assert_eq!(
        status.code(),
        Some(2),
        "expected exit code 2 under --strict; stderr={stderr}"
    );
    assert!(
        stderr.contains("found 9 deprecated keys"),
        "expected summary under --strict; stderr: {stderr}"
    );
}

#[test]
fn test_validate_strict_on_canonical_profile_returns_zero() {
    let (status, _stdout, stderr) = validate(
        "tests/fixtures/legacy_profiles/canonical_equivalent_of_all_keys.json",
        &["--strict"],
    );
    assert!(
        status.success(),
        "--strict on canonical profile should succeed; stderr={stderr}"
    );
    assert!(
        !stderr.contains("found"),
        "no summary line expected when zero deprecated keys; stderr: {stderr}"
    );
}

#[test]
fn test_validate_strict_json_branch_exits_two() {
    // The --json branch of cmd_validate has a separate exit(2) site from
    // the text branch. Cover it explicitly so a future change can't drop
    // the strict-fail behavior on JSON output without breaking a test.
    let (status, stdout, stderr) = validate(
        "tests/fixtures/legacy_profiles/legacy_all_keys.json",
        &["--json", "--strict"],
    );
    assert_eq!(
        status.code(),
        Some(2),
        "expected exit code 2 under --strict --json; stdout={stdout} stderr={stderr}"
    );
    assert!(
        stdout.contains("\"deprecated_keys\": 9") || stdout.contains("\"deprecated_keys\":9"),
        "expected JSON output to include deprecated_keys: 9; stdout: {stdout}"
    );
}

#[test]
fn test_validate_strict_with_real_validation_error_returns_one_not_two() {
    // Real validation errors must take precedence over --strict deprecation
    // promotion: the exit code reflects the harder failure (1) and the
    // deprecation summary still appears so the user sees both problems at
    // once. Document this precedence so it doesn't silently regress.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("legacy_plus_invalid.json");
    std::fs::write(
        &path,
        r#"{
            "meta": { "name": "mixed" },
            "security": { "groups": ["nonexistent_group_xyz"] }
        }"#,
    )
    .expect("write fixture");

    let (status, _stdout, stderr) = validate(path.to_str().expect("path"), &["--strict"]);
    assert_eq!(
        status.code(),
        Some(1),
        "real validation error should exit 1 even with --strict; stderr: {stderr}"
    );
    assert!(
        stderr.contains("warning: deprecated key 'security.groups'"),
        "deprecation warning should still surface alongside real error; stderr: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// CLI flag deprecation
// ---------------------------------------------------------------------------

#[test]
fn deprecated_override_deny_flag_emits_single_warning_on_stderr() {
    let out = Command::new(bin())
        .args([
            "run",
            "--dry-run",
            "--allow",
            "/tmp",
            "--override-deny",
            "/tmp",
            "--",
            "echo",
            "hello",
        ])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "dry-run with legacy flag failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let n = stderr
        .matches("warning: deprecated key '--override-deny'")
        .count();
    assert_eq!(
        n, 1,
        "expected exactly one `--override-deny` deprecation warning, got {n}. stderr: {stderr}"
    );
    assert!(
        stderr.contains("--bypass-protection"),
        "deprecation warning should point at --bypass-protection; stderr: {stderr}"
    );
}

#[test]
fn deprecated_override_deny_flag_warning_is_emitted_once_for_multiple_uses() {
    let out = Command::new(bin())
        .args([
            "run",
            "--dry-run",
            "--allow",
            "/tmp",
            "--override-deny",
            "/tmp",
            "--override-deny",
            "/tmp",
            "--",
            "echo",
        ])
        .output()
        .expect("run");
    assert!(out.status.success(), "dry-run failed: {:?}", out);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let n = stderr
        .matches("warning: deprecated key '--override-deny'")
        .count();
    assert_eq!(
        n, 1,
        "repeated --override-deny should still yield one warning, got {n}. stderr: {stderr}"
    );
}

#[test]
fn override_deny_alias_and_bypass_protection_merge_in_argv_order() {
    // The clap alias merges --override-deny invocations into the same Vec
    // as --bypass-protection, in argv order. The deprecation warning fires
    // once because at least one --override-deny was present, and the
    // resulting profile shows both paths in the bypass list.
    let dir = tempfile::tempdir().expect("tempdir");
    let path_a = dir.path().join("a");
    let path_b = dir.path().join("b");
    std::fs::create_dir_all(&path_a).expect("create a");
    std::fs::create_dir_all(&path_b).expect("create b");

    let out = Command::new(bin())
        .args([
            "run",
            "--dry-run",
            "--allow",
            path_a.to_str().expect("a"),
            "--allow",
            path_b.to_str().expect("b"),
            "--bypass-protection",
            path_a.to_str().expect("a"),
            "--override-deny",
            path_b.to_str().expect("b"),
            "--",
            "echo",
        ])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "dry-run with mixed flags failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let n = stderr
        .matches("warning: deprecated key '--override-deny'")
        .count();
    assert_eq!(
        n, 1,
        "exactly one warning for the legacy flag in a mixed invocation; stderr: {stderr}"
    );
}

#[test]
fn help_invocation_emits_no_deprecation_warning() {
    // `nono run --help` should not trip the deprecated-flag scanner because
    // the literal `--override-deny` does not appear in argv.
    let out = Command::new(bin())
        .args(["run", "--help"])
        .output()
        .expect("run --help");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("warning: deprecated key"),
        "--help should not emit deprecation warnings; stderr: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Per-fixture warning content (Critical #1 + Important I3)
// ---------------------------------------------------------------------------

/// Expected (legacy_key, canonical_key) for each single-key fixture. Drives
/// `each_legacy_single_key_fixture_emits_exact_warning_once` so a regression
/// in any single drain mapping fails specifically.
fn fixture_expectations() -> &'static [(&'static str, &'static str, &'static str)] {
    &[
        (
            "legacy_security_groups.json",
            "security.groups",
            "groups.include",
        ),
        (
            "legacy_security_allowed_commands.json",
            "security.allowed_commands",
            "commands.allow",
        ),
        (
            "legacy_policy_exclude_groups.json",
            "policy.exclude_groups",
            "groups.exclude",
        ),
        (
            "legacy_policy_add_allow_read.json",
            "policy.add_allow_read",
            "filesystem.read",
        ),
        (
            "legacy_policy_add_allow_write.json",
            "policy.add_allow_write",
            "filesystem.write",
        ),
        (
            "legacy_policy_add_allow_readwrite.json",
            "policy.add_allow_readwrite",
            "filesystem.allow",
        ),
        (
            "legacy_policy_add_deny_access.json",
            "policy.add_deny_access",
            "filesystem.deny",
        ),
        (
            "legacy_policy_add_deny_commands.json",
            "policy.add_deny_commands",
            "commands.deny",
        ),
        (
            "legacy_policy_override_deny.json",
            "policy.override_deny",
            "filesystem.bypass_protection",
        ),
    ]
}

#[test]
fn each_legacy_single_key_fixture_emits_exact_warning_once() {
    for (fixture, legacy_key, canonical_key) in fixture_expectations() {
        let path = format!("tests/fixtures/legacy_profiles/{fixture}");
        let (status, _stdout, stderr) = show_json(&path);
        assert!(
            status.success(),
            "{fixture} failed to parse; stderr: {stderr}"
        );

        let expected_substring = format!("warning: deprecated key '{legacy_key}'");
        let n = stderr.matches(&expected_substring).count();
        assert_eq!(
            n, 1,
            "{fixture}: expected exactly one warning for '{legacy_key}', got {n}. stderr: {stderr}"
        );

        assert!(
            stderr.contains(&format!("'{canonical_key}'")),
            "{fixture}: warning should reference canonical '{canonical_key}'; stderr: {stderr}"
        );
        assert!(
            stderr.contains("v1.0.0"),
            "{fixture}: warning should reference removal version v1.0.0; stderr: {stderr}"
        );
        assert!(
            stderr.contains("#594"),
            "{fixture}: warning should reference issue #594; stderr: {stderr}"
        );

        // Total warning count should equal exactly 1 for single-key fixtures
        // (catches a regression of the cmd_show double-parse on small files).
        let total = count_warnings(&stderr);
        assert_eq!(
            total, 1,
            "{fixture}: expected exactly 1 deprecation warning total, got {total}. stderr: {stderr}"
        );
    }
}

#[test]
fn fixture_expectations_cover_all_single_key_files() {
    // Guard against drift: if a new single-key fixture lands in the
    // directory, the expectations table must grow alongside it.
    let dir = std::path::Path::new("tests/fixtures/legacy_profiles");
    let mut on_disk: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(dir).expect("read dir") {
        let p = entry.expect("entry").path();
        let name = p.file_name().expect("name").to_string_lossy().to_string();
        if name.starts_with("legacy_")
            && name != "legacy_all_keys.json"
            && name != "legacy_collision_security_and_groups.json"
        {
            on_disk.push(name);
        }
    }
    on_disk.sort();
    let mut expected: Vec<String> = fixture_expectations()
        .iter()
        .map(|(f, _, _)| f.to_string())
        .collect();
    expected.sort();
    assert_eq!(
        on_disk, expected,
        "single-key fixtures on disk diverge from fixture_expectations() table"
    );
}

// ---------------------------------------------------------------------------
// Cross-section collision (Important I5; design risk #4 lines 403-405)
// ---------------------------------------------------------------------------

#[test]
fn collision_legacy_and_canonical_groups_merge_with_warnings() {
    // legacy_collision_security_and_groups.json populates both:
    //   groups.include = ["node_runtime"]
    //   security.groups = ["python_runtime"]            (legacy)
    //   security.allowed_commands = ["pip"]             (legacy)
    //   commands.allow = ["npm"]
    //
    // Contract: legacy values are appended to canonical values (extend
    // semantics — canonical-first ordering preserved). One warning fires
    // per populated legacy key. No silent merging without warning.
    let path = "tests/fixtures/legacy_profiles/legacy_collision_security_and_groups.json";
    let (status, stdout, stderr) = show_json(path);
    assert!(
        status.success(),
        "collision fixture failed; stderr: {stderr}"
    );

    // Two legacy keys → two distinct warnings.
    let n_security_groups = stderr
        .matches("warning: deprecated key 'security.groups'")
        .count();
    let n_allowed_commands = stderr
        .matches("warning: deprecated key 'security.allowed_commands'")
        .count();
    assert_eq!(
        n_security_groups, 1,
        "expected 1 warning for security.groups in collision case; stderr: {stderr}"
    );
    assert_eq!(
        n_allowed_commands, 1,
        "expected 1 warning for security.allowed_commands in collision case; stderr: {stderr}"
    );
    assert_eq!(
        count_warnings(&stderr),
        2,
        "expected exactly 2 warnings for collision fixture; stderr: {stderr}"
    );

    // Both canonical and legacy values must be present in the resolved state.
    // Parse the JSON to verify rather than substring-grepping.
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("show output is JSON");
    let groups = value
        .pointer("/groups/include")
        .and_then(|v| v.as_array())
        .expect("groups.include array");
    let group_names: Vec<&str> = groups.iter().filter_map(|v| v.as_str()).collect();
    assert!(
        group_names.contains(&"node_runtime"),
        "canonical 'node_runtime' must be present; got {group_names:?}"
    );
    assert!(
        group_names.contains(&"python_runtime"),
        "legacy-drained 'python_runtime' must be present; got {group_names:?}"
    );

    let cmds = value
        .pointer("/commands/allow")
        .and_then(|v| v.as_array())
        .expect("commands.allow array");
    let cmd_names: Vec<&str> = cmds.iter().filter_map(|v| v.as_str()).collect();
    assert!(
        cmd_names.contains(&"npm"),
        "canonical 'npm' must be present; got {cmd_names:?}"
    );
    assert!(
        cmd_names.contains(&"pip"),
        "legacy-drained 'pip' must be present; got {cmd_names:?}"
    );
}

// ---------------------------------------------------------------------------
// `nono profile diff` legacy ↔ canonical (Important I4; design line 313)
// ---------------------------------------------------------------------------

#[test]
fn legacy_all_keys_diff_canonical_shows_no_semantic_diff() {
    let out = Command::new(bin())
        .args([
            "profile",
            "diff",
            "--json",
            "tests/fixtures/legacy_profiles/legacy_all_keys.json",
            "tests/fixtures/legacy_profiles/canonical_equivalent_of_all_keys.json",
        ])
        .output()
        .expect("run nono profile diff");
    assert!(
        out.status.success(),
        "diff exited non-zero; stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let value: serde_json::Value =
        serde_json::from_str(&stdout).expect("profile diff --json output is JSON");

    // Walk every value under groups.added/removed and *.changed flags. If
    // legacy and canonical resolve to the same Profile, all "added" /
    // "removed" arrays must be empty and every "changed" boolean must be
    // false.
    fn check_no_changes(v: &serde_json::Value, path: &str, errs: &mut Vec<String>) {
        if let serde_json::Value::Object(map) = v {
            for (k, child) in map {
                let new_path = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                if (k == "added" || k == "removed")
                    && child.as_array().is_some_and(|a| !a.is_empty())
                {
                    errs.push(format!("non-empty {new_path}: {child}"));
                } else if k == "changed" && child.as_bool() == Some(true) {
                    errs.push(format!("changed=true at {new_path}"));
                } else {
                    check_no_changes(child, &new_path, errs);
                }
            }
        }
    }
    let mut errs: Vec<String> = Vec::new();
    check_no_changes(&value, "", &mut errs);
    assert!(
        errs.is_empty(),
        "legacy and canonical fixtures should be semantically identical; differences: {errs:#?}"
    );
}

// ---------------------------------------------------------------------------
// Empty-array semantics
// ---------------------------------------------------------------------------

#[test]
fn empty_legacy_arrays_emit_no_warnings() {
    // A user who writes `"policy": { "add_allow_read": [] }` (empty array)
    // is not adding any paths. The drain checks `is_empty()` and skips the
    // emission — pin this in so a future "warn on legacy section presence
    // even if empty" change is intentional, not accidental.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("empty_legacy.json");
    std::fs::write(
        &path,
        r#"{
            "meta": { "name": "empty-legacy" },
            "policy": {
                "add_allow_read": [],
                "add_allow_write": [],
                "add_deny_access": [],
                "override_deny": [],
                "exclude_groups": []
            },
            "security": {
                "groups": [],
                "allowed_commands": []
            }
        }"#,
    )
    .expect("write");

    let (status, _stdout, stderr) = show_json(path.to_str().expect("path"));
    assert!(status.success(), "show failed; stderr: {stderr}");
    assert_eq!(
        count_warnings(&stderr),
        0,
        "empty legacy arrays should not emit warnings; stderr: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Built-ins regression: zero deprecation warnings on load
// ---------------------------------------------------------------------------

#[test]
fn no_builtin_profile_emits_deprecation_warning() {
    // Per design lines 354/390/397: built-ins must be on the canonical
    // schema. Loading any of them must emit zero deprecation warnings.
    // Walk the list reported by `nono profile list --json`, run
    // `nono profile show --json <name>` for each, and assert clean stderr.
    let list = Command::new(bin())
        .args(["profile", "list", "--json"])
        .output()
        .expect("run profile list");
    assert!(
        list.status.success(),
        "profile list failed; stderr={}",
        String::from_utf8_lossy(&list.stderr)
    );
    let list_stdout = String::from_utf8_lossy(&list.stdout);
    let list_v: serde_json::Value =
        serde_json::from_str(&list_stdout).expect("profile list output is JSON");
    let arr = list_v.as_array().expect("profile list returns an array");

    let mut checked = 0usize;
    for entry in arr {
        let name = entry
            .get("name")
            .and_then(|v| v.as_str())
            .expect("profile entry has name");
        let source = entry
            .get("source")
            .and_then(|v| v.as_str())
            .unwrap_or("user");
        if source != "built-in" {
            continue;
        }

        let (status, _stdout, stderr) = show_json(name);
        assert!(
            status.success(),
            "built-in profile '{name}' failed to show; stderr: {stderr}"
        );
        assert_eq!(
            count_warnings(&stderr),
            0,
            "built-in profile '{name}' emits deprecation warning(s); migrate it to canonical schema. stderr: {stderr}"
        );
        checked += 1;
    }
    assert!(
        checked > 0,
        "expected at least one built-in profile, checked {checked}"
    );
}

#[test]
fn no_qa_profile_emits_deprecation_warning() {
    // qa-profiles/*.json are repo-shipped sample profiles. None should
    // emit deprecation warnings on load.
    let qa_dir = std::path::Path::new("../../qa-profiles");
    if !qa_dir.exists() {
        // Worktree without qa-profiles checkout: skip rather than fail.
        return;
    }
    let mut checked = 0usize;
    for entry in std::fs::read_dir(qa_dir).expect("read qa-profiles") {
        let p = entry.expect("entry").path();
        if p.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let (status, _stdout, stderr) = show_json(p.to_str().expect("path"));
        assert!(
            status.success(),
            "qa profile '{}' failed to show; stderr: {stderr}",
            p.display()
        );
        assert_eq!(
            count_warnings(&stderr),
            0,
            "qa profile '{}' emits deprecation warning(s); migrate it. stderr: {stderr}",
            p.display()
        );
        checked += 1;
    }
    assert!(
        checked > 0,
        "expected at least one qa profile, checked {checked}"
    );
}

// ---------------------------------------------------------------------------
// Extends-chain attribution
// ---------------------------------------------------------------------------

#[test]
fn legacy_keys_in_extends_parent_emit_warnings_once_via_child() {
    // Child profile uses canonical keys but extends a parent that uses
    // legacy keys. The user invokes `nono profile show child.json` and
    // should see exactly one warning per legacy key in the parent — not
    // zero (we'd lose the migration signal) and not two (we'd be
    // re-emitting on the preview parse — the very bug
    // WarningSuppressionGuard fixes).
    //
    // `extends` resolves by profile name through the user-profiles dir
    // (`$HOME/.config/nono/profiles/`) or built-ins, so we override HOME
    // to a tempdir for the spawned `nono` invocation and write the
    // parent there. The child references the parent by name.
    let dir = tempfile::tempdir().expect("tempdir");
    let user_profiles = dir.path().join(".config").join("nono").join("profiles");
    std::fs::create_dir_all(&user_profiles).expect("create profiles dir");

    let parent_name = "nono-test-legacy-parent";
    let parent_path = user_profiles.join(format!("{parent_name}.json"));
    std::fs::write(
        &parent_path,
        format!(
            r#"{{
                "meta": {{ "name": "{parent_name}" }},
                "policy": {{
                    "add_allow_read": ["/parent-read"]
                }}
            }}"#,
        ),
    )
    .expect("write parent");

    let child_path = dir.path().join("child.json");
    std::fs::write(
        &child_path,
        format!(
            r#"{{
                "meta": {{ "name": "child" }},
                "extends": "{parent_name}",
                "filesystem": {{ "allow": ["/child-allow"] }}
            }}"#
        ),
    )
    .expect("write child");

    // `resolve_user_config_dir()` consults `XDG_CONFIG_HOME` first and falls
    // back to `$HOME/.config` only when XDG is unset/invalid. CI runners set
    // XDG_CONFIG_HOME (e.g. ubuntu-latest), so setting only HOME would let
    // the spawned nono read the runner's config dir and miss our parent
    // profile. Pin XDG_CONFIG_HOME at the tempdir's `.config` directly.
    let xdg = dir.path().join(".config");
    let out = Command::new(bin())
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", &xdg)
        .args([
            "profile",
            "show",
            "--json",
            child_path.to_str().expect("path"),
        ])
        .output()
        .expect("run nono");
    assert!(
        out.status.success(),
        "show child failed; stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let n = stderr
        .matches("warning: deprecated key 'policy.add_allow_read'")
        .count();
    assert_eq!(
        n, 1,
        "expected exactly one warning for parent's legacy key; stderr: {stderr}"
    );
}
