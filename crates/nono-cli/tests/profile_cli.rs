//! Integration tests for canonical `nono profile` subcommands (inspection, comparison, validation).
//!
//! These run as separate processes, so they are fully isolated from unit tests.

use std::process::Command;

fn nono_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nono"))
}

#[test]
fn test_groups_list_output() {
    let output = nono_bin()
        .args(["profile", "groups", "--all-platforms"])
        .output()
        .expect("failed to run nono");

    assert!(output.status.success(), "expected exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("deny_credentials"),
        "expected deny_credentials in output, got:\n{stdout}"
    );
}

#[test]
fn test_groups_detail_output() {
    let output = nono_bin()
        .args(["profile", "groups", "deny_credentials"])
        .output()
        .expect("failed to run nono");

    assert!(output.status.success(), "expected exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(".ssh"),
        "expected .ssh in deny_credentials detail, got:\n{stdout}"
    );
    assert!(
        stdout.contains(".aws"),
        "expected .aws in deny_credentials detail, got:\n{stdout}"
    );
}

#[test]
fn test_groups_unknown_exits_error() {
    let output = nono_bin()
        .args(["profile", "groups", "nonexistent_group_xyz"])
        .output()
        .expect("failed to run nono");

    assert!(!output.status.success(), "expected non-zero exit");
}

#[test]
fn test_list_output() {
    let output = nono_bin()
        .args(["profile", "list"])
        .output()
        .expect("failed to run nono");

    assert!(output.status.success(), "expected exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Use two profiles that are still embedded after the
    // claude/codex move to registry packs.
    assert!(
        stdout.contains("default"),
        "expected default in profiles list, got:\n{stdout}"
    );
    assert!(
        stdout.contains("node-dev"),
        "expected node-dev in profiles list, got:\n{stdout}"
    );
}

#[test]
fn test_show_profile_output() {
    let output = nono_bin()
        .args(["profile", "show", "default"])
        .output()
        .expect("failed to run nono");

    assert!(output.status.success(), "expected exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Security groups"),
        "expected Security groups section, got:\n{stdout}"
    );
}

#[test]
fn test_show_profile_json() {
    let output = nono_bin()
        .args(["profile", "show", "default", "--json"])
        .output()
        .expect("failed to run nono");

    assert!(output.status.success(), "expected exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).expect("expected valid JSON output");
    assert!(
        val.get("security").is_some(),
        "expected security key in JSON"
    );
}

#[test]
fn test_diff_output() {
    let output = nono_bin()
        .args(["profile", "diff", "default", "node-dev"])
        .output()
        .expect("failed to run nono");

    assert!(output.status.success(), "expected exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains('+'),
        "expected + lines in diff output, got:\n{stdout}"
    );
}

#[test]
fn test_validate_valid_profile() {
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

    let output = nono_bin()
        .args(["profile", "validate", path.to_str().expect("path")])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "expected exit 0 for valid profile, stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_validate_invalid_group() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("bad-profile.json");
    std::fs::write(
        &path,
        r#"{
            "meta": { "name": "test" },
            "security": { "groups": ["fake_group_that_does_not_exist"] }
        }"#,
    )
    .expect("write");

    let output = nono_bin()
        .args(["profile", "validate", path.to_str().expect("path")])
        .output()
        .expect("failed to run nono");

    assert!(
        !output.status.success(),
        "expected non-zero exit for invalid group"
    );
}

#[test]
fn test_groups_json() {
    let output = nono_bin()
        .args(["profile", "groups", "--json", "--all-platforms"])
        .output()
        .expect("failed to run nono");

    assert!(output.status.success(), "expected exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).expect("expected valid JSON output");
    assert!(val.is_array(), "expected JSON array");
    let arr = val.as_array().expect("array");
    assert!(arr.len() > 10, "expected many groups in JSON output");
}

// ---------------------------------------------------------------------------
// nono profile show --format manifest
// ---------------------------------------------------------------------------

#[test]
fn test_show_format_manifest_default_profile() {
    let output = nono_bin()
        .args(["profile", "show", "default", "--format", "manifest"])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "expected exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value =
        serde_json::from_str(&stdout).expect("expected valid JSON manifest");
    assert_eq!(
        val.get("version").and_then(|v| v.as_str()),
        Some("0.1.0"),
        "manifest must have version 0.1.0"
    );
    assert!(
        val.get("$schema").is_some(),
        "manifest should include $schema"
    );
}

#[test]
fn test_show_format_manifest_node_dev_profile() {
    // node-dev is an embedded profile with non-empty filesystem grants,
    // standing in for the claude-code coverage that moved to the
    // always-further/claude registry pack.
    let output = nono_bin()
        .args(["profile", "show", "node-dev", "--format", "manifest"])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "expected exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value =
        serde_json::from_str(&stdout).expect("expected valid JSON manifest");
    assert_eq!(val.get("version").and_then(|v| v.as_str()), Some("0.1.0"));
    assert!(
        val.get("filesystem").is_some(),
        "node-dev manifest should have filesystem grants"
    );
    let grants = val["filesystem"]["grants"]
        .as_array()
        .expect("grants array");
    assert!(
        !grants.is_empty(),
        "node-dev should have at least one filesystem grant"
    );
}

#[test]
fn test_show_format_manifest_round_trip() {
    // Build a minimal manifest with paths that exist everywhere,
    // then feed it back via --config --dry-run.
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = dir.path().join("manifest.json");
    std::fs::write(
        &manifest_path,
        r#"{
            "version": "0.1.0",
            "filesystem": {
                "grants": [{ "path": "/tmp", "access": "read" }]
            },
            "network": { "mode": "blocked" }
        }"#,
    )
    .expect("write manifest");

    let output = nono_bin()
        .args([
            "run",
            "--config",
            manifest_path.to_str().expect("path"),
            "--dry-run",
            "--",
            "echo",
            "hello",
        ])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "round-trip failed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_show_format_manifest_all_builtins_succeed() {
    // All built-in profiles should export without errors
    let list_output = nono_bin()
        .args(["profile", "list", "--json"])
        .output()
        .expect("failed to run nono");
    assert!(list_output.status.success());

    let stdout = String::from_utf8_lossy(&list_output.stdout);
    let profiles: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let arr = profiles.as_array().expect("array of profiles");

    for profile_val in arr {
        if profile_val.get("source").and_then(|s| s.as_str()) != Some("built-in") {
            continue;
        }
        let name = profile_val
            .get("name")
            .and_then(|n| n.as_str())
            .expect("profile name");

        let output = nono_bin()
            .args(["profile", "show", name, "--format", "manifest"])
            .output()
            .expect("failed to run nono");

        assert!(
            output.status.success(),
            "profile '{}' failed manifest export, stderr: {}",
            name,
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        let val: serde_json::Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|e| panic!("profile '{}' produced invalid JSON: {}", name, e));
        assert_eq!(
            val.get("version").and_then(|v| v.as_str()),
            Some("0.1.0"),
            "profile '{}' manifest missing version",
            name
        );
    }
}

// ----------------------------------------------------------------------------
// `profile show --json` / `profile diff --json` — Debug-format leak regression
//
// Historically the hand-rolled JSON emitter rendered five enum-valued fields
// via `format!("{:?}", …)`, leaking Rust Debug syntax (`"Some(Isolated)"`,
// `"ReadWrite"`, `"None"`-as-string) into output that `profile validate`
// rejects. These tests guard against any future regression on the same code
// path. See docs/policy-show-json-serialization-leak.md.
// ----------------------------------------------------------------------------

const SECURITY_TRI_MODE: &[&str] = &["isolated", "allow_same_sandbox", "allow_all"];
const IPC_MODES: &[&str] = &["shared_memory_only", "full"];
const WSL2_POLICIES: &[&str] = &["error", "insecure_proxy"];
const WORKDIR_ACCESS: &[&str] = &["none", "read", "write", "readwrite"];

/// Asserts a security-mode field is either omitted (None became absent) or a
/// known snake_case variant. JSON `null` is treated as a failure because the
/// show emitter omits None rather than nulling.
fn assert_security_mode(security: &serde_json::Value, field: &str, valid: &[&str], ctx: &str) {
    let Some(v) = security.get(field) else {
        return;
    };
    assert!(
        !v.is_null(),
        "{ctx}: security.{field} is null; expected omitted when absent"
    );
    let Some(s) = v.as_str() else {
        panic!("{ctx}: security.{field} = {v} (expected string)");
    };
    assert!(
        valid.contains(&s),
        "{ctx}: security.{field} = {s:?} not in {valid:?}"
    );
}

/// Catches any leftover Rust Debug syntax in the raw JSON text. Belt and
/// suspenders to the structural checks above.
fn assert_no_debug_tokens(stdout: &str, ctx: &str) {
    for needle in [
        r#""Some("#,
        r#""None""#,
        r#""ReadWrite""#,
        r#""Read""#,
        r#""Write""#,
        r#""Isolated""#,
        r#""AllowSameSandbox""#,
        r#""AllowAll""#,
        r#""SharedMemoryOnly""#,
        r#""Full""#,
        r#""Error""#,
        r#""InsecureProxy""#,
    ] {
        assert!(
            !stdout.contains(needle),
            "{ctx}: output contains Debug-formatted token {needle}\n--- stdout ---\n{stdout}"
        );
    }
}

#[test]
fn test_show_profile_json_no_debug_leaks() {
    for profile in ["default", "node-dev"] {
        let output = nono_bin()
            .args(["profile", "show", profile, "--json"])
            .output()
            .expect("failed to run nono");

        assert!(
            output.status.success(),
            "{profile}: expected exit 0, stderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let val: serde_json::Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|e| panic!("{profile}: invalid JSON: {e}\n{stdout}"));

        let security = val
            .get("security")
            .unwrap_or_else(|| panic!("{profile}: missing security block"));
        assert_security_mode(security, "signal_mode", SECURITY_TRI_MODE, profile);
        assert_security_mode(security, "process_info_mode", SECURITY_TRI_MODE, profile);
        assert_security_mode(security, "ipc_mode", IPC_MODES, profile);
        assert_security_mode(security, "wsl2_proxy_policy", WSL2_POLICIES, profile);

        let workdir = val
            .get("workdir")
            .unwrap_or_else(|| panic!("{profile}: missing workdir block"));
        let access = workdir
            .get("access")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("{profile}: workdir.access missing or not a string"));
        assert!(
            WORKDIR_ACCESS.contains(&access),
            "{profile}: workdir.access = {access:?} not in {WORKDIR_ACCESS:?}"
        );

        assert_no_debug_tokens(&stdout, &format!("show {profile}"));
    }
}

#[test]
fn test_diff_profile_json_no_debug_leaks() {
    let output = nono_bin()
        .args(["profile", "diff", "default", "node-dev", "--json"])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "expected exit 0, stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("invalid diff JSON: {e}\n{stdout}"));

    // wsl2_proxy_policy.profileN: null (when None) or a known variant.
    let wsl2 = val
        .get("wsl2_proxy_policy")
        .unwrap_or_else(|| panic!("missing wsl2_proxy_policy block"));
    for side in ["profile1", "profile2"] {
        let v = wsl2
            .get(side)
            .unwrap_or_else(|| panic!("wsl2_proxy_policy.{side} missing"));
        if v.is_null() {
            continue;
        }
        let s = v
            .as_str()
            .unwrap_or_else(|| panic!("wsl2_proxy_policy.{side} = {v} (expected string)"));
        assert!(
            WSL2_POLICIES.contains(&s),
            "wsl2_proxy_policy.{side} = {s:?} not in {WSL2_POLICIES:?}"
        );
    }

    // workdir.profileN: always present, lowercase variant. WorkdirAccess is
    // not Option-wrapped in the profile struct, so null isn't expected.
    let workdir = val
        .get("workdir")
        .unwrap_or_else(|| panic!("missing workdir block"));
    for side in ["profile1", "profile2"] {
        let v = workdir
            .get(side)
            .unwrap_or_else(|| panic!("workdir.{side} missing"));
        let s = v
            .as_str()
            .unwrap_or_else(|| panic!("workdir.{side} = {v} (expected string)"));
        assert!(
            WORKDIR_ACCESS.contains(&s),
            "workdir.{side} = {s:?} not in {WORKDIR_ACCESS:?}"
        );
    }

    assert_no_debug_tokens(&stdout, "diff default node-dev");
}
