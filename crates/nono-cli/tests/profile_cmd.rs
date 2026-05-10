//! Integration tests for `nono profile` subcommands.
//!
//! These run as separate processes, so they are fully isolated from unit tests.

use std::process::Command;

fn nono_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nono"))
}

// ---------------------------------------------------------------------------
// nono profile init
// ---------------------------------------------------------------------------

#[test]
fn test_init_creates_valid_profile() {
    let dir = std::env::temp_dir().join("nono-test-profile-init");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let out = dir.join("test-agent.json");

    let output = nono_bin()
        .args([
            "profile",
            "init",
            "test-agent",
            "--extends",
            "default",
            "--groups",
            "deny_credentials",
            "--description",
            "Integration test profile",
            "--output",
        ])
        .arg(&out)
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "expected exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(out.exists(), "profile file should be created");

    // Validate the generated file with nono profile validate
    let validate = nono_bin()
        .args(["profile", "validate"])
        .arg(&out)
        .output()
        .expect("failed to run nono");

    assert!(
        validate.status.success(),
        "generated profile should be valid, stderr: {}",
        String::from_utf8_lossy(&validate.stderr)
    );

    // Parse and check content
    let content = std::fs::read_to_string(&out).expect("read profile");
    let val: serde_json::Value = serde_json::from_str(&content).expect("parse json");
    assert_eq!(val["meta"]["name"], "test-agent");
    assert_eq!(val["extends"], "default");
    assert_eq!(val["meta"]["description"], "Integration test profile");
    assert_eq!(val["groups"]["include"][0], "deny_credentials");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_init_full_creates_all_additive_sections() {
    let dir = std::env::temp_dir().join("nono-test-profile-init-full");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let out = dir.join("full-agent.json");

    let output = nono_bin()
        .args(["profile", "init", "full-agent", "--full", "--output"])
        .arg(&out)
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "expected exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let content = std::fs::read_to_string(&out).expect("read profile");
    let val: serde_json::Value = serde_json::from_str(&content).expect("parse json");

    // Full skeleton must include these additive sections
    assert!(val.get("commands").is_some(), "missing commands section");
    assert!(val.get("network").is_some(), "missing network section");
    assert!(
        val.get("env_credentials").is_some(),
        "missing env_credentials"
    );
    assert!(val.get("hooks").is_some(), "missing hooks section");
    assert!(val.get("rollback").is_some(), "missing rollback section");

    // Full skeleton must NOT include override-sensitive fields
    assert!(
        val.get("open_urls").is_none(),
        "open_urls should be omitted"
    );
    assert!(
        val.get("allow_launch_services").is_none(),
        "allow_launch_services should be omitted"
    );
    assert!(
        val.get("allow_gpu").is_none(),
        "allow_gpu should be omitted"
    );
    assert!(
        val["network"].get("network_profile").is_none(),
        "network_profile should be omitted"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_init_rejects_existing_file_without_force() {
    let dir = std::env::temp_dir().join("nono-test-profile-init-noforce");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let out = dir.join("existing.json");
    std::fs::write(&out, "{}").expect("create existing file");

    let output = nono_bin()
        .args(["profile", "init", "existing", "--output"])
        .arg(&out)
        .output()
        .expect("failed to run nono");

    assert!(!output.status.success(), "should fail without --force");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("already exists") || stderr.contains("--force"),
        "error should mention existing file, got: {stderr}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_init_force_overwrites() {
    let dir = std::env::temp_dir().join("nono-test-profile-init-force");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let out = dir.join("overwrite.json");
    std::fs::write(&out, "{}").expect("create existing file");

    let output = nono_bin()
        .args(["profile", "init", "overwrite", "--force", "--output"])
        .arg(&out)
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "should succeed with --force, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let content = std::fs::read_to_string(&out).expect("read profile");
    let val: serde_json::Value = serde_json::from_str(&content).expect("parse json");
    assert_eq!(val["meta"]["name"], "overwrite");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_init_invalid_name_exits_error() {
    let out = std::env::temp_dir().join("nono-test-badname-nonexistent.json");
    let _ = std::fs::remove_file(&out);

    let output = nono_bin()
        .args(["profile", "init", "-bad-name-", "--output"])
        .arg(&out)
        .output()
        .expect("failed to run nono");

    assert!(!output.status.success(), "should fail for invalid name");
    assert!(!out.exists(), "file should not be created");
}

#[test]
fn test_init_invalid_group_exits_error() {
    let out = std::env::temp_dir().join("nono-test-badgroup-nonexistent.json");
    let _ = std::fs::remove_file(&out);

    let output = nono_bin()
        .args([
            "profile",
            "init",
            "test-agent",
            "--groups",
            "nonexistent_group_xyz",
            "--output",
        ])
        .arg(&out)
        .output()
        .expect("failed to run nono");

    assert!(!output.status.success(), "should fail for unknown group");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("nonexistent_group_xyz"),
        "error should name the bad group, got: {stderr}"
    );
    assert!(!out.exists(), "file should not be created");
}

#[test]
fn test_init_invalid_extends_exits_error() {
    let out = std::env::temp_dir().join("nono-test-badextends-nonexistent.json");
    let _ = std::fs::remove_file(&out);

    let output = nono_bin()
        .args([
            "profile",
            "init",
            "test-agent",
            "--extends",
            "nonexistent-base-xyz",
            "--output",
        ])
        .arg(&out)
        .output()
        .expect("failed to run nono");

    assert!(!output.status.success(), "should fail for unknown base");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("nonexistent-base-xyz"),
        "error should name the bad base, got: {stderr}"
    );
    assert!(!out.exists(), "file should not be created");
}

// ---------------------------------------------------------------------------
// nono profile schema
// ---------------------------------------------------------------------------

#[test]
fn test_schema_outputs_valid_json() {
    let output = nono_bin()
        .args(["profile", "schema"])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "expected exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value =
        serde_json::from_str(&stdout).expect("schema output should be valid JSON");
    assert_eq!(
        val["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(val["title"], "nono Profile");
    assert!(
        val.get("properties").is_some(),
        "schema should have properties"
    );
}

#[test]
fn test_schema_output_to_file() {
    let dir = std::env::temp_dir().join("nono-test-profile-schema");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let out = dir.join("schema.json");

    let output = nono_bin()
        .args(["profile", "schema", "--output"])
        .arg(&out)
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "expected exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(out.exists(), "schema file should be created");

    let content = std::fs::read_to_string(&out).expect("read schema");
    let val: serde_json::Value =
        serde_json::from_str(&content).expect("schema file should be valid JSON");
    assert_eq!(val["title"], "nono Profile");

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// nono profile guide
// ---------------------------------------------------------------------------

#[test]
fn test_guide_outputs_markdown() {
    let output = nono_bin()
        .args(["profile", "guide"])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "expected exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("# nono Profile Authoring Guide"),
        "guide should start with the expected heading"
    );
    assert!(
        stdout.contains("Variable Expansion"),
        "guide should cover variable expansion"
    );
}
