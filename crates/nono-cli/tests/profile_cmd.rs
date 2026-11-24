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
    assert!(
        stdout.contains("Command-policy denials"),
        "guide should cover command-policy denials"
    );
    assert!(
        stdout.contains("Proxy credential endpoint policy"),
        "guide should cover proxy credential endpoint policy"
    );
    assert!(
        stdout.contains("invocation_policy"),
        "guide should cover invocation_policy rules"
    );
    assert!(
        stdout.contains("nono why --profile <profile> --command gh -- issue comment 1052"),
        "guide should show command-policy diagnostic query"
    );
}

#[test]
fn bundle_export_includes_bases_and_preserves_device_predicates() {
    let dir = tempfile::tempdir().expect("fixture");
    std::fs::write(
        dir.path().join("base.json"),
        r#"{
        "meta":{"name":"base"},"filesystem":{"read":["$HOME/shared", {"path":"$HOME/linux-conditional", "when":"linux"}, {"path":"$HOME/mac-conditional", "when":"macos"}]},
        "platform_overrides":{
            "macos":{"filesystem":{"read":["$HOME/mac-only"]}},
            "linux":{"filesystem":{"read":["$HOME/linux-only"]}}
        }
    }"#,
    )
    .expect("base");
    let path = dir.path().join("managed.json");
    std::fs::write(
        &path,
        r#"{"meta":{"name":"managed"},"extends":"base","filesystem":{"read":["$WORKDIR"]}}"#,
    )
    .expect("leaf");
    let output = nono_bin()
        .args(["profile", "show"])
        .arg(&path)
        .args(["--format", "bundle"])
        .output()
        .expect("export");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let exported: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("bundle export");
    use base64::Engine as _;
    let file = |path: &str| -> serde_json::Value {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(exported["files"][path].as_str().expect("included file"))
            .expect("base64");
        serde_json::from_slice(&bytes).expect("profile JSON")
    };
    let predicate = &exported["statement"]["predicate"];
    let base = file(
        predicate["profiles"]["profile-0"]
            .as_str()
            .expect("base binding"),
    );
    let root = file(
        predicate["entrypoints"]["policy"]
            .as_str()
            .expect("entrypoint"),
    );
    assert_eq!(
        exported["statement"]["predicateType"],
        "https://nono.sh/attestation/bundle/v1"
    );
    assert_eq!(
        exported["statement"]["subject"]
            .as_array()
            .expect("subjects")
            .len(),
        exported["files"].as_object().expect("files").len()
    );
    assert_eq!(base["filesystem"]["read"][0], "$HOME/shared");
    assert_eq!(
        base["filesystem"]["read"][1]["path"],
        "$HOME/linux-conditional"
    );
    assert_eq!(
        base["filesystem"]["read"][2]["path"],
        "$HOME/mac-conditional"
    );
    assert_eq!(root["filesystem"]["read"], serde_json::json!(["$WORKDIR"]));
    assert_eq!(
        base["platform_overrides"]["macos"]["filesystem"]["read"][0],
        "$HOME/mac-only"
    );
    assert_eq!(
        base["platform_overrides"]["linux"]["filesystem"]["read"][0],
        "$HOME/linux-only"
    );
}

#[test]
fn bundle_export_retains_hook_declarations_without_executing_them() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let dir = tempfile::tempdir().expect("fixture");
    let path = dir.path().join("managed.json");
    let profile = serde_json::json!({
        "meta":{"name":"managed"},
        "hooks":{"claude":{"event":"PreToolUse","matcher":"Bash","script":"missing-hook.sh"}},
        "session_hooks":{
            "before":{"script":"/missing/before.sh"},
            "after":{"script":"/missing/after.sh"}
        }
    });
    std::fs::write(&path, profile.to_string()).expect("profile");
    let output = nono_bin()
        .args(["profile", "show"])
        .arg(&path)
        .args(["--format", "bundle"])
        .output()
        .expect("export");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let export: serde_json::Value = serde_json::from_slice(&output.stdout).expect("export");
    let delivered: serde_json::Value = serde_json::from_slice(
        &STANDARD
            .decode(export["files"]["policy.json"].as_str().expect("policy"))
            .expect("base64"),
    )
    .expect("policy JSON");
    assert_eq!(delivered, profile);
}

fn complete_pack_fixture() -> (
    tempfile::TempDir,
    std::collections::BTreeMap<String, Vec<u8>>,
) {
    use serde_json::json;
    let dir = tempfile::tempdir().expect("fixture");
    let mut expected = std::collections::BTreeMap::new();
    for (name, profile) in [
        (
            "agent",
            json!({"meta":{"name":"agent"},"extends":"acme/base"}),
        ),
        (
            "base",
            json!({
                "meta":{"name":"base"},
                "hooks":{"claude":{"event":"PreToolUse","matcher":"Bash","script":"bin/hook.sh"}},
                "session_hooks":{"before":{"script":"$PACK_DIR/bin/hook.sh"}}
            }),
        ),
    ] {
        let manifest = json!({"schema_version":1,"name":name,"artifacts":[
            {"type":"profile","path":"policy.json","install_as":name},
            {"type":"plugin","path":"bin/hook.sh"},
            {"type":"plugin","path":"skills/review/SKILL.md"}
        ],"wiring":[{"type":"write_file","source":"bin/hook.sh","dest":"$HOME/SHOULD_NOT_BE_INSTALLED"}]});
        let pack = dir.path().join("config/nono/packages/acme").join(name);
        for (original, installed, bytes) in [
            (
                "package.json".to_owned(),
                "package.json".to_owned(),
                serde_json::to_vec(&manifest).expect("JSON"),
            ),
            (
                "policy.json".to_owned(),
                format!("profiles/{name}.json"),
                serde_json::to_vec(&profile).expect("JSON"),
            ),
            (
                "bin/hook.sh".to_owned(),
                "bin/hook.sh".to_owned(),
                b"#!/bin/sh\nexit 99\n".to_vec(),
            ),
            (
                "skills/review/SKILL.md".to_owned(),
                "skills/review/SKILL.md".to_owned(),
                b"# Review\nKeep this exactly.\n".to_vec(),
            ),
            (
                "bundle.sig".to_owned(),
                "bundle.sig".to_owned(),
                b"{\"upstream\":\"preserve unchanged\"}\n".to_vec(),
            ),
            (
                ".nono-trust.bundle".to_owned(),
                ".nono-trust.bundle".to_owned(),
                b"[]\n".to_vec(),
            ),
            (
                "extra/opaque.bin".to_owned(),
                "extra/opaque.bin".to_owned(),
                vec![0, 255, 1, 128],
            ),
            (
                "README.md".to_owned(),
                "README.md".to_owned(),
                b"Undeclared supporting file.\n".to_vec(),
            ),
        ] {
            let path = pack.join(installed);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("directories");
            std::fs::write(path, &bytes).expect("pack file");
            expected.insert(format!("packs/acme/{name}/{original}"), bytes);
        }
    }
    std::fs::create_dir_all(dir.path().join("home")).expect("home");
    std::fs::write(
        dir.path().join("policy.json"),
        json!({
            "meta":{"name":"managed"},"extends":["acme/agent","acme/agent"],"packs":["acme/agent"],
            "platform_overrides":{"linux":{"packs":["acme/base"]}}
        })
        .to_string(),
    )
    .expect("root");
    (dir, expected)
}

fn export_complete_pack(dir: &std::path::Path) -> std::process::Output {
    nono_bin()
        .env("HOME", dir.join("home"))
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .args(["profile", "show"])
        .arg(dir.join("policy.json"))
        .args(["--format", "bundle"])
        .output()
        .expect("export")
}

#[test]
fn bundle_export_preserves_complete_transitive_packs_without_activating_them() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use sha2::{Digest, Sha256};
    let (dir, expected) = complete_pack_fixture();
    let output = export_complete_pack(dir.path());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let export: serde_json::Value = serde_json::from_slice(&output.stdout).expect("export");
    for (path, bytes) in &expected {
        assert_eq!(
            STANDARD
                .decode(export["files"][path].as_str().expect(path))
                .expect("base64"),
            *bytes,
            "{path}"
        );
    }
    assert_eq!(
        export["files"].as_object().expect("files").len(),
        expected.len() + 4
    );
    for subject in export["statement"]["subject"].as_array().expect("subjects") {
        let bytes = STANDARD
            .decode(
                export["files"][subject["name"].as_str().expect("name")]
                    .as_str()
                    .expect("file"),
            )
            .expect("base64");
        assert_eq!(
            subject["digest"]["sha256"],
            Sha256::digest(&bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        assert_eq!(subject["annotations"]["size"], bytes.len().to_string());
    }
    let policy: serde_json::Value = serde_json::from_slice(
        &STANDARD
            .decode(export["files"]["policy.json"].as_str().expect("policy"))
            .expect("base64"),
    )
    .expect("JSON");
    assert!(policy.get("packs").is_none());
    assert!(policy["platform_overrides"]["linux"].get("packs").is_none());
    assert_eq!(
        policy["extends"],
        serde_json::json!(["profile-0", "profile-0"])
    );
    assert!(!dir.path().join("home/SHOULD_NOT_BE_INSTALLED").exists());
    let authored: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("policy.json")).expect("authored"))
            .expect("JSON");
    assert_eq!(authored["extends"][0], "acme/agent");
}

#[test]
fn bundle_export_rejects_incomplete_or_oversized_packs() {
    for oversized in [false, true] {
        let (dir, _) = complete_pack_fixture();
        let path = dir
            .path()
            .join("config/nono/packages/acme/agent/bin/hook.sh");
        if oversized {
            std::fs::write(path, vec![0; 32 * 1024 * 1024 + 1]).expect("large asset");
        } else {
            std::fs::remove_file(path).expect("missing asset");
        }
        let output = export_complete_pack(dir.path());
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(
            error.contains(if oversized {
                "size limit"
            } else {
                "declared pack artifact is missing"
            }),
            "{error}"
        );
    }
}

#[cfg(unix)]
#[test]
fn bundle_export_rejects_pack_symlinks_and_special_files() {
    for special in [false, true] {
        let (dir, _) = complete_pack_fixture();
        let path = dir
            .path()
            .join("config/nono/packages/acme/agent/unsupported");
        if special {
            let status = std::process::Command::new("mkfifo")
                .arg(&path)
                .status()
                .expect("FIFO");
            assert!(status.success());
        } else {
            std::os::unix::fs::symlink(dir.path().join("policy.json"), path).expect("symlink");
        }
        let output = export_complete_pack(dir.path());
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("must be a regular file or directory")
        );
    }
}
