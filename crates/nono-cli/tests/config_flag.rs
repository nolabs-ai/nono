//! Integration tests for `nono run --config <manifest>`.

use nono_test_support::{Argv, NonoTest, nono_test};
use std::fs;
use std::path::PathBuf;

/// Every case runs the same child; `--dry-run` never execs it.
fn echo_hello() -> Argv {
    Argv::new("echo").arg("hello")
}

fn write_manifest(t: &NonoTest, name: &str, json: &str) -> PathBuf {
    let path = t.root().join(name);
    fs::write(&path, json).expect("root is a fresh dir this test owns");
    path
}

#[test]
fn config_with_valid_manifest_is_accepted() {
    let t = nono_test!("config-valid");
    let manifest = write_manifest(
        &t,
        "valid.json",
        r#"{
            "version": "0.1.0",
            "filesystem": {
                "grants": [{ "path": "/tmp", "access": "read" }]
            },
            "network": { "mode": "blocked" }
        }"#,
    );

    t.run()
        .config(&manifest)
        .dry_run()
        .exec(echo_hello())
        .assert_success("--dry-run reports a valid manifest and exits 0");
}

#[test]
fn config_with_invalid_json_fails() {
    let t = nono_test!("config-invalid-json");
    let manifest = write_manifest(&t, "invalid.json", "not json at all");

    let completed = t
        .run()
        .config(&manifest)
        .dry_run()
        .exec(echo_hello())
        .assert_failure("a manifest that is not JSON is rejected");

    let stderr = completed.stderr();
    assert!(
        stderr.contains("invalid") || stderr.contains("error"),
        "expected error message, got: {stderr}"
    );
}

#[test]
fn config_with_missing_version_fails() {
    let t = nono_test!("config-missing-version");
    let manifest = write_manifest(&t, "missing-version.json", r#"{ "filesystem": { } }"#);

    t.run()
        .config(&manifest)
        .dry_run()
        .exec(echo_hello())
        .assert_failure("a manifest without a version is rejected");
}

#[test]
fn config_conflicts_with_allow() {
    let t = nono_test!("config-vs-allow");
    let manifest = write_manifest(&t, "conflict-allow.json", r#"{ "version": "0.1.0" }"#);

    t.run()
        .config(&manifest)
        .allow("/tmp")
        .dry_run()
        .exec(echo_hello())
        .assert_failure("--config conflicts with --allow")
        .assert_stderr_contains("cannot be used with");
}

#[test]
fn config_conflicts_with_profile() {
    let t = nono_test!("config-vs-profile");
    let manifest = write_manifest(&t, "conflict-profile.json", r#"{ "version": "0.1.0" }"#);

    t.run()
        .config(&manifest)
        .profile_name("default")
        .dry_run()
        .exec(echo_hello())
        .assert_failure("--config conflicts with --profile")
        .assert_stderr_contains("cannot be used with");
}

#[test]
fn config_nonexistent_file_fails() {
    let t = nono_test!("config-missing-file");

    t.run()
        .config(t.root().join("does-not-exist.json"))
        .dry_run()
        .exec(echo_hello())
        .assert_failure("a manifest path that does not exist is rejected");
}

#[test]
fn config_semantic_validation_rejects_bad_inject() {
    let t = nono_test!("config-bad-inject");
    let manifest = write_manifest(
        &t,
        "bad-inject.json",
        r#"{
            "version": "0.1.0",
            "credentials": [{
                "name": "test",
                "source": "env://TOKEN",
                "upstream": "https://api.example.com",
                "inject": { "mode": "url_path" }
            }]
        }"#,
    );

    let completed = t
        .run()
        .config(&manifest)
        .dry_run()
        .exec(echo_hello())
        .assert_failure("url_path inject without path_pattern is rejected");

    let stderr = completed.stderr();
    assert!(
        stderr.contains("url_path") || stderr.contains("path_pattern"),
        "expected validation error about url_path, got: {stderr}"
    );
}
