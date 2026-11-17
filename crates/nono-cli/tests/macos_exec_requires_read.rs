//! On macOS, `process-exec*` is scoped to the read set: a binary that is not
//! readable fails immediately with EPERM instead of dying obscurely at startup.

#![cfg(target_os = "macos")]

use nono_test_support::{Argv, NonoTest, Profile, nono_test};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn profile_with_reads(t: &NonoTest, name: &str, reads: &[&PathBuf]) -> Profile {
    let reads: Vec<String> = reads
        .iter()
        .map(|p| format!("\"{}\"", p.display()))
        .collect();
    t.write_profile(
        name,
        &format!(
            r#"{{
                "meta": {{ "name": "{name}-test" }},
                "filesystem": {{ "allow": ["{workspace}"], "read": [{reads}] }}
            }}"#,
            workspace = t.workspace().display(),
            reads = reads.join(",")
        ),
    )
}

fn workspace_only_profile(t: &NonoTest, name: &str) -> Profile {
    profile_with_reads(t, name, &[])
}

/// Ad hoc signed copy of `/bin/echo` placed outside the granted workspace.
fn ungranted_binary(t: &NonoTest, dir: &str) -> PathBuf {
    let dir = t.root().join(dir);
    fs::create_dir_all(&dir).expect("create dir");
    let bin = dir.join("echo-copy");
    fs::copy("/bin/echo", &bin).expect("copy echo");
    let status = Command::new("codesign")
        .args(["-f", "-s", "-"])
        .arg(&bin)
        .output()
        .expect("run codesign");
    assert!(status.status.success(), "codesign failed");
    bin.canonicalize().expect("canonicalize")
}

#[test]
fn exec_of_unreadable_binary_fails_fast() {
    let t = nono_test!("exec-unreadable");
    let bin = ungranted_binary(&t, "ungranted");
    let profile = workspace_only_profile(&t, "exec-unreadable");

    t.run()
        .profile(&profile)
        .no_rollback()
        .exec(
            Argv::new("/bin/sh")
                .arg("-c")
                .arg(format!("{} hi", bin.display())),
        )
        .assert_failure("exec of a binary outside the read set is denied")
        .assert_stderr_contains("Operation not permitted")
        .assert_stdout_lacks("hi");
}

#[test]
fn exec_of_binary_succeeds_once_read_granted() {
    let t = nono_test!("exec-granted");
    let bin = ungranted_binary(&t, "ungranted");
    let profile = profile_with_reads(&t, "exec-granted", &[&bin]);

    t.run()
        .profile(&profile)
        .no_rollback()
        .exec(
            Argv::new("/bin/sh")
                .arg("-c")
                .arg(format!("{} hi", bin.display())),
        )
        .assert_success("a read-granted binary is executable")
        .assert_stdout_contains("hi");
}

#[test]
fn exec_of_binary_in_granted_dir_succeeds() {
    let t = nono_test!("exec-dir");
    let bin = ungranted_binary(&t, "granted-dir");
    let dir = bin.parent().expect("parent").to_path_buf();
    let profile = profile_with_reads(&t, "exec-dir", &[&dir]);

    t.run()
        .profile(&profile)
        .no_rollback()
        .exec(
            Argv::new("/bin/sh")
                .arg("-c")
                .arg(format!("{} hi", bin.display())),
        )
        .assert_success("a read-granted dir allows exec");
}

#[test]
fn default_system_tools_still_run() {
    let t = nono_test!("exec-system");
    let profile = workspace_only_profile(&t, "exec-system");

    t.run()
        .profile(&profile)
        .no_rollback()
        .exec(
            Argv::new("/bin/zsh")
                .arg("-l")
                .arg("-c")
                .arg("echo login-ok"),
        )
        .assert_success("login shell runs path_helper")
        .assert_stdout_contains("login-ok");
}
