//! Regression coverage for explicit filesystem denies in `nono why`.
//!
//! macOS Seatbelt can enforce a child deny beneath an allowed parent. The
//! query command must therefore consider deny rules before broad grants.

#![cfg(target_os = "macos")]

use std::fs;
use std::process::Command;

fn fixture() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let artifact_root = std::env::current_dir()
        .expect("cwd")
        .join("target")
        .join("test-artifacts");
    fs::create_dir_all(&artifact_root).expect("create artifact root");
    let workspace = tempfile::tempdir_in(artifact_root).expect("temp workspace");
    let blocked = workspace.path().join("blocked.txt");
    let profile = workspace.path().join("policy.json");

    fs::write(
        &profile,
        r#"{
            "filesystem": {
                "allow": ["$WORKDIR"],
                "deny": ["$WORKDIR/blocked.txt"]
            }
        }"#,
    )
    .expect("write profile");

    (workspace, blocked, profile)
}

#[test]
fn why_reports_profile_deny_before_covering_allow() {
    let (workspace, blocked, profile) = fixture();
    let output = Command::new(env!("CARGO_BIN_EXE_nono"))
        .args([
            "why",
            "--profile",
            profile.to_str().expect("profile path"),
            "--op",
            "write",
            "--path",
            blocked.to_str().expect("blocked path"),
        ])
        .current_dir(workspace.path())
        .output()
        .expect("run nono why");

    assert!(
        output.status.success(),
        "nono why failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("DENIED"), "expected denial, got:\n{stdout}");
    assert!(
        stdout.contains("Reason: filesystem_deny"),
        "expected filesystem deny reason, got:\n{stdout}"
    );
    assert!(
        stdout.contains("Policy: filesystem.deny"),
        "expected deny policy source, got:\n{stdout}"
    );
}

#[test]
fn why_self_reports_active_profile_deny_before_covering_allow() {
    let (workspace, blocked, profile) = fixture();
    let nono = env!("CARGO_BIN_EXE_nono");
    let output = Command::new(nono)
        .args([
            "wrap",
            "--silent",
            "--profile",
            profile.to_str().expect("profile path"),
            "--",
            nono,
            "why",
            "--self",
            "--op",
            "write",
            "--path",
            blocked.to_str().expect("blocked path"),
        ])
        .current_dir(workspace.path())
        .output()
        .expect("run sandboxed nono why --self");

    assert!(
        output.status.success(),
        "sandboxed nono why --self failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("DENIED"), "expected denial, got:\n{stdout}");
    assert!(
        stdout.contains("Reason: filesystem_deny"),
        "expected filesystem deny reason, got:\n{stdout}"
    );
}
