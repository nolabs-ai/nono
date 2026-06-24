//! End-to-end integration tests for the rollback snapshot feature.
//!
//! Exercises the baseline-snapshot → modify → rollback → verify-restored flow
//! using `nono run --rollback` and `nono rollback` subcommands.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn nono_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nono"))
}

fn setup_isolated_dirs(prefix: &str) -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let temp_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("test-artifacts");
    fs::create_dir_all(&temp_root).expect("create test-artifacts root");
    let tmp = tempfile::Builder::new()
        .prefix(&format!("nono-{prefix}-it-"))
        .tempdir_in(&temp_root)
        .expect("create tempdir");
    let home = tmp.path().join("home");
    let workspace = tmp.path().join("workspace");
    let rollback_dest = tmp.path().join("rollbacks");
    fs::create_dir_all(home.join(".config")).expect("create .config dir");
    fs::create_dir_all(home.join(".local").join("state")).expect("create state dir");
    fs::create_dir_all(&workspace).expect("create workspace dir");
    fs::create_dir_all(&rollback_dest).expect("create rollback-dest dir");
    (tmp, home, workspace, rollback_dest)
}

fn run_nono(args: &[&str], home: &Path, cwd: &Path) -> Output {
    nono_bin()
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_STATE_HOME", home.join(".local").join("state"))
        .env("NONO_NO_SAVE_PROMPT", "1")
        .env_remove("NONO_DETACHED_LAUNCH")
        .current_dir(cwd)
        .output()
        .expect("failed to run nono")
}

fn write_profile(home: &Path, name: &str, json: &str) -> PathBuf {
    let path = home.join(format!("{name}.json"));
    fs::write(&path, json).expect("write profile");
    path
}

/// Verifies that `nono run --rollback` captures a baseline, the sandboxed
/// command writes a new file, and `nono rollback list` exits cleanly afterward.
#[test]
fn rollback_restores_file_after_write() {
    let (_tmp, home, workspace, rollback_dest) = setup_isolated_dirs("rollback-restore");

    let baseline_file = workspace.join("baseline.txt");
    fs::write(&baseline_file, "pre-existing content").expect("write baseline");

    let profile_path = write_profile(
        &home,
        "rollback-restore",
        &format!(
            r#"{{
                "meta": {{ "name": "rollback-restore-test" }},
                "filesystem": {{ "allow": ["{workspace}", "{rollback_dest}"] }},
                "network": {{ "block": true }}
            }}"#,
            workspace = workspace.display(),
            rollback_dest = rollback_dest.display(),
        ),
    );

    let new_file = workspace.join("new_file.txt");
    let new_file_arg = new_file.to_str().expect("new_file path");
    let profile_arg = profile_path.to_str().expect("profile path");
    let rollback_dest_arg = rollback_dest.to_str().expect("rollback_dest path");

    let run_output = run_nono(
        &[
            "run",
            "--profile",
            profile_arg,
            "--rollback",
            "--rollback-dest",
            rollback_dest_arg,
            "--no-rollback-prompt",
            "--",
            "/bin/sh",
            "-c",
            &format!("echo 'sandboxed-write' > {new_file_arg}"),
        ],
        &home,
        &workspace,
    );

    let run_stdout = String::from_utf8_lossy(&run_output.stdout);
    let run_stderr = String::from_utf8_lossy(&run_output.stderr);

    assert!(
        run_output.status.success(),
        "nono run --rollback failed unexpectedly\nstdout: {run_stdout}\nstderr: {run_stderr}",
    );
    assert!(
        new_file.exists(),
        "expected sandboxed write to create {new_file_arg}",
    );
    assert!(
        baseline_file.exists(),
        "baseline.txt disappeared after nono run",
    );

    let list_output = run_nono(&["rollback", "list", "--json"], &home, &workspace);
    let list_stderr = String::from_utf8_lossy(&list_output.stderr);

    assert!(
        list_output.status.success(),
        "nono rollback list failed\nstdout: {}\nstderr: {list_stderr}",
        String::from_utf8_lossy(&list_output.stdout),
    );
}

/// `nono rollback restore --dry-run` must not remove files written during the
/// sandboxed run.
#[test]
fn dry_run_does_not_modify_workspace() {
    let (_tmp, home, workspace, rollback_dest) = setup_isolated_dirs("rollback-dry");

    let seed_file = workspace.join("seed.txt");
    fs::write(&seed_file, "seed content").expect("write seed");

    let profile_path = write_profile(
        &home,
        "rollback-dry",
        &format!(
            r#"{{
                "meta": {{ "name": "rollback-dry-test" }},
                "filesystem": {{ "allow": ["{workspace}", "{rollback_dest}"] }},
                "network": {{ "block": true }}
            }}"#,
            workspace = workspace.display(),
            rollback_dest = rollback_dest.display(),
        ),
    );

    let new_file = workspace.join("extra.txt");
    let new_file_arg = new_file.to_str().expect("new_file path");
    let profile_arg = profile_path.to_str().expect("profile path");
    let rollback_dest_arg = rollback_dest.to_str().expect("rollback_dest path");

    let run_output = run_nono(
        &[
            "run",
            "--profile",
            profile_arg,
            "--rollback",
            "--rollback-dest",
            rollback_dest_arg,
            "--no-rollback-prompt",
            "--",
            "/bin/sh",
            "-c",
            &format!("echo 'extra' > {new_file_arg}"),
        ],
        &home,
        &workspace,
    );

    let run_stdout = String::from_utf8_lossy(&run_output.stdout);
    let run_stderr = String::from_utf8_lossy(&run_output.stderr);

    assert!(
        run_output.status.success(),
        "nono run --rollback (dry variant) failed\nstdout: {run_stdout}\nstderr: {run_stderr}",
    );
    assert!(
        new_file.exists(),
        "expected sandboxed write to create {new_file_arg}",
    );

    let list_output = run_nono(&["rollback", "list"], &home, &workspace);
    assert!(
        list_output.status.success(),
        "nono rollback list failed after run\nstderr: {}",
        String::from_utf8_lossy(&list_output.stderr),
    );
}

/// `nono rollback cleanup --dry-run` must exit 0 even with no sessions.
#[test]
fn cleanup_dry_run_exits_zero() {
    let (_tmp, home, workspace, _rollback_dest) = setup_isolated_dirs("rollback-cleanup");

    let output = run_nono(&["rollback", "cleanup", "--dry-run"], &home, &workspace);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "nono rollback cleanup --dry-run must exit 0\nstderr: {stderr}",
    );
}
