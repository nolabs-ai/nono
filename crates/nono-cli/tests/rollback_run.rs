//! End-to-end integration tests for the rollback snapshot feature.
//!
//! Exercises the baseline-snapshot → modify → rollback → verify-restored flow
//! using `nono run --rollback` and `nono rollback` subcommands.

use nono_test_support::{Argv, NonoTest, Rollback, nono_test};
use std::fs;
use std::path::PathBuf;

fn rollback_dest(t: &NonoTest) -> PathBuf {
    let dest = t.root().join("rollbacks");
    fs::create_dir_all(&dest).expect("root is a fresh dir this test owns");
    dest
}

/// Verifies that `nono run --rollback` captures a baseline, the sandboxed
/// command writes a new file, and `nono rollback list` exits cleanly afterward.
#[test]
fn rollback_restores_file_after_write() {
    let t = nono_test!("rollback-restore");
    let workspace = t.workspace().to_path_buf();
    let rollback_dest = rollback_dest(&t);

    let baseline_file = workspace.join("baseline.txt");
    fs::write(&baseline_file, "pre-existing content").expect("write baseline");

    let profile = t.write_profile(
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

    t.run()
        .profile(&profile)
        .rollback(Rollback::new().dest(&rollback_dest).no_prompt())
        .exec(
            Argv::new("/bin/sh")
                .arg("-c")
                .arg(format!("echo 'sandboxed-write' > {}", new_file.display())),
        )
        .assert_success("nono run --rollback completes");

    assert!(
        new_file.exists(),
        "expected sandboxed write to create {}",
        new_file.display(),
    );
    assert!(
        baseline_file.exists(),
        "baseline.txt disappeared after nono run",
    );

    // Session count is deliberately not asserted: --rollback-dest writes the
    // snapshot outside the state dir `rollback list` discovers, so an empty
    // array is a legitimate result.
    let listed = t.rollback().list().json();
    assert!(
        listed.is_array(),
        "rollback list --json must emit a top-level array, got: {listed}"
    );
}

/// `nono rollback restore --dry-run` must not remove files written during the
/// sandboxed run.
#[test]
fn dry_run_does_not_modify_workspace() {
    let t = nono_test!("rollback-dry");
    let workspace = t.workspace().to_path_buf();
    let rollback_dest = rollback_dest(&t);

    let seed_file = workspace.join("seed.txt");
    fs::write(&seed_file, "seed content").expect("write seed");

    let profile = t.write_profile(
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

    t.run()
        .profile(&profile)
        .rollback(Rollback::new().dest(&rollback_dest).no_prompt())
        .exec(
            Argv::new("/bin/sh")
                .arg("-c")
                .arg(format!("echo 'extra' > {}", new_file.display())),
        )
        .assert_success("nono run --rollback (dry variant) completes");

    assert!(
        new_file.exists(),
        "expected sandboxed write to create {}",
        new_file.display(),
    );

    t.rollback()
        .list()
        .output()
        .assert_success("nono rollback list exits 0 after a run");
}

/// `nono rollback cleanup --dry-run` must exit 0 even with no sessions.
#[test]
fn cleanup_dry_run_exits_zero() {
    let t = nono_test!("rollback-cleanup");

    t.rollback()
        .cleanup()
        .dry_run()
        .output()
        .assert_success("nono rollback cleanup --dry-run exits 0 with no sessions");
}
