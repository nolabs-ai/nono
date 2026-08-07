//! Integration tests for behaviour under a corrupt global audit ledger.
//!
//! Regression test for #1583: an unparseable audit ledger used to abort finalization outright, so
//! the audit delivery and rollback review after the append were skipped and a failing child's own
//! exit status was replaced. The gap in the chain is still fail-closed — a clean run is downgraded
//! to `1` — but only after the rest of the bookkeeping has run.

use nono_test_support::{Argv, nono_test};
use std::fs;
use std::path::Path;

/// Corrupt the ledger by dropping the newline between the last two records so one line holds two
/// JSON objects and `serde_json` fails with "trailing characters".
fn corrupt_last_newline(path: &Path) {
    let contents =
        fs::read_to_string(path).expect("callers only corrupt a ledger nono has already written");
    // Only a trailing blank is dropped: filtering every empty line would silently repair unrelated
    // damage, so the fixture could no longer claim the joined records are the sole corruption.
    let mut lines: Vec<&str> = contents.lines().collect();
    if lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    assert!(!lines.is_empty(), "ledger should have at least one record");
    assert!(
        lines.iter().all(|l| !l.is_empty()),
        "ledger should hold one record per line"
    );

    let mut corrupted = String::new();
    if lines.len() == 1 {
        corrupted.push_str(lines[0]);
        corrupted.push_str(lines[0]);
    } else {
        for line in &lines[..lines.len() - 2] {
            corrupted.push_str(line);
            corrupted.push('\n');
        }
        corrupted.push_str(lines[lines.len() - 2]);
        corrupted.push_str(lines[lines.len() - 1]);
    }
    corrupted.push('\n');
    fs::write(path, corrupted).expect("the ledger was just read from this same path");
}

/// A run left out of the ledger may not report success, but a child that failed on its own still
/// owns the exit status — a substituted code there would be indistinguishable from the command's.
#[test]
fn corrupt_audit_ledger_downgrades_only_a_clean_exit() {
    let t = nono_test!("audit-ledger");

    // Create the ledger.
    t.run()
        .allow_cwd()
        .exec("/bin/pwd")
        .assert_success("seed run should succeed");

    let ledger = t.audit_root().join("ledger.ndjson");
    assert!(ledger.exists(), "ledger should exist after a run");
    corrupt_last_newline(&ledger);

    t.run()
        .allow_cwd()
        .exec("/bin/pwd")
        .assert_exit_code(1, "an unrecorded run must not exit 0");

    t.run()
        .allow_cwd()
        .exec(Argv::new("/bin/sh").arg("-c").arg("exit 7"))
        .assert_exit_code(7, "the child's own code must survive a corrupt ledger");
}

#[test]
fn corrupt_audit_ledger_is_reported_on_every_run_and_left_untouched() {
    let t = nono_test!("audit-ledger-report");

    t.run()
        .allow_cwd()
        .exec("/bin/pwd")
        .assert_success("seed run should succeed");

    let ledger = t.audit_root().join("ledger.ndjson");
    corrupt_last_newline(&ledger);
    let corrupt_bytes = fs::read(&ledger).expect("corrupt_last_newline just wrote this file");

    for attempt in 1..=2 {
        t.run()
            .allow_cwd()
            .exec("/bin/pwd")
            .assert_stderr_contains("not recorded in the audit ledger")
            // Printed only for a ledger that no longer parses, so it also pins that the permanent
            // story is not told for a transient append failure.
            .assert_stderr_contains("The tamper-evident chain has stopped growing");
        assert_eq!(
            fs::read(&ledger).expect("a run must never remove the ledger it could not parse"),
            corrupt_bytes,
            "run {attempt} must not rewrite the ledger it could not parse"
        );
    }
}
