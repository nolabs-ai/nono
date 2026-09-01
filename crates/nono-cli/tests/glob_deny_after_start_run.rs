//! Kernel-enforcement tests for `filesystem.deny` glob patterns on macOS: a
//! file matching a deny-glob must stay denied even when created, deleted, or
//! recreated after the sandbox starts. Unlike the string-level unit tests in
//! `policy.rs`, these run a real `sandbox_init()` via the `nono` binary — see
//! https://github.com/nolabs-ai/nono/issues/1763.

#![cfg(target_os = "macos")]

use nono_test_support::{Argv, NonoTest, Profile, nono_test};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

/// Delay before the late write, must clear `nono`'s own startup or the file
/// would exist at policy-load time and get caught by a literal deny instead.
const WRITE_DELAY: Duration = Duration::from_secs(2);
/// How long the sandboxed child waits before reading.
const READ_DELAY_SECS: u64 = 3;

/// Serializes tests so concurrent CPU contention can't push `nono` startup
/// past `WRITE_DELAY` and cause a flaky false result.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial_guard() -> std::sync::MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn write_deny_glob_profile(t: &NonoTest, name: &str, deny_pattern: &str) -> Profile {
    let workspace = t.workspace().to_path_buf();
    t.write_profile(
        name,
        &format!(
            r#"{{
            "meta": {{ "name": "{name}" }},
            "workdir": {{ "access": "readwrite" }},
            "filesystem": {{
                "allow": ["{workspace}"],
                "deny": ["{deny_pattern}"]
            }}
        }}"#,
            workspace = workspace.display(),
        ),
    )
}

/// Writes `SECRET\n` to `secret_path` after `WRITE_DELAY`, then `cat`s it in
/// the sandbox and asserts the read is denied.
fn assert_deny_glob_blocks_read_after_start(t: &NonoTest, profile: &Profile, secret_path: &Path) {
    let write_path = secret_path.to_path_buf();
    thread::spawn(move || {
        thread::sleep(WRITE_DELAY);
        if let Some(parent) = write_path.parent() {
            fs::create_dir_all(parent).expect("create parent dirs for late write");
        }
        fs::write(&write_path, "SECRET\n").expect("write secret after sandbox start");
    });

    t.run()
        .profile(profile)
        .exec(Argv::new("/bin/sh").arg("-c").arg(format!(
            "sleep {READ_DELAY_SECS}; cat {}",
            secret_path.display()
        )))
        .assert_failure("deny glob must cover a file created after sandbox start")
        .assert_stdout_lacks("SECRET");
}

#[test]
fn double_star_prefix_blocks_file_created_after_start() {
    let _guard = serial_guard();
    let t = nono_test!("glob-deny-prefix");
    let workspace = t.workspace().to_path_buf();
    fs::create_dir_all(workspace.join("deep")).expect("create deep dir");
    let secret_path = workspace.join("deep").join(".env");

    let profile = write_deny_glob_profile(
        &t,
        "glob-deny-prefix",
        &format!("{}/**/.env", workspace.display()),
    );
    assert_deny_glob_blocks_read_after_start(&t, &profile, &secret_path);
}

#[test]
fn mid_pattern_double_star_blocks_file_created_after_start() {
    let _guard = serial_guard();
    let t = nono_test!("glob-deny-mid");
    let workspace = t.workspace().to_path_buf();
    fs::create_dir_all(workspace.join("a").join("b")).expect("create nested dir");
    let secret_path = workspace.join("a").join("b").join("secret.log");

    let profile = write_deny_glob_profile(
        &t,
        "glob-deny-mid",
        &format!("{}/a/**/secret.log", workspace.display()),
    );
    assert_deny_glob_blocks_read_after_start(&t, &profile, &secret_path);
}

#[test]
fn single_star_within_segment_blocks_file_created_after_start() {
    let _guard = serial_guard();
    let t = nono_test!("glob-deny-star");
    let workspace = t.workspace().to_path_buf();
    fs::create_dir_all(workspace.join("logs")).expect("create logs dir");
    let secret_path = workspace.join("logs").join("token.secret");

    let profile = write_deny_glob_profile(
        &t,
        "glob-deny-star",
        &format!("{}/logs/*.secret", workspace.display()),
    );
    assert_deny_glob_blocks_read_after_start(&t, &profile, &secret_path);
}

#[test]
fn trailing_double_star_blocks_file_created_after_start() {
    let _guard = serial_guard();
    let t = nono_test!("glob-deny-trailing");
    let workspace = t.workspace().to_path_buf();
    fs::create_dir_all(workspace.join("private").join("nested")).expect("create private dir");
    let secret_path = workspace.join("private").join("nested").join("leak.txt");

    let profile = write_deny_glob_profile(
        &t,
        "glob-deny-trailing",
        &format!("{}/private/**", workspace.display()),
    );
    assert_deny_glob_blocks_read_after_start(&t, &profile, &secret_path);
}

/// Deny globs must also block writes, not just reads.
#[test]
fn double_star_prefix_blocks_write_after_start() {
    let _guard = serial_guard();
    let t = nono_test!("glob-deny-write-after-start");
    let workspace = t.workspace().to_path_buf();
    fs::create_dir_all(workspace.join("deep")).expect("create deep dir");
    let target = workspace.join("deep").join(".env");

    let profile = write_deny_glob_profile(
        &t,
        "glob-deny-write",
        &format!("{}/**/.env", workspace.display()),
    );

    t.run()
        .profile(&profile)
        .exec(
            Argv::new("/bin/sh")
                .arg("-c")
                .arg(format!("echo pwned > {}", target.display())),
        )
        .assert_failure("a **-glob deny must block writes to a newly created matching path");

    assert!(
        !target.exists(),
        "deny glob must prevent the file from being created at all"
    );
}

/// A file deleted and recreated under the same name must stay denied —
/// isolates the regex-based deny from the literal-expansion deny, which
/// stops applying once the original match is gone.
#[test]
fn deleted_and_recreated_file_stays_denied() {
    let _guard = serial_guard();
    let t = nono_test!("glob-deny-delete-recreate");
    let workspace = t.workspace().to_path_buf();
    let deep_dir = workspace.join("deep");
    fs::create_dir_all(&deep_dir).expect("create deep dir");
    let secret_path: PathBuf = deep_dir.join(".env");
    fs::write(&secret_path, "ORIGINAL\n").expect("write original secret");

    let profile = write_deny_glob_profile(
        &t,
        "glob-deny-delete-recreate",
        &format!("{}/**/.env", workspace.display()),
    );

    fs::remove_file(&secret_path).expect("delete original secret");
    let write_path = secret_path.clone();
    thread::spawn(move || {
        thread::sleep(WRITE_DELAY);
        fs::write(&write_path, "RECREATED\n").expect("recreate secret after sandbox start");
    });

    t.run()
        .profile(&profile)
        .exec(Argv::new("/bin/sh").arg("-c").arg(format!(
            "sleep {READ_DELAY_SECS}; cat {}",
            secret_path.display()
        )))
        .assert_failure("a deleted-and-recreated file must still be covered by the deny glob")
        .assert_stdout_lacks("RECREATED");
}

/// Not a bug: `filesystem.allow` globs are a load-time snapshot with no
/// regex-based runtime rule, unlike `filesystem.deny`. A file matching an
/// allow-glob but created after sandbox start must NOT be granted.
#[test]
fn allow_glob_does_not_cover_file_created_after_start() {
    let _guard = serial_guard();
    let t = nono_test!("glob-allow-after-start");
    let workspace = t.workspace().to_path_buf();
    let data_dir = workspace.join("data");
    fs::create_dir_all(&data_dir).expect("create data dir");
    let late_path = data_dir.join("late.json");

    let profile = t.write_profile(
        "glob-allow-after-start",
        &format!(
            r#"{{
            "meta": {{ "name": "glob-allow-after-start" }},
            "workdir": {{ "access": "readwrite" }},
            "filesystem": {{
                "allow": ["{workspace}/data/*.json"]
            }}
        }}"#,
            workspace = workspace.display()
        ),
    );

    let write_path = late_path.clone();
    thread::spawn(move || {
        thread::sleep(WRITE_DELAY);
        fs::write(&write_path, "{}").expect("write file after sandbox start");
    });

    t.run()
        .profile(&profile)
        .exec(Argv::new("/bin/sh").arg("-c").arg(format!(
            "sleep {READ_DELAY_SECS}; cat {}",
            late_path.display()
        )))
        .assert_failure(
            "an allow-glob snapshot at policy load must not cover a file created afterward",
        );
}
