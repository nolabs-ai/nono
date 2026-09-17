//! Kernel-level coverage for issue #1932: a filesystem grant alone must not
//! negate the `deny_keychains_macos` deny that covers `~/Library/Keychains`.
//!
//! Every case runs against the harness's throwaway `$HOME`, never the real
//! user keychain — the fixture writes a plain file at the login keychain path
//! and asserts only on whether the sandbox lets that file be read or written.

#![cfg(target_os = "macos")]

use nono_test_support::{Argv, NonoTest, nono_test};
use std::fs;
use std::path::{Path, PathBuf};

const CONTENT: &str = "keychain-fixture\n";

fn fake_login_keychain(t: &NonoTest) -> PathBuf {
    let keychains = t.home().join("Library/Keychains");
    fs::create_dir_all(&keychains).expect("create fake keychain dir");
    let db = keychains.join("login.keychain-db");
    fs::write(&db, CONTENT).expect("write fake keychain db");
    db
}

/// `grant` is the `filesystem` key under test (`allow_file`, `read_file`,
/// `write_file`); `bypass` adds the matching `filesystem.bypass_protection`.
fn profile_json(db: &Path, grant: &str, bypass: bool) -> String {
    let bypass_entry = if bypass {
        format!(r#","bypass_protection":["{}"]"#, db.display())
    } else {
        String::new()
    };
    format!(
        r#"{{"meta":{{"name":"t"}},"workdir":{{"access":"readwrite"}},
           "filesystem":{{"{grant}":["{db}"]{bypass_entry}}}}}"#,
        db = db.display()
    )
}

fn read_argv(db: &Path) -> Argv {
    Argv::new("/bin/cat").arg(db)
}

fn write_argv(db: &Path) -> Argv {
    Argv::new("/bin/sh")
        .arg("-c")
        .arg(format!("echo rewritten > {}", db.display()))
}

#[test]
fn why_reports_keychain_grant_denied_without_bypass() {
    let t = nono_test!("keychain-why-no-bypass");
    let db = fake_login_keychain(&t);
    let profile = t.write_profile("kc", &profile_json(&db, "read_file", false));

    let output = t.why("read", &db).profile(&profile).output();

    output.assert_stdout_contains("DENIED");
}

#[test]
fn why_reports_keychain_grant_allowed_with_bypass() {
    let t = nono_test!("keychain-why-bypass");
    let db = fake_login_keychain(&t);
    let profile = t.write_profile("kc", &profile_json(&db, "read_file", true));

    let output = t.why("read", &db).profile(&profile).output();

    output.assert_stdout_contains("ALLOWED");
}

#[test]
fn read_file_grant_cannot_read_keychain_without_bypass() {
    let t = nono_test!("keychain-read-no-bypass");
    let db = fake_login_keychain(&t);
    let profile = t.write_profile("kc", &profile_json(&db, "read_file", false));

    t.run()
        .profile(&profile)
        .exec(read_argv(&db))
        .assert_failure("read_file alone must not defeat the keychain deny");
}

#[test]
fn read_file_grant_reads_keychain_with_bypass() {
    let t = nono_test!("keychain-read-bypass");
    let db = fake_login_keychain(&t);
    let profile = t.write_profile("kc", &profile_json(&db, "read_file", true));

    t.run()
        .profile(&profile)
        .exec(read_argv(&db))
        .assert_stdout_contains(CONTENT.trim());

    t.run()
        .profile(&profile)
        .exec(write_argv(&db))
        .assert_failure("a bypassed read grant must stay read-only");
}

#[test]
fn write_file_grant_cannot_write_keychain_without_bypass() {
    let t = nono_test!("keychain-write-no-bypass");
    let db = fake_login_keychain(&t);
    let profile = t.write_profile("kc", &profile_json(&db, "write_file", false));

    t.run()
        .profile(&profile)
        .exec(write_argv(&db))
        .assert_failure("write_file alone must not defeat the keychain deny");
    assert_eq!(
        fs::read_to_string(&db).expect("read back"),
        CONTENT,
        "the denied write must not have landed"
    );
}

#[test]
fn write_file_grant_writes_keychain_with_bypass() {
    let t = nono_test!("keychain-write-bypass");
    let db = fake_login_keychain(&t);
    let profile = t.write_profile("kc", &profile_json(&db, "write_file", true));

    t.run()
        .profile(&profile)
        .exec(write_argv(&db))
        .assert_success("a bypassed write grant must grant write");
    assert_eq!(fs::read_to_string(&db).expect("read back"), "rewritten\n");

    t.run()
        .profile(&profile)
        .exec(read_argv(&db))
        .assert_failure("a bypassed write grant must stay write-only");
}

#[test]
fn allow_file_grant_cannot_access_keychain_without_bypass() {
    let t = nono_test!("keychain-allow-no-bypass");
    let db = fake_login_keychain(&t);
    let profile = t.write_profile("kc", &profile_json(&db, "allow_file", false));

    t.run()
        .profile(&profile)
        .exec(read_argv(&db))
        .assert_failure("allow_file alone must not defeat the keychain deny");
    t.run()
        .profile(&profile)
        .exec(write_argv(&db))
        .assert_failure("allow_file alone must not defeat the keychain deny");
}

#[test]
fn allow_file_grant_reads_and_writes_keychain_with_bypass() {
    let t = nono_test!("keychain-allow-bypass");
    let db = fake_login_keychain(&t);
    let profile = t.write_profile("kc", &profile_json(&db, "allow_file", true));

    t.run()
        .profile(&profile)
        .exec(read_argv(&db))
        .assert_stdout_contains(CONTENT.trim());
    t.run()
        .profile(&profile)
        .exec(write_argv(&db))
        .assert_success("a bypassed read+write grant must grant write");
}
