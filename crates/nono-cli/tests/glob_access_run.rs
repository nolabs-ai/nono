//! Kernel-level checks that `filesystem.read`/`write`/`bypass_protection`
//! globs match existing files correctly, with proper read/write separation.

use nono_test_support::{Argv, nono_test};
use std::fs;

#[test]
fn read_glob_grants_read_not_write() {
    let t = nono_test!("glob-read-mode");
    let workspace = t.workspace().to_path_buf();
    fs::create_dir_all(workspace.join("logs")).expect("create logs dir");
    let target = workspace.join("logs").join("app.log");
    fs::write(&target, "content\n").expect("write log");

    let profile = t.write_profile(
        "glob-read-mode",
        &format!(
            r#"{{"meta":{{"name":"t"}},"workdir":{{"access":"readwrite"}},"filesystem":{{"read":["{}/logs/*.log"]}}}}"#,
            workspace.display()
        ),
    );

    t.run()
        .profile(&profile)
        .exec(Argv::new("/bin/cat").arg(&target))
        .assert_stdout_contains("content");

    t.run()
        .profile(&profile)
        .exec(
            Argv::new("/bin/sh")
                .arg("-c")
                .arg(format!("echo x > {}", target.display())),
        )
        .assert_failure("read-only glob must not grant write");
}

#[test]
fn write_glob_grants_write_not_read() {
    let t = nono_test!("glob-write-mode");
    let workspace = t.workspace().to_path_buf();
    fs::create_dir_all(workspace.join("out")).expect("create out dir");
    let target = workspace.join("out").join("result.txt");
    fs::write(&target, "original\n").expect("write file");

    let profile = t.write_profile(
        "glob-write-mode",
        &format!(
            r#"{{"meta":{{"name":"t"}},"workdir":{{"access":"readwrite"}},"filesystem":{{"write":["{}/out/*.txt"]}}}}"#,
            workspace.display()
        ),
    );

    t.run()
        .profile(&profile)
        .exec(
            Argv::new("/bin/sh")
                .arg("-c")
                .arg(format!("echo new > {}", target.display())),
        )
        .assert_success("write-only glob must grant write");
    assert_eq!(fs::read_to_string(&target).expect("read back"), "new\n");

    t.run()
        .profile(&profile)
        .exec(Argv::new("/bin/cat").arg(&target))
        .assert_failure("write-only glob must not grant read");
}

#[test]
fn bypass_protection_glob_requires_paired_allow() {
    let t = nono_test!("glob-bypass-requires-allow");
    let workspace = t.workspace().to_path_buf();
    fs::create_dir_all(workspace.join("creds")).expect("create creds dir");
    let target = workspace.join("creds").join("service.token");
    fs::write(&target, "secret\n").expect("write token");

    let pattern = format!("{}/creds/*.token", workspace.display());

    let no_allow = t.write_profile(
        "glob-bypass-no-allow",
        &format!(
            r#"{{"meta":{{"name":"t"}},"workdir":{{"access":"readwrite"}},"filesystem":{{"deny":["{pattern}"],"bypass_protection":["{pattern}"]}}}}"#
        ),
    );
    t.run()
        .profile(&no_allow)
        .exec(Argv::new("/bin/cat").arg(&target))
        .assert_failure("bypass_protection without a paired allow must not grant access");

    let with_allow = t.write_profile(
        "glob-bypass-with-allow",
        &format!(
            r#"{{"meta":{{"name":"t"}},"workdir":{{"access":"readwrite"}},"filesystem":{{"allow":["{pattern}"],"deny":["{pattern}"],"bypass_protection":["{pattern}"]}}}}"#
        ),
    );
    t.run()
        .profile(&with_allow)
        .exec(Argv::new("/bin/cat").arg(&target))
        .assert_stdout_contains("secret");
}
