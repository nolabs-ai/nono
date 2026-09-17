//! Mediated filesystem grants must respect the session's keychain restrictions.
#![cfg(target_os = "macos")]

use nono_test_support::{Argv, nono_test};
use serde_json::json;
use std::fs;

#[test]
fn mediated_keychain_filesystem_access_respects_outer_bypasses() {
    let t = nono_test!("mediated-keychain");
    let keychains = t.home().join("Library/Keychains");
    fs::create_dir_all(&keychains).expect("synthetic keychains");
    let db = keychains.join("login.keychain-db");
    let sibling = keychains.join("metadata.keychain-db");
    let alias = t.home().join("keychain-alias");
    std::os::unix::fs::symlink(&db, &alias).expect("alias");
    let unrelated = t.home().join("delegated-credential");
    fs::write(&unrelated, "synthetic\n").expect("unrelated credential");

    // All commands ask for read/write access. Only the outer bypass varies.
    // Include directory grants, a symlink alias, and an unrelated delegated file.
    for (index, mode, directory, via_alias) in [
        (0, None, false, false),
        (1, None, true, false),
        (2, None, false, true),
        (3, Some("read_file"), false, false),
        (4, Some("allow_file"), false, false),
        (5, Some("read_file"), true, true),
        (6, Some("write_file"), false, false),
        (7, Some("read_file"), true, false),
    ] {
        fs::write(&db, "synthetic\n").expect("db");
        fs::write(&sibling, "synthetic\n").expect("sibling");
        let mut filesystem = json!({"deny": [keychains, unrelated]});
        if let Some(mode) = mode {
            filesystem[mode] = json!([db]);
            filesystem["bypass_protection"] = json!([db]);
        }
        let mut command_grants = if directory {
            json!({"fs_write": [keychains], "fs_read_file": [unrelated]})
        } else {
            json!({"fs_write_file": [if via_alias { &alias } else { &db }, sibling],
                "fs_read_file": [unrelated]})
        };
        if directory && via_alias {
            // The alias is outside the directory grant. Seatbelt needs an
            // explicit grant for that path as well as its keychain target.
            command_grants["fs_write_file"] = json!([alias]);
        }
        let profile = t.write_profile(
            &format!("keychain-{index}"),
            &json!({
                "meta": {"name": "keychain-test"},
                "workdir": {"access": "read"},
                "filesystem": filesystem,
                "command_policies": {"commands": {"sh": {
                    "executable": "/bin/sh", "sandbox": command_grants
                }}}
            })
            .to_string(),
        );
        let result = t.run().profile(&profile).allow_cwd().no_rollback().exec(
            Argv::new("sh").arg("-c").arg(r#"
                if IFS= read -r value < "$1"; then echo READ_ALLOWED; else echo READ_DENIED; fi
                if (printf 'changed\n' > "$1"); then echo WRITE_ALLOWED; else echo WRITE_DENIED; fi
                if IFS= read -r value < "$2"; then echo SIBLING_ALLOWED; else echo SIBLING_DENIED; fi
                if IFS= read -r value < "$3"; then echo DELEGATED_ALLOWED; else echo DELEGATED_DENIED; fi
            "#).arg("probe").arg(if via_alias { &alias } else { &db }).arg(&sibling).arg(&unrelated),
        );
        result
            .assert_success("synthetic keychain probe ran inside mediated child")
            .assert_stdout_contains(if matches!(mode, Some("read_file" | "allow_file")) {
                "READ_ALLOWED"
            } else {
                "READ_DENIED"
            })
            .assert_stdout_contains(if matches!(mode, Some("write_file" | "allow_file")) {
                "WRITE_ALLOWED"
            } else {
                "WRITE_DENIED"
            })
            .assert_stdout_contains("SIBLING_DENIED")
            .assert_stdout_contains("DELEGATED_ALLOWED");
        assert_eq!(
            fs::read_to_string(&db).expect("db contents"),
            if matches!(mode, Some("write_file" | "allow_file")) {
                "changed\n"
            } else {
                "synthetic\n"
            }
        );
    }
}
