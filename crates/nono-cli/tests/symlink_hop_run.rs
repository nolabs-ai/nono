//! Kernel-level coverage: a multi-hop symlink grant must resolve under
//! the real Seatbelt sandbox.

#![cfg(target_os = "macos")]

use nono_test_support::{Argv, nono_test};
use std::fs;

/// `.gitconfig -> hosts/current/gitconfig -> hosts/mymac/gitconfig`, with
/// `hosts/current -> hosts/mymac` a symlinked directory component.
fn write_fixture(workspace: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let hosts = workspace.join("hosts");
    let mymac = hosts.join("mymac");
    fs::create_dir_all(&mymac).expect("create hosts/mymac");
    fs::write(mymac.join("gitconfig"), "trusted\n").expect("write real gitconfig");
    fs::write(mymac.join("secret.txt"), "topsecret\n").expect("write sibling secret");

    let current = hosts.join("current");
    std::os::unix::fs::symlink(&mymac, &current).expect("symlink hosts/current -> hosts/mymac");

    let gitconfig_link = workspace.join(".gitconfig");
    std::os::unix::fs::symlink(current.join("gitconfig"), &gitconfig_link)
        .expect("symlink .gitconfig -> hosts/current/gitconfig");

    (gitconfig_link, mymac.join("secret.txt"))
}

#[test]
fn multi_hop_symlinked_leaf_resolves_through_symlinked_directory() {
    let t = nono_test!("symlink-hop-positive");
    let workspace = t.workspace().to_path_buf();
    let (gitconfig_link, _secret) = write_fixture(&workspace);

    let profile = t.write_profile(
        "symlink-hop-positive",
        &format!(
            r#"{{"meta":{{"name":"t"}},"workdir":{{"access":"readwrite"}},"filesystem":{{"read":["{}"]}}}}"#,
            gitconfig_link.display()
        ),
    );

    t.run()
        .profile(&profile)
        .exec(Argv::new("/bin/cat").arg(&gitconfig_link))
        .assert_stdout_contains("trusted");
}

#[test]
fn multi_hop_symlinked_leaf_does_not_widen_access_to_sibling_in_traversed_directory() {
    let t = nono_test!("symlink-hop-negative");
    let workspace = t.workspace().to_path_buf();
    let (gitconfig_link, secret) = write_fixture(&workspace);

    let profile = t.write_profile(
        "symlink-hop-negative",
        &format!(
            r#"{{"meta":{{"name":"t"}},"workdir":{{"access":"readwrite"}},"filesystem":{{"read":["{}"]}}}}"#,
            gitconfig_link.display()
        ),
    );

    t.run()
        .profile(&profile)
        .exec(Argv::new("/bin/cat").arg(&secret))
        .assert_failure(
            "granting a multi-hop symlink must not expose sibling files under the traversed directory",
        );
}
