//! Regression test for the `--allow-cwd` deny-bypass on Linux.
//!
//! A profile that denies a path under the workdir must not be silently
//! neutralised when the user passes `--allow-cwd`. Before the fix,
//! `nono run --allow-cwd --profile <p> -- cat .ssh/id_rsa` would print the
//! contents of `.ssh/id_rsa` despite the profile's `add_deny_access` rule,
//! because Landlock cannot enforce a deny under an allow and the validator
//! did not see the CWD allow added after `from_profile` returned.
//!
//! After the fix, `prepare_sandbox` re-runs `validate_deny_overlaps` against
//! the full deny set (groups + profile `add_deny_access`) once CWD has been
//! merged in, so the binary fails closed instead of leaking the file.
//!
//! Linux-only: macOS Seatbelt enforces deny-within-allow natively and
//! `validate_deny_overlaps` is a no-op there.

#![cfg(target_os = "linux")]

use nono_test_support::{Argv, nono_test};
use std::fs;

#[test]
fn run_allow_cwd_with_profile_deny_under_workdir_fails_closed() {
    let t = nono_test!("deny-overlap-run");
    let workspace = t.workspace().to_path_buf();

    // Stand up a fake .ssh/id_rsa under the workspace. The profile denies it,
    // so even though `--allow-cwd` opens up the workspace, the run must abort
    // before the inner `cat` can read the file.
    let ssh_dir = workspace.join(".ssh");
    fs::create_dir_all(&ssh_dir).expect("create .ssh");
    let secret_path = ssh_dir.join("id_rsa");
    let secret = "-----BEGIN OPENSSH PRIVATE KEY-----\nfake-test-secret\n";
    fs::write(&secret_path, secret).expect("write fake secret");

    // Minimal profile: no `extends` so we don't depend on a registry pack
    // being installed under the test HOME. `filesystem.deny` is what we are
    // exercising; the implicit default groups merged in by the loader do
    // not allow $WORKDIR, so the only allow that covers `.ssh` is the one
    // injected by `--allow-cwd`.
    let profile = t.write_profile(
        "deny-overlap-repro",
        &format!(
            r#"{{
            "meta": {{ "name": "deny-overlap-repro" }},
            "workdir": {{ "access": "readwrite" }},
            "filesystem": {{
                "deny": ["{workspace}/.ssh"]
            }}
        }}"#,
            workspace = workspace.display()
        ),
    );

    t.run()
        .allow_cwd()
        .profile(&profile)
        .exec(Argv::new("/bin/cat").arg(&secret_path))
        .assert_failure("a profile deny overlapping --allow-cwd must fail closed")
        .assert_stderr_contains("Landlock deny-overlap")
        // A single overlap summary, not one warning per deny.
        .assert_stderr_lacks("Landlock cannot enforce deny '")
        .assert_stdout_lacks("fake-test-secret");
}
