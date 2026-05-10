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

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn nono_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nono"))
}

fn setup_isolated_home() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let temp_root = std::env::current_dir()
        .expect("cwd")
        .join("target")
        .join("test-artifacts");
    fs::create_dir_all(&temp_root).expect("create temp root");
    let tmp = tempfile::Builder::new()
        .prefix("nono-deny-overlap-run-it-")
        .tempdir_in(&temp_root)
        .expect("tempdir");
    let home = tmp.path().join("home");
    let workspace = tmp.path().join("workspace");
    fs::create_dir_all(home.join(".config")).expect("create config dir");
    fs::create_dir_all(&workspace).expect("create workspace dir");
    (tmp, home, workspace)
}

fn run_nono(args: &[&str], home: &Path, cwd: &Path) -> Output {
    nono_bin()
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        // Disable the detached-launch path and any interactive prompts —
        // `--allow-cwd` already pre-confirms CWD sharing, but be defensive.
        .env_remove("NONO_DETACHED_LAUNCH")
        .current_dir(cwd)
        .output()
        .expect("failed to run nono")
}

#[test]
fn run_allow_cwd_with_profile_deny_under_workdir_fails_closed() {
    let (_tmp, home, workspace) = setup_isolated_home();

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
    let profile_path = home.join("deny-overlap-repro.json");
    let profile_json = format!(
        r#"{{
            "meta": {{ "name": "deny-overlap-repro" }},
            "workdir": {{ "access": "readwrite" }},
            "filesystem": {{
                "deny": ["{workspace}/.ssh"]
            }}
        }}"#,
        workspace = workspace.display()
    );
    fs::write(&profile_path, profile_json).expect("write profile");

    let profile_arg = profile_path.to_string_lossy().into_owned();
    let secret_arg = secret_path.to_string_lossy().into_owned();
    let output = run_nono(
        &[
            "run",
            "--allow-cwd",
            "--profile",
            &profile_arg,
            "--",
            "/bin/cat",
            &secret_arg,
        ],
        &home,
        &workspace,
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "nono run must fail closed when a profile deny overlaps --allow-cwd; \
         instead it exited successfully.\nstdout: {stdout}\nstderr: {stderr}",
    );
    assert!(
        stderr.contains("Landlock deny-overlap"),
        "expected 'Landlock deny-overlap' refusal in stderr, got:\n{stderr}",
    );
    assert!(
        !stdout.contains("fake-test-secret"),
        "secret content leaked to stdout despite profile deny:\n{stdout}",
    );
}
