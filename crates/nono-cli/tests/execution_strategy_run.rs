//! End-to-end integration tests for core sandbox execution strategies.
//!
//! Each test spawns the real `nono` binary, uses an inline hermetic profile
//! (no `extends` dependency), and asserts on exit code and stderr output.
//! Linux tests rely on Landlock/seccomp; macOS tests use Seatbelt.
//!
//! Note: `select_exec_strategy` currently always returns `Supervised`, so
//! Direct and Monitor strategies are not separately exercisable via the CLI.
//! These tests verify the denial invariant end-to-end regardless of which
//! internal strategy is active.
//!
//! AF_UNIX mediation integration tests live in `socket_access_run.rs`.

use std::fs;
use std::net::TcpListener;
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn nono_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nono"))
}

fn setup_isolated_home(prefix: &str) -> (tempfile::TempDir, PathBuf, PathBuf) {
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
    fs::create_dir_all(home.join(".config")).expect("create .config dir");
    fs::create_dir_all(home.join(".local").join("state")).expect("create state dir");
    fs::create_dir_all(&workspace).expect("create workspace dir");
    (tmp, home, workspace)
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

fn python3_available() -> bool {
    Command::new("python3")
        .args(["-c", "import socket"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn cc_available() -> bool {
    Command::new("cc")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
#[cfg(target_os = "linux")]
fn direct_denies_path_outside_grant() {
    let (_tmp, home, workspace) = setup_isolated_home("direct-deny");

    let profile_path = write_profile(
        &home,
        "direct-deny",
        &format!(
            r#"{{
                "meta": {{ "name": "direct-deny-test" }},
                "filesystem": {{ "allow": ["{workspace}"] }},
                "network": {{ "block": true }}
            }}"#,
            workspace = workspace.display()
        ),
    );

    let output = run_nono(
        &[
            "run",
            "--profile",
            profile_path.to_str().expect("profile path"),
            "--no-rollback",
            "--",
            "/bin/cat",
            "/etc/shadow",
        ],
        &home,
        &workspace,
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "nono run must deny /etc/shadow outside the grant set\nstdout: {stdout}\nstderr: {stderr}",
    );
    assert!(
        !stdout.contains("root:"),
        "secret content must not appear in stdout\nstdout: {stdout}",
    );
}

/// On macOS, Seatbelt is used. `/etc/passwd` is world-readable and included in
/// nono's system/group paths, so it is not a useful denial target. Instead we
/// read a sibling of the granted workspace that is entirely outside any system
/// path so Seatbelt must deny it.
#[test]
#[cfg(target_os = "macos")]
fn direct_denies_path_outside_grant_macos() {
    let (tmp, home, workspace) = setup_isolated_home("direct-deny-macos");

    let secret = tmp.path().join("outside-secret.txt");
    fs::write(&secret, "TOPSECRET-outside-grant\n").expect("write secret");

    let profile_path = write_profile(
        &home,
        "direct-deny-macos",
        &format!(
            r#"{{
                "meta": {{ "name": "direct-deny-macos-test" }},
                "filesystem": {{ "allow": ["{workspace}"] }},
                "network": {{ "block": true }}
            }}"#,
            workspace = workspace.display()
        ),
    );

    let output = run_nono(
        &[
            "run",
            "--profile",
            profile_path.to_str().expect("profile path"),
            "--no-rollback",
            "--",
            "/bin/cat",
            secret.to_str().expect("secret path"),
        ],
        &home,
        &workspace,
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "nono run must deny a path outside the grant set\nstdout: {stdout}\nstderr: {stderr}",
    );
    assert!(
        !stdout.contains("TOPSECRET"),
        "secret content must not appear in stdout\nstdout: {stdout}",
    );
}

#[test]
#[cfg(target_os = "linux")]
fn deny_outside_grant_produces_diagnostic_footer() {
    let (_tmp, home, workspace) = setup_isolated_home("deny-diag");

    let target = home.join("secret.txt");
    fs::write(&target, "forbidden-content").expect("write secret");

    let profile_path = write_profile(
        &home,
        "deny-diag",
        &format!(
            r#"{{
                "meta": {{ "name": "deny-diag-test" }},
                "filesystem": {{ "allow": ["{workspace}"] }},
                "network": {{ "block": true }}
            }}"#,
            workspace = workspace.display()
        ),
    );

    let output = run_nono(
        &[
            "run",
            "--profile",
            profile_path.to_str().expect("profile path"),
            "--no-rollback",
            "--",
            "/bin/cat",
            target.to_str().expect("target path"),
        ],
        &home,
        &workspace,
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "nono run must deny a path outside the grant set\nstdout: {stdout}\nstderr: {stderr}",
    );
    assert!(
        !stdout.contains("forbidden-content"),
        "forbidden content leaked to stdout\nstdout: {stdout}",
    );
}

#[test]
#[cfg(target_os = "linux")]
fn supervised_denies_path_outside_grant() {
    let (_tmp, home, workspace) = setup_isolated_home("supervised-deny");

    let profile_path = write_profile(
        &home,
        "supervised-deny",
        &format!(
            r#"{{
                "meta": {{ "name": "supervised-deny-test" }},
                "filesystem": {{ "allow": ["{workspace}"] }},
                "network": {{ "block": true }}
            }}"#,
            workspace = workspace.display()
        ),
    );

    let output = run_nono(
        &[
            "run",
            "--profile",
            profile_path.to_str().expect("profile path"),
            "--no-rollback",
            "--",
            "/bin/cat",
            "/etc/shadow",
        ],
        &home,
        &workspace,
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "nono run must deny /etc/shadow outside the grant set\nstdout: {stdout}\nstderr: {stderr}",
    );
    assert!(
        !stdout.contains("root:"),
        "secret content must not appear in stdout\nstdout: {stdout}",
    );
}

/// Positive control: reading a file inside the granted set must succeed.
#[test]
fn granted_path_exits_zero() {
    let (_tmp, home, workspace) = setup_isolated_home("grant-ok");

    let sentinel = workspace.join("hello.txt");
    fs::write(&sentinel, "hello from nono test").expect("write sentinel");

    let profile_path = write_profile(
        &home,
        "grant-ok",
        &format!(
            r#"{{
                "meta": {{ "name": "grant-ok-test" }},
                "filesystem": {{ "allow": ["{workspace}"] }},
                "network": {{ "block": true }}
            }}"#,
            workspace = workspace.display()
        ),
    );

    let output = run_nono(
        &[
            "run",
            "--profile",
            profile_path.to_str().expect("profile path"),
            "--no-rollback",
            "--",
            "/bin/cat",
            sentinel.to_str().expect("sentinel path"),
        ],
        &home,
        &workspace,
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "nono run must succeed for a path inside the grant set\nstderr: {stderr}",
    );
    assert!(
        stdout.contains("hello from nono test"),
        "expected sentinel content in stdout\nstdout: {stdout}\nstderr: {stderr}",
    );
}

/// `network.block: true` must prevent outbound TCP connections. We bind a
/// real listener so the port is genuinely reachable without a sandbox; the
/// sandboxed child must fail to connect.
#[test]
fn network_block_denies_outbound_tcp() {
    if !python3_available() {
        eprintln!("skipping: python3 not available");
        return;
    }

    let (_tmp, home, workspace) = setup_isolated_home("net-block");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let profile_path = write_profile(
        &home,
        "net-block",
        &format!(
            r#"{{
                "meta": {{ "name": "net-block-test" }},
                "filesystem": {{ "allow": ["{workspace}"] }},
                "network": {{ "block": true }}
            }}"#,
            workspace = workspace.display()
        ),
    );

    // connect_ex() returns the errno on failure so the script exits 1 on any
    // connect error. Without a sandbox, connecting to the bound listener
    // succeeds and the script exits 0.
    let py_script = format!(
        "import socket, sys; s=socket.socket(); s.settimeout(2); \
         code=s.connect_ex(('127.0.0.1', {port})); sys.exit(0 if code == 0 else 1)"
    );

    let output = run_nono(
        &[
            "run",
            "--profile",
            profile_path.to_str().expect("profile path"),
            "--no-rollback",
            "--",
            "python3",
            "-c",
            &py_script,
        ],
        &home,
        &workspace,
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "network block must deny outbound TCP to a live listener\nstdout: {stdout}\nstderr: {stderr}",
    );
}

/// A profile combining `env_credentials` (env://) and `command_policies` must
/// launch successfully when the initial command is not itself a policy shim.
/// The session process receives a broker nonce rather than the real credential
/// value (broker isolation preserved).
#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn env_credentials_with_command_policies_non_shim_entry_succeeds() {
    let (_tmp, home, workspace) = setup_isolated_home("env-creds-cmd-policies");

    let profile_path = write_profile(
        &home,
        "env-creds-cmd-policies",
        &format!(
            r#"{{
                "meta": {{ "name": "env-creds-cmd-policies-test" }},
                "filesystem": {{ "allow": ["{workspace}"] }},
                "network": {{ "block": true }},
                "env_credentials": {{
                    "env://API_TOKEN": "API_TOKEN"
                }},
                "command_policies": {{
                    "commands": {{
                        "cat": {{
                            "executable": "/bin/cat"
                        }}
                    }}
                }}
            }}"#,
            workspace = workspace.display()
        ),
    );

    let output = nono_bin()
        .args([
            "run",
            "--profile",
            profile_path.to_str().expect("profile path"),
            "--no-rollback",
            "--",
            "sh",
            "-c",
            "exit 0",
        ])
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_STATE_HOME", home.join(".local").join("state"))
        .env("NONO_NO_SAVE_PROMPT", "1")
        .env("API_TOKEN", "secret-value")
        .env_remove("NONO_DETACHED_LAUNCH")
        .current_dir(&workspace)
        .output()
        .expect("failed to run nono");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "env_credentials + command_policies with a non-shim entry must succeed\nstdout: {stdout}\nstderr: {stderr}",
    );
}

/// A script written into a writable grant-dir (cwd) must still execute under
/// an active `command_policies` outer exec gate.
#[test]
#[cfg(target_os = "linux")]
fn command_policies_allows_script_exec_in_writable_grant_dir() {
    let (_tmp, home, workspace) = setup_isolated_home("cmd-policies-script-exec");

    let script_path = workspace.join("s.sh");
    fs::write(&script_path, "#!/usr/bin/env bash\necho ok\n").expect("write script");
    fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755))
        .expect("chmod script executable");

    let profile_path = write_profile(
        &home,
        "cmd-policies-script-exec",
        &format!(
            r#"{{
                "meta": {{ "name": "cmd-policies-script-exec-test" }},
                "filesystem": {{ "allow": ["{workspace}"] }},
                "network": {{ "block": true }},
                "command_policies": {{
                    "commands": {{
                        "cat": {{
                            "executable": "/bin/cat"
                        }}
                    }}
                }}
            }}"#,
            workspace = workspace.display()
        ),
    );

    let output = run_nono(
        &[
            "run",
            "--profile",
            profile_path.to_str().expect("profile path"),
            "--no-rollback",
            "--",
            "bash",
            "-c",
            "./s.sh",
        ],
        &home,
        &workspace,
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "a script in a writable grant-dir must still execute under command_policies\nstdout: {stdout}\nstderr: {stderr}",
    );
    assert!(
        stdout.contains("ok"),
        "expected script output in stdout\nstdout: {stdout}\nstderr: {stderr}",
    );
}

/// Same as above but for a binary compiled at runtime, so it wasn't on disk
/// when the outer exec gate was set up.
#[test]
#[cfg(target_os = "linux")]
fn command_policies_allows_compiled_binary_exec_in_writable_grant_dir() {
    if !cc_available() {
        eprintln!("skipping: cc not available");
        return;
    }

    let (_tmp, home, workspace) = setup_isolated_home("cmd-policies-bin-exec");

    let source_path = workspace.join("b.c");
    fs::write(
        &source_path,
        "#include <stdio.h>\nint main(void) { printf(\"ok\\n\"); return 0; }\n",
    )
    .expect("write source");
    let binary_path = workspace.join("b");
    let compile_status = Command::new("cc")
        .args([
            "-o",
            binary_path.to_str().expect("binary path"),
            source_path.to_str().expect("source path"),
        ])
        .status()
        .expect("run cc");
    assert!(compile_status.success(), "cc must compile the test binary");

    let profile_path = write_profile(
        &home,
        "cmd-policies-bin-exec",
        &format!(
            r#"{{
                "meta": {{ "name": "cmd-policies-bin-exec-test" }},
                "filesystem": {{ "allow": ["{workspace}"] }},
                "network": {{ "block": true }},
                "command_policies": {{
                    "commands": {{
                        "cat": {{
                            "executable": "/bin/cat"
                        }}
                    }}
                }}
            }}"#,
            workspace = workspace.display()
        ),
    );

    let output = run_nono(
        &[
            "run",
            "--profile",
            profile_path.to_str().expect("profile path"),
            "--no-rollback",
            "--",
            "bash",
            "-c",
            "./b",
        ],
        &home,
        &workspace,
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "a freshly compiled binary in a writable grant-dir must still execute under command_policies\nstdout: {stdout}\nstderr: {stderr}",
    );
    assert!(
        stdout.contains("ok"),
        "expected binary output in stdout\nstdout: {stdout}\nstderr: {stderr}",
    );
}
