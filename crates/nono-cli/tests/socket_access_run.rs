//! Runtime enforcement tests for AF_UNIX socket access control.
//!
//! Linux: `af_unix_mediation: pathname` installs a seccomp-notify BPF filter
//! that traps AF_UNIX pathname connect/bind and routes them to the supervisor.
//!
//! macOS: `filesystem.deny` on a socket path causes Seatbelt to emit both a
//! filesystem deny and a `network-outbound` deny, blocking the connect.

use std::fs;
use std::os::unix::net::{UnixDatagram, UnixListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn nono_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nono"))
}

fn setup_isolated_home(prefix: &str) -> (tempfile::TempDir, PathBuf, PathBuf) {
    let temp_root = std::env::current_dir()
        .expect("cwd")
        .join("target")
        .join("test-artifacts");
    fs::create_dir_all(&temp_root).expect("create temp root");
    let tmp = tempfile::Builder::new()
        .prefix(&format!("nono-{prefix}-it-"))
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
        .env("NONO_NO_SAVE_PROMPT", "1")
        .env_remove("NONO_DETACHED_LAUNCH")
        // Denials are the expected outcome in these tests; never open the
        // post-run denied-path review UI on the cargo test runner's TTY.
        .env("NONO_NO_SAVE_PROMPT", "1")
        .current_dir(cwd)
        .output()
        .expect("failed to run nono")
}

// Socket paths must stay under the 104-byte SUN_LEN limit; use /tmp directly
// rather than std::env::temp_dir() which on macOS expands to a long path
// under /var/folders/... that can exceed the limit.
fn short_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("nono-sock-")
        .tempdir_in(std::path::Path::new("/tmp"))
        .expect("tempdir in /tmp")
}

fn python3_available() -> bool {
    Command::new("python3")
        .args(["-c", "import socket"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
#[cfg(target_os = "linux")]
fn af_unix_mediation_pathname_blocks_connect_to_unlisted_socket() {
    if !python3_available() {
        eprintln!("skipping: python3 not available");
        return;
    }

    let (_tmp, home, workspace) = setup_isolated_home("af-unix-mediation");
    let sock_tmp = short_tempdir();
    let socket_path = sock_tmp.path().join("t.sock");
    let _listener = UnixListener::bind(&socket_path).expect("bind test socket");

    let profile_path = home.join("af-unix-test.json");
    fs::write(
        &profile_path,
        r#"{"meta":{"name":"af-unix-test"},"workdir":{"access":"readwrite"},"linux":{"af_unix_mediation":"pathname"}}"#,
    )
    .expect("write profile");

    let socket_arg = socket_path.to_string_lossy().into_owned();
    let py_script = format!(
        "import socket; s=socket.socket(socket.AF_UNIX); s.connect({socket_arg:?}); print('connected')"
    );

    let output = run_nono(
        &[
            "run",
            "--profile",
            &profile_path.to_string_lossy(),
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
        "connect to unlisted socket must be denied\nstdout: {stdout}\nstderr: {stderr}",
    );
    assert!(
        !stdout.contains("connected"),
        "connect must not complete\nstdout: {stdout}\nstderr: {stderr}",
    );
    assert!(
        stderr.contains("unix socket")
            || stderr.contains("Unix socket")
            || stderr.contains("unix_socket"),
        "expected unix socket denial in diagnostic output\nstderr: {stderr}",
    );
}

#[test]
#[cfg(target_os = "linux")]
fn af_unix_mediation_pathname_allows_connect_to_listed_socket() {
    if !python3_available() {
        eprintln!("skipping: python3 not available");
        return;
    }

    let (_tmp, home, workspace) = setup_isolated_home("af-unix-mediation-allow");
    let sock_tmp = short_tempdir();
    let socket_path = sock_tmp.path().join("a.sock");
    let _listener = UnixDatagram::bind(&socket_path).expect("bind test datagram socket");

    let socket_arg = socket_path.to_string_lossy().into_owned();
    let profile_path = home.join("af-unix-allow-test.json");
    fs::write(
        &profile_path,
        format!(
            r#"{{"meta":{{"name":"af-unix-allow-test"}},"workdir":{{"access":"readwrite"}},"linux":{{"af_unix_mediation":"pathname"}},"filesystem":{{"unix_socket":["{socket_arg}"]}}}}"#
        ),
    )
    .expect("write profile");

    // Use SOCK_DGRAM: connect() sets the peer address without requiring an
    // accept() on the far end, so the child exits immediately after the
    // syscall and we avoid a hang waiting for a stream handshake.
    let py_script = format!(
        "import socket; s=socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); s.connect({socket_arg:?}); print('ok')"
    );

    let output = run_nono(
        &[
            "run",
            "--profile",
            &profile_path.to_string_lossy(),
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

    // The supervisor must not deny the allowlisted socket path. Other system
    // sockets touched by Python or libc may still be denied; those are
    // unrelated to the allowlist entry under test.
    let denial_marker = format!("send {socket_arg}");
    assert!(
        !stderr.contains(&denial_marker),
        "supervisor must not deny the allowlisted socket path\nstdout: {stdout}\nstderr: {stderr}",
    );
}

#[test]
#[cfg(target_os = "macos")]
fn filesystem_deny_blocks_unix_socket_connect_on_macos() {
    if !python3_available() {
        eprintln!("skipping: python3 not available");
        return;
    }

    let (_tmp, home, workspace) = setup_isolated_home("macos-socket-deny");
    let sock_tmp = short_tempdir();
    let socket_path = sock_tmp.path().join("d.sock");
    let _listener = UnixListener::bind(&socket_path).expect("bind test socket");

    let socket_arg = socket_path.to_string_lossy().into_owned();
    let profile_path = home.join("macos-socket-deny.json");
    fs::write(
        &profile_path,
        format!(
            r#"{{"meta":{{"name":"macos-socket-deny"}},"workdir":{{"access":"readwrite"}},"filesystem":{{"deny":["{socket_arg}"]}}}}"#
        ),
    )
    .expect("write profile");

    let py_script = format!(
        "import socket; s=socket.socket(socket.AF_UNIX); s.connect({socket_arg:?}); print('connected')"
    );

    let output = run_nono(
        &[
            "run",
            "--profile",
            &profile_path.to_string_lossy(),
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
        "connect to denied socket path must be blocked\nstdout: {stdout}\nstderr: {stderr}",
    );
    assert!(
        !stdout.contains("connected"),
        "connect must not complete\nstdout: {stdout}\nstderr: {stderr}",
    );
}
