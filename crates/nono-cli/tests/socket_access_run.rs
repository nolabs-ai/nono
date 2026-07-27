//! Runtime enforcement tests for AF_UNIX socket access control.
//!
//! Linux: `af_unix_mediation: pathname` installs a seccomp-notify BPF filter
//! that traps AF_UNIX pathname connect/bind and routes them to the supervisor.
//!
//! macOS: `filesystem.deny` on a socket path causes Seatbelt to emit both a
//! filesystem deny and a `network-outbound` deny, blocking the connect.

use std::fs;
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixDatagram;
use std::os::unix::net::UnixListener;
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

/// Absolute path to a system `python3` (under a default-allowed bin dir),
/// preferred over a pyenv/asdf shim: shims re-exec the real interpreter from a
/// dir the sandbox doesn't grant, so the child fails to exec (exit 127).
fn python3_bin() -> Option<String> {
    for cand in ["/usr/bin/python3", "/bin/python3", "/usr/local/bin/python3"] {
        let runnable = Command::new(cand)
            .args(["-c", "import socket"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if runnable {
            return Some(cand.to_string());
        }
    }
    None
}

#[test]
#[cfg(target_os = "linux")]
fn af_unix_mediation_pathname_blocks_connect_to_unlisted_socket() {
    let Some(py) = python3_bin() else {
        eprintln!("skipping: no system python3 available");
        return;
    };

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
            &py,
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
    let Some(py) = python3_bin() else {
        eprintln!("skipping: no system python3 available");
        return;
    };

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
            &py,
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
    let Some(py) = python3_bin() else {
        eprintln!("skipping: no system python3 available");
        return;
    };

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
            &py,
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

/// Yama `ptrace_scope`, or `None` if it can't be read (non-Yama kernel).
#[cfg(target_os = "linux")]
fn yama_ptrace_scope() -> Option<i32> {
    fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Regression test for the AF_UNIX-pathname orphan `connect()` bug: a
/// double-forked grandchild reparents to pid 1, and pre-fix the supervisor
/// could no longer read its `/proc/<pid>/mem` to classify the syscall (the read
/// is ancestry-gated under Yama `ptrace_scope=1`), so its allowed TCP connect
/// was denied with `EPERM`. The child-subreaper fix keeps such descendants in
/// the supervisor's ancestry. Only manifests under `ptrace_scope >= 1`.
#[test]
#[cfg(target_os = "linux")]
fn af_unix_mediation_pathname_allows_orphaned_child_tcp_connect() {
    let Some(py) = python3_bin() else {
        eprintln!("skipping: no system python3 available");
        return;
    };
    match yama_ptrace_scope() {
        Some(0) => eprintln!(
            "note: ptrace_scope=0, the orphan-reparent regression is not exercised \
             (read succeeds regardless); asserting the positive path only"
        ),
        Some(n) => eprintln!("ptrace_scope={n}: regression is exercised"),
        None => eprintln!("note: could not read ptrace_scope (non-Yama kernel?)"),
    }

    let (_tmp, home, workspace) = setup_isolated_home("af-unix-orphan");

    // Live loopback listener so an authorized connect completes locally without
    // egress (the handshake lands in the backlog; no accept() needed).
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let port = listener.local_addr().expect("local_addr").port();

    let profile_path = home.join("af-unix-orphan.json");
    fs::write(
        &profile_path,
        r#"{"meta":{"name":"af-unix-orphan"},"workdir":{"access":"readwrite"},"network":{"block":false},"linux":{"af_unix_mediation":"pathname"}}"#,
    )
    .expect("write profile");

    // Foreground connect (always in the supervisor's ancestry) then a
    // double-forked orphan that reparents to pid 1 before it connects.
    let py_script = format!(
        r#"
import os, socket
PORT = {port}
def attempt():
    s = socket.socket(); s.settimeout(3)
    try:
        s.connect(("127.0.0.1", PORT)); return "OK"
    except OSError as e:
        return "errno=%d" % (e.errno,)
    finally:
        s.close()
print("foreground " + attempt(), flush=True)
r, w = os.pipe()
if os.fork() == 0:
    os.setsid()
    if os.fork() == 0:
        import time; time.sleep(0.5)  # let the intermediate exit -> reparent to pid 1
        os.write(w, ("orphan " + attempt()).encode()); os._exit(0)
    os._exit(0)
os.close(w)
print(os.read(r, 200).decode(), flush=True)
"#
    );

    let output = run_nono(
        &[
            "run",
            "--profile",
            &profile_path.to_string_lossy(),
            "--",
            &py,
            "-c",
            &py_script,
        ],
        &home,
        &workspace,
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Sanity: foreground connect is authorized and completes.
    assert!(
        stdout.contains("foreground OK"),
        "foreground connect should be authorized and complete\nstdout: {stdout}\nstderr: {stderr}",
    );

    // The fix: the orphaned grandchild's connect is authorized too (pre-fix it
    // was "orphan errno=1" under ptrace_scope>=1).
    assert!(
        stdout.contains("orphan OK"),
        "orphaned grandchild connect must be authorized (was EPERM before the \
         child-subreaper fix)\nstdout: {stdout}\nstderr: {stderr}",
    );

    // Fingerprint of the ancestry-gated /proc/<pid>/mem read failing.
    assert!(
        !stderr.contains("Failed to read sockaddr"),
        "supervisor failed to classify the orphan's connect (ancestry lost)\nstderr: {stderr}",
    );
}
