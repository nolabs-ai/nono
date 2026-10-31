//! End-to-end coverage for pathname Unix socket policy queries.

#![cfg(unix)]

use serde_json::Value;
#[cfg(target_os = "linux")]
use std::fs;
use std::os::unix::net::UnixListener;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;
use std::process::{Command, Output};

fn fixture() -> (tempfile::TempDir, PathBuf, UnixListener) {
    // Keep the path below sockaddr_un::sun_path limits on both platforms.
    let dir = tempfile::Builder::new()
        .prefix("nono-why-sock-")
        .tempdir_in("/tmp")
        .expect("tempdir");
    let socket = dir.path().join("s.sock");
    let listener = UnixListener::bind(&socket).expect("bind socket");
    (dir, socket, listener)
}

fn run_why(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nono"))
        .arg("why")
        .args(args)
        .output()
        .expect("run nono why")
}

fn json_output(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "nono why failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("JSON output")
}

#[cfg(target_os = "linux")]
fn write_profile(dir: &Path, name: &str, value: Value) -> PathBuf {
    let path = dir.join(format!("{name}.json"));
    fs::write(
        &path,
        serde_json::to_vec_pretty(&value).expect("serialize profile"),
    )
    .expect("write profile");
    path
}

#[test]
fn path_query_on_socket_points_to_socket_query() {
    let (_dir, socket, _listener) = fixture();
    let output = run_why(&[
        "--path",
        socket.to_str().expect("socket path"),
        "--op",
        "read",
    ]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("filesystem access only"), "{stdout}");
    assert!(stdout.contains("nono why --unix-socket"), "{stdout}");
}

#[test]
#[cfg(target_os = "linux")]
fn linux_default_reports_unmediated_even_with_block_net() {
    let (_dir, socket, _listener) = fixture();
    let output = run_why(&[
        "--json",
        "--block-net",
        "--unix-socket",
        socket.to_str().expect("socket path"),
    ]);
    let value = json_output(&output);
    assert_eq!(value["status"], "unmediated");
    assert_eq!(value["reason"], "linux_af_unix_mediation_off");
}

#[test]
#[cfg(target_os = "linux")]
fn linux_mediation_reports_granted_and_ungranted_sockets() {
    let (dir, socket, _listener) = fixture();
    let denied_profile = write_profile(
        dir.path(),
        "deny",
        serde_json::json!({
            "meta": {"name": "deny"},
            "linux": {"af_unix_mediation": "pathname"}
        }),
    );
    let allowed_profile = write_profile(
        dir.path(),
        "allow",
        serde_json::json!({
            "meta": {"name": "allow"},
            "linux": {"af_unix_mediation": "pathname"},
            "filesystem": {"unix_socket": [socket]}
        }),
    );
    let socket = socket.to_str().expect("socket path");

    let denied = json_output(&run_why(&[
        "--json",
        "--profile",
        denied_profile.to_str().expect("profile path"),
        "--unix-socket",
        socket,
    ]));
    assert_eq!(denied["status"], "denied");
    assert_eq!(denied["reason"], "unix_socket_not_granted");

    let allowed = json_output(&run_why(&[
        "--json",
        "--profile",
        allowed_profile.to_str().expect("profile path"),
        "--unix-socket",
        socket,
    ]));
    assert_eq!(allowed["status"], "allowed");
    assert_eq!(allowed["reason"], "unix_socket_granted");
}

#[test]
#[cfg(target_os = "macos")]
fn macos_blocked_network_requires_explicit_socket_grant() {
    let (_dir, socket, _listener) = fixture();
    let socket = socket.to_str().expect("socket path");

    let denied = json_output(&run_why(&[
        "--json",
        "--block-net",
        "--unix-socket",
        socket,
    ]));
    assert_eq!(denied["status"], "denied");
    assert_eq!(denied["reason"], "unix_socket_not_granted");

    let allowed = json_output(&run_why(&[
        "--json",
        "--block-net",
        "--unix-socket",
        socket,
        "--allow-unix-socket",
        socket,
    ]));
    assert_eq!(allowed["status"], "allowed");
    assert_eq!(allowed["reason"], "unix_socket_granted");
}
