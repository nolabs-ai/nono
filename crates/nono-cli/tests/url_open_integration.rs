//! End-to-end integration tests for the URL open helper feature.
//!
//! These tests exercise the full pipeline: the `nono open-url-helper` binary
//! connects to a supervisor socket, sends an OpenUrl request, and processes
//! the response. The tests run the actual CLI binary as a subprocess.

use nono::supervisor::SupervisorListener;
use nono::supervisor::types::{SupervisorMessage, SupervisorResponse};
use std::process::Command;

fn nono_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nono"))
}

fn socket_test_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("url-e2e-")
        .tempdir_in(std::path::Path::new("/tmp"))
        .expect("create test tmpdir in /tmp")
}

fn can_use_unix_sockets(dir: &std::path::Path) -> bool {
    let probe_path = dir.join("probe.sock");
    let listener = match std::os::unix::net::UnixListener::bind(&probe_path) {
        Ok(l) => l,
        Err(_) => return false,
    };
    let connect_result = std::os::unix::net::UnixStream::connect(&probe_path);
    drop(listener);
    let _ = std::fs::remove_file(&probe_path);
    connect_result.is_ok()
}

#[test]
fn test_open_url_helper_binary_succeeds_with_valid_supervisor() {
    let dir = socket_test_dir();
    if !can_use_unix_sockets(dir.path()) {
        eprintln!("Skipping: Unix socket connect() blocked by sandbox");
        return;
    }

    let sock_path = dir.path().join("supervisor.sock");
    let listener = SupervisorListener::bind(&sock_path).expect("bind listener");

    let child = nono_bin()
        .args(["open-url-helper", "https://example.com/oauth/authorize"])
        .env("NONO_SUPERVISOR_PATH", &sock_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn nono open-url-helper");

    // Accept connection from the helper binary
    let mut server_sock = loop {
        std::thread::sleep(std::time::Duration::from_millis(20));
        match listener.accept() {
            Ok(Some(s)) => break s,
            Ok(None) => continue,
            Err(e) => panic!("accept error: {e}"),
        }
    };

    // Read the OpenUrl request
    let msg = server_sock.recv_message().expect("recv message");
    match msg {
        SupervisorMessage::OpenUrl(req) => {
            assert_eq!(req.url, "https://example.com/oauth/authorize");
            assert!(req.child_pid > 0);
        }
        other => panic!("Expected OpenUrl, got: {other:?}"),
    }

    // Send success response
    let response = SupervisorResponse::UrlOpened {
        request_id: "test".to_string(),
        success: true,
        error: None,
    };
    server_sock.send_response(&response).expect("send response");

    // Verify child exits successfully
    let output = child.wait_with_output().expect("wait for child");
    assert!(
        output.status.success(),
        "open-url-helper should exit 0 on success, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_open_url_helper_binary_fails_when_supervisor_denies() {
    let dir = socket_test_dir();
    if !can_use_unix_sockets(dir.path()) {
        eprintln!("Skipping: Unix socket connect() blocked by sandbox");
        return;
    }

    let sock_path = dir.path().join("deny.sock");
    let listener = SupervisorListener::bind(&sock_path).expect("bind listener");

    let child = nono_bin()
        .args(["open-url-helper", "https://evil.example.com/phishing"])
        .env("NONO_SUPERVISOR_PATH", &sock_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn nono open-url-helper");

    let mut server_sock = loop {
        std::thread::sleep(std::time::Duration::from_millis(20));
        match listener.accept() {
            Ok(Some(s)) => break s,
            Ok(None) => continue,
            Err(e) => panic!("accept error: {e}"),
        }
    };

    let _msg = server_sock.recv_message().expect("recv message");

    // Send denial response
    let response = SupervisorResponse::UrlOpened {
        request_id: "test".to_string(),
        success: false,
        error: Some("Origin not in allowed list".to_string()),
    };
    server_sock.send_response(&response).expect("send response");

    let output = child.wait_with_output().expect("wait for child");
    assert!(
        !output.status.success(),
        "open-url-helper should exit non-zero on denial"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("denied") || stderr.contains("Origin not in allowed list"),
        "stderr should mention denial reason, got: {stderr}"
    );
}

#[test]
fn test_open_url_helper_binary_fails_when_socket_does_not_exist() {
    let output = nono_bin()
        .args(["open-url-helper", "https://example.com"])
        .env(
            "NONO_SUPERVISOR_PATH",
            "/tmp/nonexistent-nono-test-socket-99999.sock",
        )
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("run nono open-url-helper");

    assert!(
        !output.status.success(),
        "open-url-helper should exit non-zero when socket doesn't exist"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Failed to connect") || stderr.contains("supervisor socket"),
        "stderr should mention connection failure, got: {stderr}"
    );
}
