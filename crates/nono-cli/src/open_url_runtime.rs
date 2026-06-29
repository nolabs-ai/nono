use crate::cli::OpenUrlHelperArgs;
use nono::supervisor::types::{SupervisorMessage, SupervisorResponse};
use nono::supervisor::{SupervisorSocket, UrlOpenRequest};
use nono::{NonoError, Result};
use std::path::Path;

/// Internal helper invoked via BROWSER env var (Linux) or PATH shim (macOS).
///
/// Reads the supervisor socket path from `NONO_SUPERVISOR_PATH`, connects to
/// the supervisor's named socket, sends an `OpenUrl` IPC message, waits for
/// the response, and exits with the appropriate exit code.
pub(crate) fn run_open_url_helper(args: OpenUrlHelperArgs) -> Result<()> {
    run_open_url_helper_inner(&args.url)
}

fn run_open_url_helper_inner(url: &str) -> Result<()> {
    let socket_path = std::env::var("NONO_SUPERVISOR_PATH").map_err(|_| {
        NonoError::SandboxInit(
            "NONO_SUPERVISOR_PATH not set. open-url-helper must be invoked inside a nono sandbox."
                .to_string(),
        )
    })?;

    let mut socket = SupervisorSocket::connect(Path::new(&socket_path))?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;

    let request = UrlOpenRequest {
        request_id: format!("url-{}", std::process::id()),
        url: url.to_string(),
        child_pid: std::process::id(),
        session_id: String::new(),
    };

    socket.send_message(&SupervisorMessage::OpenUrl(request))?;

    let response = socket.recv_response()?;
    match response {
        SupervisorResponse::UrlOpened { success: true, .. } => Ok(()),
        SupervisorResponse::UrlOpened {
            success: false,
            error,
            ..
        } => {
            let msg = error.unwrap_or_else(|| "Unknown error".to_string());
            Err(NonoError::SandboxInit(format!(
                "Supervisor denied URL open: {msg}"
            )))
        }
        other => Err(NonoError::SandboxInit(format!(
            "Unexpected supervisor response: {other:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nono::supervisor::SupervisorListener;
    use std::path::PathBuf;

    fn socket_test_dir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("url-open-test-")
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

    /// Tests the inner IPC flow directly (bypassing the env var lookup) by
    /// simulating what happens once the socket path is known.
    #[test]
    fn test_open_url_helper_ipc_succeeds_when_supervisor_approves() {
        let dir = socket_test_dir();
        if !can_use_unix_sockets(dir.path()) {
            eprintln!("Skipping: Unix socket connect() blocked by sandbox");
            return;
        }

        let sock_path = dir.path().join("approve.sock");
        let listener = SupervisorListener::bind(&sock_path).expect("bind listener");

        let sock_path_clone = sock_path.clone();
        let handle = std::thread::spawn(move || {
            let mut socket = SupervisorSocket::connect(&sock_path_clone).expect("connect");
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .expect("set timeout");
            let request = UrlOpenRequest {
                request_id: format!("url-{}", std::process::id()),
                url: "https://example.com/oauth".to_string(),
                child_pid: std::process::id(),
                session_id: String::new(),
            };
            socket
                .send_message(&SupervisorMessage::OpenUrl(request))
                .expect("send");
            socket.recv_response()
        });

        std::thread::sleep(std::time::Duration::from_millis(50));
        let mut server_sock = listener
            .accept()
            .expect("accept should not error")
            .expect("accept should return a connection");

        let msg = server_sock.recv_message().expect("recv message");
        match msg {
            SupervisorMessage::OpenUrl(req) => {
                assert_eq!(req.url, "https://example.com/oauth");
            }
            other => panic!("Expected OpenUrl, got {:?}", other),
        }

        let response = SupervisorResponse::UrlOpened {
            request_id: "test".to_string(),
            success: true,
            error: None,
        };
        server_sock.send_response(&response).expect("send response");

        let result = handle
            .join()
            .expect("client thread")
            .expect("recv response");
        match result {
            SupervisorResponse::UrlOpened { success, .. } => assert!(success),
            other => panic!("Expected UrlOpened, got: {other:?}"),
        }
    }

    /// Tests that a supervisor denial is correctly communicated back through IPC.
    #[test]
    fn test_open_url_helper_ipc_returns_denial_from_supervisor() {
        let dir = socket_test_dir();
        if !can_use_unix_sockets(dir.path()) {
            eprintln!("Skipping: Unix socket connect() blocked by sandbox");
            return;
        }

        let sock_path = dir.path().join("deny.sock");
        let listener = SupervisorListener::bind(&sock_path).expect("bind listener");

        let sock_path_clone = sock_path.clone();
        let handle = std::thread::spawn(move || {
            let mut socket = SupervisorSocket::connect(&sock_path_clone).expect("connect");
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .expect("set timeout");
            let request = UrlOpenRequest {
                request_id: "url-deny-test".to_string(),
                url: "https://evil.example.com".to_string(),
                child_pid: std::process::id(),
                session_id: String::new(),
            };
            socket
                .send_message(&SupervisorMessage::OpenUrl(request))
                .expect("send");
            socket.recv_response()
        });

        std::thread::sleep(std::time::Duration::from_millis(50));
        let mut server_sock = listener
            .accept()
            .expect("accept should not error")
            .expect("accept should return a connection");

        let _msg = server_sock.recv_message().expect("recv message");
        let response = SupervisorResponse::UrlOpened {
            request_id: "url-deny-test".to_string(),
            success: false,
            error: Some("Origin not in allowed list".to_string()),
        };
        server_sock.send_response(&response).expect("send response");

        let result = handle
            .join()
            .expect("client thread")
            .expect("recv response");
        match result {
            SupervisorResponse::UrlOpened { success, error, .. } => {
                assert!(!success);
                assert_eq!(error.as_deref(), Some("Origin not in allowed list"));
            }
            other => panic!("Expected UrlOpened, got: {other:?}"),
        }
    }

    #[test]
    fn test_open_url_helper_fails_when_socket_path_does_not_exist() {
        let bad_path = PathBuf::from("/tmp/nonexistent-nono-socket-12345.sock");
        let result = SupervisorSocket::connect(&bad_path);
        assert!(result.is_err());
        let err_msg = format!("{}", result.err().expect("should have error"));
        assert!(
            err_msg.contains("Failed to connect"),
            "Error should mention connection failure, got: {err_msg}"
        );
    }
}
