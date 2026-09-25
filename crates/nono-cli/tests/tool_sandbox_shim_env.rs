//! Regression coverage for #2001: shim discovery must survive environment
//! sanitization, and recognized shims must never dispatch the normal CLI.

#![cfg(any(target_os = "linux", target_os = "macos"))]

use nono::supervisor::socket::recv_fd_via_socket;
use nono_test_support::{Argv, nono_test};
use serde_json::{Value, json};
use std::fs;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

const DISCOVERY_VARS: [&str; 3] = [
    "NONO_TOOL_SANDBOX_SOCKET",
    "NONO_TOOL_SANDBOX_SHIM_DIR",
    "NONO_TOOL_SANDBOX_URL_SOCKET",
];

struct Runtime {
    dir: tempfile::TempDir,
}

impl Runtime {
    fn new() -> Self {
        // Keep Unix socket paths short, including on macOS.
        let dir = tempfile::Builder::new()
            .prefix("nono-tool-sandbox-")
            .tempdir_in("/tmp")
            .expect("runtime directory");
        fs::create_dir(dir.path().join("shims")).expect("shim directory");
        Self { dir }
    }

    fn shim(&self, name: &str) -> PathBuf {
        let path = self.dir.path().join("shims").join(name);
        fs::copy(env!("CARGO_BIN_EXE_nono"), &path).expect("copy shim");
        path
    }

    fn socket(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
}

fn shim_command(exe: &Path) -> Command {
    let mut command = Command::new(exe);
    command
        .env_clear()
        .env("PATH", exe.parent().expect("shims"));
    command
}

fn assert_exit(output: &Output, code: i32) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn read_frame(stream: &mut UnixStream) -> Value {
    let mut len = [0; 4];
    stream.read_exact(&mut len).expect("frame length");
    let len = u32::from_be_bytes(len) as usize;
    assert!(len <= 1024 * 1024);
    let mut payload = vec![0; len];
    stream.read_exact(&mut payload).expect("frame payload");
    serde_json::from_slice(&payload).expect("JSON frame")
}

fn write_frame(stream: &mut UnixStream, value: Value) {
    let payload = serde_json::to_vec(&value).expect("serialize response");
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .expect("response length");
    stream.write_all(&payload).expect("response body");
}

// A protocol fixture, not an authorization substitute. Real broker coverage is
// below; this fixture checks exactly which socket and protocol the shim uses.
fn broker(
    path: &Path,
    handler: impl FnOnce(UnixStream) + Send + 'static,
) -> std::thread::JoinHandle<()> {
    let listener = UnixListener::bind(path).expect("bind broker");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).expect("blocking connection");
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .expect("read timeout");
                    handler(stream);
                    return;
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "shim did not reach its broker");
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(err) => panic!("accept: {err}"),
            }
        }
    })
}

#[test]
fn command_shim_uses_its_session_socket_and_executable_name() {
    let runtime = Runtime::new();
    let exe = runtime.shim("git");
    for conflicting_env in [false, true] {
        let socket = runtime.socket("supervisor.sock");
        let server = broker(&socket, |mut stream| {
            #[cfg(target_os = "linux")]
            let _identity = recv_fd_via_socket(stream.as_raw_fd()).expect("shim identity");
            let request = read_frame(&mut stream);
            assert_eq!(request["command"], "git");
            assert_eq!(request["argv"][1], json!(b"status".to_vec()));
            stream.write_all(&[0]).expect("frame ack");
            let _stdin = recv_fd_via_socket(stream.as_raw_fd()).expect("stdin");
            let _stdout = recv_fd_via_socket(stream.as_raw_fd()).expect("stdout");
            let _stderr = recv_fd_via_socket(stream.as_raw_fd()).expect("stderr");
            write_frame(
                &mut stream,
                json!({"exit_code": 37, "error": "test broker denial"}),
            );
        });
        let mut command = shim_command(&exe);
        // Neither argv[0] nor conflicting variables may select another broker.
        command.arg0("nono").arg("status");
        if conflicting_env {
            for key in DISCOVERY_VARS {
                command.env(key, "/tmp/another-session");
            }
        }
        let output = command.output().expect("run command shim");
        server.join().expect("broker thread");
        assert_exit(&output, 37);
        assert!(String::from_utf8_lossy(&output.stderr).contains("test broker denial"));
        fs::remove_file(socket).expect("remove socket");
    }
}

#[test]
fn url_shim_uses_its_session_socket_with_sanitized_or_conflicting_env() {
    let runtime = Runtime::new();
    let exe = runtime.shim("open");
    for success in [true, false] {
        let socket = runtime.socket("url.sock");
        let server = broker(&socket, move |mut stream| {
            let request = read_frame(&mut stream);
            assert_eq!(request["url"], "https://example.com/login");
            assert_eq!(request["command"], "");
            write_frame(
                &mut stream,
                json!({"success": success, "error": "URL policy denied"}),
            );
        });
        let mut command = shim_command(&exe);
        command.args(["https://example.com/login"]);
        if !success {
            for key in DISCOVERY_VARS {
                command.env(key, "/tmp/another-session");
            }
        }
        let output = command.output().expect("run URL shim");
        server.join().expect("broker thread");
        assert_exit(&output, if success { 0 } else { 126 });
        if !success {
            assert!(String::from_utf8_lossy(&output.stderr).contains("URL policy denied"));
        }
        fs::remove_file(socket).expect("remove socket");
    }
}

#[test]
fn missing_or_invalid_broker_never_falls_through_to_cli() {
    let runtime = Runtime::new();
    for (name, socket_name, arg) in [
        ("git", "supervisor.sock", "--version"),
        ("open", "url.sock", "https://example.com"),
    ] {
        let exe = runtime.shim(name);
        let socket = runtime.socket(socket_name);
        for invalid_socket in [false, true] {
            if invalid_socket {
                fs::write(&socket, b"not a socket").expect("invalid socket");
            }
            let output = shim_command(&exe).arg(arg).output().expect("run shim");
            assert_exit(&output, 126);
            assert!(output.stdout.is_empty());
            assert!(String::from_utf8_lossy(&output.stderr).contains(socket_name));
        }
    }
}

#[test]
fn malformed_broker_response_fails_closed() {
    let runtime = Runtime::new();
    let exe = runtime.shim("open");
    let server = broker(&runtime.socket("url.sock"), |mut stream| {
        let _ = read_frame(&mut stream);
        write_frame(&mut stream, json!({"unexpected": true}));
    });
    let output = shim_command(&exe)
        .arg("https://example.com")
        .output()
        .expect("run URL shim");
    server.join().expect("broker thread");
    assert_exit(&output, 126);
    assert!(output.stdout.is_empty());
}

#[test]
fn ordinary_cli_ignores_shim_discovery_variables() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nono"));
    command.env_clear().arg("--version");
    for key in DISCOVERY_VARS {
        command.env(key, "/tmp/another-session");
    }
    let output = command.output().expect("run CLI");
    assert_exit(&output, 0);
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("nono "));
}

#[test]
fn real_broker_mediates_nested_commands_without_discovery_variables() {
    let t = nono_test!("shim-env");
    let profile = t.write_profile(
        "shim-env",
        r#"{
            "meta": {"name": "shim-env"},
            "workdir": {"access": "read"},
            "command_policies": {
                "commands": {
                    "sh": {
                        "executable": "/bin/sh",
                        "can_use": ["env"],
                        "sandbox": {"fs_read": ["."]}
                    },
                    "env": {
                        "executable": "/usr/bin/env",
                        "from": {"sh": {"sandbox": {"fs_read": ["."]}}}
                    }
                }
            }
        }"#,
    );
    t.run()
        .profile(&profile)
        .allow_cwd()
        .no_rollback()
        .exec(Argv::new("sh").arg("-c").arg(
            r#"
            test -z "${NONO_TOOL_SANDBOX_SOCKET+x}" || exit 91
            test -z "${NONO_TOOL_SANDBOX_SHIM_DIR+x}" || exit 92
            test -z "${NONO_TOOL_SANDBOX_URL_SOCKET+x}" || exit 93
            unset NONO_TOOL_SANDBOX_SOCKET NONO_TOOL_SANDBOX_SHIM_DIR NONO_TOOL_SANDBOX_URL_SOCKET
            env
            "#,
        ))
        .assert_success("nested command reaches the authenticated broker after env sanitization")
        .assert_stdout_contains("PATH=")
        .assert_stdout_lacks("NONO_TOOL_SANDBOX_SOCKET=")
        .assert_stdout_lacks("NONO_TOOL_SANDBOX_SHIM_DIR=")
        .assert_stdout_lacks("NONO_TOOL_SANDBOX_URL_SOCKET=")
        .assert_stdout_lacks("NONO_TOOL_SANDBOX_LAUNCH_SPEC=");
}

#[test]
fn real_url_broker_preserves_origin_policy_without_discovery_variables() {
    let t = nono_test!("shim-url-env");
    let profile = t.write_profile(
        "shim-url-env",
        r#"{
            "meta": {"name": "shim-url-env"},
            "workdir": {"access": "read"},
            "command_policies": {
                "commands": {
                    "sh": {
                        "executable": "/bin/sh",
                        "sandbox": {
                            "fs_read": ["."],
                            "open_urls": {"allow_origins": ["https://example.com"]}
                        }
                    }
                }
            }
        }"#,
    );
    t.run()
        .profile(&profile)
        .allow_cwd()
        .no_rollback()
        .exec(Argv::new("sh").arg("-c").arg(
            r#"
            test -z "${NONO_TOOL_SANDBOX_URL_SOCKET+x}" || exit 91
            unset NONO_TOOL_SANDBOX_SOCKET NONO_TOOL_SANDBOX_SHIM_DIR NONO_TOOL_SANDBOX_URL_SOCKET
            open https://denied.example.org/login
            "#,
        ))
        .assert_failure("the broker denies origins outside the active command's policy")
        .assert_stderr_contains("denied opening URL");
}
