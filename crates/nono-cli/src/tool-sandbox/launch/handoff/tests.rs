use super::*;
use serde_json::json;
use std::process::Stdio;

fn spec() -> ToolSandboxChildLaunchSpec {
    serde_json::from_value(json!({
        "real_binary":[], "executable_kind":"test", "interpreter":null,
        "interpreter_args":[], "argv":[], "env":[], "cwd":[], "stdio_mode":"direct_fds",
        "stdio_limits":null, "caps":{"fs":[], "unix_sockets":[], "platform_rules":[],
            "network_blocked":true, "proxy_port":null, "proxy_bind_ports":[],
            "tcp_connect_ports":[], "tcp_bind_ports":[]},
        "expected_dev":0, "expected_ino":0, "expected_size":0,
        "expected_mtime_nanos":0, "expected_sha256":"test"
    }))
    .expect("specification")
}

const CHILD_TEST: &str = "tool_sandbox::launch::handoff::tests::handoff_child";

#[test]
fn handoff_child() {
    let Ok(expected) = std::env::var("HANDOFF_TEST_EXPECT") else {
        return;
    };
    let fd: RawFd = std::env::var(TOOL_SANDBOX_LAUNCH_FD_ENV)
        .expect("descriptor")
        .parse()
        .expect("descriptor number");
    let result = receive_launch_spec();
    // SAFETY: F_GETFD validates the descriptor without changing it.
    assert_eq!(
        unsafe { libc::fcntl(fd, libc::F_GETFD) },
        -1,
        "the tool must not inherit the handoff descriptor"
    );
    if expected == "success" {
        assert_eq!(
            result.expect("authenticated handoff").expected_sha256,
            "test"
        );
    } else {
        let error = result.expect_err("invalid handoff").to_string();
        assert!(error.contains(&expected), "{error}");
    }
}

#[test]
fn hands_off_permissions_once_without_exposing_the_channel_to_the_tool() {
    let mut launcher = prepare_launcher_command(&spec()).expect("launcher");
    launcher
        .args(["--exact", CHILD_TEST, "--nocapture"])
        .env("HANDOFF_TEST_EXPECT", "success")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = launcher.spawn().expect("handoff");
    assert!(launcher.spawn().is_err(), "one child per handoff");
    let output = child.wait_with_output().expect("child");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rejects_replayed_challenges_oversized_frames_and_truncated_permissions() {
    for expected in ["challenge does not match", "frame too large", "IPC payload"] {
        let (mut parent, child) = UnixStream::pair().expect("pair");
        set_timeout(&parent).expect("timeout");
        let fd = child.as_raw_fd();
        let mut command = Command::new(std::env::current_exe().expect("test binary"));
        command
            .args(["--exact", CHILD_TEST, "--nocapture"])
            .env(TOOL_SANDBOX_LAUNCH_FD_ENV, fd.to_string())
            .env("HANDOFF_TEST_EXPECT", expected)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // SAFETY: child owns the descriptor until spawn completes; only fcntl runs.
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let process = command.spawn().expect("child");
        drop(child);
        let mut nonce = [0u8; 32];
        parent.read_exact(&mut nonce).expect("fresh challenge");
        if expected == "challenge does not match" {
            nonce[0] ^= 1;
        }
        parent.write_all(&nonce).expect("response");
        if expected == "frame too large" {
            parent
                .write_all(&((MAX_FRAME + 1) as u32).to_be_bytes())
                .expect("length");
        } else if expected == "IPC payload" {
            parent.write_all(&100u32.to_be_bytes()).expect("length");
            parent.write_all(b"{}").expect("truncated payload");
        }
        drop(parent);
        let output = process.wait_with_output().expect("wait");
        assert!(
            output.status.success(),
            "{expected}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn oversized_permissions_are_rejected_before_spawning() {
    let mut spec = spec();
    spec.expected_sha256 = "x".repeat(MAX_FRAME + 1);
    assert!(prepare_launcher_command(&spec).is_err());
}
