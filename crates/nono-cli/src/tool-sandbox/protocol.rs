use nix::libc;
use nono::supervisor::socket::{recv_fd_via_socket, send_fd_via_socket};
use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

pub(crate) const TOOL_SANDBOX_SOCKET_ENV: &str = "NONO_TOOL_SANDBOX_SOCKET";
pub(crate) const TOOL_SANDBOX_SHIM_DIR_ENV: &str = "NONO_TOOL_SANDBOX_SHIM_DIR";
pub(crate) const TOOL_SANDBOX_LAUNCH_SPEC_ENV: &str = "NONO_TOOL_SANDBOX_LAUNCH_SPEC";
/// Path to the runtime's dedicated URL-open listener socket. Injected into the
/// brokered child so the open-url helper can reach the unsandboxed runtime.
pub(crate) const TOOL_SANDBOX_URL_SOCKET_ENV: &str = "NONO_TOOL_SANDBOX_URL_SOCKET";

/// Read/write timeout the runtime applies to an accepted URL-open connection so
/// a slow or idle client cannot stall the handler (and, on Linux, the
/// single-threaded supervisor loop that drives it).
pub(crate) const TOOL_SANDBOX_URL_IO_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(10);

/// Request from a brokered child to open a URL in the user's browser.
///
/// Sent on the dedicated URL listener socket (one message per connection, no
/// fd passing). `command` is the brokered command name, used by the runtime to
/// look up that command's `open_urls` policy for per-command origin validation.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ToolSandboxOpenUrlRequest {
    pub(crate) command: String,
    pub(crate) url: String,
}

/// Response to a [`ToolSandboxOpenUrlRequest`].
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ToolSandboxOpenUrlResponse {
    pub(crate) success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

const MAX_FRAME: usize = 1024 * 1024;
const MAX_ARGC: usize = 4096;
const MAX_ARG: usize = 128 * 1024;
const MAX_ENV: usize = 4096;
const MAX_ENV_ENTRY: usize = 128 * 1024;
const MAX_CWD: usize = 4096;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ToolSandboxShimRequest {
    pub(crate) command: String,
    pub(crate) argv: Vec<Vec<u8>>,
    pub(crate) env: Vec<Vec<u8>>,
    pub(crate) cwd: Vec<u8>,
    pub(crate) stdio_tty: [bool; 3],
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ToolSandboxShimResponse {
    pub(crate) exit_code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
    /// Captured stdout bytes for the `Capture` intercept action.
    /// Empty for `Passthrough` and `Respond` actions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) captured_stdout: Vec<u8>,
}

impl ToolSandboxShimResponse {
    fn ok(exit_code: i32) -> Self {
        Self {
            exit_code,
            error: None,
            captured_stdout: Vec::new(),
        }
    }

    fn err(exit_code: i32, error: String) -> Self {
        Self {
            exit_code,
            error: Some(error),
            captured_stdout: Vec::new(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ToolSandboxChildLaunchSpec {
    pub(crate) real_binary: Vec<u8>,
    pub(crate) executable_kind: String,
    pub(crate) interpreter: Option<Vec<u8>>,
    pub(crate) interpreter_args: Vec<String>,
    pub(crate) argv: Vec<Vec<u8>>,
    pub(crate) env: Vec<Vec<u8>>,
    pub(crate) cwd: Vec<u8>,
    pub(crate) stdio_mode: String,
    pub(crate) stdio_limits: Option<StdioLimitSpec>,
    pub(crate) caps: ChildCapsSpec,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) allowed_exec_paths: Vec<Vec<u8>>,
    pub(crate) expected_dev: u64,
    pub(crate) expected_ino: u64,
    pub(crate) expected_size: u64,
    pub(crate) expected_mtime_nanos: i128,
    pub(crate) expected_sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ChildCapsSpec {
    pub(crate) fs: Vec<FsGrantSpec>,
    pub(crate) unix_sockets: Vec<UnixSocketGrantSpec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) platform_rules: Vec<String>,
    pub(crate) network_blocked: bool,
    pub(crate) proxy_port: Option<u16>,
    pub(crate) proxy_bind_ports: Vec<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) proxy_bind_port_ranges: Vec<(u16, u16)>,
    pub(crate) tcp_connect_ports: Vec<u16>,
    pub(crate) tcp_bind_ports: Vec<u16>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct FsGrantSpec {
    pub(crate) path: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) original_path: Option<Vec<u8>>,
    pub(crate) access: String,
    pub(crate) is_file: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct UnixSocketGrantSpec {
    pub(crate) path: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) original_path: Option<Vec<u8>>,
    pub(crate) mode: String,
    pub(crate) is_directory: bool,
}

pub(crate) struct StdioFds {
    pub(crate) stdin: OwnedFd,
    pub(crate) stdout: OwnedFd,
    pub(crate) stderr: OwnedFd,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StdioLimitSpec {
    pub(crate) stdout: Option<StdioStreamLimitSpec>,
    pub(crate) stderr: Option<StdioStreamLimitSpec>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) struct StdioStreamLimitSpec {
    pub(crate) max_bytes: u64,
    pub(crate) on_limit: StdioLimitActionSpec,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StdioLimitActionSpec {
    Truncate,
    Terminate,
    Deny,
}

pub(crate) fn validate_ipc_request(request: &ToolSandboxShimRequest) -> Result<()> {
    if request.argv.is_empty() {
        return Err(NonoError::SandboxInit(
            "tool-sandbox IPC rejected empty argv".to_string(),
        ));
    }
    if request.argv.len() > MAX_ARGC {
        return Err(NonoError::SandboxInit(
            "tool-sandbox IPC argc limit exceeded".to_string(),
        ));
    }
    if request.env.len() > MAX_ENV {
        return Err(NonoError::SandboxInit(
            "tool-sandbox IPC env limit exceeded".to_string(),
        ));
    }
    if request.cwd.len() > MAX_CWD || request.cwd.contains(&0) {
        return Err(NonoError::SandboxInit(
            "tool-sandbox IPC cwd rejected".to_string(),
        ));
    }
    for arg in &request.argv {
        if arg.len() > MAX_ARG || arg.contains(&0) {
            return Err(NonoError::SandboxInit(
                "tool-sandbox IPC argv rejected".to_string(),
            ));
        }
    }
    for entry in &request.env {
        if entry.len() > MAX_ENV_ENTRY || entry.contains(&0) {
            return Err(NonoError::SandboxInit(
                "tool-sandbox IPC env rejected".to_string(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn write_response(
    stream: &mut UnixStream,
    exit_code: i32,
    error: Option<String>,
    captured_stdout: Vec<u8>,
) -> Result<()> {
    let mut response = match error {
        None => ToolSandboxShimResponse::ok(exit_code),
        Some(error) => ToolSandboxShimResponse::err(exit_code, error),
    };
    response.captured_stdout = captured_stdout;
    write_frame(stream, &response)
}

pub(crate) fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
    let payload = serde_json::to_vec(value).map_err(|err| {
        NonoError::SandboxInit(format!("failed to serialize tool-sandbox IPC frame: {err}"))
    })?;
    if payload.len() > MAX_FRAME {
        return Err(NonoError::SandboxInit(
            "tool-sandbox IPC frame too large".to_string(),
        ));
    }
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .map_err(|err| {
            NonoError::SandboxInit(format!("failed to write tool-sandbox IPC length: {err}"))
        })?;
    stream.write_all(&payload).map_err(|err| {
        NonoError::SandboxInit(format!("failed to write tool-sandbox IPC payload: {err}"))
    })
}

pub(crate) fn read_frame<T: for<'de> Deserialize<'de>>(stream: &mut UnixStream) -> Result<T> {
    let mut len = [0_u8; 4];
    stream.read_exact(&mut len).map_err(|err| {
        NonoError::SandboxInit(format!("failed to read tool-sandbox IPC length: {err}"))
    })?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(NonoError::SandboxInit(
            "tool-sandbox IPC frame too large".to_string(),
        ));
    }
    let mut payload = vec![0_u8; len];
    stream.read_exact(&mut payload).map_err(|err| {
        NonoError::SandboxInit(format!("failed to read tool-sandbox IPC payload: {err}"))
    })?;
    serde_json::from_slice(&payload).map_err(|err| {
        NonoError::SandboxInit(format!("failed to parse tool-sandbox IPC frame: {err}"))
    })
}

/// Send a 1-byte acknowledgement that the request frame has been fully read.
///
/// The runtime calls this after `read_frame` completes and before `recv_stdio_fds`.
/// The shim waits for this ack before calling `send_stdio_fds`, ensuring the
/// socket receive buffer is empty when `sendmsg` carries SCM_RIGHTS ancillary
/// data. On macOS, `sendmsg` with ancillary data on a stream socket returns
/// EMSGSIZE if the peer's receive buffer cannot accommodate the control message
/// atomically — this ack eliminates that race.
pub(crate) fn send_frame_ack(stream: &mut UnixStream) -> Result<()> {
    stream
        .write_all(&[0u8])
        .map_err(|e| NonoError::SandboxInit(format!("tool-sandbox: failed to send frame ack: {e}")))
}

/// Receive the 1-byte acknowledgement sent by `send_frame_ack`.
pub(crate) fn recv_frame_ack(stream: &mut UnixStream) -> Result<()> {
    let mut buf = [0u8; 1];
    stream.read_exact(&mut buf).map_err(|e| {
        NonoError::SandboxInit(format!("tool-sandbox: failed to receive frame ack: {e}"))
    })
}

pub(crate) fn send_stdio_fds(stream: &UnixStream) -> Result<()> {
    for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        send_fd_via_socket(stream.as_raw_fd(), fd)?;
    }
    Ok(())
}

pub(crate) fn recv_stdio_fds(stream: &UnixStream) -> Result<StdioFds> {
    let stdin = recv_fd_via_socket(stream.as_raw_fd())?;
    let stdout = recv_fd_via_socket(stream.as_raw_fd())?;
    let stderr = recv_fd_via_socket(stream.as_raw_fd())?;
    Ok(StdioFds {
        stdin,
        stdout,
        stderr,
    })
}
