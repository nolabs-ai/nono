//! Child-side URL-open helper for brokered tool-sandbox commands.
//!
//! A brokered child (e.g. `gk`) runs under a tight `process-exec` allowlist and
//! cannot launch `/usr/bin/open`, `xdg-open`, or a shell. To open a browser for
//! an OAuth2 login it instead execs the `open` shim — a copy of the nono binary
//! materialized in the shim directory and therefore exec-allowed. When invoked
//! that way, this helper connects to the runtime's dedicated URL listener
//! socket (`NONO_TOOL_SANDBOX_URL_SOCKET`) and asks the unsandboxed runtime to
//! validate and open the URL.
//!
//! The runtime resolves the requesting command from the connecting PID, so the
//! `command` field on the request is advisory (audit only) and is never trusted
//! for the origin allow-list decision.

use crate::tool_sandbox::protocol::{
    TOOL_SANDBOX_URL_SOCKET_ENV, ToolSandboxOpenUrlRequest, ToolSandboxOpenUrlResponse, read_frame,
    write_frame,
};
use nono::{NonoError, Result};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

/// Reserved shim name used to intercept browser opens inside a brokered child.
pub(crate) const URL_OPEN_SHIM_NAME: &str = "open";

/// Returns true if the current process is the brokered-child URL-open shim:
/// invoked as the reserved shim name with the URL socket env var present.
pub(crate) fn current_exe_is_url_open_shim() -> bool {
    if std::env::var_os(TOOL_SANDBOX_URL_SOCKET_ENV).is_none() {
        return false;
    }
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    exe.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == URL_OPEN_SHIM_NAME)
}

/// Entry point for the brokered-child URL-open shim.
///
/// Scans argv for the first `http(s)://` URL, forwards it to the runtime over
/// the URL listener socket, and exits with success only if the runtime opened
/// the browser.
pub(crate) fn run_url_open_shim() -> Result<()> {
    let socket_path = std::env::var_os(TOOL_SANDBOX_URL_SOCKET_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| {
            NonoError::SandboxInit(
                "tool-sandbox URL-open shim invoked without NONO_TOOL_SANDBOX_URL_SOCKET"
                    .to_string(),
            )
        })?;

    // A non-UTF-8 argument cannot be an http(s) URL
    let url = std::env::args_os()
        .skip(1)
        .filter_map(|arg| arg.into_string().ok())
        .find(|arg| arg.starts_with("http://") || arg.starts_with("https://"))
        .ok_or_else(|| {
            NonoError::SandboxInit(
                "tool-sandbox URL-open shim: no http(s) URL argument found".to_string(),
            )
        })?;

    // Advisory only: the runtime resolves the real command from the connecting
    // PID. Sent unset because the child cannot be trusted to name itself.
    let request = ToolSandboxOpenUrlRequest {
        command: String::new(),
        url: url.clone(),
    };

    let mut stream = UnixStream::connect(&socket_path).map_err(|err| {
        NonoError::SandboxInit(format!(
            "tool-sandbox URL-open shim failed to connect to {}: {err}",
            socket_path.display()
        ))
    })?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(120)))
        .map_err(|err| {
            NonoError::SandboxInit(format!(
                "tool-sandbox URL-open shim set_read_timeout: {err}"
            ))
        })?;

    write_frame(&mut stream, &request)?;
    let response: ToolSandboxOpenUrlResponse = read_frame(&mut stream)?;

    if response.success {
        Ok(())
    } else {
        let reason = response
            .error
            .unwrap_or_else(|| "unknown error".to_string());
        Err(NonoError::SandboxInit(format!(
            "tool-sandbox denied opening URL: {reason}"
        )))
    }
}
