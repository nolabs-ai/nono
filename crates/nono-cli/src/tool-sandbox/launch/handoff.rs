use crate::tool_sandbox::protocol::{
    MAX_FRAME, TOOL_SANDBOX_LAUNCH_FD_ENV, TOOL_SANDBOX_LAUNCH_SPEC_ENV,
    ToolSandboxChildLaunchSpec, read_frame,
};
use nix::libc;
use nono::{NonoError, Result};
use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::Duration;
use zeroize::Zeroizing;

mod auth;
#[cfg(test)]
mod tests;

const HANDOFF_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) struct LauncherCommand {
    command: Command,
    parent: UnixStream,
    child: Option<UnixStream>,
    payload: Zeroizing<Vec<u8>>,
}

pub(crate) fn prepare_launcher_command(
    spec: &ToolSandboxChildLaunchSpec,
) -> Result<LauncherCommand> {
    let payload = serde_json::to_vec(spec)
        .map_err(|err| handoff_error(format!("cannot serialize launch permissions: {err}")))?;
    if payload.len() > MAX_FRAME {
        return Err(handoff_error(
            "launch permissions exceed the IPC size limit",
        ));
    }
    let (parent, child) = UnixStream::pair().map_err(NonoError::CommandExecution)?;
    set_timeout(&parent).map_err(NonoError::CommandExecution)?;
    let fd = child.as_raw_fd();
    let nono_exe = std::env::current_exe().map_err(NonoError::CommandExecution)?;
    let mut command = Command::new(nono_exe);
    command
        .env_clear()
        .env(TOOL_SANDBOX_LAUNCH_FD_ENV, fd.to_string());
    for variable in ["HOME", "RUST_LOG", "TOOL_SANDBOX_PROFILE_HOTPATH"] {
        if let Some(value) = std::env::var_os(variable) {
            command.env(variable, value);
        }
    }
    // SAFETY: the child only changes descriptor flags with fcntl. LauncherCommand
    // owns this descriptor until spawn completes; every other endpoint stays CLOEXEC.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(LauncherCommand {
        command,
        parent,
        child: Some(child),
        payload: Zeroizing::new(payload),
    })
}

impl LauncherCommand {
    pub(crate) fn spawn(&mut self) -> std::io::Result<crate::owned_children::OwnedChild> {
        if self.child.is_none() {
            return Err(std::io::Error::other(
                "command-mediation handoff already consumed",
            ));
        }
        let mut child = crate::owned_children::spawn(&mut self.command)?;
        drop(self.child.take());
        let result = (|| {
            let mut challenge = [0u8; 32];
            self.parent.read_exact(&mut challenge)?;
            self.parent.write_all(&challenge)?;
            self.parent
                .write_all(&(self.payload.len() as u32).to_be_bytes())?;
            self.parent.write_all(&self.payload)
        })();
        if let Err(error) = result {
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::other(format!(
                "command-mediation supervisor handoff failed: {error}"
            )));
        }
        Ok(child)
    }
}

impl Deref for LauncherCommand {
    type Target = Command;

    fn deref(&self) -> &Command {
        &self.command
    }
}

impl DerefMut for LauncherCommand {
    fn deref_mut(&mut self) -> &mut Command {
        &mut self.command
    }
}

pub(crate) fn receive_launch_spec() -> Result<ToolSandboxChildLaunchSpec> {
    if std::env::var_os(TOOL_SANDBOX_LAUNCH_SPEC_ENV).is_some() {
        return Err(handoff_error(
            "file-based launch specifications are not accepted",
        ));
    }
    let fd = std::env::var(TOOL_SANDBOX_LAUNCH_FD_ENV)
        .ok()
        .and_then(|value| value.parse::<RawFd>().ok())
        .filter(|fd| *fd > libc::STDERR_FILENO)
        .ok_or_else(|| handoff_error("missing or invalid supervisor descriptor"))?;
    // SAFETY: fcntl validates the untrusted descriptor and returns a fresh fd.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(handoff_error(format!(
            "invalid supervisor descriptor: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: duplicate is newly owned; the original belongs to this launcher.
    let owned = unsafe { OwnedFd::from_raw_fd(duplicate) };
    unsafe {
        libc::close(fd);
    }
    let mut socket = UnixStream::from(owned);
    set_timeout(&socket).map_err(|err| handoff_error(err.to_string()))?;
    let parent = auth::authenticate_parent(socket.as_raw_fd())?;
    let challenge: [u8; 32] = rand::random();
    socket
        .write_all(&challenge)
        .map_err(|err| handoff_error(err.to_string()))?;
    let mut response = [0u8; 32];
    socket
        .read_exact(&mut response)
        .map_err(|err| handoff_error(err.to_string()))?;
    if response != challenge {
        return Err(handoff_error("supervisor challenge does not match"));
    }
    let spec = read_frame(&mut socket)?;
    if auth::authenticate_parent(socket.as_raw_fd())? != parent {
        return Err(handoff_error("supervisor identity changed during launch"));
    }
    Ok(spec)
}

fn set_timeout(socket: &UnixStream) -> std::io::Result<()> {
    socket.set_read_timeout(Some(HANDOFF_TIMEOUT))?;
    socket.set_write_timeout(Some(HANDOFF_TIMEOUT))
}

fn handoff_error(reason: impl std::fmt::Display) -> NonoError {
    NonoError::SandboxInit(format!(
        "command-mediation launch rejected: {reason}; launch permissions must come from the session supervisor"
    ))
}
