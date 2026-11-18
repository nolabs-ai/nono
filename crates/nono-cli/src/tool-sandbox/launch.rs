use std::os::unix::process::ExitStatusExt;

#[cfg(target_os = "macos")]
mod handoff;
#[cfg(target_os = "macos")]
pub(crate) use handoff::{LauncherCommand, prepare_launcher_command, receive_launch_spec};

pub(crate) fn exit_status_code(status: std::process::ExitStatus) -> i32 {
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(126)
}
