use crate::tool_sandbox::protocol::{TOOL_SANDBOX_LAUNCH_SPEC_ENV, ToolSandboxChildLaunchSpec};
use nono::{NonoError, Result};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn prepare_launcher_command(spec_path: &Path) -> Result<Command> {
    let nono_exe = std::env::current_exe().map_err(|err| {
        NonoError::SandboxInit(format!("failed to locate nono executable: {err}"))
    })?;
    let mut command = Command::new(nono_exe);
    command
        .env_clear()
        .env(TOOL_SANDBOX_LAUNCH_SPEC_ENV, spec_path);
    // Forward HOME to the launcher process (NOT the sandboxed child — the child
    // is execve'd with the filtered `spec.env`, so this HOME never reaches it).
    // The launcher is what calls `Sandbox::apply`, so the profile it generates
    // is built in an environment that must match the runtime's.
    if let Some(value) = std::env::var_os("HOME") {
        command.env("HOME", value);
    }
    // Forward RUST_LOG so the launcher process can initialize a tracing
    // subscriber at the same level as the parent. The launcher re-exec returns
    // from main() before init_tracing() runs, so without this the library's
    // `debug!("Generated Seatbelt profile…")` emitted during Sandbox::apply has
    // neither a subscriber nor a filter and is silently dropped — which is why
    // the child's profile never appears under `-vv`/RUST_LOG=debug.
    if let Some(value) = std::env::var_os("RUST_LOG") {
        command.env("RUST_LOG", value);
    }
    if let Some(value) = std::env::var_os("TOOL_SANDBOX_PROFILE_HOTPATH") {
        command.env("TOOL_SANDBOX_PROFILE_HOTPATH", value);
    }
    Ok(command)
}

pub(crate) fn write_launch_spec(
    runtime_dir: &Path,
    spec: &ToolSandboxChildLaunchSpec,
) -> Result<PathBuf> {
    let path = unique_runtime_path(runtime_dir, "launch", "json");
    let json = serde_json::to_vec(spec).map_err(|err| {
        NonoError::ConfigParse(format!(
            "failed to serialize tool-sandbox launch spec: {err}"
        ))
    })?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&path)
        .map_err(|source| NonoError::ConfigWrite {
            path: path.clone(),
            source,
        })?;
    file.write_all(&json)
        .map_err(|source| NonoError::ConfigWrite {
            path: path.clone(),
            source,
        })?;
    Ok(path)
}

pub(crate) fn remove_launch_spec(path: &Path) {
    let _ = fs::remove_file(path);
}

pub(crate) fn exit_status_code(status: std::process::ExitStatus) -> i32 {
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(126)
}

fn unique_runtime_path(base: &Path, prefix: &str, suffix: &str) -> PathBuf {
    let nonce = rand::random::<u64>();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let mut name = format!("{prefix}-{}-{now}-{nonce:x}", std::process::id());
    if !suffix.is_empty() {
        name.push('.');
        name.push_str(suffix);
    }
    base.join(name)
}
