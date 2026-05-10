use crate::cli::{Commands, RunArgs};
use crate::sandbox_prepare::resolve_detached_cwd_prompt_response;
use crate::{
    output, session, update_check, DETACHED_CWD_PROMPT_RESPONSE_ENV, DETACHED_LAUNCH_ENV,
    DETACHED_SESSION_ID_ENV,
};
#[cfg(unix)]
use nix::libc;
use nono::{NonoError, Result};
#[cfg(unix)]
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

pub(crate) fn allows_pre_exec_update_check(command: &Commands) -> bool {
    !matches!(
        command,
        Commands::Run(_) | Commands::Shell(_) | Commands::Wrap(_) | Commands::Completions(_)
    )
}

pub(crate) fn run_detached_launch(args: RunArgs, silent: bool) -> Result<()> {
    let cwd_prompt_response = resolve_detached_cwd_prompt_response(&args.sandbox, silent)?;
    let session_id = session::generate_session_id();
    let exe = std::env::current_exe().map_err(|e| {
        NonoError::SandboxInit(format!("Failed to resolve current executable: {e}"))
    })?;
    let (startup_log_path, startup_log_stdio) = create_detached_startup_log(&session_id)?;
    let mut child = Command::new(exe);
    child.args(std::env::args_os().skip(1));
    child.env(DETACHED_LAUNCH_ENV, "1");
    child.env(DETACHED_SESSION_ID_ENV, &session_id);
    if let Some(response) = cwd_prompt_response {
        child.env(DETACHED_CWD_PROMPT_RESPONSE_ENV, response.as_env_value());
    }
    child.stdin(Stdio::null());
    child.stdout(Stdio::null());
    child.stderr(startup_log_stdio);

    #[cfg(unix)]
    unsafe {
        child.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut launched = child
        .spawn()
        .map_err(|e| NonoError::SandboxInit(format!("Failed to launch detached session: {e}")))?;

    let session_path = session::session_file_path(&session_id)?;
    let attach_path = session::session_socket_path(&session_id)?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        if session_path.exists() && attach_path.exists() {
            cleanup_startup_log(&startup_log_path);
            print_detached_launch_banner(&session_id, args.name.as_deref(), silent);
            return Ok(());
        }

        if let Some(status) = launched.try_wait().map_err(|e| {
            NonoError::SandboxInit(format!("Failed to monitor detached launch: {e}"))
        })? {
            let detail = read_startup_log_summary(&startup_log_path);
            cleanup_startup_log(&startup_log_path);
            return Err(NonoError::SandboxInit(format!(
                "Detached session failed to start (exit status: {}){}",
                status,
                detail
                    .map(|summary| format!(": {summary}"))
                    .unwrap_or_default()
            )));
        }

        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    terminate_detached_launch(&mut launched);
    cleanup_startup_log(&startup_log_path);
    Err(NonoError::SandboxInit(
        "Detached session failed to become attachable within startup timeout".to_string(),
    ))
}

pub(crate) fn show_update_notification(
    handle: &mut Option<update_check::UpdateCheckHandle>,
    silent: bool,
) {
    if let Some(handle) = handle.take() {
        if let Some(info) = handle.take_result() {
            output::print_update_notification(&info, silent);
        }
    }
}

fn print_detached_launch_banner(session_id: &str, session_name: Option<&str>, silent: bool) {
    if silent {
        return;
    }

    eprintln!("Started detached session {}.", session_id);
    if let Some(name) = session_name {
        eprintln!("Name: {name}");
    }
    eprintln!("Attach with: nono attach {}", session_id);
}

fn create_detached_startup_log(session_id: &str) -> Result<(PathBuf, Stdio)> {
    let prefix = format!(".nono-detached-startup-{session_id}-");
    let mut builder = tempfile::Builder::new();
    builder.prefix(&prefix).suffix(".log");

    let file = builder.tempfile_in(std::env::temp_dir()).map_err(|e| {
        NonoError::SandboxInit(format!("Failed to create detached startup log file: {e}"))
    })?;

    let (file, path) = file.keep().map_err(|e| {
        NonoError::SandboxInit(format!("Failed to persist detached startup log: {e}"))
    })?;

    Ok((path, Stdio::from(file)))
}

fn read_startup_log_summary(path: &Path) -> Option<String> {
    let contents = std::fs::read_to_string(path).ok()?;
    summarize_startup_log_contents(&contents)
}

fn summarize_startup_log_contents(contents: &str) -> Option<String> {
    let lines: Vec<String> = contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(normalize_startup_log_line)
        .collect();

    let filtered: Vec<&str> = lines
        .iter()
        .map(String::as_str)
        .filter(|line| !is_startup_log_boilerplate(line))
        .collect();

    if let Some(headline) = filtered
        .iter()
        .copied()
        .find(|line| is_startup_headline(line))
    {
        return Some(headline.to_string());
    }

    let selected = if filtered.is_empty() {
        lines.iter().map(String::as_str).take(1).collect::<Vec<_>>()
    } else {
        filtered.into_iter().take(3).collect::<Vec<_>>()
    };

    if selected.is_empty() {
        None
    } else {
        Some(selected.join(" | "))
    }
}

fn is_startup_headline(line: &str) -> bool {
    line.contains("(exit code ")
        || line.starts_with("Command killed by signal")
        || line.starts_with("Permission denied")
        || line.starts_with("Failed to execute command")
        || line.starts_with("Command not found")
}

fn normalize_startup_log_line(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    let trimmed = trimmed.trim_start_matches("nono: ").trim();
    let trimmed = strip_startup_log_prefix(trimmed);
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn strip_startup_log_prefix(line: &str) -> &str {
    const PREFIXES: [&str; 2] = ["Applying sandbox...", "mode supervised (supervisor)"];

    let mut remaining = line;
    loop {
        let mut stripped = false;
        for prefix in PREFIXES {
            if let Some(rest) = remaining.strip_prefix(prefix) {
                remaining = rest.trim();
                stripped = true;
            }
        }

        if !stripped {
            return remaining;
        }
    }
}

fn is_startup_log_boilerplate(line: &str) -> bool {
    line.starts_with("nono v")
        || line == "Capabilities:"
        || line.starts_with('─')
        || line.starts_with("mode ")
        || line.starts_with("Applying sandbox...")
        || line.starts_with("Landlock V")
        || line.starts_with("kernel  ")
        || line == "NONO DIAGNOSTIC"
        || is_capability_summary_line(line)
        || line == "[nono]"
        || line == "[nono] Sandbox policy:"
        || line == "[nono]   Allowed paths:"
        || line.starts_with("[nono]     ")
        || line.starts_with("[nono]   Network:")
        || line.starts_with("[nono] To grant additional access")
        || line.starts_with("[nono]   --")
}

fn is_capability_summary_line(line: &str) -> bool {
    let trimmed = line.trim();

    if trimmed.starts_with("+ ") && trimmed.contains("system/group paths") {
        return true;
    }

    if trimmed == "outbound allowed"
        || trimmed == "outbound blocked"
        || trimmed.starts_with("proxy localhost:")
        || trimmed.starts_with("localhost:")
    {
        return true;
    }

    if let Some(rest) = trimmed.strip_prefix("net") {
        let rest = rest.trim();
        if rest == "outbound allowed"
            || rest == "outbound blocked"
            || rest.starts_with("proxy localhost:")
        {
            return true;
        }
    }

    if let Some(rest) = trimmed.strip_prefix("ipc") {
        let rest = rest.trim();
        if rest.starts_with("localhost:") {
            return true;
        }
    }

    let access_prefix = ["r+w", "r", "w"];
    access_prefix.iter().any(|prefix| {
        trimmed.starts_with(prefix)
            && (trimmed.contains(" (dir)") || trimmed.contains(" (file)"))
            && trimmed.contains('/')
    })
}

fn cleanup_startup_log(path: &Path) {
    let _ = std::fs::remove_file(path);
}

fn terminate_detached_launch(child: &mut Child) {
    #[cfg(unix)]
    {
        let pid = child.id() as i32;
        if pid > 0 {
            unsafe {
                libc::kill(-pid, libc::SIGTERM);
            }
        }
        for _ in 0..10 {
            if child.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        if pid > 0 {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
    }

    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::summarize_startup_log_contents;

    #[test]
    fn startup_log_summary_prefers_exit_headline_over_footer_hints() {
        let contents = r#"
nono v0.22.1
Capabilities:
[nono] Failed to execute command (exit code 127).
[nono]
[nono] Sandbox policy:
[nono]   Allowed paths:
[nono]     /tmp (read+write, dir)
[nono]   Network: allowed
[nono]
[nono] To grant additional access, re-run with:
[nono]   --allow <path>     read+write access to directory
[nono]   --allow-net        unrestricted network for this session
"#;

        assert_eq!(
            summarize_startup_log_contents(contents).as_deref(),
            Some("[nono] Failed to execute command (exit code 127).")
        );
    }

    #[test]
    fn startup_log_summary_preserves_real_error_lines() {
        let contents = r#"
2026-03-23T18:08:00.249207Z ERROR Sandbox initialization failed: Profile inheritance error: circular dependency detected: claude-code -> claude-code
"#;

        assert_eq!(
            summarize_startup_log_contents(contents).as_deref(),
            Some("2026-03-23T18:08:00.249207Z ERROR Sandbox initialization failed: Profile inheritance error: circular dependency detected: claude-code -> claude-code")
        );
    }

    #[test]
    fn startup_log_summary_extracts_error_after_applying_sandbox_prefix() {
        let contents = r#"
nono v0.22.1
mode supervised (supervisor)
Applying sandbox...[nono] Command not found (exit code 127).
[nono]
[nono] Sandbox policy:
[nono]   Allowed paths:
[nono]     /tmp (read+write, dir)
[nono]   Network: allowed
[nono]
[nono] To grant additional access, re-run with:
[nono]   --allow <path>     read+write access to directory
[nono]   --allow-net        unrestricted network for this session
"#;

        assert_eq!(
            summarize_startup_log_contents(contents).as_deref(),
            Some("[nono] Command not found (exit code 127).")
        );
    }

    #[test]
    fn startup_log_summary_skips_capability_rows_in_detached_failures() {
        let contents = r#"
nono v0.25.0
Capabilities:
r+w  /home/luke/.opencode (dir)
r+w  /home/luke/.config/opencode (dir)
r+w  /home/luke/.cache/opencode (dir)
outbound allowed
mode supervised (supervisor)
Applying sandbox...[nono] Failed to execute command (exit code 127).
"#;

        assert_eq!(
            summarize_startup_log_contents(contents).as_deref(),
            Some("[nono] Failed to execute command (exit code 127).")
        );
    }

    #[test]
    fn startup_log_summary_skips_network_badge_rows_in_detached_failures() {
        let contents = r#"
nono v0.25.0
Capabilities:
net  outbound allowed
mode supervised (supervisor)
Applying sandbox...NONO DIAGNOSTIC
Failed to execute command (exit code 127).
"#;

        assert_eq!(
            summarize_startup_log_contents(contents).as_deref(),
            Some("Failed to execute command (exit code 127).")
        );
    }

    #[test]
    fn startup_log_summary_collapses_exec_failure_path_details() {
        let contents = r#"
nono v0.25.0
Capabilities:
net  outbound allowed
mode supervised (supervisor)
Applying sandbox...NONO DIAGNOSTIC
Failed to execute command (exit code 127).
The executable '/home/linuxbrew/.linuxbrew/bin/opencode' was resolved at:
/home/linuxbrew/.linuxbrew/bin/opencode
"#;

        assert_eq!(
            summarize_startup_log_contents(contents).as_deref(),
            Some("Failed to execute command (exit code 127).")
        );
    }
}
