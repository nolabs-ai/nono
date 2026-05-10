//! Session management command implementations.
//!
//! Handles `nono ps`, `nono stop`, `nono detach`, `nono attach`, `nono logs`,
//! `nono inspect`, and `nono prune`.

use crate::cli::{AttachArgs, DetachArgs, InspectArgs, LogsArgs, PruneArgs, PsArgs, StopArgs};
use crate::command_display::{format_command_line, truncate_chars};
use crate::session::{self, SessionAttachment, SessionRecord, SessionStatus};
use colored::Colorize;
use nix::libc;
use nono::{NonoError, Result};
use std::collections::VecDeque;
use std::io::{BufRead, Seek, SeekFrom};
use std::path::Path;
use tracing::debug;

/// Refuse to run if we're inside a nono sandbox.
///
/// Commands that send signals or delete files (stop, prune) must not run
/// inside a sandbox — a sandboxed agent could use them to kill other
/// supervisors or tamper with session state.
fn reject_if_sandboxed(command: &str) -> Result<()> {
    if std::env::var_os("NONO_CAP_FILE").is_some() {
        return Err(NonoError::ConfigParse(format!(
            "`nono {}` cannot be used inside a sandbox.",
            command
        )));
    }
    Ok(())
}

/// Dispatch `nono ps`.
pub fn run_ps(args: &PsArgs) -> Result<()> {
    let sessions = session::list_sessions()?;

    // Filter: by default show live sessions, whether attached or detached.
    let filtered: Vec<&SessionRecord> = sessions
        .iter()
        .filter(|s| args.all || s.status != SessionStatus::Exited)
        .collect();

    if args.json {
        let json = serde_json::to_string_pretty(&filtered)
            .map_err(|e| nono::NonoError::ConfigParse(format!("JSON serialization failed: {e}")))?;
        println!("{json}");
        return Ok(());
    }

    if filtered.is_empty() {
        if args.all {
            eprintln!("No sessions found.");
        } else {
            eprintln!("No running or detached sessions. Use --all to include exited sessions.");
        }
        return Ok(());
    }

    // Collect plain-text cell values first so we can measure column widths.
    struct PsRow {
        session_id: String,
        name: String,
        status_text: String,
        attach_text: String,
        pid: String,
        uptime: String,
        profile: String,
        command: String,
        // originals needed for colour decisions
        status: SessionStatus,
        attachment: SessionAttachment,
        exit_code: i32,
    }

    let rows: Vec<PsRow> = filtered
        .iter()
        .map(|s| {
            let exit_code = s.exit_code.unwrap_or(-1);
            let status_text = match s.status {
                SessionStatus::Running => "running".to_string(),
                SessionStatus::Paused => "paused".to_string(),
                SessionStatus::Exited => format!("exited({exit_code})"),
            };
            let attach_text = match s.status {
                SessionStatus::Exited => "-".to_string(),
                _ => match s.attachment {
                    SessionAttachment::Attached => "attached".to_string(),
                    SessionAttachment::Detached => "detached".to_string(),
                },
            };
            PsRow {
                session_id: s.session_id.clone(),
                name: s.name.as_deref().unwrap_or("-").to_string(),
                status_text,
                attach_text,
                pid: s.child_pid.to_string(),
                uptime: format_uptime(&s.started),
                profile: s.profile.as_deref().unwrap_or("-").to_string(),
                command: format_command_line(&s.command),
                status: s.status.clone(),
                attachment: s.attachment.clone(),
                exit_code,
            }
        })
        .collect();

    // Compute each column width as max(header, data), capped for variable-length fields.
    let mut session_w = "SESSION".len();
    let mut name_w = "NAME".len();
    let mut status_w = "STATUS".len();
    let mut attach_w = "ATTACH".len();
    let mut pid_w = "PID".len();
    let mut uptime_w = "UPTIME".len();
    let mut profile_w = "PROFILE".len();

    for row in &rows {
        session_w = session_w.max(row.session_id.len());
        name_w = name_w.max(row.name.len());
        status_w = status_w.max(row.status_text.len());
        attach_w = attach_w.max(row.attach_text.len());
        pid_w = pid_w.max(row.pid.len());
        uptime_w = uptime_w.max(row.uptime.len());
        profile_w = profile_w.max(row.profile.len());
    }

    name_w = name_w.min(24);
    profile_w = profile_w.min(16);

    // Reserve space for the COMMAND column based on terminal width.
    let term_cols = terminal_columns().unwrap_or(120);
    // 7 separating spaces + "COMMAND" header (minimum 7 visible chars)
    let fixed_w = session_w
        + 1
        + name_w
        + 1
        + status_w
        + 1
        + attach_w
        + 1
        + pid_w
        + 1
        + uptime_w
        + 1
        + profile_w
        + 1;
    let cmd_w = term_cols.saturating_sub(fixed_w).max(7);

    // Header
    println!(
        "{} {} {} {} {} {} {} COMMAND",
        pad_right("SESSION", session_w),
        pad_right("NAME", name_w),
        pad_right("STATUS", status_w),
        pad_right("ATTACH", attach_w),
        pad_right("PID", pid_w),
        pad_right("UPTIME", uptime_w),
        pad_right("PROFILE", profile_w),
    );

    for row in &rows {
        let name_cell = pad_right(&truncate_chars(&row.name, name_w), name_w);
        let profile_cell = pad_right(&truncate_chars(&row.profile, profile_w), profile_w);
        let cmd_cell = truncate_chars(&row.command, cmd_w);

        // Pad status/attach to their column width *before* applying colour so
        // ANSI escape bytes don't upset the visible alignment.
        let status_padded = pad_right(&row.status_text, status_w);
        let status_colored = match row.status {
            SessionStatus::Running => status_padded.green().to_string(),
            SessionStatus::Paused => status_padded.yellow().to_string(),
            SessionStatus::Exited if row.exit_code != 0 => status_padded.red().to_string(),
            _ => status_padded,
        };

        let attach_padded = pad_right(&row.attach_text, attach_w);
        let attach_colored = match (&row.status, &row.attachment) {
            (SessionStatus::Exited, _) => attach_padded,
            (_, SessionAttachment::Attached) => attach_padded.green().to_string(),
            (_, SessionAttachment::Detached) => attach_padded.yellow().to_string(),
        };

        println!(
            "{} {} {} {} {} {} {} {}",
            pad_right(&row.session_id, session_w),
            name_cell,
            status_colored,
            attach_colored,
            pad_right(&row.pid, pid_w),
            pad_right(&row.uptime, uptime_w),
            profile_cell,
            cmd_cell,
        );
    }

    Ok(())
}

/// Left-align `s` in a field of `width` visible characters.
fn pad_right(s: &str, width: usize) -> String {
    format!("{:<width$}", s, width = width)
}

/// Return the terminal column count, or `None` when stdout is not a terminal.
fn terminal_columns() -> Option<usize> {
    // Honour the conventional COLUMNS override (pipes, scripts, tests).
    if let Ok(val) = std::env::var("COLUMNS") {
        return val.parse::<usize>().ok();
    }
    // Fall back to an ioctl on the real terminal.
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: TIOCGWINSZ writes one `winsize` struct into `ws`; the fd is
    // STDOUT_FILENO which is always a valid open fd for a CLI process.
    let ret = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) };
    if ret == 0 && ws.ws_col > 0 {
        Some(ws.ws_col as usize)
    } else {
        None
    }
}

/// Format uptime from an ISO 8601 start time string.
fn format_uptime(started: &str) -> String {
    let Ok(start) = chrono::DateTime::parse_from_rfc3339(started) else {
        return "-".to_string();
    };
    let now = chrono::Local::now();
    let duration = now.signed_duration_since(start);

    if duration.num_days() > 0 {
        format!("{}d", duration.num_days())
    } else if duration.num_hours() > 0 {
        format!("{}h", duration.num_hours())
    } else if duration.num_minutes() > 0 {
        format!("{}m", duration.num_minutes())
    } else {
        format!("{}s", duration.num_seconds().max(0))
    }
}

/// Dispatch `nono stop`.
pub fn run_stop(args: &StopArgs) -> Result<()> {
    reject_if_sandboxed("stop")?;
    let record = session::load_session(&args.session)?;

    if record.status == SessionStatus::Exited {
        return Err(NonoError::ConfigParse(format!(
            "Session {} is already exited",
            record.session_id
        )));
    }

    if !session::is_process_alive(record.supervisor_pid, record.started_epoch) {
        return Err(NonoError::ConfigParse(format!(
            "Session {} supervisor (PID {}) is no longer running",
            record.session_id, record.supervisor_pid
        )));
    }

    let pid = nix::unistd::Pid::from_raw(record.supervisor_pid as i32);

    if args.force {
        nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL)
            .map_err(|e| NonoError::ConfigParse(format!("Failed to send SIGKILL: {}", e)))?;
        eprintln!("Stopped session {}.", record.session_id);
    } else {
        nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM)
            .map_err(|e| NonoError::ConfigParse(format!("Failed to send SIGTERM: {}", e)))?;

        // Wait for the process to exit with a timeout
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(args.timeout);
        loop {
            if !session::is_process_alive(record.supervisor_pid, record.started_epoch) {
                eprintln!("Stopped session {}.", record.session_id);
                break;
            }
            if std::time::Instant::now() >= deadline {
                let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
                eprintln!("Stopped session {} (forced).", record.session_id);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }

    Ok(())
}

/// Dispatch `nono detach`.
pub fn run_detach(args: &DetachArgs) -> Result<()> {
    reject_if_sandboxed("detach")?;
    let record = session::load_session(&args.session)?;

    if record.attachment == SessionAttachment::Detached {
        eprintln!("Session {} is already detached.", record.session_id);
        return Ok(());
    }

    if record.status != SessionStatus::Running {
        return Err(NonoError::ConfigParse(format!(
            "Session {} is not running (status: {:?})",
            record.session_id, record.status
        )));
    }

    if !session::is_process_alive(record.supervisor_pid, record.started_epoch) {
        return Err(NonoError::ConfigParse(format!(
            "Session {} supervisor (PID {}) is no longer running",
            record.session_id, record.supervisor_pid
        )));
    }

    crate::pty_proxy::request_session_detach(&record.session_id)?;

    eprintln!("Detached session {}.", record.session_id);
    Ok(())
}

/// Dispatch `nono attach`.
pub fn run_attach(args: &AttachArgs) -> Result<()> {
    reject_if_sandboxed("attach")?;
    let record = session::load_session(&args.session)?;

    if record.status == SessionStatus::Exited {
        match record.exit_code {
            Some(code) => {
                eprintln!(
                    "[nono] Session {} has already exited (exit code {}).",
                    record.session_id, code
                );
            }
            None => {
                eprintln!("[nono] Session {} has already exited.", record.session_id);
            }
        }
        return Ok(());
    }

    if !session::is_process_alive(record.supervisor_pid, record.started_epoch) {
        return Err(NonoError::ConfigParse(format!(
            "Session {} supervisor (PID {}) is no longer running",
            record.session_id, record.supervisor_pid
        )));
    }

    eprintln!("[nono] Attaching to session {}...", record.session_id);

    if record.status == SessionStatus::Paused {
        return Err(NonoError::ConfigParse(format!(
            "Session {} is paused/stopped and cannot accept attach",
            record.session_id
        )));
    }

    match crate::pty_proxy::attach_to_session(&record.session_id) {
        Err(NonoError::AttachBusy) => {
            eprintln!(
                "[nono] Session {} already has an active attached client.",
                record.session_id
            );
            Ok(())
        }
        Err(NonoError::SessionGone) => {
            eprintln!(
                "[nono] Session {} exited before attach could complete.",
                record.session_id
            );
            Ok(())
        }
        other => other,
    }
}

/// Dispatch `nono logs` — placeholder for Step 3.
pub fn run_logs(args: &LogsArgs) -> Result<()> {
    let record = session::load_session(&args.session)?;
    let events_path = session::session_events_path(&record.session_id)?;

    if !events_path.exists() {
        eprintln!("No event log recorded for session {}.", record.session_id);
        return Ok(());
    }

    if args.follow {
        follow_event_log(&events_path, args.tail, args.json)
    } else {
        let lines = read_event_log_lines(&events_path, args.tail)?;
        print_event_log_lines(&lines, args.json)
    }
}

/// Dispatch `nono inspect` — placeholder for Step 4.
pub fn run_inspect(args: &InspectArgs) -> Result<()> {
    let record = session::load_session(&args.session)?;

    if args.json {
        let json = serde_json::to_string_pretty(&record)
            .map_err(|e| NonoError::ConfigParse(format!("JSON serialization failed: {e}")))?;
        println!("{json}");
        return Ok(());
    }

    println!("Session:    {}", record.session_id);
    if let Some(ref name) = record.name {
        println!("Name:       {}", name);
    }
    println!("Status:     {:?}", record.status);
    println!("Attached:   {:?}", record.attachment);
    println!(
        "PID:        {} (supervisor: {})",
        record.child_pid, record.supervisor_pid
    );
    println!("Started:    {}", record.started);
    if let Some(code) = record.exit_code {
        println!("Exit code:  {}", code);
    }
    println!("Command:    {}", format_command_line(&record.command));
    if let Some(ref profile) = record.profile {
        println!("Profile:    {}", profile);
    }
    println!("Workdir:    {}", record.workdir.display());
    println!("Network:    {}", record.network);
    if let Some(ref rollback) = record.rollback_session {
        println!("Rollback:   {}", rollback);
    }

    Ok(())
}

/// Dispatch `nono prune`.
pub fn run_prune(args: &PruneArgs) -> Result<()> {
    reject_if_sandboxed("prune")?;
    let sessions = session::list_sessions()?;

    let now = chrono::Utc::now();
    let mut to_remove: Vec<&SessionRecord> = Vec::new();

    for s in &sessions {
        // Skip running sessions
        if s.status == SessionStatus::Running {
            continue;
        }

        let should_remove = if let Some(days) = args.older_than {
            if let Ok(started) = chrono::DateTime::parse_from_rfc3339(&s.started) {
                let age = now.signed_duration_since(started);
                age.num_days() >= days as i64
            } else {
                false
            }
        } else {
            true // No age filter: all exited sessions are candidates
        };

        if should_remove {
            to_remove.push(s);
        }
    }

    // Apply --keep: keep the N most recent, remove the rest
    if let Some(keep) = args.keep {
        // to_remove is sorted newest-first (from list_sessions), so skip the first `keep`
        if to_remove.len() > keep {
            to_remove = to_remove[keep..].to_vec();
        } else {
            to_remove.clear();
        }
    }

    if to_remove.is_empty() {
        eprintln!("Nothing to prune.");
        return Ok(());
    }

    let dir = session::sessions_dir()?;

    for s in &to_remove {
        let session_file = dir.join(format!("{}.json", s.session_id));
        let events_file = dir.join(format!("{}.events.ndjson", s.session_id));

        if args.dry_run {
            eprintln!("Would remove: {} (started {})", s.session_id, s.started);
        } else {
            if let Err(e) = std::fs::remove_file(&session_file) {
                debug!(
                    "Failed to remove session file {}: {}",
                    session_file.display(),
                    e
                );
            }
            if events_file.exists() {
                if let Err(e) = std::fs::remove_file(&events_file) {
                    debug!(
                        "Failed to remove events file {}: {}",
                        events_file.display(),
                        e
                    );
                }
            }
            eprintln!("Removed: {} (started {})", s.session_id, s.started);
        }
    }

    eprintln!(
        "\n{} {} session(s).",
        if args.dry_run {
            "Would prune"
        } else {
            "Pruned"
        },
        to_remove.len()
    );

    Ok(())
}

fn read_event_log_lines(path: &Path, tail: Option<usize>) -> Result<Vec<String>> {
    let file = std::fs::File::open(path).map_err(|e| NonoError::ConfigRead {
        path: path.to_path_buf(),
        source: e,
    })?;
    let reader = std::io::BufReader::new(file);

    if let Some(limit) = tail {
        let mut lines = VecDeque::with_capacity(limit.min(256));
        for line in reader.lines() {
            let line = line.map_err(|e| NonoError::ConfigRead {
                path: path.to_path_buf(),
                source: e,
            })?;
            if lines.len() == limit {
                let _ = lines.pop_front();
            }
            lines.push_back(line);
        }
        Ok(lines.into_iter().collect())
    } else {
        reader
            .lines()
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|e| NonoError::ConfigRead {
                path: path.to_path_buf(),
                source: e,
            })
    }
}

fn print_event_log_lines(lines: &[String], as_json: bool) -> Result<()> {
    if as_json {
        let values: Vec<serde_json::Value> = lines
            .iter()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line)
                    .unwrap_or_else(|_| serde_json::Value::String(line.clone()))
            })
            .collect();
        let json = serde_json::to_string_pretty(&values)
            .map_err(|e| NonoError::ConfigParse(format!("JSON serialization failed: {e}")))?;
        println!("{json}");
    } else {
        for line in lines {
            println!("{line}");
        }
    }
    Ok(())
}

fn follow_event_log(path: &Path, tail: Option<usize>, as_json: bool) -> Result<()> {
    let initial_lines = read_event_log_lines(path, tail)?;
    if as_json {
        for line in &initial_lines {
            println!("{line}");
        }
    } else {
        print_event_log_lines(&initial_lines, false)?;
    }

    let mut file = std::fs::File::open(path).map_err(|e| NonoError::ConfigRead {
        path: path.to_path_buf(),
        source: e,
    })?;
    file.seek(SeekFrom::End(0))
        .map_err(|e| NonoError::ConfigRead {
            path: path.to_path_buf(),
            source: e,
        })?;
    let mut reader = std::io::BufReader::new(file);

    loop {
        let mut line = String::new();
        let bytes = reader
            .read_line(&mut line)
            .map_err(|e| NonoError::ConfigRead {
                path: path.to_path_buf(),
                source: e,
            })?;
        if bytes == 0 {
            std::thread::sleep(std::time::Duration::from_millis(250));
            continue;
        }
        print!("{}", line);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_uptime_seconds() {
        let now = chrono::Local::now();
        let started = (now - chrono::Duration::seconds(30)).to_rfc3339();
        let result = format_uptime(&started);
        assert!(result.ends_with('s'));
    }

    #[test]
    fn test_format_uptime_minutes() {
        let now = chrono::Local::now();
        let started = (now - chrono::Duration::minutes(5)).to_rfc3339();
        let result = format_uptime(&started);
        assert!(result.ends_with('m'));
    }
}
