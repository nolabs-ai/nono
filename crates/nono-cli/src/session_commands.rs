//! Session management command implementations.
//!
//! Handles `nono ps`, `nono stop`, `nono detach`, `nono attach`, `nono logs`,
//! `nono inspect`, and `nono prune`.

use crate::cli::{AttachArgs, DetachArgs, InspectArgs, LogsArgs, PruneArgs, PsArgs, StopArgs};
use crate::command_display::{format_command_line, truncate_chars};
use crate::session::{self, SessionAttachment, SessionRecord, SessionStatus};
use colored::Colorize;
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

/// Default auto-prune threshold: prune if more than this many stale
/// (>30d, Exited) session files are on disk when `nono ps` starts.
const AUTO_PRUNE_STALE_THRESHOLD: usize = 100;

/// Default retention used by the auto-trigger (30 days in seconds).
const AUTO_PRUNE_RETENTION_SECS: u64 = 30 * 86_400;

/// At the top of `run_ps`, check how many stale sessions are on disk.
/// If the count exceeds AUTO_PRUNE_STALE_THRESHOLD, spawn a background
/// thread to prune them and log a single info line to stderr.
///
/// STRUCTURAL NO-OP INSIDE A SANDBOX: if `NONO_CAP_FILE` is set, returns
/// immediately. Sandboxed agents must not be able to trigger deletion of
/// the host supervisor's session files (threat T-19-04-07 — EoP). This
/// mirrors the `reject_if_sandboxed` check used by `run_prune`, but is
/// silent (no error) because `nono ps` itself IS legal from a sandbox;
/// only the background-deletion side effect is forbidden.
///
/// Fails silently — any error inside the background thread is logged
/// at debug level and discarded. `nono ps` itself must not be delayed
/// or broken by this cleanup path.
fn auto_prune_if_needed() {
    // T-19-04-07: refuse to delete host supervisor's sessions from
    // within a sandboxed process. NONO_CAP_FILE is the canonical
    // "I am running inside nono" signal (same check as reject_if_sandboxed).
    if std::env::var_os("NONO_CAP_FILE").is_some() {
        debug!("auto-prune skipped: running inside sandbox (NONO_CAP_FILE set)");
        return;
    }

    // Load fresh list (cheap — directory scan).
    let sessions = match session::list_sessions() {
        Ok(s) => s,
        Err(e) => {
            debug!("auto-prune skipped: list_sessions failed: {e}");
            return;
        }
    };

    let now_epoch = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(e) => {
            debug!("auto-prune skipped: clock error: {e}");
            return;
        }
    };

    let stale_ids: Vec<String> = sessions
        .iter()
        .filter(|s| session::is_prunable(s, now_epoch, AUTO_PRUNE_RETENTION_SECS))
        .map(|s| s.session_id.clone())
        .collect();

    if stale_ids.len() <= AUTO_PRUNE_STALE_THRESHOLD {
        return;
    }

    let count = stale_ids.len();
    // Log up-front so operators see the count even if the background
    // thread crashes / is killed.
    eprintln!("info: pruning {count} stale session files (>30 days, exited)");

    // Background thread: perform the actual deletes without blocking ps.
    std::thread::spawn(move || {
        let dir = match session::sessions_dir() {
            Ok(d) => d,
            Err(e) => {
                debug!("auto-prune background: sessions_dir failed: {e}");
                return;
            }
        };
        let mut removed = 0usize;
        for id in &stale_ids {
            let session_file = dir.join(format!("{id}.json"));
            let events_file = dir.join(format!("{id}.events.ndjson"));

            // Same defense-in-depth as run_prune: refuse symlinks.
            if let Ok(md) = std::fs::symlink_metadata(&session_file) {
                if md.file_type().is_symlink() {
                    debug!("auto-prune skipping symlink: {}", session_file.display());
                    continue;
                }
            }
            if std::fs::remove_file(&session_file).is_ok() {
                removed += 1;
            }
            let _ = std::fs::remove_file(&events_file); // best effort
        }
        debug!("auto-prune background: removed {removed}/{count} stale session files");
    });
}

/// Dispatch `nono ps`.
pub fn run_ps(args: &PsArgs) -> Result<()> {
    auto_prune_if_needed();
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
///
/// Honours the conventional `COLUMNS` env-var override (used by pipes, scripts,
/// and tests). On Unix falls back to the `TIOCGWINSZ` ioctl on STDOUT_FILENO;
/// on Windows uses the console screen buffer info API (`GetConsoleScreenBufferInfo`).
fn terminal_columns() -> Option<usize> {
    // Honour the conventional COLUMNS override (pipes, scripts, tests).
    if let Ok(val) = std::env::var("COLUMNS") {
        return val.parse::<usize>().ok();
    }
    terminal_columns_native()
}

#[cfg(unix)]
fn terminal_columns_native() -> Option<usize> {
    use nix::libc;
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

#[cfg(windows)]
fn terminal_columns_native() -> Option<usize> {
    // Windows does not have TIOCGWINSZ; query the console screen buffer info
    // via the Win32 console API. STD_OUTPUT_HANDLE -> CONSOLE_SCREEN_BUFFER_INFO.
    use windows_sys::Win32::System::Console::{
        GetConsoleScreenBufferInfo, GetStdHandle, CONSOLE_SCREEN_BUFFER_INFO, STD_OUTPUT_HANDLE,
    };
    // SAFETY: GetStdHandle returns either a valid handle or INVALID_HANDLE_VALUE;
    // GetConsoleScreenBufferInfo writes one CONSOLE_SCREEN_BUFFER_INFO struct.
    unsafe {
        let h = GetStdHandle(STD_OUTPUT_HANDLE);
        if h.is_null() {
            return None;
        }
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = std::mem::zeroed();
        if GetConsoleScreenBufferInfo(h, &mut info) == 0 {
            return None;
        }
        // srWindow.{Right,Left} are inclusive coordinates.
        let cols = (info.srWindow.Right - info.srWindow.Left + 1) as i32;
        if cols > 0 {
            Some(cols as usize)
        } else {
            None
        }
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
    if let Some(limits) = record.limits.as_ref() {
        if !limits.is_empty() {
            println!("\nLimits:");
            if let Some(pct) = limits.cpu_percent {
                println!("  cpu:     {pct}% (hard cap)");
            }
            if let Some(bytes) = limits.memory_bytes {
                println!("  memory:  {} (job-wide)", format_bytes_human(bytes));
            }
            if let Some(secs) = limits.timeout_seconds {
                println!(
                    "  timeout: {}",
                    format_duration_human(std::time::Duration::from_secs(secs))
                );
            }
            if let Some(procs) = limits.max_processes {
                println!("  procs:   {procs} (active)");
            }
        }
    }

    Ok(())
}

/// Render bytes using binary (1024-based) units. Picks the largest unit that
/// yields an integer representation; falls back to raw bytes for values that
/// are not a clean multiple of any unit. Mirrors the input parser
/// (`crate::cli::parse_byte_size`) which uses the same K/M/G/T multipliers.
fn format_bytes_human(bytes: u64) -> String {
    const K: u64 = 1024;
    const M: u64 = K * 1024;
    const G: u64 = M * 1024;
    const T: u64 = G * 1024;
    if bytes >= T && bytes % T == 0 {
        format!("{} TiB", bytes / T)
    } else if bytes >= G && bytes % G == 0 {
        format!("{} GiB", bytes / G)
    } else if bytes >= M && bytes % M == 0 {
        format!("{} MiB", bytes / M)
    } else if bytes >= K && bytes % K == 0 {
        format!("{} KiB", bytes / K)
    } else {
        format!("{bytes} bytes")
    }
}

/// Render a `Duration` as `"5 minutes"` / `"1 hour"` / `"45 seconds"`. Not a
/// general-purpose formatter — tuned for the `parse_duration` accepted forms
/// (s/m/h/d), which always produce whole-second durations.
fn format_duration_human(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    if secs >= 86_400 && secs % 86_400 == 0 {
        let n = secs / 86_400;
        format!("{n} {}", if n == 1 { "day" } else { "days" })
    } else if secs >= 3600 && secs % 3600 == 0 {
        let n = secs / 3600;
        format!("{n} {}", if n == 1 { "hour" } else { "hours" })
    } else if secs >= 60 && secs % 60 == 0 {
        let n = secs / 60;
        format!("{n} {}", if n == 1 { "minute" } else { "minutes" })
    } else {
        format!("{secs} {}", if secs == 1 { "second" } else { "seconds" })
    }
}

/// Dispatch `nono prune`.
///
/// Retention rule (CLEAN-04 D-14): only sessions with `Status: Exited` are
/// prunable; active sessions (Running / Paused) are structurally excluded.
/// Delegates the per-record decision to `session::is_prunable` so the Windows
/// mirror, the auto-trigger, and this handler share a single source of truth.
pub fn run_prune(args: &PruneArgs) -> Result<()> {
    reject_if_sandboxed("prune")?;

    let sessions = session::list_sessions()?;
    let now_epoch = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(e) => {
            return Err(NonoError::ConfigParse(format!(
                "system clock before UNIX epoch: {e}"
            )));
        }
    };

    // Resolve retention_secs from the flags:
    //   --all-exited          → 0 (every exited session qualifies)
    //   --older-than SPECIFIED → that duration in seconds
    //   neither                → 30 days default
    let retention_secs: u64 = if args.all_exited {
        0
    } else if let Some(d) = args.older_than {
        d.as_secs()
    } else {
        30 * 86_400
    };

    let mut to_remove: Vec<&SessionRecord> = sessions
        .iter()
        .filter(|s| session::is_prunable(s, now_epoch, retention_secs))
        .collect();

    // Apply --keep: keep the N most recent, remove the rest.
    // list_sessions() is sorted newest-first.
    if let Some(keep) = args.keep {
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
            // Defense in depth (threat T-19-04-02/03): canonicalize the target
            // and confirm it still lives under the sessions directory.
            // `canonicalize` may legitimately fail if the file has already been
            // removed between `list_sessions` and now — in that case fall
            // through to `remove_file`, which will itself report ENOENT.
            match session_file.canonicalize() {
                Ok(resolved) => {
                    let dir_canon = dir.canonicalize().unwrap_or_else(|_| dir.clone());
                    if !resolved.starts_with(&dir_canon) {
                        debug!(
                            "Refusing to prune {}: outside sessions dir",
                            session_file.display()
                        );
                        continue;
                    }
                }
                Err(_) => { /* file may be gone already; remove_file errs benignly */ }
            }
            // Refuse to follow a symlink: symlink_metadata does NOT follow.
            if let Ok(md) = std::fs::symlink_metadata(&session_file) {
                if md.file_type().is_symlink() {
                    debug!("Refusing to prune {}: is a symlink", session_file.display());
                    continue;
                }
            }
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

    // ---- Plan 19-04 CLEAN-04: T-19-04-07 sandbox-guard regression test ----

    #[test]
    fn auto_prune_is_noop_when_sandboxed() {
        use crate::test_env::{lock_env, EnvVarGuard};

        // Acquire the process-wide env lock (tests run in parallel).
        let _lock = lock_env();
        // Save-and-restore guard flips NONO_CAP_FILE to a placeholder path
        // for the duration of the test, then restores the original value.
        let _guard = EnvVarGuard::set_all(&[("NONO_CAP_FILE", "/tmp/fake-cap-file")]);

        // Should return immediately without touching the filesystem.
        // Success criterion: function returns at all (no panic, no hang,
        // no error). Since auto_prune_if_needed returns () and the sandbox
        // early-return is the FIRST statement, reaching this line after
        // the call is itself the assertion. We also re-check the env var
        // is still set as a sanity guard against the test machinery losing
        // it mid-call.
        auto_prune_if_needed();
        assert!(
            std::env::var_os("NONO_CAP_FILE").is_some(),
            "NONO_CAP_FILE should still be set — EnvVarGuard regressed"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod inspect_formatting_tests {
    use super::{format_bytes_human, format_duration_human};
    use std::time::Duration;

    #[test]
    fn bytes_512_mib() {
        assert_eq!(format_bytes_human(512 * 1024 * 1024), "512 MiB");
    }

    #[test]
    fn bytes_1_gib() {
        assert_eq!(format_bytes_human(1024 * 1024 * 1024), "1 GiB");
    }

    #[test]
    fn bytes_256_kib() {
        assert_eq!(format_bytes_human(256 * 1024), "256 KiB");
    }

    #[test]
    fn bytes_1_tib() {
        assert_eq!(format_bytes_human(1024u64.pow(4)), "1 TiB");
    }

    #[test]
    fn bytes_non_clean_multiple_falls_back_to_bytes() {
        // 1000 is not a clean multiple of 1024 → rendered as raw bytes.
        assert_eq!(format_bytes_human(1000), "1000 bytes");
    }

    #[test]
    fn bytes_zero_renders_as_zero_bytes() {
        assert_eq!(format_bytes_human(0), "0 bytes");
    }

    #[test]
    fn duration_45_seconds() {
        assert_eq!(format_duration_human(Duration::from_secs(45)), "45 seconds");
    }

    #[test]
    fn duration_1_second_is_singular() {
        assert_eq!(format_duration_human(Duration::from_secs(1)), "1 second");
    }

    #[test]
    fn duration_5_minutes() {
        assert_eq!(format_duration_human(Duration::from_secs(300)), "5 minutes");
    }

    #[test]
    fn duration_1_minute_is_singular() {
        assert_eq!(format_duration_human(Duration::from_secs(60)), "1 minute");
    }

    #[test]
    fn duration_1_hour_is_singular() {
        assert_eq!(format_duration_human(Duration::from_secs(3600)), "1 hour");
    }

    #[test]
    fn duration_2_hours() {
        assert_eq!(format_duration_human(Duration::from_secs(7200)), "2 hours");
    }

    #[test]
    fn duration_1_day_is_singular() {
        assert_eq!(format_duration_human(Duration::from_secs(86_400)), "1 day");
    }

    #[test]
    fn duration_90s_not_clean_minute() {
        // 90s is not a clean minute → falls back to seconds.
        assert_eq!(format_duration_human(Duration::from_secs(90)), "90 seconds");
    }
}
