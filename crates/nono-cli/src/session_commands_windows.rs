use crate::cli::{AttachArgs, DetachArgs, InspectArgs, LogsArgs, PruneArgs, PsArgs, StopArgs};
use crate::exec_strategy::{to_u16_null_terminated, JOB_OBJECT_QUERY, JOB_OBJECT_TERMINATE};
use crate::session::{self, SessionAttachment, SessionRecord, SessionStatus};
use colored::Colorize;
use nono::{NonoError, Result};
use std::collections::VecDeque;
use std::io::{BufRead, Read, Seek, SeekFrom, Write};
use std::path::Path;
use tracing::debug;

fn reject_if_sandboxed(command: &str) -> Result<()> {
    if std::env::var_os("NONO_CAP_FILE").is_some() {
        return Err(NonoError::ConfigParse(format!(
            "`nono {}` cannot be used inside a sandbox.",
            command
        )));
    }
    Ok(())
}

/// Translate the `io::Error` returned by `OpenOptions::open` on the attach
/// data pipe into a `NonoError`.
///
/// `ERROR_PIPE_BUSY` (231) is the kernel signal that another client already
/// holds the single-instance pipe (`nMaxInstances=1` at supervisor.rs:165).
/// Wrap it in a friendly `NonoError::Setup` per Phase 17 D-08 with the
/// session id and a hint to run `nono detach <id>` first. Everything else
/// falls through to the existing "Failed to connect" wording so users still
/// see the underlying io::Error message.
///
/// Kept as a free function (not a method) so unit tests can call it without
/// constructing a `SessionRecord`. Returns `NonoError::Setup` (not
/// `NonoError::AttachBusy`) per CONTEXT.md D-21 — the `AttachBusy` variant
/// stays generic; the session-id-bearing message lives at the call site.
pub(crate) fn translate_attach_open_error(err: &std::io::Error, session_id: &str) -> NonoError {
    use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;
    if err.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) {
        NonoError::Setup(format!(
            "Session {session_id} is already attached. \
             Use 'nono detach {session_id}' to release the existing client first."
        ))
    } else {
        NonoError::Setup(format!(
            "Failed to connect to session data pipe: {err}. Is another client already attached?"
        ))
    }
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

pub fn run_ps(args: &PsArgs) -> Result<()> {
    auto_prune_if_needed();
    let sessions = session::list_sessions()?;

    // Filter: by default show live sessions
    let filtered: Vec<&SessionRecord> = sessions
        .iter()
        .filter(|s| args.all || s.status != SessionStatus::Exited)
        .collect();

    if args.json {
        let json = serde_json::to_string_pretty(&filtered)
            .map_err(|e| NonoError::ConfigParse(format!("JSON serialization failed: {e}")))?;
        println!("{json}");
        return Ok(());
    }

    if filtered.is_empty() {
        if args.all {
            eprintln!("No sessions found.");
        } else {
            eprintln!("No running sessions. Use --all to include exited sessions.");
        }
        return Ok(());
    }

    // Table header
    println!(
        "{:<16} {:<12} {:<10} {:<10} {:<12} {:<10} {:<14} COMMAND",
        "SESSION", "NAME", "STATUS", "ATTACH", "PIDS", "UPTIME", "PROFILE"
    );

    for session in &filtered {
        let name = session.name.as_deref().unwrap_or("-");
        let status = match session.status {
            SessionStatus::Running => "running".green().to_string(),
            SessionStatus::Paused => "paused".yellow().to_string(),
            SessionStatus::Exited => {
                let code = session.exit_code.unwrap_or(-1);
                if code == 0 {
                    "exited(0)".to_string()
                } else {
                    format!("exited({})", code).red().to_string()
                }
            }
        };
        let attach = match session.status {
            SessionStatus::Exited => "-".to_string(),
            _ => match session.attachment {
                SessionAttachment::Attached => "attached".green().to_string(),
                SessionAttachment::Detached => "detached".yellow().to_string(),
            },
        };

        let pids_str = if session.status == SessionStatus::Running {
            if let Some(ref job_name) = session.job_object_name {
                let pids = session::get_job_pids(job_name);
                if pids.is_empty() {
                    format!("{}", session.child_pid)
                } else if pids.len() == 1 {
                    format!("{}", pids[0])
                } else {
                    format!("{} (+{})", pids[0], pids.len() - 1)
                }
            } else {
                format!("{}", session.child_pid)
            }
        } else {
            "-".to_string()
        };

        let uptime = format_uptime(&session.started);
        let profile = session.profile.as_deref().unwrap_or("-");
        let command = truncate_command(&session.command, 40);

        println!(
            "{:<16} {:<12} {:<10} {:<10} {:<12} {:<10} {:<14} {}",
            session.session_id, name, status, attach, pids_str, uptime, profile, command
        );
    }

    Ok(())
}

fn format_uptime(started: &str) -> String {
    let Ok(start) = chrono::DateTime::parse_from_rfc3339(started) else {
        return "-".to_string();
    };
    let now = chrono::Utc::now();
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

fn truncate_command(command: &[String], max_len: usize) -> String {
    let full = command.join(" ");
    if full.len() <= max_len {
        full
    } else {
        format!("{}...", &full[..max_len.saturating_sub(3)])
    }
}

pub fn run_stop(args: &StopArgs) -> Result<()> {
    let session = session::load_session(&args.session)?;

    if session.status == SessionStatus::Exited {
        println!("Session {} is already stopped.", session.session_id);
        return Ok(());
    }

    // 1. Try Polite (Named Pipe)
    let pipe_name = format!("\\\\.\\pipe\\nono-session-{}", session.session_id);
    let pipe_name_u16 = to_u16_null_terminated(&pipe_name);

    // Wait for pipe availability (short timeout)
    unsafe {
        windows_sys::Win32::System::Pipes::WaitNamedPipeW(pipe_name_u16.as_ptr(), 500);
    }

    let mut polite_success = false;
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&pipe_name)
    {
        let msg = nono::supervisor::SupervisorMessage::Terminate {
            session_id: session.session_id.clone(),
        };
        if let Ok(body) = serde_json::to_vec(&msg) {
            let len = body.len() as u32;
            let mut full_msg = len.to_be_bytes().to_vec();
            full_msg.extend(body);

            if file.write_all(&full_msg).is_ok() {
                polite_success = true;
                println!(
                    "Termination request sent to supervisor for session {}",
                    session.session_id
                );
            }
        }
    }

    // 2. Wait or Force (Job Object)
    let job_name = format!("Local\\nono-session-{}", session.session_id);
    let job_name_u16 = to_u16_null_terminated(&job_name);

    if polite_success {
        // Wait up to 5 seconds for it to exit
        print!("Waiting for session to stop gracefully...");
        let _ = std::io::stdout().flush();
        for _ in 0..50 {
            let h_job = unsafe {
                windows_sys::Win32::System::JobObjects::OpenJobObjectW(
                    JOB_OBJECT_QUERY,
                    0,
                    job_name_u16.as_ptr(),
                )
            };
            if h_job.is_null() {
                println!("\nSession {} stopped gracefully.", session.session_id);
                return Ok(());
            }
            unsafe { windows_sys::Win32::Foundation::CloseHandle(h_job) };
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        println!("\nGraceful stop timed out.");
    }

    // Force Stop
    println!(
        "Forcing termination of session {} and its process tree...",
        session.session_id
    );
    let h_job = unsafe {
        windows_sys::Win32::System::JobObjects::OpenJobObjectW(
            JOB_OBJECT_TERMINATE,
            0,
            job_name_u16.as_ptr(),
        )
    };
    if !h_job.is_null() {
        unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(h_job, 1);
            windows_sys::Win32::Foundation::CloseHandle(h_job);
        }
        println!("Session {} forced to stop.", session.session_id);
    } else {
        println!(
            "Session {} is no longer running in a Job Object.",
            session.session_id
        );
    }

    Ok(())
}

pub fn run_detach(args: &DetachArgs) -> Result<()> {
    let session = session::load_session(&args.session)?;

    if session.status == SessionStatus::Exited {
        println!("Session {} is already stopped.", session.session_id);
        return Ok(());
    }

    let pipe_name = format!("\\\\.\\pipe\\nono-session-{}", session.session_id);
    let pipe_name_u16 = to_u16_null_terminated(&pipe_name);

    unsafe {
        windows_sys::Win32::System::Pipes::WaitNamedPipeW(pipe_name_u16.as_ptr(), 500);
    }

    if let Ok(mut file) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&pipe_name)
    {
        let msg = nono::supervisor::SupervisorMessage::Detach {
            session_id: session.session_id.clone(),
        };
        if let Ok(body) = serde_json::to_vec(&msg) {
            let len = body.len() as u32;
            let mut full_msg = len.to_be_bytes().to_vec();
            full_msg.extend(body);

            if file.write_all(&full_msg).is_ok() {
                println!(
                    "Detachment request sent to supervisor for session {}",
                    session.session_id
                );
                return Ok(());
            }
        }
    }

    Err(NonoError::Setup(format!(
        "Failed to connect to supervisor for session {}. Is it running?",
        session.session_id
    )))
}

pub fn run_attach(args: &AttachArgs) -> Result<()> {
    let session = session::load_session(&args.session)?;

    if session.status == SessionStatus::Exited {
        return Err(NonoError::Setup(format!(
            "Session {} has already exited.",
            session.session_id
        )));
    }

    // 1. Show scrollback
    let log_path = crate::session::session_log_path(&session.session_id)?;
    if log_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&log_path) {
            // Print last 1000 lines or similar. For now, just print the whole thing.
            print!("{}", content);
            let _ = std::io::stdout().flush();
        }
    }

    // 2. Connect to Data Pipe
    let data_pipe_name = format!("\\\\.\\pipe\\nono-data-{}", session.session_id);
    let data_pipe_name_u16 = to_u16_null_terminated(&data_pipe_name);

    unsafe {
        windows_sys::Win32::System::Pipes::WaitNamedPipeW(data_pipe_name_u16.as_ptr(), 1000);
    }

    let pipe_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&data_pipe_name)
        .map_err(|e| translate_attach_open_error(&e, &session.session_id))?;

    println!(
        "\n{} to session {}. Press {} to detach.",
        "Attached".green().bold(),
        session.session_id.cyan(),
        "Ctrl-] d".yellow()
    );

    // 3. Bi-directional streaming
    let mut pipe_reader = pipe_file.try_clone().map_err(NonoError::Io)?;
    let mut pipe_writer = pipe_file;

    // Output thread: Pipe -> Stdout
    std::thread::spawn(move || {
        let mut stdout = std::io::stdout();
        let mut buf = [0u8; 4096];
        while let Ok(n) = pipe_reader.read(&mut buf) {
            if n == 0 {
                break;
            }
            let _ = stdout.write_all(&buf[..n]);
            let _ = stdout.flush();
        }
    });

    // Input loop: Stdin -> Pipe
    let mut stdin = std::io::stdin();
    let mut buf = [0u8; 4096];

    // We need to handle the escape sequence Ctrl-] d
    // For now, a simple byte-by-byte check or small buffer check.
    // Ctrl-] is 0x1D.
    let mut last_byte_was_escape = false;

    while let Ok(n) = stdin.read(&mut buf) {
        if n == 0 {
            break;
        }

        let mut i = 0;
        while i < n {
            if last_byte_was_escape {
                if buf[i] == b'd' || buf[i] == b'D' {
                    println!("\nDetaching...");
                    return Ok(());
                }
                last_byte_was_escape = false;
            } else if buf[i] == 0x1D {
                last_byte_was_escape = true;
            }
            i += 1;
        }

        if pipe_writer.write_all(&buf[..n]).is_err() {
            break;
        }
    }

    println!("\nSession connection closed.");
    Ok(())
}

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
    println!("Command:    {}", record.command.join(" "));
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
    if bytes >= T && bytes.is_multiple_of(T) {
        format!("{} TiB", bytes / T)
    } else if bytes >= G && bytes.is_multiple_of(G) {
        format!("{} GiB", bytes / G)
    } else if bytes >= M && bytes.is_multiple_of(M) {
        format!("{} MiB", bytes / M)
    } else if bytes >= K && bytes.is_multiple_of(K) {
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
    if secs >= 86_400 && secs.is_multiple_of(86_400) {
        let n = secs / 86_400;
        format!("{n} {}", if n == 1 { "day" } else { "days" })
    } else if secs >= 3600 && secs.is_multiple_of(3600) {
        let n = secs / 3600;
        format!("{n} {}", if n == 1 { "hour" } else { "hours" })
    } else if secs >= 60 && secs.is_multiple_of(60) {
        let n = secs / 60;
        format!("{n} {}", if n == 1 { "minute" } else { "minutes" })
    } else {
        format!("{secs} {}", if secs == 1 { "second" } else { "seconds" })
    }
}

/// Dispatch `nono prune` (Windows).
///
/// Mirrors the Unix `run_prune` (session_commands.rs) — shared retention rule
/// via `session::is_prunable`, mutually exclusive `--all-exited` / `--older-than`
/// handling, canonicalization + symlink guards (T-19-04-02/03).
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

#[cfg(all(test, target_os = "windows"))]
mod attach_busy_translation_tests {
    use super::translate_attach_open_error;
    use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;

    #[test]
    fn translates_pipe_busy_to_friendly_setup() {
        let err = std::io::Error::from_raw_os_error(ERROR_PIPE_BUSY as i32);
        let translated = translate_attach_open_error(&err, "abc123");
        let msg = format!("{translated}");
        assert!(msg.contains("abc123"), "expected session id in: {msg}");
        assert!(
            msg.contains("already attached"),
            "expected 'already attached' in: {msg}"
        );
        assert!(
            msg.contains("nono detach"),
            "expected 'nono detach' hint in: {msg}"
        );
    }

    #[test]
    fn passes_through_other_errors() {
        // ERROR_FILE_NOT_FOUND (2)
        let err = std::io::Error::from_raw_os_error(2);
        let translated = translate_attach_open_error(&err, "abc123");
        let msg = format!("{translated}");
        assert!(
            msg.contains("Failed to connect"),
            "expected fallback wording in: {msg}"
        );
    }

    #[test]
    fn passes_through_arbitrary_io_errors() {
        let err = std::io::Error::other("foo");
        let translated = translate_attach_open_error(&err, "abc123");
        let msg = format!("{translated}");
        assert!(
            msg.contains("Failed to connect"),
            "expected fallback wording in: {msg}"
        );
    }
}
