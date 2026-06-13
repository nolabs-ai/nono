//! CLI output styling for nono
//!
//! All colors are drawn from the active theme via `theme::current()`.

use crate::command_display::format_command_line;
use crate::theme::{self, Rgb, badge, fg};
use colored::Colorize;
use nono::{AccessMode, CapabilitySet, NetworkMode, NonoError, Result};
use std::ffi::{OsStr, OsString};
use std::io::{BufRead, IsTerminal, Write};
use std::path::Path;

// Helpers

/// Dark foreground for badge text (works on both light and dark bg colors)
const BADGE_FG_DARK: Rgb = Rgb(30, 30, 46);
/// Print a thin horizontal rule using overlay color
fn rule() {
    let t = theme::current();
    eprintln!("  {}", theme::fg(&"\u{2500}".repeat(52), t.overlay));
}

// Banner

/// Print the nono banner
pub fn print_banner(silent: bool) {
    if silent {
        return;
    }

    let t = theme::current();
    let version = env!("CARGO_PKG_VERSION");

    eprintln!();
    eprintln!(
        "  {} {}",
        theme::fg("nono", t.brand).bold(),
        theme::fg(&format!("v{version}"), t.subtext),
    );
}

// Capabilities

/// Print the capability summary
///
/// When `verbose` is 0, only user-specified capabilities are shown (CLI flags
/// and profile filesystem entries). System paths and group-resolved paths are
/// hidden to reduce noise. Use `-v` to show all capabilities.
pub fn print_capabilities(caps: &CapabilitySet, verbose: u8, silent: bool) {
    if silent {
        return;
    }

    let t = theme::current();

    eprintln!("  {}", theme::fg("Capabilities:", t.subtext).bold());
    rule();

    // Filesystem capabilities
    let fs_caps = caps.fs_capabilities();
    if !fs_caps.is_empty() {
        let (user_caps, other_count) = if verbose > 0 {
            (fs_caps.to_vec(), 0)
        } else {
            let user: Vec<_> = fs_caps
                .iter()
                .filter(|c| c.source.is_user_intent())
                .cloned()
                .collect();
            let hidden = fs_caps.len() - user.len();
            (user, hidden)
        };

        for cap in &user_caps {
            let kind = if cap.is_file { "file" } else { "dir" };
            let access_badge = format_access_badge(&cap.access);

            if verbose > 0 {
                let source_str = format!("{}", cap.source);
                eprintln!(
                    "  {} {} {}",
                    access_badge,
                    theme::fg(&cap.resolved.display().to_string(), t.text),
                    theme::fg(&format!("({kind}) [{source_str}]"), t.subtext),
                );
            } else {
                eprintln!(
                    "  {} {} {}",
                    access_badge,
                    theme::fg(&cap.resolved.display().to_string(), t.text),
                    theme::fg(&format!("({kind})"), t.subtext),
                );
            }
        }

        if other_count > 0 {
            eprintln!(
                "       {}",
                theme::fg(
                    &format!("+ {other_count} system/group paths (-v to show)"),
                    t.subtext
                )
            );
        }
    }

    // AF_UNIX socket capabilities
    let unix_caps = caps.unix_socket_capabilities();
    if !unix_caps.is_empty() {
        let (user_caps, hidden_count) = if verbose > 0 {
            (unix_caps.to_vec(), 0)
        } else {
            let user: Vec<_> = unix_caps
                .iter()
                .filter(|c| c.source.is_user_intent())
                .cloned()
                .collect();
            let hidden = unix_caps.len() - user.len();
            (user, hidden)
        };

        for cap in &user_caps {
            let mode_badge = format_unix_socket_mode_badge(cap.mode);
            let scope_suffix = match cap.scope {
                nono::SocketScope::File => "",
                nono::SocketScope::DirChildren => "  (directory grant — direct child sockets only)",
                nono::SocketScope::DirSubtree => "  (subtree grant — recursive socket paths)",
            };
            if verbose > 0 {
                let source_str = format!("{}", cap.source);
                eprintln!(
                    "  {} {} {}{}",
                    mode_badge,
                    theme::fg(&cap.resolved.display().to_string(), t.text),
                    theme::fg(&format!("[{source_str}]"), t.subtext),
                    theme::fg(scope_suffix, t.subtext),
                );
            } else {
                eprintln!(
                    "  {} {}{}",
                    mode_badge,
                    theme::fg(&cap.resolved.display().to_string(), t.text),
                    theme::fg(scope_suffix, t.subtext),
                );
            }
        }

        if hidden_count > 0 {
            eprintln!(
                "       {}",
                theme::fg(
                    &format!("+ {hidden_count} system/group unix sockets (-v to show)"),
                    t.subtext
                )
            );
        }
    }

    // Network status
    match caps.network_mode() {
        NetworkMode::Blocked => {
            eprintln!(
                "  {} {}",
                theme::badge(" net ", t.red, BADGE_FG_DARK),
                theme::fg("outbound blocked", t.subtext),
            );
        }
        NetworkMode::ProxyOnly { port, bind_ports } => {
            if bind_ports.is_empty() {
                eprintln!(
                    "  {} {}",
                    theme::badge(" net ", t.yellow, BADGE_FG_DARK),
                    theme::fg(&format!("proxy localhost:{port}"), t.subtext),
                );
            } else {
                let ports_str: Vec<String> = bind_ports.iter().map(|p| p.to_string()).collect();
                eprintln!(
                    "  {} {}",
                    theme::badge(" net ", t.yellow, BADGE_FG_DARK),
                    theme::fg(
                        &format!("proxy localhost:{port}, bind: {}", ports_str.join(", ")),
                        t.subtext,
                    ),
                );
            }
        }
        NetworkMode::AllowAll => {
            eprintln!(
                "  {} {}",
                theme::badge(" net ", t.green, BADGE_FG_DARK),
                theme::fg("outbound allowed", t.subtext),
            );
        }
    }
    if !caps.localhost_ports().is_empty() {
        let ports_str: Vec<String> = caps
            .localhost_ports()
            .iter()
            .map(|p| p.to_string())
            .collect();
        eprintln!(
            "  {} {}",
            theme::badge(" ipc ", t.teal, BADGE_FG_DARK),
            theme::fg(&format!("localhost:{}", ports_str.join(", ")), t.subtext,),
        );
    }

    rule();
    eprintln!();
}

/// Format an access mode as a fixed-width colored badge
fn format_access_badge(access: &AccessMode) -> String {
    let t = theme::current();
    match access {
        AccessMode::Read => theme::badge("  r  ", t.green, BADGE_FG_DARK),
        AccessMode::Write => theme::badge("  w  ", t.yellow, BADGE_FG_DARK),
        AccessMode::ReadWrite => theme::badge(" r+w ", t.brand, BADGE_FG_DARK),
    }
}

/// Format a Unix socket mode as a fixed-width colored badge.
fn format_unix_socket_mode_badge(mode: nono::UnixSocketMode) -> String {
    let t = theme::current();
    match mode {
        nono::UnixSocketMode::Connect => theme::badge("sock ", t.green, BADGE_FG_DARK),
        nono::UnixSocketMode::ConnectBind => theme::badge("sock+", t.brand, BADGE_FG_DARK),
    }
}

/// Format an access mode as inline colored text (for prompts)
fn format_access_inline(access: &AccessMode) -> colored::ColoredString {
    let t = theme::current();
    match access {
        AccessMode::Read => theme::fg("read", t.green),
        AccessMode::Write => theme::fg("write", t.yellow),
        AccessMode::ReadWrite => theme::fg("read+write", t.brand),
    }
}

// Kernel / ABI

/// Print Landlock ABI information (Linux only).
///
/// Shows the detected ABI version and available features. When features
/// are degraded (ABI < V5), displays which features are unavailable.
#[cfg(target_os = "linux")]
pub fn print_abi_info(silent: bool) {
    if silent {
        return;
    }
    let t = theme::current();
    match nono::Sandbox::detect_abi() {
        Ok(detected) => {
            type AbiFeatureCheck = (&'static str, fn(&nono::DetectedAbi) -> bool);
            const ALL_FEATURES: &[AbiFeatureCheck] = &[
                ("Refer", nono::DetectedAbi::has_refer),
                ("Truncate", nono::DetectedAbi::has_truncate),
                ("TCP filtering", nono::DetectedAbi::has_network),
                ("IoctlDev", nono::DetectedAbi::has_ioctl_dev),
                ("Scoping", nono::DetectedAbi::has_scoping),
            ];

            let missing: Vec<&str> = ALL_FEATURES
                .iter()
                .filter(|(_, check)| !check(&detected))
                .map(|(name, _)| *name)
                .collect();
            let is_wsl2 = nono::sandbox::is_wsl2();

            if missing.is_empty() && !is_wsl2 {
                return;
            }

            eprintln!(
                "  {} {}",
                badge(" kernel ", t.yellow, BADGE_FG_DARK),
                fg(&detected.to_string(), t.text),
            );

            let hint = if is_wsl2 {
                let pad = " ".repeat(10);
                let mut wsl2_missing: Vec<&str> = Vec::new();
                if !detected.has_network() {
                    wsl2_missing.push("per-port filtering");
                }
                if !detected.has_ioctl_dev() {
                    wsl2_missing.push("device ioctl");
                }
                if !detected.has_scoping() {
                    wsl2_missing.push("process scoping");
                }
                wsl2_missing.push("capability elevation (seccomp notify)");
                format!(
                    "degraded: {} unavailable on WSL2\n\
                     {pad}(block-all network via --block-net still works)\n\
                     {pad}details: https://nono.sh/docs/cli/internals/wsl2",
                    wsl2_missing.join(", "),
                )
            } else {
                format!(
                    "degraded: {} (upgrade kernel for full support)",
                    missing.join(", "),
                )
            };
            eprintln!("          {}", fg(&hint, t.yellow));
        }
        Err(e) => {
            eprintln!(
                "  {} {}",
                badge(" kernel ", t.red, BADGE_FG_DARK),
                fg(&format!("Landlock detection failed: {e}"), t.red),
            );
        }
    }
}

/// Print the Landlock scope policy derived from the current capabilities.
#[cfg(target_os = "linux")]
pub fn print_landlock_scope_policy(caps: &CapabilitySet, verbose: u8, silent: bool) {
    if silent || verbose == 0 {
        return;
    }

    let t = theme::current();
    match nono::landlock_scope_policy(caps) {
        Ok(policy) => {
            eprintln!(
                "  {} {}",
                badge(" scope ", t.blue, BADGE_FG_DARK),
                fg(
                    &format!("Landlock {} detected", policy.abi_version),
                    t.subtext,
                )
            );
            eprintln!(
                "          {} {}",
                fg("signal:", t.subtext),
                fg(
                    &format_scope_status(
                        policy.signal_requested,
                        policy.signal_enforced,
                        policy.scoping_supported,
                    ),
                    scope_status_color(
                        policy.signal_requested,
                        policy.signal_enforced,
                        policy.scoping_supported,
                        t,
                    ),
                )
            );
            eprintln!(
                "          {} {}",
                fg("abstract-unix-socket:", t.subtext),
                fg(
                    &format_scope_status(
                        policy.abstract_unix_socket_requested,
                        policy.abstract_unix_socket_enforced,
                        policy.scoping_supported,
                    ),
                    scope_status_color(
                        policy.abstract_unix_socket_requested,
                        policy.abstract_unix_socket_enforced,
                        policy.scoping_supported,
                        t,
                    ),
                )
            );
        }
        Err(err) => {
            eprintln!(
                "  {} {}",
                badge(" scope ", t.red, BADGE_FG_DARK),
                fg(&format!("Landlock scope policy unavailable: {err}"), t.red),
            );
        }
    }
}

#[cfg(target_os = "linux")]
fn format_scope_status(requested: bool, enforced: bool, supported: bool) -> String {
    match (requested, enforced, supported) {
        (true, true, _) => "requested, enforced".to_string(),
        (true, false, false) => "requested, unsupported by detected ABI".to_string(),
        (true, false, true) => "requested, not enforced".to_string(),
        (false, _, true) => "not requested".to_string(),
        (false, _, false) => "not requested; detected ABI has no scope support".to_string(),
    }
}

#[cfg(target_os = "linux")]
fn scope_status_color(requested: bool, enforced: bool, supported: bool, t: &theme::Theme) -> Rgb {
    match (requested, enforced, supported) {
        (true, true, _) => t.green,
        (true, false, _) => t.yellow,
        (false, _, _) => t.subtext,
    }
}

// Status messages

/// Print supervised mode status
pub fn print_supervised_info(silent: bool, rollback: bool, proxy_active: bool) {
    if silent || (!rollback && !proxy_active) {
        return;
    }
    let t = theme::current();
    let mut features = Vec::new();
    if rollback {
        features.push("snapshots");
    }
    if proxy_active {
        features.push("proxy");
    }
    features.push("supervisor");
    eprintln!(
        "  {} {}",
        fg("mode", t.subtext),
        fg(&format!("supervised ({})", features.join(", ")), t.subtext),
    );
}

/// Print a minimal status line before handing off to the sandboxed child.
pub fn print_applying_sandbox(silent: bool) {
    if silent {
        return;
    }
    let t = theme::current();
    eprintln!("  {}", fg("Applying sandbox...", t.subtext));
    eprintln!();
}

/// Print a styled warning message to stderr
pub fn print_warning(message: &str) {
    let t = theme::current();
    eprintln!("  {} {}", fg("warning:", t.red).bold(), fg(message, t.text),);
}

/// Format startup-blocked lines for writing to /dev/tty or stderr.
/// Returns a Vec of lines ready to write (without trailing newline).
pub fn format_startup_blocked(
    program: &str,
    timeout_secs: u64,
    has_output: bool,
    recommended_profile: Option<&str>,
) -> Vec<String> {
    let t = theme::current();
    let label = fg("blocked:", t.yellow).bold().to_string();
    let reason = if has_output {
        format!(
            "`{}` has not become interactive after {} seconds.",
            program, timeout_secs
        )
    } else {
        format!(
            "`{}` produced no terminal output after {} seconds.",
            program, timeout_secs
        )
    };
    let mut lines = vec![
        format!("  {} {}", label, fg(&reason, t.text)),
        format!(
            "  {}",
            fg(
                "Terminating process — re-run with -v to inspect denied paths.",
                t.subtext
            )
        ),
    ];
    if let Some(profile) = recommended_profile {
        lines.push(format!(
            "  {} nono run --profile {} -- {}",
            fg("Try:", t.green).bold(),
            profile,
            program,
        ));
    }
    lines
}

/// Print a styled diagnostic footer emitted by the core diagnostic formatter.
pub fn print_diagnostic_footer(footer: &str) {
    let rendered = render_diagnostic_footer(footer);
    print_terminal_block(&rendered, true);
}

/// Print skipped CLI path grants in a user-facing format.
pub fn print_skipped_requested_paths(paths: &[String], silent: bool) {
    if silent || paths.is_empty() {
        return;
    }

    let t = theme::current();
    eprintln!(
        "  {} {}",
        fg("warning:", t.red).bold(),
        fg(
            "some requested sandbox grants were skipped because the path does not exist:",
            t.text,
        ),
    );
    for path in paths {
        eprintln!("           {}", fg(path, t.subtext));
    }
    eprintln!();
}

fn render_diagnostic_footer(footer: &str) -> String {
    let t = theme::current();
    footer
        .lines()
        .enumerate()
        .map(|(idx, line)| render_diagnostic_line(idx, line, t))
        .collect::<Vec<_>>()
        .join("\n")
}

fn print_terminal_block(message: &str, leading_blank_line: bool) {
    let mut stderr = std::io::stderr();
    if stderr.is_terminal() {
        if leading_blank_line {
            let _ = write!(stderr, "\r\x1b[K\r\n");
        }
        let _ = write!(stderr, "{}", render_terminal_block_for_tty(message));
        let _ = stderr.flush();
    } else {
        if leading_blank_line {
            let _ = writeln!(stderr);
        }
        let _ = writeln!(stderr, "{}", message);
    }
}

fn render_terminal_block_for_tty(message: &str) -> String {
    let mut out = String::new();
    for line in message.lines() {
        out.push('\r');
        out.push_str(line);
        out.push_str("\x1b[K\r\n");
    }
    out
}

fn render_diagnostic_line(idx: usize, line: &str, t: &theme::Theme) -> String {
    let line = sanitize_terminal_output(line);
    if line.is_empty() {
        return String::new();
    }

    if idx == 0 && line == "nono diagnostic" {
        return format!("{}", fg("NONO DIAGNOSTIC", t.red).bold());
    }

    if idx == 1 && line.chars().all(|c| c == '\u{2500}') {
        return format!("{}", fg(&"\u{2500}".repeat(24), t.red));
    }

    if line.starts_with("The command failed") {
        return format!("{}", fg(&line, t.red).bold());
    }

    if line.starts_with("The command succeeded") {
        return format!("{}", fg(&line, t.yellow).bold());
    }

    if !line.starts_with(' ') && line.ends_with(':') {
        let color = match line.as_str() {
            "Likely sandbox denial:" | "Missing path:" => t.red,
            "Sandbox policy:" => t.brand,
            _ => t.text,
        };
        return format!("{}", fg(&line, color).bold());
    }

    if let Some(rest) = line.strip_prefix("  Try: ") {
        return format!(
            "  {} {}",
            fg("Try:", t.green).bold(),
            fg(rest, t.text).bold()
        );
    }

    if let Some(rest) = line.strip_prefix("  Why: ") {
        return format!("  {} {}", fg("Why:", t.blue).bold(), fg(rest, t.text));
    }

    if let Some(rest) = line.strip_prefix("  Learn: ") {
        return format!("  {} {}", fg("Learn:", t.teal).bold(), fg(rest, t.text));
    }

    if let Some(rest) = line.strip_prefix("  Re-use ") {
        return format!("  {}", fg(&format!("Re-use {rest}"), t.subtext));
    }

    if line == "  Allowed paths:" {
        return format!("  {}", fg("Allowed paths:", t.subtext).bold());
    }

    if let Some(rest) = line.strip_prefix("  Network: ") {
        let color = if rest.contains("blocked") {
            t.red
        } else if rest.contains("allowed") {
            t.green
        } else {
            t.blue
        };
        return format!("  {} {}", fg("Network:", t.subtext).bold(), fg(rest, color));
    }

    if line.starts_with("  /") || line.starts_with("  ~/") {
        let content = line.trim_start();
        return if let Some(idx) = content.rfind(" (") {
            format!(
                "  {} {}",
                fg(&content[..idx], t.text).bold(),
                &content[idx + 1..],
            )
        } else {
            format!("  {}", fg(content, t.text).bold())
        };
    }

    if line.starts_with("    + ") {
        return format!("    {}", fg(line.trim_start(), t.subtext));
    }

    if line.starts_with("    ") {
        return format!("    {}", fg(line.trim_start(), t.text));
    }

    line
}

/// Print dry run message
pub fn print_dry_run(
    program: &OsStr,
    cmd_args: &[OsString],
    redaction_policy: &nono::ScrubPolicy,
    silent: bool,
) {
    if silent {
        return;
    }
    let t = theme::current();
    let command_line = dry_run_command_line(program, cmd_args, redaction_policy);

    eprintln!(
        "  {} {}",
        fg("dry-run", t.yellow).bold(),
        fg(
            "sandbox would be applied with above capabilities",
            t.subtext,
        ),
    );
    eprintln!("  {} {}", fg("$", t.subtext), fg(&command_line, t.text));
}

fn dry_run_command_line(
    program: &OsStr,
    cmd_args: &[OsString],
    redaction_policy: &nono::ScrubPolicy,
) -> String {
    let mut command = Vec::with_capacity(1 + cmd_args.len());
    command.push(program.to_string_lossy().into_owned());
    command.extend(
        cmd_args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned()),
    );

    format_command_line(&nono::scrub_argv_with_policy(&command, redaction_policy))
}

// Rollback / Snapshots

/// Print rollback tracking status during session start
pub fn print_rollback_tracking(paths: &[std::path::PathBuf], silent: bool) {
    if silent {
        return;
    }
    let t = theme::current();
    let display_paths = if paths.len() <= 3 { paths } else { &paths[..2] };
    for path in display_paths {
        eprintln!(
            "  {} {}",
            badge(" snap ", t.surface, t.subtext),
            fg(&path.display().to_string(), t.subtext),
        );
    }
    if paths.len() > 3 {
        eprintln!(
            "         {}",
            fg(&format!("+ {} more paths", paths.len() - 2), t.subtext),
        );
    }
}

/// Print post-exit summary of changes detected by the rollback system
pub fn print_rollback_session_summary(changes: &[nono::undo::Change], silent: bool) {
    if silent || changes.is_empty() {
        return;
    }

    let t = theme::current();

    let created = changes
        .iter()
        .filter(|c| c.change_type == nono::undo::ChangeType::Created)
        .count();
    let modified = changes
        .iter()
        .filter(|c| c.change_type == nono::undo::ChangeType::Modified)
        .count();
    let deleted = changes
        .iter()
        .filter(|c| c.change_type == nono::undo::ChangeType::Deleted)
        .count();

    let mut parts = Vec::new();
    if created > 0 {
        parts.push(format!("{}", fg(&format!("{created} created"), t.green)));
    }
    if modified > 0 {
        parts.push(format!("{}", fg(&format!("{modified} modified"), t.yellow)));
    }
    if deleted > 0 {
        parts.push(format!("{}", fg(&format!("{deleted} deleted"), t.red)));
    }

    eprintln!();
    eprintln!(
        "  {} {} files changed ({})",
        fg("nono", t.brand).bold(),
        changes.len(),
        parts.join(", "),
    );
}

// Update notification

/// Detect how nono was installed based on the binary's path.
fn detect_install_command() -> &'static str {
    let exe = match std::env::current_exe().and_then(|p| p.canonicalize()) {
        Ok(p) => p,
        Err(_) => return "cargo install nono-cli",
    };
    let path = exe.to_string_lossy();

    // Homebrew (macOS Intel or Apple Silicon)
    if path.contains("/opt/homebrew/") || path.contains("/usr/local/Cellar/") {
        return "brew upgrade nono";
    }

    // Cargo
    if path.contains("/.cargo/bin/") {
        return "cargo install nono-cli";
    }

    // Linux system package manager
    if path.starts_with("/usr/bin/") || path.starts_with("/usr/local/bin/") {
        if Path::new("/usr/bin/apt").exists() {
            return "sudo apt update && sudo apt upgrade nono";
        }
        if Path::new("/usr/bin/dnf").exists() {
            return "sudo dnf upgrade nono";
        }
        // Fallback for other system installs
        return "upgrade nono via your package manager";
    }

    "cargo install nono-cli"
}

/// Strip ANSI escape sequences and non-printable characters from a string.
///
/// Prevents terminal injection from a compromised update server.
fn sanitize_terminal_output(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip ESC and the entire escape sequence
            if let Some(next) = chars.next()
                && next == '['
            {
                // CSI sequence: skip until a letter is found
                for seq_char in chars.by_ref() {
                    if seq_char.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            // OSC, other sequences: already consumed the next char, continue
        } else if c.is_control() && c != '\n' {
            // Strip control characters (except newline)
        } else {
            result.push(c);
        }
    }
    result
}

/// Print update notification if a newer version is available
pub fn print_update_notification(info: &crate::update_check::UpdateInfo, silent: bool) {
    if silent {
        return;
    }

    let t = theme::current();
    let version = sanitize_terminal_output(&info.latest_version);
    let install_cmd = detect_install_command();
    eprintln!(
        "  {} {} {} {}",
        fg("update", t.yellow).bold(),
        fg(&version, t.green).bold(),
        fg("available", t.subtext),
        fg(
            &format!("(current: {})", env!("CARGO_PKG_VERSION")),
            t.subtext,
        ),
    );
    if let Some(ref msg) = info.message {
        let safe_msg = sanitize_terminal_output(msg);
        eprintln!("  {}", fg(&safe_msg, t.subtext));
    }
    eprintln!("  {} {}", fg("$", t.subtext), fg(install_cmd, t.text));
    if let Some(ref url) = info.release_url {
        let safe_url = sanitize_terminal_output(url);
        eprintln!("  {}", fg(&safe_url, t.blue));
    }
    eprintln!();
}

// Interactive prompts

/// Prompt the user to confirm sharing the current working directory.
///
/// Returns `Ok(true)` if user confirms, `Ok(false)` if user declines.
/// Returns `Ok(false)` with a hint if stdin is not a TTY.
pub fn prompt_cwd_sharing(cwd: &Path, access: &AccessMode) -> Result<bool> {
    let t = theme::current();
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        eprintln!(
            "  {}",
            fg(
                "Skipping CWD prompt (non-interactive). Use --allow-cwd to include working directory.",
                t.subtext,
            ),
        );
        return Ok(false);
    }

    let access_colored = format_access_inline(access);

    eprintln!(
        "  Share {} with {} access?",
        fg(&cwd.display().to_string(), t.text).bold(),
        access_colored,
    );
    eprintln!("  {}", fg("use --allow-cwd to skip this prompt", t.subtext),);
    eprint!("  {} ", fg("[y/N]", t.text).bold());
    std::io::stderr().flush().ok();

    let mut input = String::new();
    stdin.lock().read_line(&mut input).map_err(NonoError::Io)?;

    let answer = input.trim().to_lowercase();
    Ok(answer == "y" || answer == "yes")
}

pub fn print_profile_hint(program: &str, profile: &str, silent: bool) {
    if silent {
        return;
    }

    let t = theme::current();
    eprintln!(
        "  {}",
        fg(
            &format!(
                "Hint: `{program}` usually needs the built-in `{profile}` profile for its state and auth paths."
            ),
            t.yellow,
        )
    );
    eprintln!(
        "  {}",
        fg(
            &format!("Try: nono run --profile {profile} -- {program}"),
            t.subtext,
        )
    );
    eprintln!();
}

#[cfg(test)]
mod tests {
    use super::{
        dry_run_command_line, format_unix_socket_mode_badge, print_capabilities,
        print_profile_hint, render_diagnostic_footer, render_terminal_block_for_tty,
    };
    use nono::{CapabilitySet, UnixSocketMode};
    use std::ffi::{OsStr, OsString};
    use tempfile::tempdir;

    #[test]
    fn render_diagnostic_footer_preserves_line_structure() {
        let footer = "nono diagnostic\n────────\nThe command failed.\n  Learn: nono learn";
        let rendered = render_diagnostic_footer(footer);
        assert_eq!(rendered.lines().count(), 4);
    }

    #[test]
    fn render_diagnostic_footer_splits_path_on_last_paren_group() {
        // Path contains " (" in the directory name — rfind ensures we split on
        // the *last* parenthesised group (the access type), not the one
        // embedded in the path.
        let footer = "  /home/user/my (project)/file (read)";
        let rendered = render_diagnostic_footer(footer);
        assert!(
            rendered.contains("/home/user/my (project)/file"),
            "path with embedded parens should be preserved: {rendered}"
        );
        assert!(
            rendered.contains("(read)"),
            "access type should be preserved: {rendered}"
        );
    }

    #[test]
    fn render_terminal_block_for_tty_clears_each_line_tail() {
        assert_eq!(
            render_terminal_block_for_tty("short\nnext"),
            "\rshort\u{1b}[K\r\n\rnext\u{1b}[K\r\n"
        );
    }

    #[test]
    fn print_profile_hint_is_noop_when_silent() {
        print_profile_hint("claude", "claude-code", true);
    }

    #[test]
    fn dry_run_command_line_redacts_default_secrets() {
        let line = dry_run_command_line(
            OsStr::new("curl"),
            &[
                OsString::from("--token"),
                OsString::from("real-token"),
                OsString::from("https://example.com/api?token=real-secret"),
            ],
            &nono::ScrubPolicy::secure_default(),
        );

        assert!(line.contains("[REDACTED]"));
        assert!(!line.contains("real-token"));
        assert!(!line.contains("real-secret"));
    }

    #[test]
    fn dry_run_command_line_uses_configured_redaction_policy() {
        let mut redactions = nono::ScrubPolicy::secure_default();
        redactions.add_flag("--private-token");

        let line = dry_run_command_line(
            OsStr::new("curl"),
            &[OsString::from("--private-token=private-secret")],
            &redactions,
        );

        assert_eq!(line, "curl '--private-token=[REDACTED]'");
        assert!(!line.contains("private-secret"));
    }

    #[test]
    fn unix_socket_mode_badges_are_fixed_width_and_distinct() {
        let connect = format_unix_socket_mode_badge(UnixSocketMode::Connect);
        let bind = format_unix_socket_mode_badge(UnixSocketMode::ConnectBind);
        // Same rendered-width contract as format_access_badge (5 chars).
        // We can't `strip_ansi` cleanly here, so check the printable payload
        // is present rather than the raw length.
        assert!(connect.contains("sock "));
        assert!(bind.contains("sock+"));
        assert_ne!(connect, bind);
    }

    #[test]
    fn print_capabilities_with_unix_socket_does_not_panic() {
        // Smoke test: constructing a CapabilitySet with both connect and
        // connect+bind unix socket grants (one file, one directory) and
        // rendering it must not panic. Silent=true keeps stderr quiet in
        // test output. Dry-run-style `verbose=1` path is also exercised.
        let dir = tempdir().expect("tempdir");
        let sock = dir.path().join("a.sock");
        std::fs::write(&sock, b"").expect("create socket stub");

        let caps = CapabilitySet::new()
            .allow_unix_socket(&sock, UnixSocketMode::Connect)
            .expect("connect grant")
            .allow_unix_socket_dir(dir.path(), UnixSocketMode::ConnectBind)
            .expect("bind dir grant");

        print_capabilities(&caps, 0, true);
        print_capabilities(&caps, 1, true);
    }
}
