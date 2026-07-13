//! CLI output styling for nono
//!
//! All colors are drawn from the active theme via `theme::current()`.

use crate::command_display::format_command_line;
#[cfg(target_os = "linux")]
use crate::resource_cgroup::{OomReport, PidsReport};
use crate::theme::{self, Rgb, badge, fg};
use colored::Colorize;
#[cfg(target_os = "linux")]
use nono::resource::format_bytes;
use nono::{AccessMode, CapabilitySet, NetworkMode, NonoError, Result};
use std::ffi::{OsStr, OsString};
use std::io::{BufRead, IsTerminal, Write};
use std::path::Path;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Dark foreground for badge text (works on both light and dark bg colors)
const BADGE_FG_DARK: Rgb = Rgb(30, 30, 46);
/// Print a thin horizontal rule using overlay color
fn rule() {
    let t = theme::current();
    eprintln!("  {}", theme::fg(&"\u{2500}".repeat(52), t.overlay));
}

// ---------------------------------------------------------------------------
// Banner
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------

/// The parenthetical after the `resources` summary, spelling out breach behavior so
/// the two caps aren't confused: over memory the tree is killed; over the process
/// count new forks are refused (nothing dies). Only rendered for a non-empty limit
/// set, so the `_` arm is memory-only — `(false, false)` never reaches here.
fn resource_limit_note(has_memory: bool, has_processes: bool) -> &'static str {
    match (has_memory, has_processes) {
        (true, true) => {
            "(hard caps — over memory the process tree is killed; over the process count new forks are refused)"
        }
        (false, true) => "(hard cap — new processes are refused past this count)",
        _ => "(hard cap — the process tree is killed if it exceeds this)",
    }
}

/// Print the capability summary
///
/// When `verbose` is 0, only user-specified capabilities are shown (CLI flags
/// and profile filesystem entries). System paths and group-resolved paths are
/// hidden to reduce noise. Use `-v` to show all capabilities.
pub fn print_capabilities(
    caps: &CapabilitySet,
    blocked_grants: &[(std::path::PathBuf, Option<String>)],
    verbose: u8,
    silent: bool,
    proxy_pending: bool,
) {
    if silent {
        return;
    }

    let t = theme::current();

    eprintln!("  {}", theme::fg("Capabilities:", t.subtext).bold());
    rule();

    // Resource limits are shown here; enforcement happens in the supervised runtime.
    if let Some(limits) = caps.resource_limits()
        && !limits.is_empty()
    {
        eprintln!(
            "  {} {} {}",
            theme::fg("resources", t.yellow).bold(),
            theme::fg(&limits.summary(), t.subtext),
            theme::fg(
                resource_limit_note(
                    limits.memory_bytes.is_some(),
                    limits.max_processes.is_some(),
                ),
                t.subtext,
            ),
        );
    }

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

    // Protected paths kept blocked despite a user grant (macOS deny groups).
    // Folded into one row by default so a broad grant (e.g. ~/Library) that
    // overlaps several deny groups does not produce a wall of warnings.
    print_blocked_grants(blocked_grants, verbose, t);

    // AF_UNIX socket capabilities (issue #685 / #696)
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
            if proxy_pending {
                // Profile set network.block but CLI added proxy flags — proxy
                // will start in strict_filter mode and owns the network mode.
                eprintln!(
                    "  {} {}",
                    theme::badge(" net ", t.yellow, BADGE_FG_DARK),
                    theme::fg("proxy (strict)", t.subtext),
                );
            } else {
                eprintln!(
                    "  {} {}",
                    theme::badge(" net ", t.red, BADGE_FG_DARK),
                    theme::fg("outbound blocked", t.subtext),
                );
            }
        }
        NetworkMode::ProxyOnly { port, bind_ports } => {
            let port_str = if *port == 0 {
                String::new()
            } else {
                format!(" localhost:{port}")
            };
            if bind_ports.is_empty() {
                eprintln!(
                    "  {} {}",
                    theme::badge(" net ", t.yellow, BADGE_FG_DARK),
                    theme::fg(&format!("proxy{port_str}"), t.subtext),
                );
            } else {
                let ports_str: Vec<String> = bind_ports.iter().map(|p| p.to_string()).collect();
                let bind_info = format!(", bind: {}", ports_str.join(", "));
                eprintln!(
                    "  {} {}",
                    theme::badge(" net ", t.yellow, BADGE_FG_DARK),
                    theme::fg(&format!("proxy{port_str}{bind_info}"), t.subtext,),
                );
            }
        }
        NetworkMode::AllowAll => {
            if proxy_pending {
                eprintln!(
                    "  {} {}",
                    theme::badge(" net ", t.yellow, BADGE_FG_DARK),
                    theme::fg("proxy", t.subtext),
                );
            } else {
                eprintln!(
                    "  {} {}",
                    theme::badge(" net ", t.green, BADGE_FG_DARK),
                    theme::fg("outbound allowed", t.subtext),
                );
            }
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
/// Render the paths that a deny group keeps blocked despite a user grant.
///
/// Collapsed by default to a single row (a broad grant such as `~/Library`
/// overlaps many deny groups and would otherwise emit one warning per path).
/// `-v` expands to the full paths grouped by the deny rule that blocks them,
/// with the `--bypass-protection` escape hatch shown once.
fn print_blocked_grants(
    blocked: &[(std::path::PathBuf, Option<String>)],
    verbose: u8,
    t: &theme::Theme,
) {
    if blocked.is_empty() {
        return;
    }

    let badge = theme::badge("deny ", t.yellow, BADGE_FG_DARK);

    if verbose == 0 {
        let n = blocked.len();
        let noun = if n == 1 { "path" } else { "paths" };
        eprintln!(
            "  {} {}",
            badge,
            theme::fg(
                &format!("{n} sensitive {noun} kept blocked inside your grants (-v to show)"),
                t.subtext,
            ),
        );
        return;
    }

    eprintln!(
        "  {} {}",
        badge,
        theme::fg("sensitive paths kept blocked despite your grants:", t.text),
    );

    // Group by the deny rule that blocks each path, preserving first-seen order.
    let mut groups: Vec<(String, Vec<&std::path::Path>)> = Vec::new();
    for (path, group) in blocked {
        let group_name = group.as_deref().unwrap_or("a deny rule");
        match groups.iter_mut().find(|(name, _)| name == group_name) {
            Some((_, paths)) => paths.push(path.as_path()),
            None => groups.push((group_name.to_string(), vec![path.as_path()])),
        }
    }

    for (name, paths) in &groups {
        eprintln!("       {}", theme::fg(name, t.subtext));
        for path in paths {
            eprintln!("         {}", theme::fg(&path.to_string_lossy(), t.text));
        }
    }

    eprintln!(
        "       {}",
        theme::fg(
            "use --bypass-protection <path> to allow a specific path",
            t.subtext,
        ),
    );
}

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

// ---------------------------------------------------------------------------
// Kernel / ABI
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Status messages
// ---------------------------------------------------------------------------

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

/// Print proxy credential warnings collected at startup.
pub fn print_proxy_diagnostics(diagnostics: &[nono_proxy::ProxyDiagnostic]) {
    if diagnostics.is_empty() {
        return;
    }

    let t = theme::current();
    eprintln!();
    eprintln!(
        "  {}",
        theme::fg("Proxy credential warnings:", t.red).bold(),
    );
    for diagnostic in diagnostics {
        let code = diagnostic.code.as_str();
        eprintln!(
            "  {} /{} — {}",
            theme::fg(code, t.subtext),
            diagnostic.route_prefix,
            fg(&diagnostic.message, t.text),
        );
        if let Some(hint) = &diagnostic.hint {
            eprintln!("    {}", theme::fg(hint, t.subtext));
        } else if let Some(action) = proxy_diagnostic_action(&diagnostic.code) {
            eprintln!("    {}", theme::fg(action, t.subtext));
        }
    }
}

fn proxy_diagnostic_action(code: &nono_proxy::ProxyDiagnosticCode) -> Option<&'static str> {
    use nono_proxy::ProxyDiagnosticCode;
    match code {
        ProxyDiagnosticCode::CredentialNotFound => Some(
            "Configure a valid credential reference for this route, or use an explicit upstream credential.",
        ),
        ProxyDiagnosticCode::CredentialUnavailable => Some(
            "Unlock the system keychain or authenticate with your credential provider (e.g. `op signin`).",
        ),
        ProxyDiagnosticCode::OAuthClientIdUnavailable
        | ProxyDiagnosticCode::OAuthClientSecretUnavailable => {
            Some("Provide OAuth client credentials via env/keystore configuration for this route.")
        }
        ProxyDiagnosticCode::OAuthTokenExchangeFailed => {
            Some("Verify OAuth client credentials and provider availability, then retry.")
        }
        _ => None,
    }
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

/// Explain that the kernel OOM-killed the sandbox for exceeding its `--memory`
/// ceiling.
///
/// Without this a memory-cap kill surfaces only as a bare SIGKILL (exit 137),
/// so the run looks like it died for no reason. We name the limit, the peak the
/// tree reached, and how to relax it. Suppressed under `--silent`.
#[cfg(target_os = "linux")]
pub fn print_oom_diagnostic(report: &OomReport, silent: bool) {
    if silent {
        return;
    }
    let t = theme::current();
    let emit = crate::startup_prompt::print_terminal_safe_stderr;

    // A labelled row: indented, the label padded on the plain text before
    // coloring so values line up despite the invisible ANSI escapes.
    let row = |label: &str, value: &str| {
        emit(&format!(
            "       {} {}",
            fg(&format!("{label:<17}"), t.subtext),
            fg(value, t.text),
        ));
    };

    emit(&format!(
        "{} {}",
        fg("[nono] memory limit exceeded:", t.red).bold(),
        fg(
            "the sandboxed process tree was killed by the kernel for using too much memory.",
            t.text,
        ),
    ));
    let limit = report
        .limit_bytes
        .map_or_else(|| "unset".to_string(), format_bytes);
    row("limit (--memory):", &limit);
    if let Some(peak) = report.peak_bytes {
        row("peak memory:", &format_bytes(peak));
    }
    row(
        "OOM kills:",
        &format!(
            "{} (whole-sandbox kills: {})",
            report.oom_kills, report.oom_group_kills
        ),
    );
    row(
        "swap:",
        "disabled (memory.swap.max=0) — nothing could spill to swap",
    );
    row(
        "scope:",
        "the whole sandbox was killed together (memory.oom.group=1)",
    );
    emit(&format!(
        "       {} {}",
        fg("hint:", t.yellow).bold(),
        fg(
            "raise the ceiling to allow more memory, e.g. --memory 1G.",
            t.text,
        ),
    ));
}

/// Explain that the sandbox hit its `--max-processes` ceiling.
///
/// Unlike the memory cap this kills nothing — the kernel just refused a `fork`/`clone`
/// (EAGAIN), which the program may surface as an opaque "resource temporarily
/// unavailable" under any exit code. Naming the limit and the denied-fork count turns
/// that into an explained failure. Printed whenever the cap was hit, any exit code.
#[cfg(target_os = "linux")]
pub fn print_pids_diagnostic(report: &PidsReport, silent: bool) {
    if silent {
        return;
    }
    let t = theme::current();
    let emit = crate::startup_prompt::print_terminal_safe_stderr;

    // Pad to the longest label ("limit (--max-processes):" == 24) so the values
    // line up, matching the memory diagnostic's aligned look.
    let row = |label: &str, value: &str| {
        emit(&format!(
            "       {} {}",
            fg(&format!("{label:<24}"), t.subtext),
            fg(value, t.text),
        ));
    };

    emit(&format!(
        "{} {}",
        fg("[nono] process limit reached:", t.red).bold(),
        fg(
            "the sandbox hit its process cap; the kernel refused new processes (fork failed) — \
             it was not killed.",
            t.text,
        ),
    ));
    let limit = report
        .limit
        .map_or_else(|| "unset".to_string(), |n| n.to_string());
    row("limit (--max-processes):", &limit);
    if let Some(peak) = report.peak {
        row("peak processes:", &peak.to_string());
    }
    row("denied forks:", &report.max_events.to_string());
    emit(&format!(
        "       {} {}",
        fg("hint:", t.yellow).bold(),
        fg(
            "raise the ceiling to allow more processes, e.g. --max-processes 256.",
            t.text,
        ),
    ));
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

// ---------------------------------------------------------------------------
// Rollback / Snapshots
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Update notification
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Interactive prompts
// ---------------------------------------------------------------------------

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
    use super::theme;
    use super::{
        dry_run_command_line, format_unix_socket_mode_badge, print_blocked_grants,
        print_capabilities, print_profile_hint, render_diagnostic_footer,
        render_terminal_block_for_tty,
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

        print_capabilities(&caps, &[], 0, true, false);
        print_capabilities(&caps, &[], 1, true, false);
    }

    #[test]
    fn print_blocked_grants_collapsed_and_verbose_do_not_panic() {
        // Blocked grants render as one folded row by default and expand under
        // -v; both paths (and the empty case) must render without panicking.
        let t = theme::current();
        let blocked = vec![
            (
                std::path::PathBuf::from("/Users/x/Library/Application Support/Google/Chrome"),
                Some("deny_browser_data_macos".to_string()),
            ),
            (
                std::path::PathBuf::from("/Users/x/Library/Application Support/1Password"),
                Some("deny_keychains_macos".to_string()),
            ),
            (
                std::path::PathBuf::from("/Users/x/Library/Application Support/Unknown"),
                None,
            ),
        ];

        print_blocked_grants(&blocked, 0, t);
        print_blocked_grants(&blocked, 1, t);
        print_blocked_grants(&[], 0, t);
    }

    #[test]
    fn resource_limit_note_matches_the_active_ceilings() {
        use super::resource_limit_note;

        // Both ceilings: the note must spell out both breach behaviors.
        let both = resource_limit_note(true, true);
        assert!(
            both.contains("memory") && both.contains("forks are refused"),
            "both-ceilings note must describe both mechanisms: {both}"
        );

        // Process-only: forks are refused, and it must NOT claim anything is killed.
        let procs = resource_limit_note(false, true);
        assert_eq!(
            procs,
            "(hard cap — new processes are refused past this count)"
        );
        assert!(
            !procs.contains("killed"),
            "a pids cap kills nothing: {procs}"
        );

        // Memory-only falls to the kill-the-tree note; the unreachable empty input
        // folds into the same arm (documented fallback, never rendered in practice).
        let mem = resource_limit_note(true, false);
        assert!(
            mem.contains("killed"),
            "memory-only note must say killed: {mem}"
        );
        assert_eq!(
            resource_limit_note(false, false),
            mem,
            "the (false,false) fallback must match the memory-only note"
        );
    }

    /// The `--max-processes` breach footer renders across every report shape without
    /// panicking: silent is a no-op, a full report prints, and the Option branches
    /// (an unset limit -> "unset", an absent peak -> the row is skipped) are safe.
    #[test]
    #[cfg(target_os = "linux")]
    fn print_pids_diagnostic_renders_all_report_shapes() {
        use super::print_pids_diagnostic;
        use crate::resource_cgroup::PidsReport;

        let full = PidsReport {
            max_events: 4,
            limit: Some(5),
            peak: Some(5),
        };
        // Silent short-circuits before any rendering.
        print_pids_diagnostic(&full, true);
        // Full report: limit + peak rows present.
        print_pids_diagnostic(&full, false);
        // Degenerate report: unlimited/unreadable limit and no kernel peak, so the
        // "unset" limit branch and the skipped-peak branch are both exercised.
        print_pids_diagnostic(
            &PidsReport {
                max_events: 1,
                limit: None,
                peak: None,
            },
            false,
        );
    }
}
