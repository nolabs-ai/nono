//! Native OS-dialog approval backend for supervisor IPC.
//!
//! Prompts the user with a native modal dialog (macOS `osascript`, Linux
//! `zenity`/`kdialog`) instead of the terminal. The dialog is delivered by the
//! window/display server — a channel completely separate from the controlling
//! terminal — so it renders and accepts input correctly even when a full-screen
//! TUI (e.g. an AI coding agent) owns the tty, which is exactly where the
//! `terminal` backend auto-denies or hangs.
//!
//! Security posture (this file is security-critical, see AGENTS.md):
//! - **Fail secure**: when no GUI display is reachable (headless, SSH,
//!   container, CI) the backend denies immediately without spawning anything.
//!   There is deliberately no fallback to the terminal backend.
//! - **No injection**: every untrusted `ApprovalRequest` field is sanitized
//!   (control/ANSI stripped) and length-bounded, then passed to the dialog tool
//!   as a *single* process argument — never interpolated into an AppleScript
//!   program or a shell string. The message always begins with a fixed,
//!   non-`-` prefix so untrusted content can never be parsed as a CLI option.
//! - **Fixed choices**: button labels are compile-time constants; untrusted
//!   text never reaches a button.
//! - **Absolute binaries**: dialog tools are located by absolute path, never
//!   via `$PATH`.
//! - **Bounded wait**: the dialog is force-terminated after a wall-clock
//!   deadline, so a walked-away user resolves to `Timeout` (treated as a denial
//!   by the supervisor) rather than blocking forever.

use crate::command_policy::ApprovalBackendConfig;
use nono::{ApprovalBackend, ApprovalDecision, ApprovalRequest, Result};

/// Default dialog timeout when the backend config does not set `timeout_secs`.
const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// Reason returned when no GUI display is reachable. Names the likely causes and
/// points operators at the non-interactive alternative, matching the
/// fail-secure design in the feature issue.
const NO_DISPLAY_REASON: &str = "no reachable GUI display for dialog approval \
    (headless, SSH, container, or CI); configure a non-interactive approval \
    backend such as `webhook` for this environment";

/// Native OS-dialog approval backend.
///
/// Carries the configured backend name (recorded in the audit trail via
/// [`ApprovalBackend::backend_name`]) and the per-request dialog timeout.
pub struct DialogApproval {
    name: String,
    timeout: std::time::Duration,
}

impl DialogApproval {
    /// Build a dialog backend from its config entry. `timeout_secs` is clamped
    /// to at least one second; a zero/absent value falls back to the default.
    pub fn new(name: &str, config: &ApprovalBackendConfig) -> Self {
        let secs = config
            .timeout_secs
            .filter(|&t| t > 0)
            .unwrap_or(DEFAULT_TIMEOUT_SECS);
        Self {
            name: name.to_string(),
            timeout: std::time::Duration::from_secs(secs),
        }
    }
}

impl ApprovalBackend for DialogApproval {
    fn request_approval(&self, request: &ApprovalRequest) -> Result<ApprovalDecision> {
        // `detect_and_prompt` returns `None` when no display channel is
        // reachable on this platform; we fail secure with a denial.
        match detect_and_prompt(request, self.timeout)? {
            Some(decision) => Ok(decision),
            None => Ok(ApprovalDecision::Denied {
                reason: NO_DISPLAY_REASON.to_string(),
            }),
        }
    }

    fn backend_name(&self) -> &str {
        &self.name
    }
}

// ── shared message construction (unix engines) ───────────────────────────────

/// Fixed dialog title. Not derived from untrusted input.
#[cfg(any(target_os = "macos", target_os = "linux"))]
const TITLE: &str = "nono — approval required";

/// Maximum characters kept per untrusted field before truncation. Bounds the
/// dialog size so a crafted value cannot push buttons off-screen or otherwise
/// distort the layout.
#[cfg(any(target_os = "macos", target_os = "linux"))]
const MAX_FIELD_CHARS: usize = 256;

/// Sanitize (strip control/ANSI) and length-bound a single untrusted field.
///
/// `sanitize_for_terminal` strips C0/C1 control codes (including `\n`/`\r`) but
/// NOT the Unicode line/paragraph separators U+2028/U+2029, which are category
/// `Zl`/`Zp` (so `char::is_control()` returns false for them). Terminals ignore
/// those, but GUI toolkits (Cocoa, GTK/Pango, Qt) render them as hard line
/// breaks — which would let an untrusted field inject extra lines into the
/// dialog and defeat the per-field length bound that keeps the buttons on
/// screen. Collapse them to spaces here so every field stays a single line.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn field(value: &str) -> String {
    let sanitized: String = crate::terminal_approval::sanitize_for_terminal(value)
        .chars()
        .map(|c| {
            if matches!(c, '\u{2028}' | '\u{2029}') {
                ' '
            } else {
                c
            }
        })
        .collect();
    let mut out: String = sanitized.chars().take(MAX_FIELD_CHARS).collect();
    if sanitized.chars().count() > MAX_FIELD_CHARS {
        out.push('…');
    }
    out
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn access_mode_label(access: &nono::AccessMode) -> &'static str {
    match access {
        nono::AccessMode::Read => "read-only",
        nono::AccessMode::Write => "write-only",
        nono::AccessMode::ReadWrite => "read+write",
    }
}

/// Build the human-readable dialog body for a request.
///
/// The returned string always starts with a fixed, non-`-` prefix so that when
/// it is handed to a dialog tool as an argument it can never be mistaken for a
/// command-line option, regardless of the untrusted field contents.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn build_message(request: &ApprovalRequest) -> String {
    let mut m = String::from("The sandboxed process is requesting approval.\n\n");
    match request {
        ApprovalRequest::Capability {
            path,
            access,
            reason,
            ..
        } => {
            m.push_str("Type: Filesystem access\n");
            m.push_str(&format!("Path: {}\n", field(&path.display().to_string())));
            m.push_str(&format!("Access: {}\n", access_mode_label(access)));
            append_reason(&mut m, reason);
        }
        ApprovalRequest::Network {
            host,
            port,
            protocol,
            reason,
            ..
        } => {
            m.push_str("Type: Network access\n");
            m.push_str(&format!("Host: {}\n", field(host)));
            m.push_str(&format!("Port: {port}\n"));
            m.push_str(&format!("Protocol: {}\n", field(protocol)));
            append_reason(&mut m, reason);
        }
        ApprovalRequest::Command {
            command,
            args,
            caller,
            reason,
            ..
        } => {
            m.push_str("Type: Command launch\n");
            m.push_str(&format!("Command: {}\n", field(command)));
            let display_args: Vec<String> = args.iter().skip(1).map(|a| field(a)).collect();
            if !display_args.is_empty() {
                m.push_str(&format!("Args: {}\n", display_args.join(" ")));
            }
            m.push_str(&format!("Caller: {}\n", field(caller)));
            append_reason(&mut m, reason);
        }
        ApprovalRequest::Endpoint {
            route_id,
            upstream,
            method,
            path,
            reason,
            ..
        } => {
            m.push_str("Type: Proxy endpoint\n");
            m.push_str(&format!("Route: {}\n", field(route_id)));
            m.push_str(&format!("Method: {}\n", field(method)));
            m.push_str(&format!("Path: {}\n", field(path)));
            m.push_str(&format!("Upstream: {}\n", field(upstream)));
            append_reason(&mut m, reason);
        }
    }
    // Session context, common to every request variant. The internal rule label
    // (e.g. `invocation_policy.approve[0]`) is deliberately omitted from the
    // human prompt — it is policy-engine jargon; the `Reason` line conveys the
    // intent, and the full label is still recorded in the audit log.
    m.push_str(&session_footer(request));
    m.push_str("\nAllow this action?");
    m
}

/// Session footer shared by all request variants, so the operator can
/// correlate the prompt with a running session and with audit entries.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn session_footer(request: &ApprovalRequest) -> String {
    let session_id = match request {
        ApprovalRequest::Capability { session_id, .. }
        | ApprovalRequest::Network { session_id, .. }
        | ApprovalRequest::Endpoint { session_id, .. }
        | ApprovalRequest::Command { session_id, .. } => session_id,
    };
    format!("\nSession: {}\n", field(session_id))
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn append_reason(m: &mut String, reason: &Option<String>) {
    if let Some(r) = reason {
        m.push_str(&format!("Reason: {}\n", field(r)));
    }
}

/// Spawn `cmd` and wait up to `wall`. Returns `Ok(None)` if the deadline is hit
/// (the child is killed), otherwise the exit status and captured stdout.
///
/// stdin/stderr are detached; stdout is captured for tools that report the
/// decision on stdout (osascript). Dialog output is tiny, so reading after exit
/// cannot deadlock on a full pipe.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn run_with_timeout(
    mut cmd: std::process::Command,
    wall: std::time::Duration,
) -> Result<Option<(std::process::ExitStatus, String)>> {
    use std::io::Read;
    use std::process::Stdio;

    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().map_err(|e| {
        nono::NonoError::SandboxInit(format!("failed to launch approval dialog: {e}"))
    })?;

    let deadline = std::time::Instant::now() + wall;
    loop {
        match child.try_wait().map_err(|e| {
            nono::NonoError::SandboxInit(format!("failed to wait on approval dialog: {e}"))
        })? {
            Some(status) => {
                let mut out = String::new();
                if let Some(mut stdout) = child.stdout.take() {
                    let _ = stdout.read_to_string(&mut out);
                }
                return Ok(Some((status, out)));
            }
            None => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Ok(None);
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
}

/// Wall-clock grace added on top of the dialog's own timeout, so the tool's
/// native "give up" fires first (yielding a clean result) and the hard kill is
/// only a backstop.
#[cfg(any(target_os = "macos", target_os = "linux"))]
const WALL_CLOCK_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

// ── macOS: osascript ─────────────────────────────────────────────────────────

/// AppleScript program run by `osascript`. All untrusted content is passed via
/// `on run argv` (bound to `item 1 of argv`), never interpolated into this
/// source, so there is no AppleScript injection surface.
#[cfg(target_os = "macos")]
const OSASCRIPT_PROGRAM: &str = r#"on run argv
    set theText to item 1 of argv
    set theTitle to item 2 of argv
    set theTimeout to (item 3 of argv) as integer
    try
        set theResult to display dialog theText with title theTitle buttons {"Deny", "Allow"} default button "Deny" cancel button "Deny" with icon caution giving up after theTimeout
    on error number -128
        return "DENY"
    end try
    if (gave up of theResult) then
        return "TIMEOUT"
    end if
    if (button returned of theResult) is "Allow" then
        return "ALLOW"
    end if
    return "DENY"
end run"#;

/// True only when the current process runs inside an Aqua (GUI login) session.
///
/// A process reached over SSH runs in a non-Aqua domain even if a user is
/// logged in at the console, so this correctly denies rather than trying to
/// hijack the console user's screen. Any failure is treated as "no session"
/// (fail secure).
#[cfg(target_os = "macos")]
fn macos_has_gui_session() -> bool {
    match std::process::Command::new("/bin/launchctl")
        .arg("managername")
        .output()
    {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim() == "Aqua",
        _ => false,
    }
}

#[cfg(target_os = "macos")]
fn detect_and_prompt(
    request: &ApprovalRequest,
    timeout: std::time::Duration,
) -> Result<Option<ApprovalDecision>> {
    if !macos_has_gui_session() {
        return Ok(None);
    }
    let message = build_message(request);
    let secs = timeout.as_secs().max(1);
    let wall = timeout.saturating_add(WALL_CLOCK_GRACE);

    let mut cmd = std::process::Command::new("/usr/bin/osascript");
    cmd.arg("-e")
        .arg(OSASCRIPT_PROGRAM)
        // argv items 1..=3 for the run handler. `message` begins with a fixed
        // prefix, so it cannot be parsed as an osascript option.
        .arg(&message)
        .arg(TITLE)
        .arg(secs.to_string());

    match run_with_timeout(cmd, wall)? {
        None => Ok(Some(ApprovalDecision::Timeout)),
        Some((status, out)) => Ok(Some(match out.trim() {
            "ALLOW" => ApprovalDecision::Granted,
            "TIMEOUT" => ApprovalDecision::Timeout,
            "DENY" => ApprovalDecision::Denied {
                reason: "user denied via dialog".to_string(),
            },
            _ => ApprovalDecision::Denied {
                reason: format!(
                    "dialog approval could not be presented (osascript exit {:?})",
                    status.code()
                ),
            },
        })),
    }
}

// ── Linux: zenity / kdialog ──────────────────────────────────────────────────

/// Absolute paths searched for each dialog tool. `$PATH` is never consulted.
#[cfg(target_os = "linux")]
const ZENITY_PATHS: &[&str] = &["/usr/bin/zenity", "/bin/zenity", "/usr/local/bin/zenity"];
#[cfg(target_os = "linux")]
const KDIALOG_PATHS: &[&str] = &["/usr/bin/kdialog", "/bin/kdialog", "/usr/local/bin/kdialog"];

#[cfg(target_os = "linux")]
enum LinuxDialog {
    Zenity(std::path::PathBuf),
    Kdialog(std::path::PathBuf),
}

#[cfg(target_os = "linux")]
fn first_existing(paths: &[&str]) -> Option<std::path::PathBuf> {
    paths
        .iter()
        .map(std::path::PathBuf::from)
        .find(|p| p.is_file())
}

/// Locate a usable dialog tool, but only when a display server is reachable.
/// Absence of both `$WAYLAND_DISPLAY` and `$DISPLAY` means headless → deny.
#[cfg(target_os = "linux")]
fn detect_linux_dialog() -> Option<LinuxDialog> {
    let has_display = std::env::var_os("WAYLAND_DISPLAY")
        .filter(|v| !v.is_empty())
        .or_else(|| std::env::var_os("DISPLAY").filter(|v| !v.is_empty()))
        .is_some();
    if !has_display {
        return None;
    }
    if let Some(path) = first_existing(ZENITY_PATHS) {
        return Some(LinuxDialog::Zenity(path));
    }
    first_existing(KDIALOG_PATHS).map(LinuxDialog::Kdialog)
}

/// Escape Pango/HTML markup so untrusted text is shown literally and cannot
/// inject formatting into GTK/Qt dialog bodies.
#[cfg(target_os = "linux")]
fn escape_markup(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(target_os = "linux")]
fn detect_and_prompt(
    request: &ApprovalRequest,
    timeout: std::time::Duration,
) -> Result<Option<ApprovalDecision>> {
    let Some(dialog) = detect_linux_dialog() else {
        return Ok(None);
    };
    let message = escape_markup(&build_message(request));
    let secs = timeout.as_secs().max(1);
    let wall = timeout.saturating_add(WALL_CLOCK_GRACE);

    let decision = match dialog {
        LinuxDialog::Zenity(path) => {
            let mut cmd = std::process::Command::new(path);
            // `--opt=value` binds each untrusted value to its option, so it can
            // never be reparsed as a separate flag.
            cmd.arg("--question")
                .arg(format!("--title={TITLE}"))
                .arg(format!("--text={message}"))
                .arg("--ok-label=Allow")
                .arg("--cancel-label=Deny")
                .arg("--default-cancel")
                .arg(format!("--timeout={secs}"));
            match run_with_timeout(cmd, wall)? {
                None => ApprovalDecision::Timeout,
                Some((status, _)) => match status.code() {
                    Some(0) => ApprovalDecision::Granted,
                    Some(5) => ApprovalDecision::Timeout,
                    _ => ApprovalDecision::Denied {
                        reason: "user denied via dialog".to_string(),
                    },
                },
            }
        }
        LinuxDialog::Kdialog(path) => {
            let mut cmd = std::process::Command::new(path);
            cmd.arg("--title")
                .arg(TITLE)
                .arg("--yes-label")
                .arg("Allow")
                .arg("--no-label")
                .arg("Deny")
                // Message is the value of `--warningyesno` and begins with a
                // fixed prefix, so it is never parsed as an option.
                .arg("--warningyesno")
                .arg(&message);
            match run_with_timeout(cmd, wall)? {
                None => ApprovalDecision::Timeout,
                Some((status, _)) => match status.code() {
                    Some(0) => ApprovalDecision::Granted,
                    _ => ApprovalDecision::Denied {
                        reason: "user denied via dialog".to_string(),
                    },
                },
            }
        }
    };
    Ok(Some(decision))
}

// ── unsupported platforms: always fail secure ───────────────────────────────

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn detect_and_prompt(
    _request: &ApprovalRequest,
    _timeout: std::time::Duration,
) -> Result<Option<ApprovalDecision>> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_policy::{ApprovalBackendConfig, ApprovalBackendType};
    use nono::AccessMode;

    fn config(timeout_secs: Option<u64>) -> ApprovalBackendConfig {
        ApprovalBackendConfig {
            backend_type: ApprovalBackendType::Dialog,
            url: None,
            timeout_secs,
            mode: None,
            backends: Vec::new(),
        }
    }

    fn command_request(reason: Option<String>) -> ApprovalRequest {
        ApprovalRequest::Command {
            request_id: "cmd-1".to_string(),
            command: "git".to_string(),
            args: vec!["git".to_string(), "push".to_string(), "--force".to_string()],
            caller: "session".to_string(),
            intercept_rule: "invocation_policy.approve[0]".to_string(),
            reason,
            child_pid: 42,
            session_id: "sess-1".to_string(),
        }
    }

    #[test]
    fn backend_name_is_configured_name() {
        let backend = DialogApproval::new("desktop", &config(None));
        assert_eq!(backend.backend_name(), "desktop");
    }

    #[test]
    fn timeout_defaults_and_clamps() {
        assert_eq!(
            DialogApproval::new("d", &config(None)).timeout,
            std::time::Duration::from_secs(DEFAULT_TIMEOUT_SECS)
        );
        // A zero timeout must not become an instant deadline.
        assert_eq!(
            DialogApproval::new("d", &config(Some(0))).timeout,
            std::time::Duration::from_secs(DEFAULT_TIMEOUT_SECS)
        );
        assert_eq!(
            DialogApproval::new("d", &config(Some(30))).timeout,
            std::time::Duration::from_secs(30)
        );
    }

    // ── message construction (unix engines) ──────────────────────────────────

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn message_starts_with_fixed_non_dash_prefix() {
        // The fixed prefix guarantees the message cannot be parsed as a CLI
        // option even if a field begins with '-'.
        let req = ApprovalRequest::Capability {
            request_id: "c".to_string(),
            path: "-rf".into(),
            access: AccessMode::ReadWrite,
            reason: Some("--evil".to_string()),
            child_pid: 1,
            session_id: "s".to_string(),
        };
        let msg = build_message(&req);
        assert!(msg.starts_with("The sandboxed process"));
        assert!(!msg.starts_with('-'));
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn message_strips_control_and_ansi_from_untrusted_fields() {
        let req = command_request(Some(
            "line1\r\nline2\x1b[2K\x1b]0;title\x07\0end".to_string(),
        ));
        let msg = build_message(&req);
        assert!(!msg.contains('\r'));
        assert!(!msg.contains('\x1b'));
        assert!(!msg.contains('\x07'));
        assert!(!msg.contains('\0'));
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn field_is_length_bounded() {
        let long = "a".repeat(MAX_FIELD_CHARS * 4);
        let out = field(&long);
        // Truncated to the cap plus a single ellipsis marker.
        assert_eq!(out.chars().count(), MAX_FIELD_CHARS + 1);
        assert!(out.ends_with('…'));
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn field_strips_line_and_paragraph_separators() {
        // U+2028/U+2029 are not `char::is_control()`, so `sanitize_for_terminal`
        // leaves them intact; GUI toolkits render them as line breaks, letting a
        // crafted field forge extra dialog lines. `field` must neutralize them.
        let out = field("host\u{2028}Access: read+write\u{2029}spoof");
        assert!(!out.contains('\u{2028}'));
        assert!(!out.contains('\u{2029}'));
        assert!(!out.contains('\n'));
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn message_omits_internal_rule_label() {
        // The policy-engine rule label (e.g. `invocation_policy.approve[0]`) is
        // jargon and must not appear in the operator-facing prompt.
        let msg = build_message(&command_request(None));
        assert!(
            !msg.contains("Rule:"),
            "rule label leaked into dialog: {msg}"
        );
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn message_includes_session_footer() {
        // The session id lets the operator correlate the prompt with a running
        // session and with audit entries.
        let msg = build_message(&command_request(None));
        assert!(msg.contains("Session: sess-1"), "{msg}");
        // Footer stays above the closing question.
        let session_at = msg.find("Session:").expect("session line present");
        let question_at = msg.find("Allow this action?").expect("question present");
        assert!(session_at < question_at);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn escape_markup_neutralizes_entities() {
        let out = escape_markup("<b>&</b>");
        assert_eq!(out, "&lt;b&gt;&amp;&lt;/b&gt;");
        assert!(!out.contains('<'));
        assert!(!out.contains('>'));
    }

    // ── fail secure ──────────────────────────────────────────────────────────
    //
    // On Linux we can prove the no-display path denies WITHOUT spawning any
    // dialog by clearing the display env vars. (macOS session detection is not
    // env-driven, so we don't exercise a live prompt here — that would risk
    // popping a real dialog on a developer's Aqua session.)

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_denies_without_display() {
        let _guard = crate::test_env::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        // Register both vars in the guard so originals are captured and
        // restored on drop, then remove them to simulate a headless session.
        let _env = crate::test_env::EnvVarGuard::set_all(&[
            ("WAYLAND_DISPLAY", ""),
            ("DISPLAY", ""),
        ]);
        _env.remove("WAYLAND_DISPLAY");
        _env.remove("DISPLAY");

        let backend = DialogApproval::new("desktop", &config(Some(1)));
        let decision = backend.request_approval(&command_request(None));

        match decision {
            Ok(ApprovalDecision::Denied { reason }) => {
                assert!(reason.contains("no reachable GUI display"));
            }
            other => panic!("expected fail-secure Denied, got {other:?}"),
        }
    }
}
