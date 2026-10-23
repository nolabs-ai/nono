//! Terminal-based interactive approval backend for supervisor IPC
//!
//! Prompts the user at the terminal when the sandboxed child requests
//! additional filesystem access. This is the default approval backend
//! for `nono run`.

use nono::{AccessMode, ApprovalBackend, ApprovalDecision, ApprovalRequest, NonoError, Result};
use std::sync::{Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

/// Bound the complete attempt, including waiting for another prompt and the
/// anti-type-ahead delay, before the proxy's timeout-plus-grace backstop.
pub(crate) const TERMINAL_APPROVAL_TIMEOUT: Duration = Duration::from_secs(600);
static APPROVAL_PROMPT_LOCK: Mutex<()> = Mutex::new(());

/// Interactive terminal approval backend.
///
/// Prints capability expansion requests to stderr and reads the user's
/// response from `/dev/tty` (not stdin, which belongs to the sandboxed child).
///
/// Returns `Denied` automatically if no terminal is available.
pub struct TerminalApproval;

impl ApprovalBackend for TerminalApproval {
    fn request_approval(&self, request: &ApprovalRequest) -> Result<ApprovalDecision> {
        self.request_approval_with_timeout(request, TERMINAL_APPROVAL_TIMEOUT, None)
    }

    fn request_approval_with_deadline(
        &self,
        request: &ApprovalRequest,
        deadline: Instant,
    ) -> Result<ApprovalDecision> {
        self.request_approval_with_timeout(request, TERMINAL_APPROVAL_TIMEOUT, Some(deadline))
    }

    fn backend_name(&self) -> &str {
        "terminal"
    }

    fn approval_timeout(&self) -> Option<Duration> {
        Some(TERMINAL_APPROVAL_TIMEOUT)
    }
}

impl TerminalApproval {
    pub(crate) fn request_approval_with_timeout(
        &self,
        request: &ApprovalRequest,
        timeout: Duration,
        caller_deadline: Option<Instant>,
    ) -> Result<ApprovalDecision> {
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            NonoError::ConfigParse("Terminal approval timeout is too large".to_string())
        })?;
        let deadline = caller_deadline.map_or(deadline, |caller| deadline.min(caller));
        if Instant::now() >= deadline {
            return Ok(ApprovalDecision::Timeout);
        }
        // Check the controlling terminal itself, in the same read/write mode
        // used to prompt, so we don't print a prompt we cannot safely answer.
        if !crate::terminal_prompt::consent_prompt_available() {
            return Ok(ApprovalDecision::Denied {
                reason: "No terminal available for interactive approval".to_string(),
            });
        }

        Self::prompt(
            request,
            deadline,
            crate::terminal_prompt::read_consent_line_until,
        )
    }

    fn prompt(
        request: &ApprovalRequest,
        deadline: Instant,
        read_line: impl FnOnce(&str, Instant) -> Result<Option<String>>,
    ) -> Result<ApprovalDecision> {
        // Serialize the request text as well as the read, so concurrent hosts
        // cannot print one request's context over another request's answer.
        let Some(_prompt_guard) = acquire_prompt_slot(&APPROVAL_PROMPT_LOCK, deadline)? else {
            return Ok(ApprovalDecision::Timeout);
        };
        eprintln!();
        match request {
            ApprovalRequest::Capability {
                path,
                access,
                reason,
                ..
            } => {
                eprintln!("[nono] The sandboxed process is requesting additional access:");
                eprintln!(
                    "[nono]   Path:   {}",
                    sanitize_for_terminal(&path.display().to_string())
                );
                eprintln!("[nono]   Access: {}", format_access_mode(access));
                if let Some(r) = reason {
                    eprintln!("[nono]   Reason: {}", sanitize_for_terminal(r));
                }
            }
            ApprovalRequest::Network {
                host,
                port,
                protocol,
                reason,
                ..
            } => {
                eprintln!("[nono] The sandboxed process is requesting network access:");
                eprintln!("[nono]   Host:     {}", sanitize_for_terminal(host));
                eprintln!("[nono]   Port:     {port}");
                eprintln!("[nono]   Protocol: {protocol}");
                if let Some(r) = reason {
                    eprintln!("[nono]   Reason: {}", sanitize_for_terminal(r));
                }
            }
            ApprovalRequest::Command {
                command,
                args,
                caller,
                intercept_rule,
                reason,
                ..
            } => {
                eprintln!("[nono] command-policy launch requires approval:");
                eprintln!("[nono]   Command: {}", sanitize_for_terminal(command));
                let display_args: Vec<String> = args
                    .iter()
                    .skip(1)
                    .map(|a| sanitize_for_terminal(a))
                    .collect();
                if !display_args.is_empty() {
                    eprintln!("[nono]   Args:    {}", display_args.join(" "));
                }
                eprintln!("[nono]   Caller:  {}", sanitize_for_terminal(caller));
                eprintln!(
                    "[nono]   Rule:    {}",
                    sanitize_for_terminal(intercept_rule)
                );
                if let Some(r) = reason {
                    eprintln!("[nono]   Reason: {}", sanitize_for_terminal(r));
                }
            }
            ApprovalRequest::Endpoint {
                route_id,
                upstream,
                method,
                path,
                rule_label,
                reason,
                ..
            } => {
                eprintln!("[nono] Proxy endpoint access requires approval:");
                eprintln!("[nono]   Route:   {}", sanitize_for_terminal(route_id));
                eprintln!("[nono]   Method:  {}", sanitize_for_terminal(method));
                eprintln!("[nono]   Path:    {}", sanitize_for_terminal(path));
                eprintln!("[nono]   Upstream: {}", sanitize_for_terminal(upstream));
                eprintln!("[nono]   Rule:    {}", sanitize_for_terminal(rule_label));
                if let Some(r) = reason {
                    eprintln!("[nono]   Reason: {}", sanitize_for_terminal(r));
                }
            }
        }
        eprintln!("[nono]");

        // Network prompts offer session-scoped choices so an "always" answer
        // suppresses re-prompting for the rest of the session. Every other
        // request type keeps the one-shot [y/N] prompt.
        let is_network = matches!(request, ApprovalRequest::Network { .. });
        let prompt = if is_network {
            eprintln!("[nono]   1) Allow once");
            eprintln!("[nono]   2) Always allow (this session)");
            eprintln!("[nono]   3) Deny once");
            eprintln!("[nono]   4) Always deny (this session)");
            "[nono] Choose [1-4, default 3]: "
        } else {
            "[nono] Grant access? [y/N] "
        };
        let Some(input) = read_line(prompt, deadline)? else {
            eprintln!("\n[nono] Approval timed out; access denied.");
            return Ok(ApprovalDecision::Timeout);
        };
        if Instant::now() >= deadline {
            return Ok(ApprovalDecision::Timeout);
        }

        if is_network {
            // Fail secure: an empty line (EOF), whitespace, or any unrecognized
            // answer denies this one request without persisting the decision.
            match input.trim().to_ascii_lowercase().as_str() {
                "1" | "y" | "yes" => {
                    eprintln!("[nono] Access granted.");
                    Ok(ApprovalDecision::Granted)
                }
                "2" => {
                    eprintln!("[nono] Access granted for this session.");
                    Ok(ApprovalDecision::GrantedForSession)
                }
                "4" => {
                    eprintln!("[nono] Access denied for this session.");
                    Ok(ApprovalDecision::DeniedForSession)
                }
                _ => {
                    eprintln!("[nono] Access denied.");
                    Ok(ApprovalDecision::Denied {
                        reason: "User denied the request".to_string(),
                    })
                }
            }
        } else if is_affirmative_response(&input) {
            eprintln!("[nono] Access granted.");
            Ok(ApprovalDecision::Granted)
        } else {
            eprintln!("[nono] Access denied.");
            Ok(ApprovalDecision::Denied {
                reason: "User denied the request".to_string(),
            })
        }
    }
}

fn acquire_prompt_slot(lock: &Mutex<()>, deadline: Instant) -> Result<Option<MutexGuard<'_, ()>>> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        match lock.try_lock() {
            Ok(guard) => return Ok(Some(guard)),
            Err(TryLockError::Poisoned(_)) => {
                return Err(NonoError::SandboxInit(
                    "Terminal approval lock poisoned".to_string(),
                ));
            }
            Err(TryLockError::WouldBlock) => {
                std::thread::sleep(remaining.min(Duration::from_millis(10)));
            }
        }
    }
}

fn is_affirmative_response(response: &str) -> bool {
    matches!(response.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Strip control characters and ANSI escape sequences from untrusted input
/// before displaying on the terminal.
///
/// Handles all standard escape sequence types:
/// - CSI (ESC [): cursor movement, SGR colors, erase commands
/// - OSC (ESC ]): title changes, hyperlinks — terminated by BEL or ST
/// - DCS (ESC P), APC (ESC _), PM (ESC ^), SOS (ESC X): all consume through ST
///
/// All control characters (0x00-0x1F, 0x7F) are replaced with space.
pub(crate) fn sanitize_for_terminal(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if let Some(&next) = chars.peek() {
                if next == '[' {
                    // CSI sequence: consume until final byte 0x40-0x7E
                    chars.next();
                    for seq_c in chars.by_ref() {
                        if ('\x40'..='\x7e').contains(&seq_c) {
                            break;
                        }
                    }
                } else if matches!(next, ']' | 'P' | '_' | '^' | 'X') {
                    // String sequences (OSC, DCS, APC, PM, SOS):
                    // consume until ST (ESC \) or BEL (0x07)
                    chars.next();
                    let mut prev = '\0';
                    for seq_c in chars.by_ref() {
                        if seq_c == '\x07' || (prev == '\x1b' && seq_c == '\\') {
                            break;
                        }
                        prev = seq_c;
                    }
                }
                // Other ESC sequences (e.g. ESC c, ESC 7): drop the ESC
            }
            continue;
        }

        if c.is_control() {
            result.push(' ');
        } else {
            result.push(c);
        }
    }

    result
}

/// Format an access mode for human-readable display.
fn format_access_mode(access: &AccessMode) -> &'static str {
    match access {
        AccessMode::Read => "read-only",
        AccessMode::Write => "write-only",
        AccessMode::ReadWrite => "read+write",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nono::{AccessMode, ApprovalRequest};
    use std::io::IsTerminal;

    // ── helpers ──────────────────────────────────────────────────────────────

    fn capability_request() -> ApprovalRequest {
        ApprovalRequest::Capability {
            request_id: "cap-001".to_string(),
            path: "/tmp/test".into(),
            access: AccessMode::ReadWrite,
            reason: Some("need scratch space".to_string()),
            child_pid: 42,
            session_id: "sess-001".to_string(),
        }
    }

    fn network_request() -> ApprovalRequest {
        ApprovalRequest::Network {
            request_id: "net-001".to_string(),
            host: "api.example.com".to_string(),
            port: 443,
            protocol: "tcp".to_string(),
            resolved_ips: vec!["93.184.216.34".to_string()],
            reason: Some("fetch credentials".to_string()),
            child_pid: 42,
            session_id: "sess-001".to_string(),
        }
    }

    fn command_request() -> ApprovalRequest {
        ApprovalRequest::Command {
            request_id: "cmd-001".to_string(),
            command: "git".to_string(),
            args: vec!["git".to_string(), "push".to_string(), "--force".to_string()],
            caller: "session".to_string(),
            intercept_rule: "push --force".to_string(),
            reason: None,
            child_pid: 42,
            session_id: "sess-001".to_string(),
        }
    }

    fn endpoint_request() -> ApprovalRequest {
        ApprovalRequest::Endpoint {
            request_id: "endpoint-001".to_string(),
            route_id: "internal-api".to_string(),
            upstream: "https://api.internal.example".to_string(),
            method: "POST".to_string(),
            path: "/v1/tasks/1/comments".to_string(),
            rule_label: "endpoint_policy.approve[POST /v1/tasks/*/comments]".to_string(),
            reason: Some("comment write".to_string()),
            child_pid: 42,
            session_id: "sess-001".to_string(),
        }
    }

    // ── backend name ─────────────────────────────────────────────────────────

    #[test]
    fn test_terminal_approval_backend_name() {
        let backend = TerminalApproval;
        assert_eq!(backend.backend_name(), "terminal");
    }

    #[test]
    fn terminal_approval_requires_explicit_yes() {
        assert!(is_affirmative_response("y"));
        assert!(is_affirmative_response(" YES \n"));
        assert!(!is_affirmative_response(""));
        assert!(!is_affirmative_response("n"));
        assert!(!is_affirmative_response("anything else"));
    }

    #[test]
    fn terminal_timeout_includes_waiting_for_the_prompt_slot() {
        let lock = Mutex::new(());
        let _held = lock.lock().expect("hold prompt slot");
        let start = Instant::now();
        assert!(
            acquire_prompt_slot(&lock, start + Duration::from_millis(20))
                .expect("wait for prompt slot")
                .is_none()
        );
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn timed_out_terminal_attempt_finishes_before_another_prompt_starts() {
        use crate::terminal_prompt::read_consent_line_from;
        use nix::pty::{OpenptyResult, openpty};
        use std::sync::mpsc;

        let OpenptyResult { master, slave } = openpty(None, None).expect("openpty");
        let observer = nix::unistd::dup(&slave).expect("observe terminal");
        let saved = nix::sys::termios::tcgetattr(&observer).expect("save terminal state");
        let (finished_tx, finished_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = TerminalApproval::prompt(
                &network_request(),
                Instant::now() + Duration::from_millis(50),
                |prompt, deadline| {
                    read_consent_line_from(
                        std::fs::File::from(slave),
                        prompt,
                        Duration::ZERO,
                        Some(deadline),
                    )
                },
            );
            finished_tx.send(result).expect("report completed prompt");
        });
        let decision = finished_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("terminal reader must finish without input")
            .expect("prompt result");
        assert!(matches!(decision, ApprovalDecision::Timeout));
        worker.join().expect("no active prompt worker remains");
        assert_eq!(
            nix::sys::termios::tcgetattr(&observer).expect("restored terminal"),
            saved
        );
        assert!(
            APPROVAL_PROMPT_LOCK.try_lock().is_ok(),
            "prompt slot released"
        );

        // A late affirmative answer must not authorize the next attempt. The
        // next reader discards it, times out without fresh input, and releases
        // the same prompt slot rather than competing with an abandoned reader.
        nix::unistd::write(&master, b"1\n").expect("late answer");
        let second = TerminalApproval::prompt(
            &network_request(),
            Instant::now() + Duration::from_millis(50),
            |prompt, deadline| {
                read_consent_line_from(
                    std::fs::File::from(observer),
                    prompt,
                    Duration::ZERO,
                    Some(deadline),
                )
            },
        )
        .expect("second prompt");
        assert!(matches!(second, ApprovalDecision::Timeout));
    }

    // ── non-TTY auto-deny (all three variants) ────────────────────────────────
    //
    // When stderr is not a terminal (e.g. in CI or when redirected), the
    // backend must return Denied for every request type without attempting to
    // read from /dev/tty. These tests are skipped when running interactively
    // (stderr is a TTY) because the real backend would block waiting for input.

    #[test]
    fn non_tty_auto_denies_capability_request() {
        if std::io::stderr().is_terminal() {
            return;
        }
        let backend = TerminalApproval;
        let decision = backend
            .request_approval(&capability_request())
            .expect("no error");
        assert!(
            decision.is_denied(),
            "expected Denied when stderr is not a terminal"
        );
    }

    #[test]
    fn non_tty_auto_denies_network_request() {
        if std::io::stderr().is_terminal() {
            return;
        }
        let backend = TerminalApproval;
        let decision = backend
            .request_approval(&network_request())
            .expect("no error");
        assert!(decision.is_denied());
    }

    #[test]
    fn non_tty_auto_denies_command_request() {
        if std::io::stderr().is_terminal() {
            return;
        }
        let backend = TerminalApproval;
        let decision = backend
            .request_approval(&command_request())
            .expect("no error");
        assert!(decision.is_denied());
    }

    #[test]
    fn non_tty_auto_denies_endpoint_request() {
        if std::io::stderr().is_terminal() {
            return;
        }
        let backend = TerminalApproval;
        let decision = backend
            .request_approval(&endpoint_request())
            .expect("no error");
        assert!(decision.is_denied());
    }

    // ── auto-deny reason is populated ─────────────────────────────────────────

    #[test]
    fn non_tty_denial_carries_reason() {
        if std::io::stderr().is_terminal() {
            return;
        }
        let backend = TerminalApproval;
        let decision = backend
            .request_approval(&command_request())
            .expect("no error");
        match decision {
            nono::ApprovalDecision::Denied { reason } => {
                assert!(!reason.is_empty(), "denial reason must not be empty");
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    // ── sanitize_for_terminal: adversarial network/command fields ──────────────
    //
    // The host, command, caller, and intercept_rule fields come from untrusted
    // IPC input (the shim or the policy) and must be sanitised before display.

    #[test]
    fn sanitize_network_host_strips_ansi() {
        let malicious_host = "api.example.com\x1b[2K\x1b[1Aevil.host";
        let sanitized = sanitize_for_terminal(malicious_host);
        assert!(!sanitized.contains('\x1b'));
        assert!(sanitized.contains("api.example.com"));
    }

    #[test]
    fn sanitize_network_host_strips_carriage_return() {
        let malicious = "real.host\r\nevil.host";
        let sanitized = sanitize_for_terminal(malicious);
        assert!(!sanitized.contains('\r'));
        assert!(!sanitized.contains('\n'));
        assert!(sanitized.contains("real.host"));
    }

    #[test]
    fn sanitize_command_name_strips_escape_sequences() {
        let malicious_cmd = "git\x1b[1mgit\x1b[0m";
        let sanitized = sanitize_for_terminal(malicious_cmd);
        assert!(!sanitized.contains('\x1b'));
        assert!(sanitized.contains("git"));
    }

    #[test]
    fn sanitize_command_args_strips_null_bytes() {
        let malicious_arg = "push\0--force";
        let sanitized = sanitize_for_terminal(malicious_arg);
        assert!(!sanitized.contains('\0'));
    }

    #[test]
    fn sanitize_intercept_rule_strips_osc_title_change() {
        // OSC sequence that would change the terminal title to disguise the rule
        let malicious_rule = "push\x1b]0;harmless rule\x07--force";
        let sanitized = sanitize_for_terminal(malicious_rule);
        assert!(!sanitized.contains('\x1b'));
        assert!(!sanitized.contains('\x07'));
        assert!(sanitized.contains("push"));
    }

    #[test]
    fn sanitize_caller_strips_control_chars() {
        // Caller name from command-mediation IPC — must not contain control characters
        let malicious_caller = "session\x01\x02\x03injected";
        let sanitized = sanitize_for_terminal(malicious_caller);
        assert!(!sanitized.chars().any(|c| c.is_control()));
        assert!(sanitized.contains("session"));
    }

    // ── access-mode display ───────────────────────────────────────────────────

    #[test]
    fn test_format_access_mode() {
        assert_eq!(format_access_mode(&AccessMode::Read), "read-only");
        assert_eq!(format_access_mode(&AccessMode::Write), "write-only");
        assert_eq!(format_access_mode(&AccessMode::ReadWrite), "read+write");
    }

    #[test]
    fn test_sanitize_clean_input() {
        assert_eq!(sanitize_for_terminal("/tmp/harmless"), "/tmp/harmless");
    }

    #[test]
    fn test_sanitize_carriage_return_overwrite() {
        // An attacker could use \r to overwrite the displayed path
        let malicious = "/etc/shadow\r/tmp/harmless";
        let sanitized = sanitize_for_terminal(malicious);
        assert!(!sanitized.contains('\r'));
        assert!(sanitized.contains("/etc/shadow"));
        assert!(sanitized.contains("/tmp/harmless"));
    }

    #[test]
    fn test_sanitize_ansi_escape_csi() {
        // ANSI CSI sequence to change colors / move cursor
        let malicious = "/tmp/\x1b[2K\x1b[1A/etc/shadow";
        let sanitized = sanitize_for_terminal(malicious);
        assert!(!sanitized.contains('\x1b'));
        assert!(sanitized.contains("/tmp/"));
    }

    #[test]
    fn test_sanitize_ansi_escape_osc() {
        // OSC sequence (e.g., change terminal title)
        let malicious = "/tmp/\x1b]0;evil\x07path";
        let sanitized = sanitize_for_terminal(malicious);
        assert!(!sanitized.contains('\x1b'));
        assert!(!sanitized.contains('\x07'));
    }

    #[test]
    fn test_sanitize_null_bytes() {
        let malicious = "/tmp/\0evil";
        let sanitized = sanitize_for_terminal(malicious);
        assert!(!sanitized.contains('\0'));
    }

    #[test]
    fn test_sanitize_all_control_chars_replaced() {
        for byte in 0x00u8..=0x1f {
            let input = format!("/tmp/{}evil", byte as char);
            let sanitized = sanitize_for_terminal(&input);
            assert!(
                !sanitized.chars().any(|c| c == byte as char),
                "Control byte 0x{:02x} should be stripped",
                byte
            );
        }
        // DEL (0x7F) is handled as control too
        let del_input = "/tmp/\x7Fevil";
        let sanitized = sanitize_for_terminal(del_input);
        assert!(!sanitized.contains('\x7F'));
    }

    #[test]
    fn test_sanitize_dcs_sequence() {
        // DCS (ESC P ... ST) -- Device Control String
        let malicious = "/tmp/\x1bPq#0;2;0;0;0#1;2;100;100;0\x1b\\path";
        let sanitized = sanitize_for_terminal(malicious);
        assert!(!sanitized.contains('\x1b'));
        assert!(sanitized.contains("/tmp/"));
        assert!(sanitized.contains("path"));
    }

    #[test]
    fn test_sanitize_apc_sequence() {
        // APC (ESC _) -- Application Program Command
        let malicious = "/tmp/\x1b_evil-command\x1b\\path";
        let sanitized = sanitize_for_terminal(malicious);
        assert!(!sanitized.contains('\x1b'));
        assert!(sanitized.contains("/tmp/"));
        assert!(sanitized.contains("path"));
    }

    #[test]
    fn test_sanitize_pm_sequence() {
        // PM (ESC ^) -- Privacy Message
        let malicious = "/tmp/\x1b^private-data\x1b\\path";
        let sanitized = sanitize_for_terminal(malicious);
        assert!(!sanitized.contains('\x1b'));
        assert!(sanitized.contains("/tmp/"));
        assert!(sanitized.contains("path"));
    }

    #[test]
    fn test_sanitize_sos_sequence() {
        // SOS (ESC X) -- Start of String
        let malicious = "/tmp/\x1bXsome-string\x1b\\path";
        let sanitized = sanitize_for_terminal(malicious);
        assert!(!sanitized.contains('\x1b'));
        assert!(sanitized.contains("/tmp/"));
        assert!(sanitized.contains("path"));
    }

    #[test]
    fn test_sanitize_unterminated_csi() {
        // Unterminated CSI: ESC [ with no final byte -- exhausts iterator cleanly
        let malicious = "/tmp/\x1b[999";
        let sanitized = sanitize_for_terminal(malicious);
        assert!(!sanitized.contains('\x1b'));
        assert!(sanitized.contains("/tmp/"));
    }
}
