//! Cross-platform OS notification dispatch for network approval.
//!
//! Shows an interactive notification/dialog when the sandbox proxy
//! blocks a request to an unknown host and `--network-approval ask`
//! is enabled. The user can approve or deny directly from the
//! notification.
//!
//! Platform implementations:
//! - **Linux**: `notify-rust` with XDG action buttons
//! - **macOS**: `osascript display dialog` (native modal)
//! - **Windows**: PowerShell WPF dialog (native modal)

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "windows")]
mod windows;

/// How long an approval decision should last.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDuration {
    /// Approve only this single request; next request to the same host will prompt again.
    Once,
    /// Approve for the remainder of this session.
    Session,
    /// Approve and persist so future sessions also allow the host.
    Always,
}

impl std::str::FromStr for ApprovalDuration {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Once" => Ok(Self::Once),
            "Session" => Ok(Self::Session),
            "Always" => Ok(Self::Always),
            _ => Err(format!("invalid approval duration: {s}")),
        }
    }
}

/// Result of a user interaction with a network approval notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotificationResult {
    /// User approved the request with the given duration.
    Approve(ApprovalDuration),
    /// User denied the request with the given duration.
    Deny(ApprovalDuration),
    /// Notification was dismissed / timed out without user action.
    Dismissed,
}

/// Show an OS-level approval dialog for a blocked network request.
///
/// This is a **blocking** call — it waits until the user responds
/// or the timeout expires. Callers should wrap this in
/// `tokio::task::spawn_blocking()` to avoid blocking the async runtime.
///
/// # Arguments
///
/// * `host` - The hostname that was blocked (sanitized before display)
/// * `timeout_secs` - How long to wait before returning `Dismissed`
///
/// # Security
///
/// The `host` string is sanitized before being interpolated into any
/// platform-specific command to prevent injection attacks.
pub fn show_approval_dialog(host: &str, timeout_secs: u64) -> NotificationResult {
    let sanitized = sanitize_host(host);
    dispatch_notification(&sanitized, timeout_secs)
}

#[cfg(target_os = "linux")]
fn dispatch_notification(host: &str, timeout_secs: u64) -> NotificationResult {
    linux::show_linux_notification(host, timeout_secs)
}

#[cfg(target_os = "macos")]
fn dispatch_notification(host: &str, timeout_secs: u64) -> NotificationResult {
    macos::show_macos_dialog(host, timeout_secs)
}

#[cfg(target_os = "windows")]
fn dispatch_notification(host: &str, timeout_secs: u64) -> NotificationResult {
    windows::show_windows_notification(host, timeout_secs)
}

/// Sanitize a hostname for safe display in notifications.
///
/// Strips control characters and characters that could be used for
/// shell/AppleScript injection. Hostnames are restricted to alphanumeric
/// characters, hyphens, dots, and underscores by RFC 952/1123.
fn sanitize_host(host: &str) -> String {
    host.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_' || c == ':' {
                c
            } else {
                '?'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_host_clean() {
        assert_eq!(sanitize_host("example.com"), "example.com");
    }

    #[test]
    fn test_sanitize_host_with_port() {
        assert_eq!(sanitize_host("example.com:443"), "example.com:443");
    }

    #[test]
    fn test_sanitize_host_strips_injection() {
        let malicious = "evil.com\"; rm -rf /";
        let sanitized = sanitize_host(malicious);
        assert!(!sanitized.contains('"'));
        assert!(!sanitized.contains(';'));
        assert!(!sanitized.contains(' '));
    }

    #[test]
    fn test_sanitize_host_applescript_injection() {
        let malicious = "host\\\" display dialog \\\"pwned\\\"";
        let sanitized = sanitize_host(malicious);
        assert!(!sanitized.contains('\\'));
        assert!(!sanitized.contains('"'));
    }

    #[test]
    fn test_sanitize_host_shell_injection() {
        let malicious = "host$(evil)";
        let sanitized = sanitize_host(malicious);
        assert!(!sanitized.contains('$'));
        assert!(!sanitized.contains('('));
        assert!(!sanitized.contains(')'));
    }

    #[test]
    fn test_sanitize_host_backtick_injection() {
        let malicious = "host`evil`";
        let sanitized = sanitize_host(malicious);
        assert!(!sanitized.contains('`'));
    }
}
