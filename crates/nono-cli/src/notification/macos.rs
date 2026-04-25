//! macOS notification backend using `osascript`.
//!
//! macOS `display dialog` only supports up to 3 buttons, so we use
//! `choose from list` for the approval dialog. The dialog presents
//! six options: Approve/Deny x Once/Session/Always.
//!
//! This approach:
//! - Works without an app bundle
//! - Gives a real modal dialog (not a fleeting banner)
//! - Supports timeout by killing the osascript process after N seconds
//! - Returns which option was selected

use super::{ApprovalDuration, NotificationResult};

/// Show a macOS dialog asking the user to approve a network request.
///
/// Uses `osascript` with `choose from list` to present six options:
/// Approve/Deny combined with Once/Session/Always duration.
/// If the user cancels the dialog (presses Cancel or it times out),
/// returns `Dismissed`.
pub fn show_macos_dialog(host: &str, timeout_secs: u64) -> NotificationResult {
    let script = format!(
        "try\n\
         \tset theChoice to choose from list {{\"Approve \u{2013} Once\", \"Approve \u{2013} Session\", \"Approve \u{2013} Always\", \"Deny \u{2013} Once\", \"Deny \u{2013} Session\", \"Deny \u{2013} Always\"}} \
         with title \"nono: Network access blocked\" \
         with prompt \"Host: {host}\" \
         default items {{\"Approve \u{2013} Session\"}}\n\
         \tif theChoice is false then\n\
         \t\treturn \"Dismissed\"\n\
         \telse\n\
         \t\treturn item 1 of theChoice\n\
         \tend if\n\
         on error number -128\n\
         \treturn \"Dismissed\"\n\
         end try"
    );

    let mut child = match std::process::Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Failed to run osascript for network approval: {e}");
            return NotificationResult::Dismissed;
        }
    };

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return NotificationResult::Dismissed;
                }
                let stdout = child.stdout.take().map_or(String::new(), |mut out| {
                    let mut buf = String::new();
                    let _ = std::io::Read::read_to_string(&mut out, &mut buf);
                    buf
                });
                return parse_response(&stdout);
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return NotificationResult::Dismissed;
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            Err(e) => {
                tracing::warn!("osascript wait error: {e}");
                let _ = child.kill();
                return NotificationResult::Dismissed;
            }
        }
    }
}

const EN_DASH: &str = "\u{2013}";

fn parse_response(stdout: &str) -> NotificationResult {
    let trimmed = stdout.trim();
    if let Some(duration_str) = trimmed.strip_prefix(&format!("Approve {EN_DASH} ")) {
        match duration_str.parse::<ApprovalDuration>() {
            Ok(d) => NotificationResult::Approve(d),
            Err(_) => {
                tracing::warn!("Unknown approval duration in osascript response: {trimmed}");
                NotificationResult::Dismissed
            }
        }
    } else if let Some(duration_str) = trimmed.strip_prefix(&format!("Deny {EN_DASH} ")) {
        match duration_str.parse::<ApprovalDuration>() {
            Ok(d) => NotificationResult::Deny(d),
            Err(_) => {
                tracing::warn!("Unknown deny duration in osascript response: {trimmed}");
                NotificationResult::Dismissed
            }
        }
    } else {
        match trimmed {
            "Dismissed" | "" => NotificationResult::Dismissed,
            _ => {
                tracing::warn!("Unknown osascript response: {trimmed}");
                NotificationResult::Dismissed
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_approve_once() {
        assert_eq!(
            parse_response("Approve \u{2013} Once"),
            NotificationResult::Approve(ApprovalDuration::Once)
        );
    }

    #[test]
    fn test_parse_approve_session() {
        assert_eq!(
            parse_response("Approve \u{2013} Session"),
            NotificationResult::Approve(ApprovalDuration::Session)
        );
    }

    #[test]
    fn test_parse_approve_always() {
        assert_eq!(
            parse_response("Approve \u{2013} Always"),
            NotificationResult::Approve(ApprovalDuration::Always)
        );
    }

    #[test]
    fn test_parse_deny_once() {
        assert_eq!(
            parse_response("Deny \u{2013} Once"),
            NotificationResult::Deny(ApprovalDuration::Once)
        );
    }

    #[test]
    fn test_parse_deny_session() {
        assert_eq!(
            parse_response("Deny \u{2013} Session"),
            NotificationResult::Deny(ApprovalDuration::Session)
        );
    }

    #[test]
    fn test_parse_deny_always() {
        assert_eq!(
            parse_response("Deny \u{2013} Always"),
            NotificationResult::Deny(ApprovalDuration::Always)
        );
    }

    #[test]
    fn test_parse_dismissed() {
        assert_eq!(parse_response("Dismissed"), NotificationResult::Dismissed);
    }

    #[test]
    fn test_parse_empty() {
        assert_eq!(parse_response(""), NotificationResult::Dismissed);
    }

    #[test]
    fn test_parse_unknown() {
        assert_eq!(parse_response("Something"), NotificationResult::Dismissed);
    }
}
