//! Linux notification backend using `notify-rust` with XDG action buttons.
//!
//! On Linux, `notify-rust` supports interactive action buttons via the
//! XDG Desktop Notification specification. The user can click one of
//! six actions directly in the notification: Approve/Deny combined with
//! Once/Session/Always duration.

use super::{ApprovalDuration, NotificationResult};

/// Show a Linux desktop notification with action buttons for network approval.
///
/// Uses `notify-rust` to create an XDG notification with action
/// buttons. Blocks until the user clicks a button or the notification
/// is closed/dismissed.
pub fn show_linux_notification(host: &str, timeout_secs: u64) -> NotificationResult {
    use notify_rust::{Hint, Notification, Timeout};

    let result = Notification::new()
        .appname("nono")
        .summary("nono: Network access blocked")
        .body(&format!(
            "Request to <b>{host}</b> was blocked.\n\
             Allow this host to access the network?"
        ))
        .action("approve_once", "Approve \u{2013} Once")
        .action("approve_session", "Approve \u{2013} Session")
        .action("approve_always", "Approve \u{2013} Always")
        .action("deny_once", "Deny \u{2013} Once")
        .action("deny_session", "Deny \u{2013} Session")
        .action("deny_always", "Deny \u{2013} Always")
        .hint(Hint::Resident(true))
        .timeout(Timeout::Milliseconds(
            (timeout_secs * 1000).try_into().unwrap_or(u32::MAX),
        ))
        .show();

    match result {
        Ok(handle) => {
            let mut action_result = NotificationResult::Dismissed;
            handle.wait_for_action(|action| {
                action_result = match action {
                    "approve_once" => NotificationResult::Approve(ApprovalDuration::Once),
                    "approve_session" => NotificationResult::Approve(ApprovalDuration::Session),
                    "approve_always" => NotificationResult::Approve(ApprovalDuration::Always),
                    "deny_once" => NotificationResult::Deny(ApprovalDuration::Once),
                    "deny_session" => NotificationResult::Deny(ApprovalDuration::Session),
                    "deny_always" => NotificationResult::Deny(ApprovalDuration::Always),
                    "__closed" => NotificationResult::Dismissed,
                    _ => {
                        tracing::warn!("Unknown Linux notification action: {action}");
                        NotificationResult::Dismissed
                    }
                };
            });
            action_result
        }
        Err(e) => {
            tracing::warn!("Failed to show Linux notification: {e}");
            NotificationResult::Dismissed
        }
    }
}
