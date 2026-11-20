//! Supervisor-owned presentation state; never participates in approval decisions.

use crate::output::{SummaryKind, summary_heading, summary_row};
use crate::terminal_approval::{request_summary, sanitize_for_terminal};
use nono::ApprovalRequest;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};
use uuid::Uuid;

const DISPLAY_DELAY: Duration = Duration::from_millis(300);
static PENDING: Mutex<BTreeMap<Uuid, PendingApproval>> = Mutex::new(BTreeMap::new());

#[derive(Clone)]
pub(crate) struct PendingApproval {
    backend: String,
    summary: String,
    started: Instant,
    timeout: Duration,
    platform: bool,
}

impl PendingApproval {
    pub(crate) fn new(
        backend: &str,
        request: &ApprovalRequest,
        timeout: Duration,
        platform: bool,
    ) -> Self {
        Self {
            backend: sanitize_for_terminal(backend),
            summary: request_summary(request),
            started: Instant::now(),
            timeout,
            platform,
        }
    }
}

/// Removal on every return path, including backend errors and unwinding.
pub(crate) struct PendingNotice(Uuid);

impl PendingNotice {
    pub(crate) fn start(
        backend: &str,
        request: &ApprovalRequest,
        timeout: Duration,
        platform: bool,
    ) -> Self {
        let id = Uuid::new_v4();
        PENDING
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                id,
                PendingApproval::new(backend, request, timeout, platform),
            );
        Self(id)
    }
}

impl Drop for PendingNotice {
    fn drop(&mut self) {
        PENDING
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.0);
    }
}

pub(crate) fn snapshot() -> BTreeMap<Uuid, PendingApproval> {
    PENDING
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

#[derive(Default)]
pub(crate) struct ApprovalView {
    dismissed: BTreeSet<Uuid>,
    shown: BTreeSet<Uuid>,
    pub(crate) frame: Option<String>,
    pub(crate) size: (u16, u16),
}

impl ApprovalView {
    pub(crate) fn dismiss(&mut self) {
        self.dismissed.extend(&self.shown);
    }

    pub(crate) fn render(
        &mut self,
        pending: &BTreeMap<Uuid, PendingApproval>,
        now: Instant,
    ) -> Option<String> {
        self.dismissed.retain(|id| pending.contains_key(id));
        self.shown = pending.keys().copied().collect();
        let approval = pending
            .iter()
            .filter(|(id, approval)| {
                !self.dismissed.contains(id)
                    && now.saturating_duration_since(approval.started) >= DISPLAY_DELAY
            })
            .min_by_key(|(_, approval)| approval.started)?
            .1;
        let mut text = summary_heading("Approval", SummaryKind::Attention);
        text.push_str(&summary_row(
            "Status",
            if approval.platform {
                "Waiting for platform approval"
            } else {
                "Waiting for approval backend"
            },
        ));
        text.push_str(&summary_row("Backend", &approval.backend));
        text.push_str(&summary_row("Request", &approval.summary));
        text.push_str(&summary_row(
            "Waiting",
            &format!(
                "{}s (timeout {}s)",
                now.saturating_duration_since(approval.started).as_secs(),
                approval.timeout.as_secs()
            ),
        ));
        if pending.len() > 1 {
            text.push_str(&summary_row("Pending", &pending.len().to_string()));
        }
        text.push_str("\n    Esc: return to agent; approval remains pending.\n");
        Some(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn request() -> ApprovalRequest {
        ApprovalRequest::Network {
            request_id: "test-approval".into(),
            host: "api.example.com".into(),
            port: 443,
            protocol: "tcp".into(),
            resolved_ips: vec![],
            reason: Some("secret reason must not be displayed".into()),
            child_pid: 42,
            session_id: "test-session".into(),
        }
    }

    #[test]
    fn delayed_view_tracks_concurrent_requests_until_the_last_completes() {
        let approval = PendingApproval::new("platform", &request(), Duration::from_secs(60), true);
        let now = approval.started;
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let mut pending = BTreeMap::from([(first, approval.clone()), (second, approval)]);
        let mut view = ApprovalView::default();
        assert!(view.render(&pending, now).is_none());
        let later = now + DISPLAY_DELAY;
        let frame = view.render(&pending, later).expect("delayed view");
        assert!(frame.contains("Waiting for platform approval"));
        assert!(frame.contains("api.example.com:443"));
        assert!(frame.contains("Pending") && frame.contains('2'));
        assert!(!frame.contains("secret"));
        pending.remove(&first);
        assert!(view.render(&pending, later).is_some());
        pending.remove(&second);
        assert!(view.render(&pending, later).is_none());
    }

    #[test]
    fn dismissing_is_only_presentation_and_new_requests_can_show() {
        let approval = PendingApproval::new("webhook", &request(), Duration::from_secs(60), false);
        let later = approval.started + DISPLAY_DELAY;
        let mut pending = BTreeMap::from([(Uuid::new_v4(), approval.clone())]);
        let mut view = ApprovalView::default();
        assert!(view.render(&pending, later).is_some());
        view.dismiss();
        assert!(view.render(&pending, later).is_none());
        assert_eq!(pending.len(), 1);
        pending.insert(Uuid::new_v4(), approval);
        assert!(view.render(&pending, later).is_some());
    }

    #[test]
    fn notice_is_removed_on_success_error_and_unwinding() {
        let id = {
            let notice = PendingNotice::start("test", &request(), Duration::from_secs(60), true);
            assert!(snapshot().contains_key(&notice.0));
            notice.0
        };
        assert!(!snapshot().contains_key(&id));

        fn fail(failed_id: &mut Option<Uuid>) -> Result<(), ()> {
            let notice = PendingNotice::start("test", &request(), Duration::from_secs(60), true);
            *failed_id = Some(notice.0);
            Err(())
        }
        let mut failed_id = None;
        let result = fail(&mut failed_id);
        assert!(result.is_err());
        assert!(!snapshot().contains_key(&failed_id.expect("notice id")));

        let mut panic_id = None;
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let notice = PendingNotice::start("test", &request(), Duration::from_secs(60), true);
            panic_id = Some(notice.0);
            panic!("backend panic");
        }));
        assert!(!snapshot().contains_key(&panic_id.expect("notice id")));
    }

    #[test]
    fn untrusted_backend_names_cannot_inject_terminal_controls() {
        let approval = PendingApproval::new(
            "evil\x1b]0;pwned\x07\nbackend",
            &request(),
            Duration::from_secs(60),
            false,
        );
        assert!(!approval.backend.contains(['\x1b', '\x07', '\n']));
    }
}
