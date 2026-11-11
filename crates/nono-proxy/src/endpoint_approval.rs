//! Endpoint-policy approval workflow shared by the reverse-proxy and
//! CONNECT-intercept paths.
//!
//! A request can need approval from more than one route: the `_ep_<domain>`
//! authorization route built from `allow_domain` and the credential route that
//! will inject a credential. [`authorize`] asks once for all of them (once per
//! distinct backend), honors session-scoped answers, and coalesces identical
//! in-flight prompts so a burst of requests shares one prompt.
//!
//! Only approvals with [`PendingApproval::session_scope`] (the `_ep_` routes)
//! cache session answers; credential-route approvals stay one-shot. A session
//! answer is keyed by route, the request's upstream, the credential route, and
//! the scoped rule label (see `config::approval_scope_path`), and it is stored
//! only for the approval the prompt showed. Callers evaluate `deny`/`allow`
//! rules and the policy default before calling in, so a cached answer only
//! ever replaces a prompt and can never override a deny.

use crate::approval::ApprovalBackendRegistry;
use crate::audit;
use crate::connect::{InFlight, InFlightLeader, InFlightMap};
use nono::supervisor::{ApprovalDecision, ApprovalRequest};
use nono::undo::{NetworkAuditDecision, NetworkAuditDenialCategory};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tracing::warn;

/// Default prompt timeout when a rule does not set `timeout_secs`.
const DEFAULT_ENDPOINT_APPROVAL_TIMEOUT: Duration = Duration::from_secs(60);

/// Session answers kept per proxy session. Past this, new answers are not
/// cached and their scopes keep asking, which fails secure.
const MAX_SESSION_DECISIONS: usize = 1024;

/// Prompts that may run at once per proxy session. Each holds a blocking-pool
/// thread until the backend returns, so extra prompts wait for a permit,
/// bounded by their own deadline.
const MAX_CONCURRENT_PROMPTS: usize = 4;

/// What one session answer covers.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ScopeKey {
    route_id: String,
    /// The request's upstream, so a wildcard route's answer covers one host.
    upstream: String,
    credential_route: Option<String>,
    /// Scoped rule label, which names the request method.
    rule_label: String,
    /// AWS operation, so a grant for one operation cannot satisfy another.
    operation: Option<String>,
}

/// Per-proxy-session endpoint approval state. Owned by the
/// [`ApprovalBackendRegistry`], which lives for one proxy session.
pub(crate) struct EndpointSessionState {
    /// Session-scoped answers: `true` = allow, `false` = deny.
    decisions: Mutex<HashMap<ScopeKey, bool>>,
    /// Prompts in progress, so identical requests await one answer.
    in_flight: InFlightMap<ScopeKey>,
    prompts: Arc<Semaphore>,
}

impl Default for EndpointSessionState {
    fn default() -> Self {
        Self {
            decisions: Mutex::default(),
            in_flight: Mutex::default(),
            prompts: Arc::new(Semaphore::new(MAX_CONCURRENT_PROMPTS)),
        }
    }
}

impl EndpointSessionState {
    fn remember(&self, key: &ScopeKey, allow: bool) {
        let mut decisions = self.decisions.lock().unwrap_or_else(|e| e.into_inner());
        if decisions.len() >= MAX_SESSION_DECISIONS && !decisions.contains_key(key) {
            warn!(
                "endpoint approval session cache is full ({} entries); not caching {}",
                MAX_SESSION_DECISIONS, key.rule_label
            );
            return;
        }
        decisions.insert(key.clone(), allow);
    }
}

/// One route's `approve` outcome for the current request.
pub(crate) struct PendingApproval<'a> {
    pub route_id: &'a str,
    /// The route's configured upstream, for audit.
    pub upstream: &'a str,
    pub backend: Option<&'a str>,
    pub reason: Option<&'a str>,
    pub timeout_secs: Option<u64>,
    /// Scoped rule label, e.g. `endpoint_policy.approve[GET /torvalds/linux/**]`.
    pub rule_label: String,
    /// Whether a session answer may be cached for this approval. `false`
    /// collapses session answers to one-shot ones (credential routes).
    pub session_scope: bool,
    /// Region derived from the host for AWS wildcard-region routes.
    pub aws_region: Option<String>,
    /// AWS operation for `aws_auth` routes (`Unknown` when unresolved);
    /// `None` for other routes.
    pub operation: Option<&'a str>,
    /// AWS protocol the operation was resolved from, for audit.
    pub operation_protocol: Option<&'a str>,
}

/// The request being approved and where its audit events go.
pub(crate) struct ApprovalTarget<'a> {
    pub method: &'a str,
    pub path: &'a str,
    /// The upstream this request goes to, e.g. `https://api.github.com`. Shown
    /// in the prompt and part of the session key; for a wildcard route it is
    /// the concrete host, never the pattern.
    pub upstream: &'a str,
    /// Route that will inject a credential if the request is approved.
    pub credential_route: Option<&'a str>,
    pub audit_log: Option<&'a audit::SharedAuditLog>,
    pub mode: audit::ProxyMode,
    /// Base audit context; route, rule, backend, and upstream are filled in
    /// per pending approval.
    pub audit_ctx: &'a audit::EventContext<'a>,
    pub audit_target: &'a str,
    pub audit_port: Option<u16>,
    /// Distinguishes approval request ids, e.g. the service or `host-port`.
    pub request_id_scope: &'a str,
}

/// Outcome of one prompt, as seen by the request that issued it.
enum PromptResult {
    Decision(ApprovalDecision),
    Error(String),
    TimedOut,
}

/// How a group of pending approvals was resolved.
enum GroupResult {
    Cached(bool),
    Prompted(PromptResult),
}

/// Ask for every pending approval with one prompt per distinct backend.
///
/// Returns `true` only when all of them are granted. A missing registry, an
/// unresolvable backend, a refusal, a timeout, or any error denies, and every
/// outcome is audited. All backends are resolved before anything is asked.
pub(crate) async fn authorize(
    registry: Option<&ApprovalBackendRegistry>,
    pending: &[PendingApproval<'_>],
    target: &ApprovalTarget<'_>,
) -> bool {
    let Some(first) = pending.first() else {
        return true;
    };
    let Some(registry) = registry else {
        let reason = format!(
            "endpoint approval required by {} but no approval backend is configured",
            first.rule_label
        );
        warn!("{}", reason);
        log_outcome(
            target,
            first,
            None,
            NetworkAuditDecision::ApproveError,
            Some(&reason),
            true,
        );
        return false;
    };

    let mut groups: Vec<(
        String,
        Arc<dyn nono::ApprovalBackend>,
        Vec<&PendingApproval<'_>>,
    )> = Vec::new();
    for approval in pending {
        let (name, backend) = match registry.resolve(approval.backend) {
            Ok(resolved) => resolved,
            Err(err) => {
                let reason = format!("endpoint approval backend resolution failed: {err}");
                warn!("{}", reason);
                log_outcome(
                    target,
                    approval,
                    None,
                    NetworkAuditDecision::ApproveError,
                    Some(&reason),
                    true,
                );
                return false;
            }
        };
        match groups.iter_mut().find(|(existing, _, _)| *existing == name) {
            Some((_, _, members)) => members.push(approval),
            None => groups.push((name, backend, vec![approval])),
        }
    }

    for (name, backend, members) in groups {
        if !authorize_group(registry, &name, backend, &members, target).await {
            return false;
        }
    }
    true
}

fn scope_key(approval: &PendingApproval<'_>, target: &ApprovalTarget<'_>) -> ScopeKey {
    ScopeKey {
        route_id: approval.route_id.to_string(),
        upstream: target.upstream.to_ascii_lowercase(),
        credential_route: target.credential_route.map(str::to_string),
        rule_label: approval.rule_label.clone(),
        operation: approval.operation.map(str::to_string),
    }
}

/// The request's deadline: the strictest timeout among its approvals.
fn group_deadline(members: &[&PendingApproval<'_>]) -> Instant {
    let timeout = members
        .iter()
        .map(|approval| {
            approval
                .timeout_secs
                .map(Duration::from_secs)
                .unwrap_or(DEFAULT_ENDPOINT_APPROVAL_TIMEOUT)
        })
        .min()
        .unwrap_or(DEFAULT_ENDPOINT_APPROVAL_TIMEOUT);
    Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now)
}

async fn authorize_group(
    registry: &ApprovalBackendRegistry,
    backend_name: &str,
    backend: Arc<dyn nono::ApprovalBackend>,
    members: &[&PendingApproval<'_>],
    target: &ApprovalTarget<'_>,
) -> bool {
    let state = registry.endpoint_sessions();
    let keys: Vec<Option<ScopeKey>> = members
        .iter()
        .map(|approval| approval.session_scope.then(|| scope_key(approval, target)))
        .collect();
    let deadline = group_deadline(members);

    // `decided` lists the members the result is about: the ones asked, or
    // the cached ones that answered.
    let (result, decided) = loop {
        // Check the cache while holding the election lock: a leader may have
        // stored a session answer since this request arrived.
        let election = {
            let mut map = state.in_flight.lock().unwrap_or_else(|e| e.into_inner());
            let uncached: Vec<usize> = {
                let decisions = state.decisions.lock().unwrap_or_else(|e| e.into_inner());
                let cached = |i: usize| keys[i].as_ref().and_then(|key| decisions.get(key));
                if let Some(denied) = (0..keys.len()).find(|&i| cached(i) == Some(&false)) {
                    break (GroupResult::Cached(false), vec![denied]);
                }
                (0..keys.len()).filter(|&i| cached(i).is_none()).collect()
            };
            let Some(&shown) = uncached.first() else {
                break (GroupResult::Cached(true), (0..keys.len()).collect());
            };
            // Only the approval the prompt shows can be answered for the
            // session, so only its key coalesces requests.
            match &keys[shown] {
                Some(key) => match map.get(key) {
                    Some(existing) => Err((Arc::clone(existing), uncached)),
                    None => {
                        let shared = InFlight::new();
                        map.insert(key.clone(), Arc::clone(&shared));
                        Ok((
                            Some(InFlightLeader::new(&state.in_flight, key.clone(), shared)),
                            uncached,
                        ))
                    }
                },
                None => Ok((None, uncached)),
            }
        };

        match election {
            // Only a session answer, now cached, carries over from another
            // request's prompt. After any other outcome this request is
            // asked itself; either way it waits no longer than its own
            // deadline.
            Err((follower, uncached)) => {
                if tokio::time::timeout_at(
                    tokio::time::Instant::from_std(deadline),
                    follower.await_decision(),
                )
                .await
                .is_err()
                {
                    break (GroupResult::Prompted(PromptResult::TimedOut), uncached);
                }
            }
            Ok((leader, uncached)) => {
                let asked: Vec<&PendingApproval<'_>> =
                    uncached.iter().map(|&i| members[i]).collect();
                for approval in &asked {
                    let reason = request_reason(approval, target);
                    log_outcome(
                        target,
                        approval,
                        Some(backend_name),
                        NetworkAuditDecision::ApproveRequested,
                        Some(&reason),
                        false,
                    );
                }
                let (mut result, in_time) =
                    run_prompt(registry, state, &backend, &asked, target, deadline).await;
                let shown_key = &keys[uncached[0]];
                if let PromptResult::Decision(decision) = &mut result {
                    match (shown_key, &*decision) {
                        (Some(key), ApprovalDecision::GrantedForSession) if in_time => {
                            state.remember(key, true);
                        }
                        (Some(key), ApprovalDecision::DeniedForSession) if in_time => {
                            state.remember(key, false);
                        }
                        (None, _) => *decision = decision.clone().without_session_scope(),
                        _ => {}
                    }
                }
                if let Some(leader) = leader {
                    leader.resolve(match &result {
                        PromptResult::Decision(decision) => decision.clone(),
                        PromptResult::Error(reason) => ApprovalDecision::Denied {
                            reason: reason.clone(),
                        },
                        PromptResult::TimedOut => ApprovalDecision::Timeout,
                    });
                }
                break (GroupResult::Prompted(result), uncached);
            }
        }
    };

    let (granted, decision, reason) = describe(result, members[decided[0]], target);
    if let Some(reason) = &reason
        && !granted
    {
        warn!("{}", crate::approval::sanitize_reason_for_log(reason));
    }
    for (i, approval) in members.iter().enumerate() {
        if decided.contains(&i) {
            log_outcome(
                target,
                approval,
                Some(backend_name),
                decision.clone(),
                reason.as_deref(),
                false,
            );
        } else if granted {
            // Covered by a session answer while another member was asked.
            log_outcome(
                target,
                approval,
                Some(backend_name),
                NetworkAuditDecision::ApproveGranted,
                Some("granted for this session"),
                false,
            );
        }
    }
    granted
}

/// Ask the backend once for `asked`, showing the first approval and every
/// reason. Runs on the blocking pool, bounded by `deadline` and by the
/// session's prompt limit. Returns the result and whether it arrived before
/// the deadline; a late answer is a timeout and is never cached.
async fn run_prompt(
    registry: &ApprovalBackendRegistry,
    state: &EndpointSessionState,
    backend: &Arc<dyn nono::ApprovalBackend>,
    asked: &[&PendingApproval<'_>],
    target: &ApprovalTarget<'_>,
    deadline: Instant,
) -> (PromptResult, bool) {
    let tokio_deadline = tokio::time::Instant::from_std(deadline);
    let permit =
        match tokio::time::timeout_at(tokio_deadline, Arc::clone(&state.prompts).acquire_owned())
            .await
        {
            Ok(Ok(permit)) => permit,
            Ok(Err(err)) => {
                return (
                    PromptResult::Error(format!("endpoint approval prompt limit failed: {err}")),
                    true,
                );
            }
            Err(_) => return (PromptResult::TimedOut, false),
        };
    let shown = asked[0];
    let mut reasons: Vec<String> = Vec::with_capacity(asked.len());
    for approval in asked {
        let reason = request_reason(approval, target);
        if !reasons.contains(&reason) {
            reasons.push(reason);
        }
    }
    let request = ApprovalRequest::Endpoint {
        request_id: crate::reverse::endpoint_approval_request_id(target.request_id_scope),
        route_id: shown.route_id.to_string(),
        credential_route: target.credential_route.map(str::to_string),
        upstream: target.upstream.to_string(),
        method: target.method.to_string(),
        path: target.path.to_string(),
        rule_label: shown.rule_label.clone(),
        operation: shown.operation.map(str::to_string),
        reason: Some(reasons.join("; ")),
        child_pid: 0,
        session_id: registry.session_id().to_string(),
    };
    let backend = Arc::clone(backend);
    // The permit moves into the blocking task so it is held until the
    // backend returns, even after this request gives up at the deadline.
    let joined = tokio::time::timeout_at(
        tokio_deadline,
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            backend.request_approval_with_deadline(&request, deadline)
        }),
    )
    .await;
    match joined {
        Ok(Ok(Ok(decision))) => {
            if Instant::now() >= deadline {
                (PromptResult::TimedOut, false)
            } else {
                (PromptResult::Decision(decision), true)
            }
        }
        Ok(Ok(Err(err))) => (
            PromptResult::Error(format!("endpoint approval backend error: {err}")),
            true,
        ),
        Ok(Err(err)) => (
            PromptResult::Error(format!("endpoint approval task failed: {err}")),
            true,
        ),
        Err(_) => (PromptResult::TimedOut, false),
    }
}

/// Map a group result to (granted, audit decision, reason).
fn describe(
    result: GroupResult,
    approval: &PendingApproval<'_>,
    target: &ApprovalTarget<'_>,
) -> (bool, NetworkAuditDecision, Option<String>) {
    let decision = match result {
        GroupResult::Cached(true) => {
            return (
                true,
                NetworkAuditDecision::ApproveGranted,
                Some("granted for this session".to_string()),
            );
        }
        GroupResult::Cached(false) => {
            return (
                false,
                NetworkAuditDecision::ApproveDenied,
                Some("endpoint approval denied for this session".to_string()),
            );
        }
        GroupResult::Prompted(PromptResult::Error(reason)) => {
            return (false, NetworkAuditDecision::ApproveError, Some(reason));
        }
        GroupResult::Prompted(PromptResult::TimedOut) => {
            return (
                false,
                NetworkAuditDecision::ApproveTimeout,
                Some(format!(
                    "endpoint approval timed out by {}: {} {} on route '{}'",
                    approval.rule_label, target.method, target.path, approval.route_id
                )),
            );
        }
        GroupResult::Prompted(PromptResult::Decision(decision)) => decision,
    };
    match decision {
        ApprovalDecision::Granted | ApprovalDecision::GrantedForSession => {
            (true, NetworkAuditDecision::ApproveGranted, None)
        }
        ApprovalDecision::Denied { reason } => (
            false,
            NetworkAuditDecision::ApproveDenied,
            Some(if reason.is_empty() {
                "endpoint approval denied".to_string()
            } else {
                format!("endpoint approval denied: {reason}")
            }),
        ),
        ApprovalDecision::DeniedForSession => (
            false,
            NetworkAuditDecision::ApproveDenied,
            Some("endpoint approval denied for this session".to_string()),
        ),
        ApprovalDecision::Timeout => (
            false,
            NetworkAuditDecision::ApproveTimeout,
            Some(format!(
                "endpoint approval backend reported timeout for {} {} on route '{}'",
                target.method, target.path, approval.route_id
            )),
        ),
    }
}

fn request_reason(approval: &PendingApproval<'_>, target: &ApprovalTarget<'_>) -> String {
    let mut reason = approval.reason.map(str::to_string).unwrap_or_else(|| {
        format!(
            "endpoint approval required by {} for {} {}{}",
            approval.rule_label,
            target.method,
            target.path,
            approval
                .operation
                .map(|op| format!(" (operation {op})"))
                .unwrap_or_default()
        )
    });
    if let Some(region) = &approval.aws_region {
        reason.push_str(&format!(" (AWS region: {region})"));
    }
    reason
}

fn log_outcome(
    target: &ApprovalTarget<'_>,
    approval: &PendingApproval<'_>,
    backend_name: Option<&str>,
    decision: NetworkAuditDecision,
    reason: Option<&str>,
    policy_denial: bool,
) {
    let ctx = audit::EventContext {
        route_id: Some(approval.route_id),
        endpoint_operation: approval.operation,
        endpoint_protocol: approval.operation_protocol,
        denial_category: policy_denial.then_some(NetworkAuditDenialCategory::EndpointPolicy),
        endpoint_policy_action: Some("approve"),
        endpoint_policy_rule: Some(&approval.rule_label),
        approval_backend: backend_name,
        // A wildcard route audits the concrete host, not the pattern.
        upstream: Some(if approval.upstream.contains('*') {
            target.upstream
        } else {
            approval.upstream
        }),
        ..target.audit_ctx.clone()
    };
    audit::log_l7_policy_decision(
        target.audit_log,
        target.mode,
        &ctx,
        target.audit_target,
        target.audit_port,
        target.method,
        target.path,
        decision,
        "approve",
        &approval.rule_label,
        reason,
    );
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// Answers with the queued decisions in order (the last one repeats),
    /// after `delay`, and records every request.
    struct ScriptedBackend {
        decisions: Mutex<VecDeque<ApprovalDecision>>,
        requests: Mutex<Vec<ApprovalRequest>>,
        delay: Duration,
    }

    impl ScriptedBackend {
        fn new(decisions: &[ApprovalDecision], delay: Duration) -> Arc<Self> {
            Arc::new(Self {
                decisions: Mutex::new(decisions.iter().cloned().collect()),
                requests: Mutex::new(Vec::new()),
                delay,
            })
        }

        fn calls(&self) -> usize {
            self.requests.lock().unwrap().len()
        }
    }

    impl nono::ApprovalBackend for ScriptedBackend {
        fn request_approval(&self, request: &ApprovalRequest) -> nono::Result<ApprovalDecision> {
            self.requests.lock().unwrap().push(request.clone());
            std::thread::sleep(self.delay);
            let mut decisions = self.decisions.lock().unwrap();
            let decision = if decisions.len() > 1 {
                decisions.pop_front()
            } else {
                decisions.front().cloned()
            };
            Ok(decision.unwrap_or(ApprovalDecision::Timeout))
        }

        fn backend_name(&self) -> &str {
            "scripted"
        }
    }

    fn ep_approval(rule_label: &str, timeout_secs: Option<u64>) -> PendingApproval<'_> {
        PendingApproval {
            route_id: "_ep_*.example.com",
            upstream: "https://*.example.com",
            backend: None,
            reason: Some("endpoint reason"),
            timeout_secs,
            rule_label: rule_label.to_string(),
            session_scope: true,
            aws_region: None,
            operation: None,
            operation_protocol: None,
        }
    }

    fn credential_approval(rule_label: &str) -> PendingApproval<'_> {
        PendingApproval {
            route_id: "github",
            upstream: "https://api.example.com",
            backend: None,
            reason: Some("credential reason"),
            timeout_secs: None,
            rule_label: rule_label.to_string(),
            session_scope: false,
            aws_region: None,
            operation: None,
            operation_protocol: None,
        }
    }

    async fn ask(
        registry: &ApprovalBackendRegistry,
        pending: &[PendingApproval<'_>],
        upstream: &str,
        method: &str,
    ) -> bool {
        let audit_ctx = audit::EventContext::default();
        let target = ApprovalTarget {
            method,
            path: "/a/b",
            upstream,
            credential_route: None,
            audit_log: None,
            mode: audit::ProxyMode::ConnectIntercept,
            audit_ctx: &audit_ctx,
            audit_target: "example.com",
            audit_port: Some(443),
            request_id_scope: "test",
        };
        authorize(Some(registry), pending, &target).await
    }

    #[tokio::test]
    async fn session_answer_on_a_wildcard_route_covers_one_host() {
        let backend = ScriptedBackend::new(&[ApprovalDecision::GrantedForSession], Duration::ZERO);
        let registry = ApprovalBackendRegistry::singleton(backend.clone());
        let pending = [ep_approval("endpoint_policy.approve[GET /a/**]", None)];

        assert!(ask(&registry, &pending, "https://api.example.com", "GET").await);
        assert!(ask(&registry, &pending, "https://API.example.com", "GET").await);
        assert_eq!(backend.calls(), 1);
        assert!(ask(&registry, &pending, "https://other.example.com", "GET").await);
        assert_eq!(backend.calls(), 2, "another host must ask again");
        match backend.requests.lock().unwrap().last() {
            Some(ApprovalRequest::Endpoint { upstream, .. }) => {
                assert_eq!(upstream, "https://other.example.com");
            }
            other => panic!("expected an endpoint request, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn credential_route_session_answers_stay_one_shot() {
        let backend = ScriptedBackend::new(&[ApprovalDecision::GrantedForSession], Duration::ZERO);
        let registry = ApprovalBackendRegistry::singleton(backend.clone());
        let pending = [credential_approval("endpoint_policy.approve[GET /**]")];
        for _ in 0..2 {
            assert!(ask(&registry, &pending, "https://api.example.com", "GET").await);
        }
        assert_eq!(backend.calls(), 2);

        let backend = ScriptedBackend::new(
            &[
                ApprovalDecision::DeniedForSession,
                ApprovalDecision::Granted,
            ],
            Duration::ZERO,
        );
        let registry = ApprovalBackendRegistry::singleton(backend.clone());
        assert!(!ask(&registry, &pending, "https://api.example.com", "GET").await);
        assert!(ask(&registry, &pending, "https://api.example.com", "GET").await);
        assert_eq!(backend.calls(), 2, "a session denial must not be cached");
    }

    #[tokio::test]
    async fn grouped_prompt_caches_only_the_shown_approval() {
        let backend = ScriptedBackend::new(&[ApprovalDecision::GrantedForSession], Duration::ZERO);
        let registry = ApprovalBackendRegistry::singleton(backend.clone());
        let both = [
            ep_approval("endpoint_policy.approve[GET /a/**]", None),
            credential_approval("endpoint_policy.approve[GET /**]"),
        ];
        assert!(ask(&registry, &both, "https://api.example.com", "GET").await);
        match backend.requests.lock().unwrap().last() {
            Some(ApprovalRequest::Endpoint {
                route_id, reason, ..
            }) => {
                assert_eq!(route_id, "_ep_*.example.com");
                assert_eq!(
                    reason.as_deref(),
                    Some("endpoint reason; credential reason"),
                    "the prompt must carry every member's reason"
                );
            }
            other => panic!("expected an endpoint request, got {other:?}"),
        }
        let state = registry.endpoint_sessions();
        let decisions = state.decisions.lock().unwrap();
        assert_eq!(decisions.len(), 1);
        assert!(
            decisions
                .keys()
                .all(|key| key.route_id == "_ep_*.example.com")
        );
    }

    #[tokio::test]
    async fn waiting_request_does_not_inherit_a_one_shot_denial() {
        let backend = ScriptedBackend::new(
            &[
                ApprovalDecision::Denied {
                    reason: "no".to_string(),
                },
                ApprovalDecision::Granted,
            ],
            Duration::from_millis(200),
        );
        let registry = ApprovalBackendRegistry::singleton(backend.clone());
        let pending = [ep_approval("endpoint_policy.approve[GET /a/**]", None)];

        let leader = ask(&registry, &pending, "https://api.example.com", "GET");
        let follower = async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            ask(&registry, &pending, "https://api.example.com", "GET").await
        };
        let (leader, follower) = tokio::join!(leader, follower);

        assert!(!leader);
        assert!(follower, "the waiting request must be asked itself");
        assert_eq!(backend.calls(), 2);
    }

    #[tokio::test]
    async fn waiting_request_shares_a_session_answer() {
        let backend = ScriptedBackend::new(
            &[ApprovalDecision::GrantedForSession],
            Duration::from_millis(200),
        );
        let registry = ApprovalBackendRegistry::singleton(backend.clone());
        let pending = [ep_approval("endpoint_policy.approve[GET /a/**]", None)];
        let (first, second) = tokio::join!(
            ask(&registry, &pending, "https://api.example.com", "GET"),
            ask(&registry, &pending, "https://api.example.com", "GET"),
        );
        assert!(first && second);
        assert_eq!(backend.calls(), 1);
    }

    #[tokio::test]
    async fn waiting_request_is_bounded_by_its_own_deadline() {
        let backend = ScriptedBackend::new(
            &[ApprovalDecision::GrantedForSession],
            Duration::from_millis(2500),
        );
        let registry = ApprovalBackendRegistry::singleton(backend.clone());
        let slow = [ep_approval("endpoint_policy.approve[GET /a/**]", Some(10))];
        let strict = [ep_approval("endpoint_policy.approve[GET /a/**]", Some(1))];

        let leader = ask(&registry, &slow, "https://api.example.com", "GET");
        let follower = async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let started = Instant::now();
            let granted = ask(&registry, &strict, "https://api.example.com", "GET").await;
            (granted, started.elapsed())
        };
        let (leader, (follower, waited)) = tokio::join!(leader, follower);

        assert!(leader);
        assert!(!follower);
        assert!(waited < Duration::from_millis(2000), "waited {waited:?}");
    }

    #[test]
    fn group_deadline_uses_the_strictest_timeout() {
        let members = [
            ep_approval("a", Some(60)),
            ep_approval("b", Some(1)),
            ep_approval("c", None),
        ];
        let refs: Vec<&PendingApproval<'_>> = members.iter().collect();
        let deadline = group_deadline(&refs);
        assert!(deadline <= Instant::now() + Duration::from_secs(1));
    }

    #[test]
    fn session_cache_stops_growing_at_its_cap() {
        let state = EndpointSessionState::default();
        let key = |i: usize| ScopeKey {
            route_id: "_ep_example.com".to_string(),
            upstream: "https://example.com".to_string(),
            credential_route: None,
            rule_label: format!("endpoint_policy.approve[GET /{i}/**]"),
            operation: None,
        };
        for i in 0..MAX_SESSION_DECISIONS {
            state.remember(&key(i), true);
        }
        state.remember(&key(MAX_SESSION_DECISIONS), true);
        state.remember(&key(0), false);
        let decisions = state.decisions.lock().unwrap();
        assert_eq!(decisions.len(), MAX_SESSION_DECISIONS);
        assert!(!decisions.contains_key(&key(MAX_SESSION_DECISIONS)));
        assert_eq!(
            decisions.get(&key(0)),
            Some(&false),
            "known keys still update"
        );
    }

    #[tokio::test]
    async fn concurrent_prompts_are_limited_per_session() {
        assert_eq!(MAX_CONCURRENT_PROMPTS, 4, "update the five requests below");
        let backend =
            ScriptedBackend::new(&[ApprovalDecision::Granted], Duration::from_millis(300));
        let registry = ApprovalBackendRegistry::singleton(backend.clone());
        let labels: Vec<String> = (0..5)
            .map(|i| format!("endpoint_policy.approve[GET /{i}/**]"))
            .collect();
        let p: Vec<[PendingApproval<'_>; 1]> = labels
            .iter()
            .map(|label| [ep_approval(label, Some(10))])
            .collect();
        let upstream = "https://api.example.com";
        let started = Instant::now();
        let results = tokio::join!(
            ask(&registry, &p[0], upstream, "GET"),
            ask(&registry, &p[1], upstream, "GET"),
            ask(&registry, &p[2], upstream, "GET"),
            ask(&registry, &p[3], upstream, "GET"),
            ask(&registry, &p[4], upstream, "GET"),
        );
        assert!(results.0 && results.1 && results.2 && results.3 && results.4);
        assert_eq!(backend.calls(), 5);
        assert!(
            started.elapsed() >= Duration::from_millis(550),
            "one prompt over the limit must wait for a permit"
        );
    }
}
