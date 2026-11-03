//! Endpoint-policy approval workflow shared by the reverse-proxy and
//! CONNECT-intercept paths.
//!
//! A request can need approval from more than one route: the `_ep_<domain>`
//! authorization route built from `allow_domain` and the credential route that
//! will inject a credential. [`authorize`] asks once for all of them (once per
//! distinct backend), honors session-scoped answers, and coalesces identical
//! in-flight prompts so a burst of requests shares one prompt.
//!
//! Session answers are keyed by route plus the scoped rule label (see
//! `config::approval_scope_path`), so "always" on `* /torvalds/linux/**`
//! covers exactly that scope. Callers evaluate `deny`/`allow` rules and the
//! policy default before calling in, so a cached answer only ever replaces a
//! prompt and can never override a deny.

use crate::approval::ApprovalBackendRegistry;
use crate::audit;
use nono::supervisor::{ApprovalDecision, ApprovalRequest};
use nono::undo::{NetworkAuditDecision, NetworkAuditDenialCategory};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tracing::warn;

/// Default prompt timeout when a rule does not set `timeout_secs`.
const DEFAULT_ENDPOINT_APPROVAL_TIMEOUT: Duration = Duration::from_secs(60);

/// Session-cache key: the route whose rule asked plus its scoped rule label.
type ScopeKey = (String, String);

/// Per-proxy-session endpoint approval state. Owned by the
/// [`ApprovalBackendRegistry`], which lives for one proxy session.
#[derive(Default)]
pub(crate) struct EndpointSessionState {
    /// Session-scoped answers: `true` = allow, `false` = deny.
    decisions: Mutex<HashMap<ScopeKey, bool>>,
    /// Prompts in progress, so identical requests await one answer.
    in_flight: Mutex<HashMap<ScopeKey, Arc<InFlight>>>,
}

impl EndpointSessionState {
    fn remember(&self, keys: &[ScopeKey], allow: bool) {
        let mut decisions = self.decisions.lock().unwrap_or_else(|e| e.into_inner());
        for key in keys {
            decisions.insert(key.clone(), allow);
        }
    }
}

/// Shared slot through which a prompting request publishes its answer to
/// concurrent requests with the same scope.
struct InFlight {
    tx: watch::Sender<Option<ApprovalDecision>>,
}

impl InFlight {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            tx: watch::channel(None).0,
        })
    }

    async fn await_decision(&self) -> ApprovalDecision {
        let mut rx = self.tx.subscribe();
        loop {
            if let Some(decision) = rx.borrow_and_update().clone() {
                return decision;
            }
            if rx.changed().await.is_err() {
                return ApprovalDecision::Denied {
                    reason: "endpoint approval leader disappeared".to_string(),
                };
            }
        }
    }
}

/// Releases the in-flight slots and wakes followers, even when the prompting
/// request is cancelled (the client disconnected). A vanished leader denies.
struct InFlightLeader<'a> {
    state: &'a EndpointSessionState,
    keys: Vec<ScopeKey>,
    shared: Arc<InFlight>,
    decision: Option<ApprovalDecision>,
}

impl Drop for InFlightLeader<'_> {
    fn drop(&mut self) {
        let mut map = self
            .state
            .in_flight
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for key in &self.keys {
            if map
                .get(key)
                .is_some_and(|slot| Arc::ptr_eq(slot, &self.shared))
            {
                map.remove(key);
            }
        }
        let decision = self
            .decision
            .take()
            .unwrap_or_else(|| ApprovalDecision::Denied {
                reason: "endpoint approval leader cancelled".to_string(),
            });
        self.shared.tx.send_replace(Some(decision));
    }
}

/// One route's `approve` outcome for the current request.
pub(crate) struct PendingApproval<'a> {
    pub route_id: &'a str,
    pub upstream: &'a str,
    pub backend: Option<&'a str>,
    pub reason: Option<&'a str>,
    pub timeout_secs: Option<u64>,
    /// Scoped rule label, e.g. `endpoint_policy.approve[* /torvalds/linux/**]`.
    pub rule_label: String,
}

/// The request being approved and where its audit events go.
pub(crate) struct ApprovalTarget<'a> {
    pub method: &'a str,
    pub path: &'a str,
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
    Followed(ApprovalDecision),
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

async fn authorize_group(
    registry: &ApprovalBackendRegistry,
    backend_name: &str,
    backend: Arc<dyn nono::ApprovalBackend>,
    members: &[&PendingApproval<'_>],
    target: &ApprovalTarget<'_>,
) -> bool {
    let state = registry.endpoint_sessions();
    let keys: Vec<ScopeKey> = members
        .iter()
        .map(|approval| (approval.route_id.to_string(), approval.rule_label.clone()))
        .collect();

    let result = loop {
        // Check the cache while holding the election lock: a leader may have
        // stored a session answer since this request arrived.
        let election = {
            let mut map = state.in_flight.lock().unwrap_or_else(|e| e.into_inner());
            let uncached: Vec<usize> = {
                let decisions = state.decisions.lock().unwrap_or_else(|e| e.into_inner());
                if keys.iter().any(|key| decisions.get(key) == Some(&false)) {
                    break GroupResult::Cached(false);
                }
                (0..keys.len())
                    .filter(|&i| !decisions.contains_key(&keys[i]))
                    .collect()
            };
            if uncached.is_empty() {
                break GroupResult::Cached(true);
            }
            match uncached.iter().find_map(|&i| map.get(&keys[i])) {
                Some(existing) => Err(Arc::clone(existing)),
                None => {
                    let shared = InFlight::new();
                    let leader_keys: Vec<ScopeKey> =
                        uncached.iter().map(|&i| keys[i].clone()).collect();
                    for key in &leader_keys {
                        map.insert(key.clone(), Arc::clone(&shared));
                    }
                    Ok((
                        InFlightLeader {
                            state,
                            keys: leader_keys,
                            shared,
                            decision: None,
                        },
                        uncached,
                    ))
                }
            }
        };

        match election {
            Err(follower) => match follower.await_decision().await {
                // A one-shot grant covers only the leader's request; session
                // answers are now cached. Either way, re-run the election.
                ApprovalDecision::Granted
                | ApprovalDecision::GrantedForSession
                | ApprovalDecision::DeniedForSession => continue,
                decision => break GroupResult::Followed(decision),
            },
            Ok((mut leader, uncached)) => {
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
                let (result, in_time) = run_prompt(registry, &backend, asked[0], target).await;
                let shared_decision = match &result {
                    PromptResult::Decision(decision) => decision.clone(),
                    PromptResult::Error(reason) => ApprovalDecision::Denied {
                        reason: reason.clone(),
                    },
                    PromptResult::TimedOut => ApprovalDecision::Timeout,
                };
                if in_time {
                    match shared_decision {
                        ApprovalDecision::GrantedForSession => state.remember(&leader.keys, true),
                        ApprovalDecision::DeniedForSession => state.remember(&leader.keys, false),
                        _ => {}
                    }
                }
                leader.decision = Some(shared_decision);
                drop(leader);
                break GroupResult::Prompted(result);
            }
        }
    };

    let (granted, decision, reason) = describe(result, members[0], target);
    if let Some(reason) = &reason
        && !granted
    {
        warn!("{}", crate::approval::sanitize_reason_for_log(reason));
    }
    for approval in members {
        log_outcome(
            target,
            approval,
            Some(backend_name),
            decision.clone(),
            reason.as_deref(),
            false,
        );
    }
    granted
}

/// Ask the backend on the blocking pool, bounded by the rule's timeout.
/// Returns the result and whether it arrived before the deadline; a late
/// answer is a timeout and is never cached.
async fn run_prompt(
    registry: &ApprovalBackendRegistry,
    backend: &Arc<dyn nono::ApprovalBackend>,
    approval: &PendingApproval<'_>,
    target: &ApprovalTarget<'_>,
) -> (PromptResult, bool) {
    let request = ApprovalRequest::Endpoint {
        request_id: crate::reverse::endpoint_approval_request_id(target.request_id_scope),
        route_id: approval.route_id.to_string(),
        credential_route: target.credential_route.map(str::to_string),
        upstream: approval.upstream.to_string(),
        method: target.method.to_string(),
        path: target.path.to_string(),
        rule_label: approval.rule_label.clone(),
        reason: Some(request_reason(approval, target)),
        child_pid: 0,
        session_id: registry.session_id().to_string(),
    };
    let timeout = approval
        .timeout_secs
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_ENDPOINT_APPROVAL_TIMEOUT);
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    let backend = Arc::clone(backend);
    let joined = tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        tokio::task::spawn_blocking(move || {
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
        GroupResult::Prompted(PromptResult::Decision(decision))
        | GroupResult::Followed(decision) => decision,
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
    approval.reason.map(str::to_string).unwrap_or_else(|| {
        format!(
            "endpoint approval required by {} for {} {}",
            approval.rule_label, target.method, target.path
        )
    })
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
        denial_category: policy_denial.then_some(NetworkAuditDenialCategory::EndpointPolicy),
        endpoint_policy_action: Some("approve"),
        endpoint_policy_rule: Some(&approval.rule_label),
        approval_backend: backend_name,
        upstream: Some(approval.upstream),
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
