//! Audit logging for proxy requests.
//!
//! Logs all proxy requests with structured fields via `tracing`.
//! Sensitive data (authorization headers, tokens, request bodies)
//! is never included in audit logs.

use nono::undo::{
    NetworkAuditAuthMechanism, NetworkAuditAuthOutcome, NetworkAuditDecision,
    NetworkAuditDenialCategory, NetworkAuditEvent, NetworkAuditInjectionMode, NetworkAuditMode,
};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

/// Maximum number of in-memory network audit events kept per proxy session.
const MAX_AUDIT_EVENTS: usize = 4096;

/// Shared in-memory sink for network audit events.
pub type SharedAuditLog = Arc<Mutex<Vec<NetworkAuditEvent>>>;

/// Proxy mode for audit logging.
#[derive(Debug, Clone, Copy)]
pub enum ProxyMode {
    /// CONNECT tunnel (host filtering only, no L7 visibility)
    Connect,
    /// CONNECT tunnel that the proxy terminated locally for L7 inspection
    /// and/or credential injection.
    ConnectIntercept,
    /// Reverse proxy (credential injection)
    Reverse,
    /// External proxy passthrough (enterprise)
    External,
}

/// Optional structured audit context attached to a proxy event.
#[derive(Debug, Clone, Default)]
pub struct EventContext<'a> {
    pub route_id: Option<&'a str>,
    pub auth_mechanism: Option<NetworkAuditAuthMechanism>,
    pub auth_outcome: Option<NetworkAuditAuthOutcome>,
    pub managed_credential_active: Option<bool>,
    pub injection_mode: Option<NetworkAuditInjectionMode>,
    pub denial_category: Option<NetworkAuditDenialCategory>,
    pub endpoint_policy_action: Option<&'a str>,
    pub endpoint_policy_rule: Option<&'a str>,
    pub approval_backend: Option<&'a str>,
    pub upstream: Option<&'a str>,
    pub spiffe_context: Option<nono::undo::SpiffeAuditContext>,
}

impl std::fmt::Display for ProxyMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyMode::Connect => write!(f, "connect"),
            ProxyMode::ConnectIntercept => write!(f, "connect_intercept"),
            ProxyMode::Reverse => write!(f, "reverse"),
            ProxyMode::External => write!(f, "external"),
        }
    }
}

/// Create a shared in-memory audit log.
#[must_use]
pub fn new_audit_log() -> SharedAuditLog {
    Arc::new(Mutex::new(Vec::new()))
}

/// Drain all network audit events collected so far.
#[must_use]
pub fn drain_audit_events(audit_log: &SharedAuditLog) -> Vec<NetworkAuditEvent> {
    match audit_log.lock() {
        Ok(mut events) => events.drain(..).collect(),
        Err(e) => {
            warn!(
                "Network audit log mutex poisoned while draining events: {}",
                e
            );
            Vec::new()
        }
    }
}

fn now_unix_millis() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            let millis = duration.as_millis();
            if millis > u128::from(u64::MAX) {
                warn!("System clock millis exceeded u64::MAX; clamping audit timestamp");
                u64::MAX
            } else {
                millis as u64
            }
        }
        Err(e) => {
            warn!(
                "System clock before UNIX_EPOCH while generating audit timestamp: {}",
                e
            );
            0
        }
    }
}

fn map_mode(mode: ProxyMode) -> NetworkAuditMode {
    match mode {
        ProxyMode::Connect => NetworkAuditMode::Connect,
        ProxyMode::ConnectIntercept => NetworkAuditMode::ConnectIntercept,
        ProxyMode::Reverse => NetworkAuditMode::Reverse,
        ProxyMode::External => NetworkAuditMode::External,
    }
}

fn push_event(audit_log: Option<&SharedAuditLog>, event: NetworkAuditEvent) {
    let Some(audit_log) = audit_log else {
        return;
    };

    match audit_log.lock() {
        Ok(mut events) => {
            if events.len() < MAX_AUDIT_EVENTS {
                events.push(event);
            } else {
                warn!(
                    "Network audit buffer full ({} events); dropping event",
                    MAX_AUDIT_EVENTS
                );
            }
        }
        Err(e) => {
            warn!(
                "Network audit log mutex poisoned while recording event: {}",
                e
            );
        }
    }
}

/// Log an allowed proxy request.
pub fn log_allowed(
    audit_log: Option<&SharedAuditLog>,
    mode: ProxyMode,
    ctx: &EventContext<'_>,
    host: &str,
    port: u16,
    method: &str,
) {
    info!(
        target: "nono_proxy::audit",
        mode = %mode,
        host = host,
        port = port,
        method = method,
        decision = "allow",
        "proxy request allowed"
    );

    push_event(
        audit_log,
        NetworkAuditEvent {
            timestamp_unix_ms: now_unix_millis(),
            mode: map_mode(mode),
            decision: NetworkAuditDecision::Allow,
            route_id: ctx.route_id.map(str::to_string),
            auth_mechanism: ctx.auth_mechanism.clone(),
            auth_outcome: ctx.auth_outcome.clone(),
            managed_credential_active: ctx.managed_credential_active,
            injection_mode: ctx.injection_mode.clone(),
            denial_category: None,
            endpoint_policy_action: ctx.endpoint_policy_action.map(str::to_string),
            endpoint_policy_rule: ctx.endpoint_policy_rule.map(str::to_string),
            approval_backend: ctx.approval_backend.map(str::to_string),
            credential_capture_action: None,
            credential_capture_name: None,
            credential_capture_command: None,
            credential_capture_argv: None,
            credential_capture_exit_status: None,
            credential_capture_duration_ms: None,
            credential_capture_stdout_bytes: None,
            credential_capture_stderr: None,
            credential_capture_cache_scope: None,
            credential_capture_output_format: None,
            credential_capture_header_names: None,
            credential_capture_stdin_mode: None,
            credential_capture_interactive: None,
            spiffe_context: ctx.spiffe_context.clone(),
            target: host.to_string(),
            upstream: ctx.upstream.map(str::to_string),
            port: Some(port),
            method: Some(method.to_string()),
            path: None,
            status: None,
            reason: None,
        },
    );
}

/// Log a denied proxy request.
pub fn log_denied(
    audit_log: Option<&SharedAuditLog>,
    mode: ProxyMode,
    ctx: &EventContext<'_>,
    host: &str,
    port: u16,
    reason: &str,
) {
    info!(
        target: "nono_proxy::audit",
        mode = %mode,
        host = host,
        port = port,
        decision = "deny",
        reason = reason,
        "proxy request denied"
    );

    push_event(
        audit_log,
        NetworkAuditEvent {
            timestamp_unix_ms: now_unix_millis(),
            mode: map_mode(mode),
            decision: NetworkAuditDecision::Deny,
            route_id: ctx.route_id.map(str::to_string),
            auth_mechanism: ctx.auth_mechanism.clone(),
            auth_outcome: ctx.auth_outcome.clone(),
            managed_credential_active: ctx.managed_credential_active,
            injection_mode: ctx.injection_mode.clone(),
            denial_category: ctx.denial_category.clone(),
            endpoint_policy_action: ctx.endpoint_policy_action.map(str::to_string),
            endpoint_policy_rule: ctx.endpoint_policy_rule.map(str::to_string),
            approval_backend: ctx.approval_backend.map(str::to_string),
            credential_capture_action: None,
            credential_capture_name: None,
            credential_capture_command: None,
            credential_capture_argv: None,
            credential_capture_exit_status: None,
            credential_capture_duration_ms: None,
            credential_capture_stdout_bytes: None,
            credential_capture_stderr: None,
            credential_capture_cache_scope: None,
            credential_capture_output_format: None,
            credential_capture_header_names: None,
            credential_capture_stdin_mode: None,
            credential_capture_interactive: None,
            spiffe_context: ctx.spiffe_context.clone(),
            target: host.to_string(),
            upstream: ctx.upstream.map(str::to_string),
            port: Some(port),
            method: None,
            path: None,
            status: None,
            reason: Some(reason.to_string()),
        },
    );
}

/// Log an L7 request that the proxy decoded (reverse proxy or intercepted CONNECT).
///
/// Used for both `Reverse` and `ConnectIntercept` modes. `External` and
/// `Connect` (transparent tunnel) modes have no L7 visibility and use
/// `log_allowed`/`log_denied` instead.
pub fn log_l7_request(
    audit_log: Option<&SharedAuditLog>,
    mode: ProxyMode,
    ctx: &EventContext<'_>,
    target: &str,
    method: &str,
    path: &str,
    status: u16,
) {
    info!(
        target: "nono_proxy::audit",
        mode = %mode,
        target = target,
        method = method,
        path = path,
        status = status,
        "l7 proxy response"
    );

    push_event(
        audit_log,
        NetworkAuditEvent {
            timestamp_unix_ms: now_unix_millis(),
            mode: map_mode(mode),
            decision: NetworkAuditDecision::Allow,
            route_id: ctx.route_id.map(str::to_string),
            auth_mechanism: ctx.auth_mechanism.clone(),
            auth_outcome: ctx.auth_outcome.clone(),
            managed_credential_active: ctx.managed_credential_active,
            injection_mode: ctx.injection_mode.clone(),
            denial_category: None,
            endpoint_policy_action: ctx.endpoint_policy_action.map(str::to_string),
            endpoint_policy_rule: ctx.endpoint_policy_rule.map(str::to_string),
            approval_backend: ctx.approval_backend.map(str::to_string),
            credential_capture_action: None,
            credential_capture_name: None,
            credential_capture_command: None,
            credential_capture_argv: None,
            credential_capture_exit_status: None,
            credential_capture_duration_ms: None,
            credential_capture_stdout_bytes: None,
            credential_capture_stderr: None,
            credential_capture_cache_scope: None,
            credential_capture_output_format: None,
            credential_capture_header_names: None,
            credential_capture_stdin_mode: None,
            credential_capture_interactive: None,
            spiffe_context: ctx.spiffe_context.clone(),
            target: target.to_string(),
            upstream: ctx.upstream.map(str::to_string),
            port: None,
            method: Some(method.to_string()),
            path: Some(path.to_string()),
            status: Some(status),
            reason: None,
        },
    );
}

/// Log an L7 endpoint-policy decision before the upstream request is made.
#[allow(clippy::too_many_arguments)]
pub fn log_l7_policy_decision(
    audit_log: Option<&SharedAuditLog>,
    mode: ProxyMode,
    ctx: &EventContext<'_>,
    target: &str,
    port: Option<u16>,
    method: &str,
    path: &str,
    decision: NetworkAuditDecision,
    action: &str,
    rule_label: &str,
    reason: Option<&str>,
) {
    info!(
        target: "nono_proxy::audit",
        mode = %mode,
        target = target,
        method = method,
        path = path,
        decision = ?decision,
        endpoint_policy_action = action,
        endpoint_policy_rule = rule_label,
        "l7 endpoint policy decision"
    );

    push_event(
        audit_log,
        NetworkAuditEvent {
            timestamp_unix_ms: now_unix_millis(),
            mode: map_mode(mode),
            decision,
            route_id: ctx.route_id.map(str::to_string),
            auth_mechanism: ctx.auth_mechanism.clone(),
            auth_outcome: ctx.auth_outcome.clone(),
            managed_credential_active: ctx.managed_credential_active,
            injection_mode: ctx.injection_mode.clone(),
            denial_category: ctx.denial_category.clone(),
            endpoint_policy_action: Some(action.to_string()),
            endpoint_policy_rule: Some(rule_label.to_string()),
            approval_backend: ctx.approval_backend.map(str::to_string),
            credential_capture_action: None,
            credential_capture_name: None,
            credential_capture_command: None,
            credential_capture_argv: None,
            credential_capture_exit_status: None,
            credential_capture_duration_ms: None,
            credential_capture_stdout_bytes: None,
            credential_capture_stderr: None,
            credential_capture_cache_scope: None,
            credential_capture_output_format: None,
            credential_capture_header_names: None,
            credential_capture_stdin_mode: None,
            credential_capture_interactive: None,
            spiffe_context: ctx.spiffe_context.clone(),
            target: target.to_string(),
            upstream: ctx.upstream.map(str::to_string),
            port,
            method: Some(method.to_string()),
            path: Some(path.to_string()),
            status: None,
            reason: reason.map(str::to_string),
        },
    );
}

/// Structured details for a command-backed credential capture audit event.
#[derive(Debug, Clone)]
pub struct CredentialCaptureAudit<'a> {
    pub route_id: &'a str,
    pub credential_name: &'a str,
    pub action: &'a str,
    pub decision: NetworkAuditDecision,
    pub command: Option<&'a str>,
    pub argv: Option<&'a [String]>,
    pub exit_status: Option<i32>,
    pub duration_ms: Option<u64>,
    pub stdout_bytes: Option<usize>,
    pub stderr_redacted: Option<&'a str>,
    pub cache_scope: Option<&'a str>,
    pub output_format: Option<&'a str>,
    pub header_names: Option<&'a [String]>,
    pub stdin_mode: Option<&'a str>,
    pub interactive: Option<bool>,
    pub upstream: Option<&'a str>,
    pub request_host: &'a str,
    pub request_port: Option<u16>,
    pub request_method: &'a str,
    pub request_path: &'a str,
    pub reason: Option<&'a str>,
}

/// Log a command-backed credential capture event. The captured credential value
/// is never recorded; only command metadata, timing, byte counts, and redacted
/// diagnostics are persisted.
pub fn log_credential_capture(
    audit_log: Option<&SharedAuditLog>,
    mode: ProxyMode,
    event: CredentialCaptureAudit<'_>,
) {
    info!(
        target: "nono_proxy::audit",
        mode = %mode,
        route_id = event.route_id,
        credential = event.credential_name,
        action = event.action,
        decision = ?event.decision,
        method = event.request_method,
        path = event.request_path,
        "credential capture event"
    );

    push_event(
        audit_log,
        NetworkAuditEvent {
            timestamp_unix_ms: now_unix_millis(),
            mode: map_mode(mode),
            decision: event.decision,
            route_id: Some(event.route_id.to_string()),
            auth_mechanism: None,
            auth_outcome: None,
            managed_credential_active: Some(true),
            injection_mode: None,
            denial_category: event
                .reason
                .map(|_| NetworkAuditDenialCategory::ManagedCredentialUnavailable),
            endpoint_policy_action: None,
            endpoint_policy_rule: None,
            approval_backend: None,
            credential_capture_action: Some(event.action.to_string()),
            credential_capture_name: Some(event.credential_name.to_string()),
            credential_capture_command: event.command.map(str::to_string),
            credential_capture_argv: event.argv.map(<[String]>::to_vec),
            credential_capture_exit_status: event.exit_status,
            credential_capture_duration_ms: event.duration_ms,
            credential_capture_stdout_bytes: event.stdout_bytes,
            credential_capture_stderr: event.stderr_redacted.map(str::to_string),
            credential_capture_cache_scope: event.cache_scope.map(str::to_string),
            credential_capture_output_format: event.output_format.map(str::to_string),
            credential_capture_header_names: event.header_names.map(<[String]>::to_vec),
            credential_capture_stdin_mode: event.stdin_mode.map(str::to_string),
            credential_capture_interactive: event.interactive,
            spiffe_context: None,
            target: event.request_host.to_string(),
            upstream: event.upstream.map(str::to_string),
            port: event.request_port,
            method: Some(event.request_method.to_string()),
            path: Some(event.request_path.to_string()),
            status: None,
            reason: event.reason.map(str::to_string),
        },
    );
}

/// Compatibility shim for the previous `log_reverse_proxy` API. New code
/// should call [`log_l7_request`] directly with the appropriate
/// [`ProxyMode`] instead.
#[deprecated(since = "0.46.0", note = "use log_l7_request with ProxyMode::Reverse")]
pub fn log_reverse_proxy(
    audit_log: Option<&SharedAuditLog>,
    service: &str,
    method: &str,
    path: &str,
    status: u16,
) {
    log_l7_request(
        audit_log,
        ProxyMode::Reverse,
        &EventContext {
            route_id: Some(service),
            ..EventContext::default()
        },
        service,
        method,
        path,
        status,
    );
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn log_allowed_records_event() {
        let log = new_audit_log();

        log_allowed(
            Some(&log),
            ProxyMode::Connect,
            &EventContext::default(),
            "api.openai.com",
            443,
            "CONNECT",
        );

        let events = drain_audit_events(&log);
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.mode, NetworkAuditMode::Connect);
        assert_eq!(event.decision, NetworkAuditDecision::Allow);
        assert_eq!(event.route_id, None);
        assert_eq!(event.auth_mechanism, None);
        assert_eq!(event.target, "api.openai.com");
        assert_eq!(event.port, Some(443));
        assert_eq!(event.method.as_deref(), Some("CONNECT"));
        assert!(event.timestamp_unix_ms > 0);
    }

    #[test]
    fn log_denied_records_reason() {
        let log = new_audit_log();

        log_denied(
            Some(&log),
            ProxyMode::External,
            &EventContext::default(),
            "169.254.169.254",
            80,
            "blocked by metadata deny list",
        );

        let events = drain_audit_events(&log);
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.mode, NetworkAuditMode::External);
        assert_eq!(event.decision, NetworkAuditDecision::Deny);
        assert_eq!(event.route_id, None);
        assert_eq!(event.auth_mechanism, None);
        assert_eq!(
            event.reason.as_deref(),
            Some("blocked by metadata deny list")
        );
    }

    #[test]
    fn log_l7_policy_decision_records_endpoint_context() {
        let log = new_audit_log();

        log_l7_policy_decision(
            Some(&log),
            ProxyMode::Reverse,
            &EventContext {
                route_id: Some("internal-api"),
                managed_credential_active: Some(true),
                injection_mode: Some(NetworkAuditInjectionMode::Header),
                approval_backend: Some("terminal"),
                upstream: Some("https://api.internal.example"),
                ..EventContext::default()
            },
            "internal-api",
            None,
            "POST",
            "/v1/tasks/123/comments",
            NetworkAuditDecision::ApproveRequested,
            "approve",
            "endpoint_policy.approve[POST /v1/tasks/*/comments]",
            Some("approval required"),
        );

        let events = drain_audit_events(&log);
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.mode, NetworkAuditMode::Reverse);
        assert_eq!(event.decision, NetworkAuditDecision::ApproveRequested);
        assert_eq!(event.route_id.as_deref(), Some("internal-api"));
        assert_eq!(event.managed_credential_active, Some(true));
        assert_eq!(
            event.injection_mode,
            Some(NetworkAuditInjectionMode::Header)
        );
        assert_eq!(event.endpoint_policy_action.as_deref(), Some("approve"));
        assert_eq!(
            event.endpoint_policy_rule.as_deref(),
            Some("endpoint_policy.approve[POST /v1/tasks/*/comments]")
        );
        assert_eq!(event.approval_backend.as_deref(), Some("terminal"));
        assert_eq!(
            event.upstream.as_deref(),
            Some("https://api.internal.example")
        );
        assert_eq!(event.target, "internal-api");
        assert_eq!(event.port, None);
        assert_eq!(event.method.as_deref(), Some("POST"));
        assert_eq!(event.path.as_deref(), Some("/v1/tasks/123/comments"));
        assert_eq!(event.reason.as_deref(), Some("approval required"));
    }
}
