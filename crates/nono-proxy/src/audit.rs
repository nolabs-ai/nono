//! Audit logging for proxy requests.
//!
//! Logs all proxy requests with structured fields via `tracing`.
//! Sensitive data (authorization headers, tokens, request bodies)
//! is never included in audit logs.

use nono::undo::{
    NetworkAuditAuthMechanism, NetworkAuditAuthOutcome, NetworkAuditDecision,
    NetworkAuditDenialCategory, NetworkAuditEvent, NetworkAuditInjectionMode, NetworkAuditMode,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

/// Maximum number of in-memory network audit events kept per proxy session.
const MAX_AUDIT_EVENTS: usize = 4096;

/// Sink for streaming network audit events to a durable destination as they
/// occur. Implementations must be cheap to call from async request handlers
/// and must not panic; failures should be logged and swallowed so audit
/// recording cannot break network operations.
///
/// `record` is the hot path and must not block. Implementations that buffer
/// or offload writes asynchronously must drain their buffer in `flush`,
/// which the audit log calls during `close` so that the caller can safely
/// append further events (e.g. a `session_ended` record) directly to the
/// underlying store without racing the sink's background writer.
pub trait NetworkAuditSink: Send + Sync {
    fn record(&self, event: &NetworkAuditEvent);

    /// Drain any buffered events. Returns only after every event passed to
    /// `record` before this call is durable in the sink's destination.
    /// Default no-op for sinks that write synchronously inside `record`.
    fn flush(&self) {}
}

/// Shared sink for network audit events.
///
/// Holds an in-memory buffer (used to populate `SessionMetadata.network_events`
/// at session end) and an optional streaming sink that writes each event to a
/// durable log as it occurs. Without the streaming sink, events are only
/// persisted at session exit, which loses them on crash and silently drops
/// past `MAX_AUDIT_EVENTS`.
pub struct AuditLog {
    events: Mutex<Vec<NetworkAuditEvent>>,
    streaming_sink: OnceLock<Arc<dyn NetworkAuditSink>>,
    closed: AtomicBool,
}

impl AuditLog {
    fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            streaming_sink: OnceLock::new(),
            closed: AtomicBool::new(false),
        }
    }

    /// Attach a streaming sink. Returns `Err` if a sink was already attached.
    pub fn set_streaming_sink(
        &self,
        sink: Arc<dyn NetworkAuditSink>,
    ) -> std::result::Result<(), Arc<dyn NetworkAuditSink>> {
        self.streaming_sink.set(sink)
    }

    /// True if a streaming sink has been attached.
    #[must_use]
    pub fn streaming_active(&self) -> bool {
        self.streaming_sink.get().is_some()
    }

    /// Stop accepting new events, then drain the streaming sink.
    ///
    /// Called by the supervisor immediately before recording `session_ended`,
    /// so that late events (in-flight responses still being audited after the
    /// child has exited) cannot append past the Merkle root that gets written
    /// into the session metadata. Without this, post-finalize events would
    /// extend the file past the stored root and cause `verify_audit_log` to
    /// fail with a Merkle mismatch.
    ///
    /// The `closed` flag is set with release ordering before `flush` so that
    /// no in-flight `push_event` can enqueue a new event after the sink
    /// confirms its queue is empty.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        if let Some(sink) = self.streaming_sink.get() {
            sink.flush();
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

/// Shared in-memory sink for network audit events.
pub type SharedAuditLog = Arc<AuditLog>;

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
    Arc::new(AuditLog::new())
}

/// Drain all network audit events collected so far.
#[must_use]
pub fn drain_audit_events(audit_log: &SharedAuditLog) -> Vec<NetworkAuditEvent> {
    match audit_log.events.lock() {
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

    if audit_log.is_closed() {
        // Session is over — dropping post-finalize events keeps the file
        // consistent with the Merkle root recorded in session metadata.
        return;
    }

    // Stream to the durable sink first so events survive a process crash
    // and are not lost when the in-memory buffer hits MAX_AUDIT_EVENTS.
    if let Some(sink) = audit_log.streaming_sink.get() {
        sink.record(&event);
    }

    match audit_log.events.lock() {
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
            target: host.to_string(),
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
            target: host.to_string(),
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
            target: target.to_string(),
            port: None,
            method: Some(method.to_string()),
            path: Some(path.to_string()),
            status: Some(status),
            reason: None,
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

    #[derive(Default)]
    struct CountingSink {
        events: Mutex<Vec<NetworkAuditEvent>>,
    }

    impl NetworkAuditSink for CountingSink {
        fn record(&self, event: &NetworkAuditEvent) {
            self.events.lock().unwrap().push(event.clone());
        }
    }

    #[test]
    fn streaming_sink_receives_events_immediately() {
        let log = new_audit_log();
        let counter = Arc::new(CountingSink::default());
        let sink: Arc<dyn NetworkAuditSink> = counter.clone();
        assert!(log.set_streaming_sink(sink).is_ok());

        log_allowed(
            Some(&log),
            ProxyMode::Connect,
            &EventContext::default(),
            "api.openai.com",
            443,
            "CONNECT",
        );
        log_denied(
            Some(&log),
            ProxyMode::Connect,
            &EventContext::default(),
            "evil.example",
            443,
            "blocked",
        );

        let streamed = counter.events.lock().unwrap();
        assert_eq!(
            streamed.len(),
            2,
            "sink must receive each event as it occurs"
        );
        assert_eq!(streamed[0].target, "api.openai.com");
        assert_eq!(streamed[1].target, "evil.example");
    }

    #[test]
    fn streaming_does_not_skip_in_memory_buffer() {
        let log = new_audit_log();
        let counter = Arc::new(CountingSink::default());
        let sink: Arc<dyn NetworkAuditSink> = counter.clone();
        assert!(log.set_streaming_sink(sink).is_ok());

        log_allowed(
            Some(&log),
            ProxyMode::Connect,
            &EventContext::default(),
            "api.openai.com",
            443,
            "CONNECT",
        );

        let drained = drain_audit_events(&log);
        assert_eq!(
            drained.len(),
            1,
            "buffer must still hold the event for session metadata"
        );
        assert_eq!(counter.events.lock().unwrap().len(), 1);
    }

    #[test]
    fn streaming_active_reflects_sink_attachment() {
        let log = new_audit_log();
        assert!(!log.streaming_active());
        let sink: Arc<dyn NetworkAuditSink> = Arc::new(CountingSink::default());
        assert!(log.set_streaming_sink(sink).is_ok());
        assert!(log.streaming_active());
    }

    #[test]
    fn close_drops_subsequent_events() {
        let log = new_audit_log();
        let counter = Arc::new(CountingSink::default());
        let sink: Arc<dyn NetworkAuditSink> = counter.clone();
        assert!(log.set_streaming_sink(sink).is_ok());

        log_allowed(
            Some(&log),
            ProxyMode::Connect,
            &EventContext::default(),
            "before.example",
            443,
            "CONNECT",
        );
        log.close();
        log_allowed(
            Some(&log),
            ProxyMode::Connect,
            &EventContext::default(),
            "after.example",
            443,
            "CONNECT",
        );

        let drained = drain_audit_events(&log);
        assert_eq!(
            drained.len(),
            1,
            "post-close events must not enter the buffer"
        );
        assert_eq!(drained[0].target, "before.example");
        let streamed = counter.events.lock().unwrap();
        assert_eq!(
            streamed.len(),
            1,
            "post-close events must not reach the sink"
        );
    }

    #[test]
    fn second_set_streaming_sink_returns_err() {
        let log = new_audit_log();
        let first: Arc<dyn NetworkAuditSink> = Arc::new(CountingSink::default());
        assert!(log.set_streaming_sink(first).is_ok());
        let second: Arc<dyn NetworkAuditSink> = Arc::new(CountingSink::default());
        assert!(
            log.set_streaming_sink(second).is_err(),
            "OnceLock must reject second sink attachment"
        );
    }
}
