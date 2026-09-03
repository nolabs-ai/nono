//! HTTP CONNECT tunnel handler (Mode 1 — Host Filtering).
//!
//! Handles `CONNECT host:port HTTP/1.1` requests by:
//! 1. Validating the session token
//! 2. Checking the host against the filter (cloud metadata deny list, then allowlist)
//! 3. Establishing a TCP connection to the upstream
//! 4. Returning `200 Connection Established`
//! 5. Relaying bytes bidirectionally (transparent TLS tunnel)
//!
//! The proxy never terminates TLS — it just passes encrypted bytes through.
//! Streaming (SSE, MCP Streamable HTTP, A2A) works transparently.

use crate::audit;
use crate::error::{ProxyError, Result};
use crate::filter::ProxyFilter;
use crate::token;
use nono::net_filter::FilterResult;
use nono::supervisor::{ApprovalDecision, ApprovalRequest};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tracing::{debug, warn};
use zeroize::Zeroizing;

/// Timeout for upstream TCP connect.
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Grace added on top of a backend's own configured timeout when sizing the
/// backstop deadline, so the backstop never preempts a legitimately-configured
/// (possibly long) prompt timeout — the backend's own timeout fires first,
/// yielding a clean `Timeout` decision.
const NETWORK_APPROVAL_BACKSTOP_GRACE: Duration = Duration::from_secs(30);

/// Backstop wall-clock cap applied only to a backend that reports no timeout of
/// its own ([`nono::ApprovalBackend::approval_timeout`] returns `None`, e.g. a
/// `terminal` backend blocking on `/dev/tty`). Without this, such a backend
/// could pin a blocking-pool thread indefinitely. On expiry the request is
/// denied. A backend that reports a timeout is instead bounded by that timeout
/// plus [`NETWORK_APPROVAL_BACKSTOP_GRACE`].
const NETWORK_APPROVAL_UNBOUNDED_BACKSTOP: Duration = Duration::from_secs(600);

/// Map coordinating in-flight approval prompts, keyed by `(host, port)`, so
/// concurrent first-touch connections to the same host share a single prompt.
pub type InFlightMap = Mutex<HashMap<(String, u16), Arc<InFlight>>>;

/// Shared slot coordinating concurrent first-touch approval attempts for one
/// `(host, port)`.
///
/// The first connection to a not-yet-decided host (the leader) fires the
/// prompt; concurrent connections (followers) await the leader's decision
/// instead of firing a duplicate prompt. This is a UX de-duplication only —
/// each connection still independently re-resolves and re-vets the host against
/// the SSRF guard before connecting, so coalescing the *decision* never widens
/// the security check.
pub struct InFlight {
    /// `None` until the leader decides, then `Some(allow)`.
    tx: watch::Sender<Option<bool>>,
}

impl InFlight {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            tx: watch::channel(None).0,
        })
    }

    /// Publish the leader's decision to any waiting followers.
    fn resolve(&self, allow: bool) {
        // Ignored error means no followers are listening — nothing to do.
        let _ = self.tx.send(Some(allow));
    }

    /// Await the leader's decision. Returns the leader's `allow` boolean, or
    /// `false` (fail secure) if the leader vanished without deciding.
    async fn await_decision(&self) -> bool {
        let mut rx = self.tx.subscribe();
        loop {
            if let Some(allow) = *rx.borrow_and_update() {
                return allow;
            }
            if rx.changed().await.is_err() {
                // All senders dropped without a decision (leader task gone):
                // deny rather than hang or fail open.
                return false;
            }
        }
    }
}

/// Interactive network-approval context threaded into the CONNECT handler.
///
/// Present only when the profile's `network:` section configures an approval
/// backend. When absent, a host that is not on the allowlist is denied exactly
/// as before (an immediate 403).
pub struct NetworkApproval<'a> {
    /// Backend that answers prompts for hosts not on the allowlist.
    pub backend: &'a Arc<dyn nono::ApprovalBackend>,
    /// Session-scoped decisions keyed by `(host, port)`: `true` = allow for the
    /// session, `false` = deny for the session. Shared across all connections
    /// handled by one proxy (one session), so "Always allow"/"Always deny"
    /// suppress re-prompting for the rest of the session.
    pub session_decisions: &'a Mutex<HashMap<(String, u16), bool>>,
    /// In-flight prompt coordination so concurrent first-touch connections to
    /// the same host share one prompt instead of stacking duplicate dialogs.
    pub in_flight: &'a InFlightMap,
    /// Session identifier recorded in the approval request.
    pub session_id: &'a str,
}

impl NetworkApproval<'_> {
    /// Look up a previously recorded session decision. Poison is recovered
    /// (a panicked holder cannot leave the cache unusable / fail-open).
    fn cached_decision(&self, key: &(String, u16)) -> Option<bool> {
        self.session_decisions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .copied()
    }

    /// Record a session-scoped decision for `(host, port)`.
    fn remember(&self, key: (String, u16), allow: bool) {
        self.session_decisions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key, allow);
    }
}

/// How the CONNECT handler treats `Proxy-Authorization` on the transparent
/// tunnel path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectAuthMode {
    /// Auth disabled (`nono proxy --no-auth`): skip the check entirely.
    Disabled,
    /// Sandboxed `run`/`shell`/`wrap`: validate but treat failure as non-fatal.
    /// Node.js undici doesn't echo URL-userinfo credentials as
    /// `Proxy-Authorization` on CONNECT, and the OS sandbox — not the token —
    /// is the trust boundary, so an unauthenticated tunnel still proceeds
    /// (host filtering continues to apply).
    Lenient,
    /// Standalone `nono proxy` with auth on: a failed check is fatal. Respond
    /// `407` and stop before any DNS/filter/upstream handling, because the
    /// session token is the auth boundary for the external tools pointed at it.
    Strict,
}

/// Handle an HTTP CONNECT request.
///
/// `first_line` is the already-read CONNECT line (e.g., "CONNECT api.openai.com:443 HTTP/1.1").
/// `stream` is the raw TCP stream from the client.
#[allow(clippy::too_many_arguments)]
pub async fn handle_connect(
    first_line: &str,
    stream: &mut TcpStream,
    filter: &ProxyFilter,
    session_token: &Zeroizing<String>,
    remaining_header: &[u8],
    auth_mode: ConnectAuthMode,
    audit_log: Option<&audit::SharedAuditLog>,
    network_approval: Option<&NetworkApproval<'_>>,
) -> Result<()> {
    // Parse host:port from CONNECT line
    let (host, port) = parse_connect_target(first_line)?;
    debug!("CONNECT request to {}:{}", host, port);

    // Validate session token from Proxy-Authorization header. See
    // [`ConnectAuthMode`] for why each mode behaves the way it does.
    if auth_mode != ConnectAuthMode::Disabled
        && let Err(e) = validate_proxy_auth(remaining_header, session_token)
    {
        if auth_mode == ConnectAuthMode::Strict {
            debug!("CONNECT auth failed: {}", e);
            stream
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=\"nono\"\r\n\
                      Content-Length: 0\r\n\r\n",
                )
                .await?;
            return Ok(());
        }
        debug!("CONNECT auth skipped: {}", e);
    }

    // Check host against filter (DNS resolution happens here)
    let check = filter.check_host(&host, port).await?;

    // Resolve the set of vetted upstream addresses to connect to. An allowed
    // host uses the addresses the filter already resolved. A host that is not
    // on the allowlist may still proceed if the operator interactively approves
    // it (or approved it earlier this session) — but only a plain allowlist
    // miss is eligible; metadata / link-local / deny-list denials are hard and
    // never reach a prompt. See `maybe_approve_host`.
    //
    // `approved_backend` carries the approval backend name when the host was
    // authorized by an operator decision (interactive or session-cached), so
    // the success audit below records `ApproveGranted` rather than a plain
    // allowlist `Allow` — keeping the audit trail able to distinguish a runtime
    // approval from a static allowlist hit.
    let mut approved_backend: Option<String> = None;
    let resolved: Vec<SocketAddr> = if check.result.is_allowed() {
        check.resolved_addrs
    } else {
        match maybe_approve_host(&host, port, &check.result, network_approval, filter).await? {
            ApprovalOutcome::Approved { addrs, backend } => {
                approved_backend = Some(backend);
                addrs
            }
            ApprovalOutcome::Denied { backend, reason } => {
                // The operator (or a cached session decision / backend) refused
                // this host, or the approved host was blocked by the SSRF guard.
                // Record it as an approval denial, distinct from a static deny.
                let reason = reason.unwrap_or_else(|| check.result.reason());
                audit::log_connect_approval(
                    audit_log,
                    &audit::EventContext {
                        denial_category: Some(nono::undo::NetworkAuditDenialCategory::HostDenied),
                        approval_backend: Some(&backend),
                        ..audit::EventContext::default()
                    },
                    &host,
                    port,
                    nono::undo::NetworkAuditDecision::ApproveDenied,
                    Some(&reason),
                );
                send_response(stream, 403, &format!("Forbidden: {}", reason)).await?;
                return Err(ProxyError::HostDenied { host, reason });
            }
            ApprovalOutcome::NotApplicable => {
                // Not approval-eligible (hard SSRF/deny-list denial) or no
                // backend configured: the historical static-deny audit path.
                let reason = check.result.reason();
                audit::log_denied(
                    audit_log,
                    audit::ProxyMode::Connect,
                    &audit::EventContext {
                        denial_category: Some(nono::undo::NetworkAuditDenialCategory::HostDenied),
                        ..audit::EventContext::default()
                    },
                    &host,
                    port,
                    &reason,
                );
                send_response(stream, 403, &format!("Forbidden: {}", reason)).await?;
                return Err(ProxyError::HostDenied { host, reason });
            }
        }
    };

    // Connect to the resolved IP directly — NOT re-resolving the hostname.
    // This eliminates the DNS rebinding TOCTOU: the IPs were already checked
    // against the link-local range (in check_host(), or in resolve_approved_host
    // for an interactively approved host).
    let resolved = &resolved;
    if resolved.is_empty() {
        let reason = "DNS resolution returned no addresses".to_string();
        // Discard the write result so a client-side hangup during the 502
        // doesn't shadow the more descriptive UpstreamConnect error below.
        // The audit entry is recorded inside write_upstream_failure before
        // the response is sent, so audit coverage is preserved regardless.
        let _ = write_upstream_failure(stream, audit_log, &host, port, &reason).await;
        return Err(ProxyError::UpstreamConnect {
            host: host.clone(),
            reason,
        });
    }

    let mut upstream = match connect_to_resolved(resolved, &host).await {
        Ok(stream) => stream,
        Err(err) => {
            // Mirror the empty-DNS branch above: surface the upstream
            // failure with a 502 and an audit entry instead of dropping
            // the client socket silently. See issue #998.
            let reason = match &err {
                ProxyError::UpstreamConnect { reason, .. } => reason.clone(),
                other => other.to_string(),
            };
            // Discard the write result for the same reason as the empty-DNS
            // branch above: preserve the original UpstreamConnect error.
            let _ = write_upstream_failure(stream, audit_log, &host, port, &reason).await;
            return Err(err);
        }
    };

    // Send 200 Connection Established
    send_response(stream, 200, "Connection Established").await?;
    if let Some(backend) = approved_backend.as_deref() {
        // Host was authorized by a runtime approval decision, not the static
        // allowlist — record it as such, with the deciding backend.
        audit::log_connect_approval(
            audit_log,
            &audit::EventContext {
                approval_backend: Some(backend),
                ..audit::EventContext::default()
            },
            &host,
            port,
            nono::undo::NetworkAuditDecision::ApproveGranted,
            None,
        );
    } else {
        audit::log_allowed(
            audit_log,
            audit::ProxyMode::Connect,
            &audit::EventContext::default(),
            &host,
            port,
            "CONNECT",
        );
    }

    // Bidirectional relay
    let result = tokio::io::copy_bidirectional(stream, &mut upstream).await;
    debug!("CONNECT tunnel closed for {}:{}: {:?}", host, port, result);

    Ok(())
}

/// The result of evaluating a not-allowlisted host for interactive approval.
enum ApprovalOutcome {
    /// Not approval-eligible (a hard SSRF/deny-list denial), or no approval
    /// backend is configured. The caller uses the historical static-deny path.
    NotApplicable,
    /// Authorized by an operator decision (interactive, or a cached session
    /// decision). `addrs` are freshly resolved and re-vetted against the SSRF
    /// guard, safe to connect to without re-resolving. `backend` is the
    /// deciding backend's name, for the audit trail.
    Approved {
        addrs: Vec<SocketAddr>,
        backend: String,
    },
    /// Refused by the operator (interactive or cached), by the backend, on
    /// timeout/error (fail secure), or because the approved host resolved to an
    /// address the SSRF guard blocks. `backend` is the deciding backend's name;
    /// `reason` overrides the default 403 reason when set (e.g. SSRF block).
    Denied {
        backend: String,
        reason: Option<String>,
    },
}

/// Decide whether a not-allowed host may still be tunnelled, via the session
/// cache or an interactive approval prompt.
///
/// Only a plain allowlist miss ([`FilterResult::DenyNotAllowed`]) is eligible.
/// A metadata / link-local / deny-list denial ([`FilterResult::DenyHost`] /
/// [`FilterResult::DenyLinkLocal`]) is authoritative and never prompts —
/// approval can never override an SSRF-guard denial.
///
/// Concurrent first-touch connections to the same host coalesce onto a single
/// prompt: the first (leader) prompts; the rest (followers) await its decision.
/// Every authorized connection independently re-resolves and re-vets the host
/// (see [`resolve_approved`]), so coalescing the decision never widens the SSRF
/// check.
async fn maybe_approve_host(
    host: &str,
    port: u16,
    result: &FilterResult,
    network_approval: Option<&NetworkApproval<'_>>,
    filter: &ProxyFilter,
) -> Result<ApprovalOutcome> {
    if !matches!(result, FilterResult::DenyNotAllowed { .. }) {
        return Ok(ApprovalOutcome::NotApplicable);
    }
    let Some(approval) = network_approval else {
        return Ok(ApprovalOutcome::NotApplicable);
    };

    let backend_name = approval.backend.backend_name().to_string();
    let key = (host.to_string(), port);

    // Fast path: a session-scoped decision already exists — no re-prompt.
    if let Some(allow) = approval.cached_decision(&key) {
        if !allow {
            debug!("network approval: {host}:{port} denied by session cache");
        }
        return outcome_from_allow(allow, backend_name, filter, host, port).await;
    }

    // Coalesce concurrent first-touch prompts: become the leader that prompts,
    // or a follower that awaits the leader's decision.
    let leader = {
        let mut map = approval.in_flight.lock().unwrap_or_else(|e| e.into_inner());
        match map.get(&key) {
            Some(existing) => Err(Arc::clone(existing)),
            None => {
                let shared = InFlight::new();
                map.insert(key.clone(), Arc::clone(&shared));
                Ok(shared)
            }
        }
    };

    let allow = match leader {
        Err(follower) => follower.await_decision().await,
        Ok(shared) => {
            let allow = run_prompt(approval, &backend_name, host, port, &key).await;
            // Publish to any waiting followers, then release the slot so a
            // later burst re-prompts. Both happen unconditionally so a follower
            // can never be left waiting on a vanished leader.
            shared.resolve(allow);
            approval
                .in_flight
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&key);
            allow
        }
    };

    outcome_from_allow(allow, backend_name, filter, host, port).await
}

/// Run the interactive prompt as the leader and return the authorization
/// boolean, populating the session cache for session-scoped decisions.
///
/// `request_approval` is synchronous and may block (dialog subprocess, webhook
/// HTTP, terminal read), so it never runs on a Tokio worker thread — it is
/// moved to the blocking pool and bounded by a backstop deadline. The backstop
/// is derived from the backend's own configured timeout so it never preempts a
/// legitimately-longer prompt; a backend that reports no timeout is capped by
/// [`NETWORK_APPROVAL_UNBOUNDED_BACKSTOP`]. Any error, task failure, or backstop
/// expiry fails secure (denies).
async fn run_prompt(
    approval: &NetworkApproval<'_>,
    backend_name: &str,
    host: &str,
    port: u16,
    key: &(String, u16),
) -> bool {
    let request = ApprovalRequest::Network {
        request_id: format!("net-{host}:{port}"),
        host: host.to_string(),
        port,
        protocol: "tcp".to_string(),
        resolved_ips: Vec::new(),
        reason: None,
        child_pid: 0,
        session_id: approval.session_id.to_string(),
    };
    let backstop = approval
        .backend
        .approval_timeout()
        .map(|t| t.saturating_add(NETWORK_APPROVAL_BACKSTOP_GRACE))
        .unwrap_or(NETWORK_APPROVAL_UNBOUNDED_BACKSTOP);

    let backend = Arc::clone(approval.backend);
    let decision = match tokio::time::timeout(
        backstop,
        tokio::task::spawn_blocking(move || backend.request_approval(&request)),
    )
    .await
    {
        Ok(Ok(Ok(decision))) => decision,
        Ok(Ok(Err(e))) => {
            warn!("network approval backend '{backend_name}' error for {host}:{port}: {e}");
            return false;
        }
        Ok(Err(e)) => {
            warn!("network approval task failed for {host}:{port}: {e}");
            return false;
        }
        Err(_) => {
            warn!("network approval timed out for {host}:{port}");
            return false;
        }
    };

    match decision {
        ApprovalDecision::Granted => true,
        ApprovalDecision::GrantedForSession => {
            approval.remember(key.clone(), true);
            true
        }
        ApprovalDecision::DeniedForSession => {
            approval.remember(key.clone(), false);
            false
        }
        ApprovalDecision::Denied { .. } | ApprovalDecision::Timeout => false,
    }
}

/// Turn an authorization boolean into an [`ApprovalOutcome`], re-resolving and
/// re-vetting the host against the SSRF guard on the allow path.
async fn outcome_from_allow(
    allow: bool,
    backend: String,
    filter: &ProxyFilter,
    host: &str,
    port: u16,
) -> Result<ApprovalOutcome> {
    if !allow {
        return Ok(ApprovalOutcome::Denied {
            backend,
            reason: None,
        });
    }
    match resolve_approved(filter, host, port).await? {
        Some(addrs) => Ok(ApprovalOutcome::Approved { addrs, backend }),
        None => {
            warn!("network approval: {host}:{port} approved but blocked by SSRF guard");
            Ok(ApprovalOutcome::Denied {
                backend,
                reason: Some(
                    "approved host resolved to a blocked address (cloud-metadata/link-local guard)"
                        .to_string(),
                ),
            })
        }
    }
}

/// Resolve an approved host and re-vet the resolved IPs against the SSRF guard.
///
/// Returns `Ok(Some(addrs))` when the addresses pass the guard (possibly empty,
/// which the caller surfaces as a 502 upstream failure), or `Ok(None)` when a
/// resolved IP is in a denied metadata / link-local range — approval never
/// overrides that guard.
async fn resolve_approved(
    filter: &ProxyFilter,
    host: &str,
    port: u16,
) -> Result<Option<Vec<SocketAddr>>> {
    let check = filter.resolve_approved_host(host, port).await?;
    if check.result.is_allowed() {
        Ok(Some(check.resolved_addrs))
    } else {
        Ok(None)
    }
}

/// Connect to one of the pre-resolved socket addresses with timeout.
///
/// Tries each address in order until one succeeds. This connects to the
/// IP directly (not re-resolving the hostname), preventing DNS rebinding.
async fn connect_to_resolved(addrs: &[SocketAddr], host: &str) -> Result<TcpStream> {
    let mut last_err = None;
    for addr in addrs {
        match tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => {
                debug!("Connect to {} failed: {}", addr, e);
                last_err = Some(e.to_string());
            }
            Err(_) => {
                debug!("Connect to {} timed out", addr);
                last_err = Some("connection timed out".to_string());
            }
        }
    }
    Err(ProxyError::UpstreamConnect {
        host: host.to_string(),
        reason: last_err.unwrap_or_else(|| "no addresses to connect to".to_string()),
    })
}

/// Parse the target host and port from a CONNECT request line.
///
/// Expected format: "CONNECT host:port HTTP/1.1"
fn parse_connect_target(line: &str) -> Result<(String, u16)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 || parts[0] != "CONNECT" {
        return Err(ProxyError::HttpParse(format!(
            "malformed CONNECT line: {}",
            line
        )));
    }

    let authority = parts[1];
    if let Some((host, port_str)) = authority.rsplit_once(':') {
        let port = port_str.parse::<u16>().map_err(|_| {
            ProxyError::HttpParse(format!("invalid port in CONNECT: {}", authority))
        })?;
        Ok((host.to_string(), port))
    } else {
        // No port specified, default to 443 for CONNECT
        Ok((authority.to_string(), 443))
    }
}

/// Validate the Proxy-Authorization header against the session token.
///
/// Delegates to `token::validate_proxy_auth` which accepts both Bearer
/// and Basic auth formats.
fn validate_proxy_auth(header_bytes: &[u8], session_token: &Zeroizing<String>) -> Result<()> {
    token::validate_proxy_auth(header_bytes, session_token)
}

/// Send an HTTP response line to the client.
///
/// The `reason` phrase is sanitised by replacing `\r` and `\n` with spaces
/// before being inlined into the status line. This is defence in depth
/// against HTTP response splitting: today's call sites all produce safe
/// strings, but `send_response` is on a protocol-formatting boundary and
/// guarding it makes future call sites safe by construction.
async fn send_response<S: AsyncWrite + Unpin>(
    stream: &mut S,
    status: u16,
    reason: &str,
) -> Result<()> {
    let sanitised_reason = reason.replace(['\r', '\n'], " ");
    let response = format!("HTTP/1.1 {} {}\r\n\r\n", status, sanitised_reason);
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

/// Surface an upstream-connect failure to both the client and the audit log.
///
/// Used by the two failure branches in [`handle_connect`] that cannot
/// establish the upstream TCP leg: empty DNS resolution, and a refused or
/// timed-out connect to a resolved address. Both shapes share the same
/// observable contract — `502 Bad Gateway` to the client, `log_denied` with
/// [`NetworkAuditDenialCategory::UpstreamConnectFailed`] in the audit log.
async fn write_upstream_failure<S: AsyncWrite + Unpin>(
    stream: &mut S,
    audit_log: Option<&audit::SharedAuditLog>,
    host: &str,
    port: u16,
    reason: &str,
) -> Result<()> {
    audit::log_denied(
        audit_log,
        audit::ProxyMode::Connect,
        &audit::EventContext {
            denial_category: Some(nono::undo::NetworkAuditDenialCategory::UpstreamConnectFailed),
            ..audit::EventContext::default()
        },
        host,
        port,
        reason,
    );
    send_response(stream, 502, &format!("Upstream connect failed: {}", reason)).await
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_connect_with_port() {
        let (host, port) = parse_connect_target("CONNECT api.openai.com:443 HTTP/1.1").unwrap();
        assert_eq!(host, "api.openai.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_connect_without_port() {
        let (host, port) = parse_connect_target("CONNECT example.com HTTP/1.1").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_connect_custom_port() {
        let (host, port) = parse_connect_target("CONNECT internal:8443 HTTP/1.1").unwrap();
        assert_eq!(host, "internal");
        assert_eq!(port, 8443);
    }

    #[test]
    fn test_parse_connect_malformed() {
        assert!(parse_connect_target("GET /").is_err());
        assert!(parse_connect_target("").is_err());
    }

    #[test]
    fn test_validate_proxy_auth_valid() {
        let token = Zeroizing::new("abc123".to_string());
        let header = b"Proxy-Authorization: Bearer abc123\r\n\r\n";
        assert!(validate_proxy_auth(header, &token).is_ok());
    }

    #[test]
    fn test_validate_proxy_auth_invalid() {
        let token = Zeroizing::new("abc123".to_string());
        let header = b"Proxy-Authorization: Bearer wrong\r\n\r\n";
        assert!(validate_proxy_auth(header, &token).is_err());
    }

    #[test]
    fn test_validate_proxy_auth_missing() {
        let token = Zeroizing::new("abc123".to_string());
        let header = b"Host: example.com\r\n\r\n";
        assert!(validate_proxy_auth(header, &token).is_err());
    }

    use nono::undo::{NetworkAuditDecision, NetworkAuditDenialCategory, NetworkAuditMode};
    use tokio::io::{AsyncReadExt, duplex};

    /// Drain the reader end of a duplex pair until EOF and return the bytes
    /// as a String.
    async fn read_to_string<R: tokio::io::AsyncRead + Unpin>(mut reader: R) -> String {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[tokio::test]
    async fn write_upstream_failure_sends_502_status_line() {
        let (server, client) = duplex(1024);
        let mut server = server;

        write_upstream_failure(&mut server, None, "example.com", 443, "connection refused")
            .await
            .unwrap();
        drop(server);

        let response = read_to_string(client).await;
        assert!(
            response.starts_with("HTTP/1.1 502 "),
            "expected 502 status line, got: {:?}",
            response
        );
        assert!(
            response.contains("Upstream connect failed: connection refused"),
            "expected reason on status line, got: {:?}",
            response
        );
    }

    #[tokio::test]
    async fn write_upstream_failure_records_audit_entry() {
        let (mut server, _client) = duplex(1024);
        let log = audit::new_audit_log();

        write_upstream_failure(
            &mut server,
            Some(&log),
            "example.com",
            443,
            "connection refused",
        )
        .await
        .unwrap();

        let events = audit::drain_audit_events(&log);
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.mode, NetworkAuditMode::Connect);
        assert_eq!(event.decision, NetworkAuditDecision::Deny);
        assert_eq!(
            event.denial_category,
            Some(NetworkAuditDenialCategory::UpstreamConnectFailed)
        );
        assert_eq!(event.target, "example.com");
        assert_eq!(event.port, Some(443));
        assert_eq!(event.reason.as_deref(), Some("connection refused"));
    }

    #[tokio::test]
    async fn write_upstream_failure_without_audit_log_still_writes_response() {
        let (mut server, client) = duplex(1024);

        write_upstream_failure(&mut server, None, "example.com", 443, "connection refused")
            .await
            .unwrap();
        drop(server);

        let response = read_to_string(client).await;
        assert!(response.starts_with("HTTP/1.1 502 "));
    }

    #[tokio::test]
    async fn write_upstream_failure_sanitises_crlf_in_reason() {
        let (mut server, client) = duplex(1024);

        write_upstream_failure(
            &mut server,
            None,
            "example.com",
            443,
            "connection refused\r\nX-Injected: yes",
        )
        .await
        .unwrap();
        drop(server);

        let response = read_to_string(client).await;

        // The status line must contain neither raw CR nor LF until the
        // single CRLFCRLF terminator at the end. Response splitting via a
        // crafted reason string must not be possible.
        let terminator = "\r\n\r\n";
        let body_end = response.find(terminator).expect("response must terminate");
        let status_line = &response[..body_end];
        assert!(
            !status_line.contains('\r'),
            "status line must not contain CR, got: {:?}",
            status_line
        );
        assert!(
            !status_line.contains('\n'),
            "status line must not contain LF, got: {:?}",
            status_line
        );

        // The injected header name should not appear as a real header
        // (i.e., must not be split out of the reason phrase).
        assert!(
            !response.contains("\r\nX-Injected:"),
            "injected header must not be split into a real header: {:?}",
            response
        );
    }

    #[tokio::test]
    async fn write_upstream_failure_round_trips_timeout_reason() {
        let (mut server, client) = duplex(1024);
        let log = audit::new_audit_log();

        write_upstream_failure(
            &mut server,
            Some(&log),
            "slow.example.com",
            443,
            "connection timed out",
        )
        .await
        .unwrap();
        drop(server);

        let response = read_to_string(client).await;
        assert!(response.contains("connection timed out"));

        let events = audit::drain_audit_events(&log);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].reason.as_deref(), Some("connection timed out"));
    }

    // --- Network approval (session-scoped host decisions) ---

    use std::sync::atomic::{AtomicUsize, Ordering};

    /// An approval backend that returns a fixed decision and counts how many
    /// times it was consulted, so tests can assert the session cache suppresses
    /// re-prompting.
    struct CountingBackend {
        decision: ApprovalDecision,
        calls: Arc<AtomicUsize>,
    }

    impl nono::ApprovalBackend for CountingBackend {
        fn request_approval(&self, _request: &ApprovalRequest) -> nono::Result<ApprovalDecision> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.decision.clone())
        }

        fn backend_name(&self) -> &str {
            "counting"
        }
    }

    fn deny_not_allowed(host: &str) -> FilterResult {
        FilterResult::DenyNotAllowed {
            host: host.to_string(),
        }
    }

    fn empty_in_flight() -> InFlightMap {
        Mutex::new(HashMap::new())
    }

    impl ApprovalOutcome {
        fn is_denied(&self) -> bool {
            matches!(self, ApprovalOutcome::Denied { .. })
        }

        fn is_not_applicable(&self) -> bool {
            matches!(self, ApprovalOutcome::NotApplicable)
        }
    }

    #[test]
    fn session_cache_round_trips_allow_and_deny() {
        let decisions = Mutex::new(HashMap::new());
        let backend: Arc<dyn nono::ApprovalBackend> = Arc::new(CountingBackend {
            decision: ApprovalDecision::Denied {
                reason: "unused".to_string(),
            },
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let in_flight = empty_in_flight();
        let approval = NetworkApproval {
            backend: &backend,
            session_decisions: &decisions,
            in_flight: &in_flight,
            session_id: "test",
        };

        assert_eq!(approval.cached_decision(&("a.com".to_string(), 443)), None);
        approval.remember(("a.com".to_string(), 443), true);
        approval.remember(("b.com".to_string(), 443), false);
        assert_eq!(
            approval.cached_decision(&("a.com".to_string(), 443)),
            Some(true)
        );
        assert_eq!(
            approval.cached_decision(&("b.com".to_string(), 443)),
            Some(false)
        );
        // Port is part of the key.
        assert_eq!(approval.cached_decision(&("a.com".to_string(), 8443)), None);
    }

    #[tokio::test]
    async fn maybe_approve_skips_backend_when_host_already_allowed() {
        let calls = Arc::new(AtomicUsize::new(0));
        let decisions = Mutex::new(HashMap::new());
        let backend: Arc<dyn nono::ApprovalBackend> = Arc::new(CountingBackend {
            decision: ApprovalDecision::Granted,
            calls: Arc::clone(&calls),
        });
        let in_flight = empty_in_flight();
        let approval = NetworkApproval {
            backend: &backend,
            session_decisions: &decisions,
            in_flight: &in_flight,
            session_id: "test",
        };
        let filter = ProxyFilter::allow_all();

        // A non-`DenyNotAllowed` result is never approval-eligible.
        let out = maybe_approve_host(
            "api.example.com",
            443,
            &FilterResult::Allow,
            Some(&approval),
            &filter,
        )
        .await
        .unwrap();
        assert!(out.is_not_applicable());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn maybe_approve_without_backend_is_a_no_op() {
        let filter = ProxyFilter::new(&[]);
        let out = maybe_approve_host(
            "blocked.example.com",
            443,
            &deny_not_allowed("blocked.example.com"),
            None,
            &filter,
        )
        .await
        .unwrap();
        assert!(out.is_not_applicable());
    }

    #[tokio::test]
    async fn maybe_approve_honours_cached_session_deny_without_prompting() {
        let calls = Arc::new(AtomicUsize::new(0));
        let decisions = Mutex::new(HashMap::new());
        decisions
            .lock()
            .unwrap()
            .insert(("blocked.example.com".to_string(), 443), false);
        let backend: Arc<dyn nono::ApprovalBackend> = Arc::new(CountingBackend {
            decision: ApprovalDecision::Granted,
            calls: Arc::clone(&calls),
        });
        let in_flight = empty_in_flight();
        let approval = NetworkApproval {
            backend: &backend,
            session_decisions: &decisions,
            in_flight: &in_flight,
            session_id: "test",
        };
        let filter = ProxyFilter::new(&[]);

        let out = maybe_approve_host(
            "blocked.example.com",
            443,
            &deny_not_allowed("blocked.example.com"),
            Some(&approval),
            &filter,
        )
        .await
        .unwrap();

        assert!(out.is_denied(), "cached deny must block the connection");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "cached deny must not consult the backend"
        );
    }

    #[tokio::test]
    async fn maybe_approve_caches_session_denial_from_backend() {
        let calls = Arc::new(AtomicUsize::new(0));
        let decisions = Mutex::new(HashMap::new());
        let backend: Arc<dyn nono::ApprovalBackend> = Arc::new(CountingBackend {
            decision: ApprovalDecision::DeniedForSession,
            calls: Arc::clone(&calls),
        });
        let in_flight = empty_in_flight();
        let approval = NetworkApproval {
            backend: &backend,
            session_decisions: &decisions,
            in_flight: &in_flight,
            session_id: "test",
        };
        let filter = ProxyFilter::new(&[]);

        let out = maybe_approve_host(
            "blocked.example.com",
            443,
            &deny_not_allowed("blocked.example.com"),
            Some(&approval),
            &filter,
        )
        .await
        .unwrap();

        assert!(out.is_denied());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            approval.cached_decision(&("blocked.example.com".to_string(), 443)),
            Some(false),
            "DeniedForSession must be remembered for the session"
        );
    }

    #[tokio::test]
    async fn maybe_approve_does_not_cache_one_shot_denial() {
        let calls = Arc::new(AtomicUsize::new(0));
        let decisions = Mutex::new(HashMap::new());
        let backend: Arc<dyn nono::ApprovalBackend> = Arc::new(CountingBackend {
            decision: ApprovalDecision::Denied {
                reason: "no".to_string(),
            },
            calls: Arc::clone(&calls),
        });
        let in_flight = empty_in_flight();
        let approval = NetworkApproval {
            backend: &backend,
            session_decisions: &decisions,
            in_flight: &in_flight,
            session_id: "test",
        };
        let filter = ProxyFilter::new(&[]);

        let out = maybe_approve_host(
            "blocked.example.com",
            443,
            &deny_not_allowed("blocked.example.com"),
            Some(&approval),
            &filter,
        )
        .await
        .unwrap();

        assert!(out.is_denied());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            approval.cached_decision(&("blocked.example.com".to_string(), 443)),
            None,
            "a one-shot Denied must not populate the session cache"
        );
    }

    /// An approval backend that blocks briefly before answering, so a burst of
    /// concurrent first-touch connections is guaranteed to overlap the leader's
    /// prompt and exercise the follower path.
    struct SlowBackend {
        decision: ApprovalDecision,
        calls: Arc<AtomicUsize>,
    }

    impl nono::ApprovalBackend for SlowBackend {
        fn request_approval(&self, _request: &ApprovalRequest) -> nono::Result<ApprovalDecision> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(50));
            Ok(self.decision.clone())
        }

        fn backend_name(&self) -> &str {
            "slow"
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_first_touch_prompts_coalesce_onto_one_backend_call() {
        let calls = Arc::new(AtomicUsize::new(0));
        let decisions = Mutex::new(HashMap::new());
        let backend: Arc<dyn nono::ApprovalBackend> = Arc::new(SlowBackend {
            // A session denial avoids any DNS re-resolution on the allow path,
            // keeping the test hermetic while still exercising coalescing.
            decision: ApprovalDecision::DeniedForSession,
            calls: Arc::clone(&calls),
        });
        let in_flight = empty_in_flight();
        let approval = NetworkApproval {
            backend: &backend,
            session_decisions: &decisions,
            in_flight: &in_flight,
            session_id: "test",
        };
        let filter = ProxyFilter::new(&[]);

        // Fire several concurrent first-touch attempts for the same host. They
        // are polled on one task by `join!`, so the first to reach the in-flight
        // lock leads and the rest follow its single prompt.
        let result = deny_not_allowed("blocked.example.com");
        let attempt = || {
            maybe_approve_host(
                "blocked.example.com",
                443,
                &result,
                Some(&approval),
                &filter,
            )
        };
        let outcomes = tokio::join!(
            attempt(),
            attempt(),
            attempt(),
            attempt(),
            attempt(),
            attempt(),
            attempt(),
            attempt(),
        );

        for outcome in [
            outcomes.0, outcomes.1, outcomes.2, outcomes.3, outcomes.4, outcomes.5, outcomes.6,
            outcomes.7,
        ] {
            assert!(outcome.unwrap().is_denied());
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "concurrent first-touch prompts must coalesce onto a single backend call"
        );
    }
}
