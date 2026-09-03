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
use tracing::{debug, warn};
use zeroize::Zeroizing;

/// Timeout for upstream TCP connect.
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Backstop wall-clock cap on an interactive network-approval prompt.
///
/// Each configured backend enforces its own (usually shorter) timeout — the
/// dialog force-kills, the webhook has an HTTP deadline. This only bounds a
/// backend that could otherwise block a blocking-pool thread indefinitely (e.g.
/// a `terminal` backend reading `/dev/tty`). On expiry the request is denied.
const NETWORK_APPROVAL_HARD_TIMEOUT: Duration = Duration::from_secs(600);

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
    let resolved: Vec<SocketAddr> = if check.result.is_allowed() {
        check.resolved_addrs
    } else {
        match maybe_approve_host(&host, port, &check.result, network_approval, filter).await? {
            Some(addrs) => addrs,
            None => {
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
    audit::log_allowed(
        audit_log,
        audit::ProxyMode::Connect,
        &audit::EventContext::default(),
        &host,
        port,
        "CONNECT",
    );

    // Bidirectional relay
    let result = tokio::io::copy_bidirectional(stream, &mut upstream).await;
    debug!("CONNECT tunnel closed for {}:{}: {:?}", host, port, result);

    Ok(())
}

/// Decide whether a not-allowed host may still be tunnelled, via the session
/// cache or an interactive approval prompt.
///
/// Returns `Ok(Some(addrs))` when the connection is authorized — `addrs` are
/// freshly resolved and re-vetted against the SSRF guard, safe to connect to
/// without re-resolving. Returns `Ok(None)` when the caller must send a 403:
/// the host is not approval-eligible, no backend is configured, the operator
/// (or a cached session decision) denied it, or the approval backend errored
/// (fail-secure).
///
/// Only a plain allowlist miss ([`FilterResult::DenyNotAllowed`]) is eligible.
/// A metadata / link-local / deny-list denial ([`FilterResult::DenyHost`] /
/// [`FilterResult::DenyLinkLocal`]) is authoritative and never prompts —
/// approval can never override an SSRF-guard denial.
async fn maybe_approve_host(
    host: &str,
    port: u16,
    result: &FilterResult,
    network_approval: Option<&NetworkApproval<'_>>,
    filter: &ProxyFilter,
) -> Result<Option<Vec<SocketAddr>>> {
    if !matches!(result, FilterResult::DenyNotAllowed { .. }) {
        return Ok(None);
    }
    let Some(approval) = network_approval else {
        return Ok(None);
    };

    let key = (host.to_string(), port);

    // Fast path: a session-scoped decision already exists — no re-prompt.
    if let Some(allow) = approval.cached_decision(&key) {
        return if allow {
            resolve_approved(filter, host, port).await
        } else {
            debug!("network approval: {host}:{port} denied by session cache");
            Ok(None)
        };
    }

    // `request_approval` is synchronous and may block (dialog subprocess,
    // webhook HTTP, terminal read) — it must never run on a Tokio worker
    // thread. Move it to the blocking pool and bound it with a backstop
    // deadline so a wedged backend cannot hang the connection forever.
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
    let backend = Arc::clone(approval.backend);
    let decision = match tokio::time::timeout(
        NETWORK_APPROVAL_HARD_TIMEOUT,
        tokio::task::spawn_blocking(move || backend.request_approval(&request)),
    )
    .await
    {
        Ok(Ok(Ok(decision))) => decision,
        Ok(Ok(Err(e))) => {
            warn!("network approval backend error for {host}:{port}: {e}");
            return Ok(None);
        }
        Ok(Err(e)) => {
            warn!("network approval task failed for {host}:{port}: {e}");
            return Ok(None);
        }
        Err(_) => {
            warn!("network approval timed out for {host}:{port}");
            return Ok(None);
        }
    };

    match decision {
        ApprovalDecision::Granted => resolve_approved(filter, host, port).await,
        ApprovalDecision::GrantedForSession => {
            approval.remember(key, true);
            resolve_approved(filter, host, port).await
        }
        ApprovalDecision::DeniedForSession => {
            approval.remember(key, false);
            Ok(None)
        }
        ApprovalDecision::Denied { .. } | ApprovalDecision::Timeout => Ok(None),
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
        warn!("network approval: {host}:{port} approved but blocked by SSRF guard");
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

    #[test]
    fn session_cache_round_trips_allow_and_deny() {
        let decisions = Mutex::new(HashMap::new());
        let backend: Arc<dyn nono::ApprovalBackend> = Arc::new(CountingBackend {
            decision: ApprovalDecision::Denied {
                reason: "unused".to_string(),
            },
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let approval = NetworkApproval {
            backend: &backend,
            session_decisions: &decisions,
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
        let approval = NetworkApproval {
            backend: &backend,
            session_decisions: &decisions,
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
        assert!(out.is_none());
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
        assert!(out.is_none());
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
        let approval = NetworkApproval {
            backend: &backend,
            session_decisions: &decisions,
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

        assert!(out.is_none(), "cached deny must block the connection");
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
        let approval = NetworkApproval {
            backend: &backend,
            session_decisions: &decisions,
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

        assert!(out.is_none());
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
        let approval = NetworkApproval {
            backend: &backend,
            session_decisions: &decisions,
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

        assert!(out.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            approval.cached_decision(&("blocked.example.com".to_string(), 443)),
            None,
            "a one-shot Denied must not populate the session cache"
        );
    }
}
