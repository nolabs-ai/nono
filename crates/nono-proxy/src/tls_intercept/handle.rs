//! CONNECT-intercept entry point.
//!
//! Terminates TLS from the agent, reads the inner HTTP/1.1 request, and
//! dispatches it via [`crate::forward::forward_request`].
//!
//! Route selection for each inner request:
//!   - **1 match** — inject that route's managed credential.
//!   - **0 matches** — forward without credentials (passthrough).
//!   - **2+ matches** — reject as ambiguous (403).
//!
//! Auth is validated on the outer CONNECT `Proxy-Authorization` only;
//! inner requests are not required to carry a token.

use crate::audit;
use crate::capture::CredentialCaptureBackend;
use crate::config::EndpointPolicyOutcome;
use crate::credential::CredentialStore;
use crate::error::{ProxyError, Result};
use crate::filter::ProxyFilter;
use crate::forward::{self, AuditCtx, UpstreamScheme, UpstreamSpec, UpstreamStrategy};
use crate::oauth_capture::OAuthCaptureStore;
use crate::reverse;
use crate::route::RouteStore;
use crate::tls_intercept::cert_cache::CertCache;
use crate::tls_intercept::{acceptor, h2_forward};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, warn};
use zeroize::Zeroizing;

/// Header byte cap matching the outer proxy's `MAX_HEADER_SIZE` to keep the
/// memory ceiling consistent.
const MAX_HEADER_SIZE: usize = 64 * 1024;

type InterceptResponseRewrite<'a> =
    Box<dyn Fn(u16, &[(String, String)], &[u8]) -> Result<Vec<u8>> + Send + Sync + 'a>;

/// Resolved upstream proxy for the intercept path.
///
/// When `Some`, the upstream leg of the intercepted request must chain
/// through the corporate proxy via CONNECT instead of connecting directly.
/// The caller ([`crate::server::handle_connection`]) is responsible for
/// deciding whether the target host should use the upstream proxy or route
/// direct (based on the bypass list).
#[derive(Clone, Copy)]
pub struct InterceptUpstreamProxy<'a> {
    /// `host:port` of the corporate proxy (e.g. `"proxy.corporate.com:80"`).
    pub proxy_addr: &'a str,
    /// Literal value for `Proxy-Authorization` sent to the corporate proxy,
    /// or `None` for unauthenticated proxies.
    pub proxy_auth_header: Option<&'a str>,
}

/// Select the upstream strategy based on whether an upstream proxy is
/// configured for this intercepted request.
///
/// When `upstream_proxy` is `Some`, returns [`UpstreamStrategy::ExternalProxy`]
/// to chain through the corporate proxy. Otherwise returns
/// [`UpstreamStrategy::Direct`] with the caller-provided resolved addresses.
pub fn select_upstream_strategy<'a>(
    upstream_proxy: &'a Option<InterceptUpstreamProxy<'a>>,
    resolved_addrs: &'a [std::net::SocketAddr],
) -> UpstreamStrategy<'a> {
    if let Some(proxy) = upstream_proxy {
        UpstreamStrategy::ExternalProxy {
            proxy_addr: proxy.proxy_addr,
            proxy_auth_header: proxy.proxy_auth_header,
        }
    } else {
        UpstreamStrategy::Direct { resolved_addrs }
    }
}

/// Select the h2 upstream TLS connector for an intercepted target.
///
/// HTTP/2 opens one upstream connection before individual request streams are
/// selected. To keep per-route TLS behavior aligned with the HTTP/1.1 path
/// without leaking an mTLS/client-cert config across unrelated routes, all
/// intercepted routes for the same upstream must agree on the TLS config.
pub(crate) fn select_h2_tls_connector_for_target(
    route_store: &RouteStore,
    host: &str,
    port: u16,
    default_connector: &tokio_rustls::TlsConnector,
) -> Result<(tokio_rustls::TlsConnector, String)> {
    let host_port = crate::route::format_host_port(host, port);
    let candidates = route_store.lookup_all_by_upstream(&host_port);
    let mut selected: Option<(Option<String>, Option<std::sync::Arc<rustls::ClientConfig>>)> = None;

    for (_, route) in candidates
        .iter()
        .copied()
        .filter(|(_, route)| route.requires_intercept)
    {
        let key = route.tls_config_key.clone();
        let config = route.tls_client_config.clone();
        match &selected {
            None => selected = Some((key, config)),
            Some((existing_key, _)) if existing_key == &key => {}
            Some(_) => {
                return Err(ProxyError::Config(format!(
                    "intercepted h2 routes for {} require different TLS configs; \
                     split the upstreams or disable h2 for this session",
                    host_port
                )));
            }
        }
    }

    match selected.and_then(|(key, config)| key.zip(config)) {
        Some((key, config)) => {
            let cache_key = format!("route:{}", key);
            Ok((h2_connector_from_config(&config), cache_key))
        }
        None => Ok((default_connector.clone(), "default".to_string())),
    }
}

fn h2_connector_from_config(
    config: &std::sync::Arc<rustls::ClientConfig>,
) -> tokio_rustls::TlsConnector {
    let mut config = (**config).clone();
    config.alpn_protocols = vec![b"h2".to_vec()];
    tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
}

/// Per-connection context passed to [`handle_intercept_connect`].
pub struct InterceptCtx<'a> {
    pub route_id: Option<&'a str>,
    pub host: &'a str,
    pub port: u16,
    pub route_store: Arc<RouteStore>,
    pub credential_store: Arc<CredentialStore>,
    pub oauth_capture_store: Arc<OAuthCaptureStore>,
    pub session_token: &'a Zeroizing<String>,
    pub cert_cache: Arc<CertCache>,
    pub tls_connector: &'a tokio_rustls::TlsConnector,
    pub tls_connector_h2: &'a tokio_rustls::TlsConnector,
    pub filter: &'a ProxyFilter,
    pub audit_log: Option<&'a audit::SharedAuditLog>,
    /// When `Some`, the upstream leg chains through an enterprise proxy
    /// instead of connecting directly to the target.
    pub upstream_proxy: Option<InterceptUpstreamProxy<'a>>,
    pub approval_backends: Option<crate::approval::ApprovalBackendRegistry>,
    pub credential_capture_backend: Option<Arc<dyn CredentialCaptureBackend>>,
    /// Optional nonce resolver for substituting tool-sandbox broker nonces
    /// (`nono_<hex>`) found in request header values before forwarding upstream.
    pub nonce_resolver: Option<Arc<dyn crate::token::NonceResolver>>,
    pub enable_h2: bool,
}

/// Handle a CONNECT request that matched a route requiring L7 visibility.
///
/// Caller responsibilities (already enforced in `server.rs`):
/// * Validate strict OUTER `Proxy-Authorization` against the session token.
/// * Confirm `route_store.has_intercept_route(host, port)`.
pub async fn handle_intercept_connect(stream: &mut TcpStream, ctx: InterceptCtx<'_>) -> Result<()> {
    debug!(
        "tls_intercept: accepting CONNECT to {}:{} for L7 inspection",
        ctx.host, ctx.port
    );

    // 200 to the agent before the inner TLS handshake.
    let response = b"HTTP/1.1 200 Connection Established\r\n\r\n";
    stream.write_all(response).await?;
    stream.flush().await?;

    let server_config = acceptor::build_server_config(Arc::clone(&ctx.cert_cache), ctx.enable_h2)?;
    let tls_acceptor = TlsAcceptor::from(server_config);

    let mut tls_stream = match tls_acceptor.accept(&mut *stream).await {
        Ok(s) => s,
        Err(e) => {
            // Hard fail: never silently degrade. Agent sees a TLS error,
            // we record the failure with a sanitized rustls Display string.
            let reason = format!("tls handshake failed: {}", e);
            warn!(
                "tls_intercept: handshake failed for {}:{} — {}. \
                 Agent likely pins certs or carries a hard-coded trust list. \
                 Remove endpoint_rules / credential_key from the route to fall \
                 back to a transparent CONNECT tunnel.",
                ctx.host, ctx.port, e
            );
            audit::log_denied(
                ctx.audit_log,
                audit::ProxyMode::ConnectIntercept,
                &audit::EventContext {
                    route_id: ctx.route_id,
                    auth_mechanism: Some(nono::undo::NetworkAuditAuthMechanism::ProxyAuthorization),
                    auth_outcome: Some(nono::undo::NetworkAuditAuthOutcome::Succeeded),
                    denial_category: Some(
                        nono::undo::NetworkAuditDenialCategory::InterceptHandshakeFailed,
                    ),
                    ..audit::EventContext::default()
                },
                ctx.host,
                ctx.port,
                &reason,
            );
            return Ok(());
        }
    };

    // Acceptance event: the inner TLS handshake completed. Per-request L7
    // events are emitted by `forward_request` once we hand off below.
    audit::log_allowed(
        ctx.audit_log,
        audit::ProxyMode::ConnectIntercept,
        &audit::EventContext {
            route_id: ctx.route_id,
            auth_mechanism: Some(nono::undo::NetworkAuditAuthMechanism::ProxyAuthorization),
            auth_outcome: Some(nono::undo::NetworkAuditAuthOutcome::Succeeded),
            ..audit::EventContext::default()
        },
        ctx.host,
        ctx.port,
        "CONNECT",
    );

    let alpn = tls_stream.get_ref().1.alpn_protocol();
    match alpn {
        Some(b"h2") => {
            debug!(
                "tls_intercept: h2 negotiated for {}:{}, using h2 forward path",
                ctx.host, ctx.port
            );
            if let Err(e) = h2_forward::forward_h2_connection(tls_stream, &ctx).await {
                debug!(
                    "tls_intercept: h2 forwarding failed for {}:{}: {}",
                    ctx.host, ctx.port, e
                );
            }
        }
        _ => {
            if let Err(e) = handle_inner_request(&mut tls_stream, &ctx).await {
                debug!(
                    "tls_intercept: inner-request handling failed for {}:{}: {}",
                    ctx.host, ctx.port, e
                );
            }
        }
    }
    Ok(())
}

/// The parts of an inner HTTP/1.1 request that have been read off the wire
/// but not yet acted on. Produced by [`parse_inner_request`] and consumed by
/// [`handle_inner_request`].
struct ParsedRequest {
    method: String,
    path: String,
    version: String,
    /// Raw header lines (excluding the request line and the blank terminator).
    header_bytes: Vec<u8>,
    /// Bytes already pulled into the `BufReader` buffer beyond the headers.
    buffered: Vec<u8>,
}

/// Calls [`ProxyFilter::check_host`] and handles the denial path.
///
/// On success returns the resolved addresses for use in [`select_upstream_strategy`].
/// On denial writes the 403, emits the audit event, and returns `Ok(None)` so
/// the caller can `return Ok(())` without duplicating the send/log boilerplate.
async fn resolve_upstream_or_deny<S>(
    stream: &mut S,
    ctx: &InterceptCtx<'_>,
    deny_event_ctx: audit::EventContext<'_>,
) -> Result<Option<Vec<std::net::SocketAddr>>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let check = ctx.filter.check_host(ctx.host, ctx.port).await?;
    if !check.result.is_allowed() {
        let reason = check.result.reason();
        warn!("tls_intercept: upstream host denied by filter: {}", reason);
        audit::log_denied(
            ctx.audit_log,
            audit::ProxyMode::ConnectIntercept,
            &audit::EventContext {
                denial_category: Some(nono::undo::NetworkAuditDenialCategory::HostDenied),
                ..deny_event_ctx
            },
            ctx.host,
            ctx.port,
            &reason,
        );
        reverse::send_error_generic(stream, 403, "Forbidden").await?;
        return Ok(None);
    }
    Ok(Some(check.resolved_addrs))
}

/// Read and parse one inner HTTP/1.1 request from `stream`, returning the
/// request line components and raw header bytes as a [`ParsedRequest`].
///
/// Returns `Ok(None)` in two terminal-but-non-error cases that the caller
/// should treat as "nothing to do":
/// - The connection closed before a request line arrived (clean EOF).
/// - The headers exceeded [`MAX_HEADER_SIZE`]; a 431 has been sent and the
///   connection should be dropped.
async fn parse_inner_request<S>(stream: &mut S) -> Result<Option<ParsedRequest>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut buf_reader = BufReader::new(&mut *stream);
    let mut first_line = String::new();
    buf_reader.read_line(&mut first_line).await?;
    if first_line.is_empty() {
        return Ok(None);
    }

    let mut header_bytes = Vec::new();
    loop {
        let mut line = String::new();
        let n = buf_reader.read_line(&mut line).await?;
        if n == 0 || line.trim().is_empty() {
            break;
        }
        header_bytes.extend_from_slice(line.as_bytes());
        if header_bytes.len() > MAX_HEADER_SIZE {
            // Mirror the outer proxy's behaviour. We have to write into the
            // BufReader's inner stream — release it first.
            drop(buf_reader);
            stream
                .write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n")
                .await?;
            return Ok(None);
        }
    }
    let buffered = buf_reader.buffer().to_vec();
    drop(buf_reader);

    let first_line = first_line.trim_end();
    let (method, path, version) = parse_request_line(first_line)?;
    Ok(Some(ParsedRequest {
        method,
        path,
        version,
        header_bytes,
        buffered,
    }))
}

/// Outcome of endpoint-policy evaluation + route selection on the
/// CONNECT-intercept path. Shared by the HTTP/1.1 and HTTP/2 forwarders so the
/// two protocols cannot diverge in L7 authorization behavior.
pub(crate) enum RouteSelection<'a> {
    /// The request was rejected. The denial has already been audited; the
    /// caller must return the given HTTP status to the client and stop.
    Rejected(u16),
    /// Endpoint policy authorized the request. The selected route (if any) is
    /// the one whose credential should be injected; `None` means forward
    /// without credentials (passthrough).
    Selected(Option<(&'a str, &'a crate::route::LoadedRoute)>),
}

/// Evaluate endpoint policy for every candidate route on an intercepted
/// upstream and select the route whose credential (if any) applies.
///
/// This is the single source of truth for per-request L7 authorization on the
/// CONNECT-intercept path, shared by both [`handle_inner_request`] (HTTP/1.1)
/// and [`super::h2_forward`] (HTTP/2). It must not be duplicated per protocol:
/// a divergence here is a security gap, since gRPC traffic would otherwise
/// bypass deny/approve/default-deny policies that the HTTP/1.1 path enforces.
///
/// `endpoint_policy` subsumes the legacy `endpoint_rules` (they are merged at
/// compile time in `route::LoadedRoute::load`), so it is the authoritative
/// source for allow / deny / approve decisions. The loop runs the approval
/// workflow when required and emits L7 audit records. Bucketing mirrors
/// `route::select_route` so a credential catch-all is not shadowed by a
/// passthrough endpoint route.
pub(crate) async fn select_intercept_route<'a>(
    route_store: &'a RouteStore,
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    audit_log: Option<&audit::SharedAuditLog>,
    approval_backends: Option<&crate::approval::ApprovalBackendRegistry>,
) -> RouteSelection<'a> {
    let host_port = format!("{}:{}", host.to_lowercase(), port);
    let candidates = route_store.lookup_all_by_upstream(&host_port);
    if candidates.is_empty() {
        warn!(
            "tls_intercept: no route for {} after intercept handshake",
            host_port
        );
        return RouteSelection::Rejected(502);
    }

    let mut matched_cred: Vec<(&str, &crate::route::LoadedRoute)> = Vec::new();
    let mut matched_passthrough: Vec<(&str, &crate::route::LoadedRoute)> = Vec::new();
    let mut catchall_cred: Vec<(&str, &crate::route::LoadedRoute)> = Vec::new();
    let mut catchall_passthrough: Vec<(&str, &crate::route::LoadedRoute)> = Vec::new();
    let mut has_endpoint_only_route = false;
    let mut endpoint_authorized = false;
    for (prefix, route) in &candidates {
        if route.endpoint_policy.allows_all_without_l7() {
            if route.requires_managed_credential {
                catchall_cred.push((prefix, route));
            } else {
                catchall_passthrough.push((prefix, route));
            }
            continue;
        }
        match route.endpoint_policy.evaluate(method, path) {
            EndpointPolicyOutcome::Allow { rule_label } => {
                audit::log_l7_policy_decision(
                    audit_log,
                    audit::ProxyMode::ConnectIntercept,
                    &audit::EventContext {
                        route_id: Some(prefix),
                        endpoint_policy_action: Some("allow"),
                        endpoint_policy_rule: Some(&rule_label),
                        upstream: Some(&route.upstream),
                        ..audit::EventContext::default()
                    },
                    host,
                    Some(port),
                    method,
                    path,
                    nono::undo::NetworkAuditDecision::Allow,
                    "allow",
                    &rule_label,
                    None,
                );
                if route.requires_managed_credential {
                    matched_cred.push((prefix, route));
                } else {
                    matched_passthrough.push((prefix, route));
                    endpoint_authorized = true;
                }
            }
            EndpointPolicyOutcome::Approve {
                backend,
                reason,
                timeout_secs,
                rule_label,
            } => {
                let Some(approval_backends) = approval_backends else {
                    let deny_reason = format!(
                        "endpoint approval required by {} but no approval backend is configured",
                        rule_label
                    );
                    warn!("tls_intercept: {}", deny_reason);
                    audit::log_denied(
                        audit_log,
                        audit::ProxyMode::ConnectIntercept,
                        &audit::EventContext {
                            denial_category: Some(
                                nono::undo::NetworkAuditDenialCategory::EndpointPolicy,
                            ),
                            route_id: Some(prefix),
                            endpoint_policy_action: Some("approve"),
                            endpoint_policy_rule: Some(&rule_label),
                            upstream: Some(&route.upstream),
                            ..audit::EventContext::default()
                        },
                        host,
                        port,
                        &deny_reason,
                    );
                    return RouteSelection::Rejected(403);
                };
                let (backend_name, backend) = match approval_backends.resolve(backend) {
                    Ok(resolved) => resolved,
                    Err(err) => {
                        let deny_reason =
                            format!("endpoint approval backend resolution failed: {err}");
                        warn!("tls_intercept: {}", deny_reason);
                        audit::log_l7_policy_decision(
                            audit_log,
                            audit::ProxyMode::ConnectIntercept,
                            &audit::EventContext {
                                denial_category: Some(
                                    nono::undo::NetworkAuditDenialCategory::EndpointPolicy,
                                ),
                                route_id: Some(prefix),
                                endpoint_policy_action: Some("approve"),
                                endpoint_policy_rule: Some(&rule_label),
                                upstream: Some(&route.upstream),
                                ..audit::EventContext::default()
                            },
                            host,
                            Some(port),
                            method,
                            path,
                            nono::undo::NetworkAuditDecision::ApproveError,
                            "approve",
                            &rule_label,
                            Some(&deny_reason),
                        );
                        return RouteSelection::Rejected(403);
                    }
                };
                let request_reason = reason.map(str::to_string).unwrap_or_else(|| {
                    format!(
                        "endpoint approval required by {} for {} {}",
                        rule_label, method, path
                    )
                });
                let approval_ctx = audit::EventContext {
                    route_id: Some(prefix),
                    endpoint_policy_action: Some("approve"),
                    endpoint_policy_rule: Some(&rule_label),
                    approval_backend: Some(&backend_name),
                    upstream: Some(&route.upstream),
                    ..audit::EventContext::default()
                };
                audit::log_l7_policy_decision(
                    audit_log,
                    audit::ProxyMode::ConnectIntercept,
                    &approval_ctx,
                    host,
                    Some(port),
                    method,
                    path,
                    nono::undo::NetworkAuditDecision::ApproveRequested,
                    "approve",
                    &rule_label,
                    Some(&request_reason),
                );
                let request = nono::supervisor::ApprovalRequest::Endpoint {
                    request_id: format!("proxy-endpoint-approval-{}-{}", host, port),
                    route_id: (*prefix).to_string(),
                    upstream: route.upstream.clone(),
                    method: method.to_string(),
                    path: path.to_string(),
                    rule_label: rule_label.clone(),
                    reason: Some(request_reason),
                    child_pid: 0,
                    session_id: "proxy".to_string(),
                };
                let timeout = std::time::Duration::from_secs(timeout_secs.unwrap_or(60));
                let decision = tokio::time::timeout(
                    timeout,
                    tokio::task::spawn_blocking(move || backend.request_approval(&request)),
                )
                .await;
                match decision {
                    Ok(Ok(Ok(decision))) if decision.is_granted() => {
                        audit::log_l7_policy_decision(
                            audit_log,
                            audit::ProxyMode::ConnectIntercept,
                            &approval_ctx,
                            host,
                            Some(port),
                            method,
                            path,
                            nono::undo::NetworkAuditDecision::ApproveGranted,
                            "approve",
                            &rule_label,
                            None,
                        );
                        if route.requires_managed_credential {
                            matched_cred.push((prefix, route));
                        } else {
                            matched_passthrough.push((prefix, route));
                            endpoint_authorized = true;
                        }
                    }
                    Ok(Ok(Ok(_))) => {
                        audit::log_l7_policy_decision(
                            audit_log,
                            audit::ProxyMode::ConnectIntercept,
                            &approval_ctx,
                            host,
                            Some(port),
                            method,
                            path,
                            nono::undo::NetworkAuditDecision::ApproveDenied,
                            "approve",
                            &rule_label,
                            Some("endpoint approval denied"),
                        );
                        if !route.requires_managed_credential {
                            has_endpoint_only_route = true;
                        }
                    }
                    Ok(Ok(Err(err))) => {
                        let deny_reason = format!("endpoint approval backend error: {err}");
                        audit::log_l7_policy_decision(
                            audit_log,
                            audit::ProxyMode::ConnectIntercept,
                            &approval_ctx,
                            host,
                            Some(port),
                            method,
                            path,
                            nono::undo::NetworkAuditDecision::ApproveError,
                            "approve",
                            &rule_label,
                            Some(&deny_reason),
                        );
                        warn!("{}", deny_reason);
                        if !route.requires_managed_credential {
                            has_endpoint_only_route = true;
                        }
                    }
                    Ok(Err(err)) => {
                        let deny_reason = format!("endpoint approval task failed: {err}");
                        audit::log_l7_policy_decision(
                            audit_log,
                            audit::ProxyMode::ConnectIntercept,
                            &approval_ctx,
                            host,
                            Some(port),
                            method,
                            path,
                            nono::undo::NetworkAuditDecision::ApproveError,
                            "approve",
                            &rule_label,
                            Some(&deny_reason),
                        );
                        warn!("{}", deny_reason);
                        if !route.requires_managed_credential {
                            has_endpoint_only_route = true;
                        }
                    }
                    Err(_) => {
                        let deny_reason = format!(
                            "endpoint approval timed out by {}: {} {} on route '{}'",
                            rule_label, method, path, prefix
                        );
                        audit::log_l7_policy_decision(
                            audit_log,
                            audit::ProxyMode::ConnectIntercept,
                            &approval_ctx,
                            host,
                            Some(port),
                            method,
                            path,
                            nono::undo::NetworkAuditDecision::ApproveTimeout,
                            "approve",
                            &rule_label,
                            Some(&deny_reason),
                        );
                        warn!("{}", deny_reason);
                        if !route.requires_managed_credential {
                            has_endpoint_only_route = true;
                        }
                    }
                }
            }
            EndpointPolicyOutcome::Deny { reason, rule_label } => {
                // A legacy `endpoint_rules` allow-list compiles to a
                // non-explicit default-deny policy. When the request path is
                // not in that list the route simply does not apply — it must
                // not hard-deny the whole request, because another route
                // sharing this upstream may still authorize and inject a
                // credential. Mirror `route::select_route`: drop a managed-
                // credential route, or let a credential-less endpoint-only
                // (`_ep_`) route gate the request via `has_endpoint_only_route`
                // so the post-loop check produces the 403 only when nothing
                // authorized it. Explicit endpoint policies keep their
                // authoritative hard-deny below.
                if !route.endpoint_policy.is_explicit() {
                    if !route.requires_managed_credential {
                        has_endpoint_only_route = true;
                    }
                    continue;
                }
                let deny_reason = reason.unwrap_or("endpoint denied by policy");
                audit::log_l7_policy_decision(
                    audit_log,
                    audit::ProxyMode::ConnectIntercept,
                    &audit::EventContext {
                        route_id: Some(prefix),
                        denial_category: Some(
                            nono::undo::NetworkAuditDenialCategory::EndpointPolicy,
                        ),
                        endpoint_policy_action: Some("deny"),
                        endpoint_policy_rule: Some(&rule_label),
                        upstream: Some(&route.upstream),
                        ..audit::EventContext::default()
                    },
                    host,
                    Some(port),
                    method,
                    path,
                    nono::undo::NetworkAuditDecision::Deny,
                    "deny",
                    &rule_label,
                    Some(deny_reason),
                );
                return RouteSelection::Rejected(403);
            }
        }
    }

    // A credential catch-all must not be shadowed by an endpoint-only route that
    // gated the request but failed authorization. Mirrors `route::select_route`.
    if has_endpoint_only_route && !endpoint_authorized {
        let reason = format!(
            "endpoint rules denied {} {}: no rule matched on {}:{}",
            method, path, host, port
        );
        warn!("tls_intercept: {}", reason);
        audit::log_denied(
            audit_log,
            audit::ProxyMode::ConnectIntercept,
            &audit::EventContext {
                denial_category: Some(nono::undo::NetworkAuditDenialCategory::EndpointPolicy),
                ..audit::EventContext::default()
            },
            host,
            port,
            &reason,
        );
        return RouteSelection::Rejected(403);
    }

    // Ambiguity applies only to credential-injection routes within the active
    // layer; multiple endpoint-only authorization routes matching is fine.
    let credential_layer: &[(&str, &crate::route::LoadedRoute)] = if matched_cred.is_empty() {
        &catchall_cred
    } else {
        &matched_cred
    };
    if credential_layer.len() > 1 {
        let names: Vec<&str> = credential_layer.iter().map(|(p, _)| *p).collect();
        let reason = format!(
            "ambiguous route: {} {} matched {} credential routes: {:?}. \
             Narrow endpoint rules so each request matches exactly one route.",
            method,
            path,
            names.len(),
            names
        );
        warn!("tls_intercept: {}", reason);
        audit::log_denied(
            audit_log,
            audit::ProxyMode::ConnectIntercept,
            &audit::EventContext {
                denial_category: Some(nono::undo::NetworkAuditDenialCategory::EndpointPolicy),
                ..audit::EventContext::default()
            },
            host,
            port,
            &reason,
        );
        return RouteSelection::Rejected(403);
    }

    let selected = credential_layer
        .first()
        .copied()
        .or_else(|| matched_passthrough.first().copied())
        .or_else(|| catchall_passthrough.first().copied());
    match selected.map(|(s, _)| s) {
        Some(svc) => debug!(
            "tls_intercept: selected route '{}' for {} {}",
            svc, method, path
        ),
        None => debug!(
            "tls_intercept: no endpoint_rules matched {} {}, forwarding without credentials",
            method, path
        ),
    }
    RouteSelection::Selected(selected)
}

/// A managed credential resolved for an intercept request. Borrowed for static
/// credentials (the hot path; no secret copy), owned for command-backed
/// captures which are minted per request.
pub(crate) enum ResolvedCredential<'a> {
    Static(&'a crate::credential::LoadedCredential),
    Captured(Box<crate::credential::LoadedCredential>),
}

impl ResolvedCredential<'_> {
    pub(crate) fn as_ref(&self) -> &crate::credential::LoadedCredential {
        match self {
            ResolvedCredential::Static(cred) => cred,
            ResolvedCredential::Captured(cred) => cred,
        }
    }
}

/// Outcome of resolving the managed credential for an already-authorized
/// intercept request. Shared by the HTTP/1.1 and HTTP/2 forwarders so the two
/// protocols apply identical credential gating, AWS handling, and command
/// capture — a divergence here would let one protocol forward a request the
/// other rejects (e.g. an unsigned AWS request, or one missing a managed key).
pub(crate) enum CredentialResolution<'a> {
    /// The request must be rejected with this HTTP status; the denial has
    /// already been audited.
    Rejected(u16),
    /// Forward the request, optionally injecting `credential`.
    Forward {
        credential: Option<ResolvedCredential<'a>>,
    },
}

/// Resolve the managed credential for an authorized intercept request.
///
/// Runs the shared post-selection credential pipeline: the
/// [`LoadedRoute::missing_managed_credential`] gate, the AWS SigV4 stub (not
/// yet implemented → reject), and command-backed credential capture. Static
/// credentials are returned cloned. OAuth2 routes are not injected on the
/// CONNECT-intercept path (parity with the legacy behavior); their presence
/// only satisfies the gate.
///
/// This is the single source of truth shared by [`handle_inner_request`]
/// (HTTP/1.1) and [`super::h2_forward`] (HTTP/2).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn resolve_managed_credential<'a>(
    credential_store: &'a CredentialStore,
    credential_capture_backend: Option<&Arc<dyn CredentialCaptureBackend>>,
    audit_log: Option<&audit::SharedAuditLog>,
    host: &str,
    port: u16,
    service: Option<&str>,
    route: Option<&crate::route::LoadedRoute>,
    method: &str,
    path: &str,
) -> CredentialResolution<'a> {
    let static_cred = service.and_then(|s| credential_store.get(s));
    let cmd_route = service.and_then(|s| credential_store.get_cmd(s));
    let oauth2_route = service.and_then(|s| credential_store.get_oauth2(s));
    let spiffe_assertion_route = service.and_then(|s| credential_store.get_spiffe_assertion(s));
    let aws_route = service.and_then(|s| credential_store.get_aws(s));
    let has_spiffe = route.is_some_and(|rt| rt.has_spiffe_source());

    if let Some(rt) = route
        && rt.missing_managed_credential(
            static_cred.is_some() || (cmd_route.is_some() && credential_capture_backend.is_some()),
            oauth2_route.is_some() || spiffe_assertion_route.is_some(),
            aws_route.is_some(),
            has_spiffe,
        )
    {
        let svc = service.unwrap_or("unknown");
        let reason = format!(
            "managed credential unavailable for route '{}': intercepted request requires proxy-supplied auth",
            svc
        );
        warn!("tls_intercept: {}", reason);
        audit::log_denied(
            audit_log,
            audit::ProxyMode::ConnectIntercept,
            &audit::EventContext {
                route_id: service,
                auth_mechanism: rt.managed_auth_mechanism.clone(),
                auth_outcome: Some(nono::undo::NetworkAuditAuthOutcome::Failed),
                managed_credential_active: Some(false),
                injection_mode: rt.managed_injection_mode.clone(),
                denial_category: Some(
                    nono::undo::NetworkAuditDenialCategory::ManagedCredentialUnavailable,
                ),
                ..audit::EventContext::default()
            },
            host,
            port,
            &reason,
        );
        return CredentialResolution::Rejected(503);
    }

    // AWS SigV4 signing is not yet implemented. Return 501 so the caller knows
    // the route exists but is not functional. Crucially this rejects rather
    // than forwarding an unsigned request — the HTTP/2 path must not silently
    // pass AWS traffic upstream just because it lacks a signing branch.
    if aws_route.is_some() {
        return CredentialResolution::Rejected(501);
    }

    // Command-backed credential capture (mints a per-request credential).
    if let (Some(svc), Some(cmd)) = (service, cmd_route)
        && static_cred.is_none()
    {
        match reverse::capture_cmd_credential(
            cmd,
            svc,
            route.map(|r| r.upstream.as_str()).unwrap_or(""),
            path,
            method,
            host,
            port,
            audit::ProxyMode::ConnectIntercept,
            audit_log,
            credential_capture_backend.cloned(),
        )
        .await
        {
            Ok(credential) => {
                return CredentialResolution::Forward {
                    credential: Some(ResolvedCredential::Captured(Box::new(credential))),
                };
            }
            Err(err) => {
                let reason = err.to_string();
                warn!("tls_intercept: {}", reason);
                audit::log_denied(
                    audit_log,
                    audit::ProxyMode::ConnectIntercept,
                    &audit::EventContext {
                        route_id: service,
                        auth_mechanism: route.and_then(|r| r.managed_auth_mechanism.clone()),
                        auth_outcome: Some(nono::undo::NetworkAuditAuthOutcome::Failed),
                        managed_credential_active: Some(false),
                        injection_mode: route.and_then(|r| r.managed_injection_mode.clone()),
                        denial_category: Some(
                            nono::undo::NetworkAuditDenialCategory::ManagedCredentialUnavailable,
                        ),
                        ..audit::EventContext::default()
                    },
                    host,
                    port,
                    &reason,
                );
                return CredentialResolution::Rejected(503);
            }
        }
    }

    CredentialResolution::Forward {
        credential: static_cred.map(ResolvedCredential::Static),
    }
}

/// Read one inner HTTP/1.1 request, select the matching route, inject
/// credentials if matched, and forward upstream.
async fn handle_inner_request<S>(tls_stream: &mut S, ctx: &InterceptCtx<'_>) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let req = match parse_inner_request(tls_stream).await? {
        Some(r) => r,
        None => return Ok(()),
    };
    debug!("tls_intercept: inner request {} {}", req.method, req.path);

    // Endpoint authorization + credential route selection. Shared with the
    // HTTP/2 path via [`select_intercept_route`] so the two protocols cannot
    // diverge in L7 policy enforcement.
    let method = req.method.clone();
    let path = req.path.clone();
    let host_port = format!("{}:{}", ctx.host.to_lowercase(), ctx.port);
    let is_oauth_capture_host = ctx.oauth_capture_store.host_policy(&host_port).is_some();
    let oauth_endpoint = ctx.oauth_capture_store.lookup(&host_port, &req.path);
    let selected = if oauth_endpoint.is_some() {
        None
    } else {
        match select_intercept_route(
            &ctx.route_store,
            ctx.host,
            ctx.port,
            &method,
            &path,
            ctx.audit_log,
            ctx.approval_backends.as_ref(),
        )
        .await
        {
            RouteSelection::Rejected(status) => {
                let msg = match status {
                    502 => "Bad Gateway",
                    _ => "Forbidden",
                };
                reverse::send_error_generic(tls_stream, status, msg).await?;
                return Ok(());
            }
            RouteSelection::Selected(selected) => selected,
        }
    };
    let service: Option<&str> = selected.map(|(s, _)| s);
    let route: Option<&crate::route::LoadedRoute> = selected.map(|(_, r)| r);

    // SPIFFE routes bypass the normal credential resolution path entirely and
    // use mTLS / JWT-SVID auth instead of injected headers.
    if route.is_some_and(|rt| rt.has_spiffe_source())
        && let (Some(svc), Some(rt)) = (service, route)
    {
        return handle_spiffe_intercept_request(tls_stream, ctx, &req, svc, rt, &method, &path)
            .await;
    }

    // OAuth2 presence only affects the audit `managed_credential_active` flag
    // on this path; injection is not performed for intercepted requests.
    let oauth2_route = service.and_then(|s| ctx.credential_store.get_oauth2(s));
    let spiffe_assertion_route = service.and_then(|s| ctx.credential_store.get_spiffe_assertion(s));

    // Early branch: AWS SigV4 path is completely self-contained. Must be
    // checked before calling resolve_managed_credential, which still carries
    // a 501 stub for the aws_route case.
    let aws_route = service.and_then(|s| ctx.credential_store.get_aws(s));
    if let Some(aws) = aws_route {
        return handle_inner_request_aws(tls_stream, ctx, aws, route, service, &req).await;
    }

    // Managed credential gating and command-backed capture are shared with the
    // HTTP/2 path via [`resolve_managed_credential`] so the two protocols
    // cannot diverge (e.g. forwarding an unsigned request).
    let resolved = match resolve_managed_credential(
        &ctx.credential_store,
        ctx.credential_capture_backend.as_ref(),
        ctx.audit_log,
        ctx.host,
        ctx.port,
        service,
        route,
        &method,
        &path,
    )
    .await
    {
        CredentialResolution::Rejected(status) => {
            let msg = match status {
                501 => "Not Implemented",
                _ => "Service Unavailable",
            };
            reverse::send_error_generic(tls_stream, status, msg).await?;
            return Ok(());
        }
        CredentialResolution::Forward { credential } => credential,
    };
    let cred = resolved.as_ref().map(|c| c.as_ref());

    // --- Path / credential transformation ---
    // Shared with the HTTP/2 path so URL-mode injection cannot diverge.
    let transformed_path = reverse::transform_path_for_credential(cred, &req.path)?;

    // --- Resolve upstream IPs (DNS-rebind-safe via filter) ---
    let resolved_addrs = match resolve_upstream_or_deny(
        tls_stream,
        ctx,
        audit::EventContext {
            route_id: service,
            managed_credential_active: Some(cred.is_some() || oauth2_route.is_some()),
            injection_mode: cred
                .map(|c| reverse::audit_injection_mode_for_inject_mode(&c.inject_mode)),
            ..audit::EventContext::default()
        },
    )
    .await?
    {
        Some(addrs) => addrs,
        None => return Ok(()),
    };

    // If there's a SPIFFE assertion route, fetch the access token now.
    // Fail the request if the SVID is revoked (Credential error); use stale on transient failures.
    let spiffe_bearer = if let Some(assertion_route) = spiffe_assertion_route {
        match assertion_route.cache.get_or_refresh().await {
            Ok(token) => Some(token),
            Err(e) => {
                warn!("tls_intercept: SPIFFE assertion token unavailable: {}", e);
                reverse::send_error_generic(tls_stream, 503, "Service Unavailable").await?;
                return Ok(());
            }
        }
    } else {
        None
    };

    // --- Read body (Content-Length only; chunked is rare in API requests
    // and matches the existing reverse-proxy contract). ---
    let strip_header = cred.map(|c| c.proxy_header_name.as_str()).unwrap_or("");
    let mut filtered_headers = reverse::filter_headers(&req.header_bytes, strip_header);
    if is_oauth_capture_host {
        filtered_headers.retain(|(name, _)| !name.eq_ignore_ascii_case("accept-encoding"));
        filtered_headers.push(("Accept-Encoding".to_string(), "identity".to_string()));
    }
    let content_length = reverse::extract_content_length(&req.header_bytes);
    let body = match reverse::read_request_body(tls_stream, content_length, &req.buffered).await? {
        Some(b) => b,
        None => return Ok(()),
    };
    let body = if let Some(endpoint) = oauth_endpoint {
        ctx.oauth_capture_store
            .rewrite_request_body(endpoint, &body)?
    } else {
        body
    };

    // --- Build upstream request bytes ---
    let upstream_authority = reverse::format_host_header(UpstreamScheme::Https, ctx.host, ctx.port);
    let mut request = Zeroizing::new(format!(
        "{} {} {}\r\nHost: {}\r\n",
        req.method, transformed_path, req.version, upstream_authority
    ));
    if let Some(cred) = cred {
        reverse::inject_credential_for_mode(cred, &mut request);
    } else if let Some(token) = &spiffe_bearer {
        request.push_str(&format!("Authorization: Bearer {}\r\n", token.as_str()));
    }
    let injected_header_names = reverse::injected_credential_header_names(cred);
    let nonce_consumer = service.map(|s| format!("proxy.{s}"));
    for (name, value) in &filtered_headers {
        if injected_header_names
            .iter()
            .any(|header| name.eq_ignore_ascii_case(header))
        {
            continue;
        }
        let resolved_value = nonce_consumer
            .as_deref()
            .and_then(|consumer| {
                ctx.nonce_resolver
                    .as_deref()
                    .and_then(|resolver| resolve_nonce_in_header_value(value, consumer, resolver))
            })
            .unwrap_or_else(|| value.clone());
        request.push_str(&format!("{}: {}\r\n", name, resolved_value));
    }
    request.push_str("Connection: close\r\n");
    if !body.is_empty() {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");

    // --- Forward via shared pipeline ---
    let connector = route
        .and_then(|r| r.tls_connector.as_ref())
        .unwrap_or(ctx.tls_connector);
    let strategy = select_upstream_strategy(&ctx.upstream_proxy, &resolved_addrs);
    let upstream_spec = UpstreamSpec {
        scheme: UpstreamScheme::Https,
        host: ctx.host,
        port: ctx.port,
        strategy,
        tls_connector: connector,
    };
    let spiffe_audit_ctx = spiffe_bearer.as_ref().and_then(|_| {
        spiffe_assertion_route.map(|r| {
            let id = &r.cache.workload_spiffe_id;
            let trust_domain = crate::auth::extract_trust_domain(id);
            nono::undo::SpiffeAuditContext {
                workload_spiffe_id: id.clone(),
                trust_domain,
                svid_type: "jwt".to_string(),
                source: "spire-workload-api".to_string(),
                upstream_spiffe_id: None,
                delegation: None,
            }
        })
    });
    let event_ctx = audit::EventContext {
        route_id: service,
        auth_mechanism: cred
            .map(|c| reverse::auth_mechanism_for_inject_mode(&c.proxy_inject_mode))
            .or_else(|| {
                spiffe_bearer
                    .as_ref()
                    .map(|_| nono::undo::NetworkAuditAuthMechanism::SpiffeJwtBearer)
            }),
        auth_outcome: cred
            .map(|_| nono::undo::NetworkAuditAuthOutcome::Succeeded)
            .or_else(|| {
                spiffe_bearer
                    .as_ref()
                    .map(|_| nono::undo::NetworkAuditAuthOutcome::Succeeded)
            }),
        managed_credential_active: Some(
            cred.is_some() || oauth2_route.is_some() || spiffe_bearer.is_some(),
        ),
        injection_mode: cred
            .map(|c| reverse::audit_injection_mode_for_inject_mode(&c.inject_mode))
            .or_else(|| {
                spiffe_bearer
                    .as_ref()
                    .map(|_| nono::undo::NetworkAuditInjectionMode::SpiffeJwt)
            }),
        spiffe_context: spiffe_audit_ctx,
        denial_category: None,
        ..audit::EventContext::default()
    };
    let audit_ctx = AuditCtx {
        log: ctx.audit_log,
        mode: audit::ProxyMode::ConnectIntercept,
        event_ctx: event_ctx.clone(),
        target: ctx.host,
        method: &req.method,
        path: &req.path,
    };
    let response_rewrite: Option<InterceptResponseRewrite<'_>> =
        if let Some(endpoint) = oauth_endpoint {
            Some(Box::new(
                move |status: u16, _headers: &[(String, String)], body: &[u8]| {
                    if (200..300).contains(&status) {
                        ctx.oauth_capture_store
                            .rewrite_response_body(endpoint, body)
                    } else {
                        ctx.oauth_capture_store
                            .inspect_capture_host_response(&host_port, &path, status, body)
                    }
                },
            ))
        } else if is_oauth_capture_host {
            Some(Box::new(
                move |status: u16, _headers: &[(String, String)], body: &[u8]| {
                    ctx.oauth_capture_store
                        .inspect_capture_host_response(&host_port, &path, status, body)
                },
            ))
        } else {
            None
        };
    let response_rewrite_ref = response_rewrite
        .as_ref()
        .map(|rewrite| rewrite.as_ref() as forward::ResponseRewrite<'_>);

    if let Err(e) = forward::forward_request_with_response_rewrite(
        tls_stream,
        request.as_bytes(),
        &body,
        upstream_spec,
        audit_ctx,
        response_rewrite_ref,
    )
    .await
    {
        warn!("tls_intercept: upstream forwarding failed: {}", e);
        audit::log_denied(
            ctx.audit_log,
            audit::ProxyMode::ConnectIntercept,
            &audit::EventContext {
                denial_category: Some(
                    nono::undo::NetworkAuditDenialCategory::UpstreamConnectFailed,
                ),
                ..event_ctx
            },
            ctx.host,
            ctx.port,
            &e.to_string(),
        );
        let _ = reverse::send_error_generic(tls_stream, 502, "Bad Gateway").await;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_spiffe_intercept_request<S>(
    tls_stream: &mut S,
    ctx: &InterceptCtx<'_>,
    req: &ParsedRequest,
    service: &str,
    route: &crate::route::LoadedRoute,
    method: &str,
    path: &str,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let auth_result = route.managed_auth.as_ref().ok_or_else(|| {
        crate::error::ProxyError::Credential("no managed auth on SPIFFE route".into())
    });
    let material = match auth_result {
        Ok(auth) => match auth.acquire().await {
            Ok(m) => m,
            Err(e) => {
                let reason = e.to_string();
                warn!("tls_intercept: SPIFFE credential unavailable: {}", reason);
                audit::log_denied(
                    ctx.audit_log,
                    audit::ProxyMode::ConnectIntercept,
                    &audit::EventContext {
                        route_id: Some(service),
                        auth_mechanism: route.managed_auth_mechanism.clone(),
                        auth_outcome: Some(nono::undo::NetworkAuditAuthOutcome::Failed),
                        managed_credential_active: Some(false),
                        injection_mode: route.managed_injection_mode.clone(),
                        denial_category: Some(
                            nono::undo::NetworkAuditDenialCategory::ManagedCredentialUnavailable,
                        ),
                        ..audit::EventContext::default()
                    },
                    ctx.host,
                    ctx.port,
                    &reason,
                );
                reverse::send_error_generic(tls_stream, 503, "Service Unavailable").await?;
                return Ok(());
            }
        },
        Err(e) => {
            let reason = e.to_string();
            warn!("tls_intercept: SPIFFE credential unavailable: {}", reason);
            audit::log_denied(
                ctx.audit_log,
                audit::ProxyMode::ConnectIntercept,
                &audit::EventContext {
                    route_id: Some(service),
                    auth_mechanism: route.managed_auth_mechanism.clone(),
                    auth_outcome: Some(nono::undo::NetworkAuditAuthOutcome::Failed),
                    managed_credential_active: Some(false),
                    injection_mode: route.managed_injection_mode.clone(),
                    denial_category: Some(
                        nono::undo::NetworkAuditDenialCategory::ManagedCredentialUnavailable,
                    ),
                    ..audit::EventContext::default()
                },
                ctx.host,
                ctx.port,
                &reason,
            );
            reverse::send_error_generic(tls_stream, 503, "Service Unavailable").await?;
            return Ok(());
        }
    };

    let spiffe_ctx = material.spiffe_audit_context();
    let event_ctx = audit::EventContext {
        route_id: Some(service),
        auth_mechanism: route.managed_auth_mechanism.clone(),
        auth_outcome: Some(nono::undo::NetworkAuditAuthOutcome::Succeeded),
        managed_credential_active: Some(true),
        injection_mode: route.managed_injection_mode.clone(),
        spiffe_context: Some(spiffe_ctx),
        ..audit::EventContext::default()
    };

    let resolved_addrs = match resolve_upstream_or_deny(
        tls_stream,
        ctx,
        audit::EventContext {
            route_id: Some(service),
            managed_credential_active: Some(true),
            injection_mode: route.managed_injection_mode.clone(),
            ..audit::EventContext::default()
        },
    )
    .await?
    {
        Some(addrs) => addrs,
        None => return Ok(()),
    };

    let crate::auth::UpstreamAuthMaterial::BearerToken {
        ref header,
        ref token,
        ref credential_format,
        ..
    } = material;
    let inject_header = Some(header.clone());
    let inject_value = Some(credential_format.replace("{}", token.as_str()));
    let tls_connector_owned: Option<tokio_rustls::TlsConnector> = None;

    let strip_header = inject_header.as_deref().unwrap_or("");
    let filtered_headers = reverse::filter_headers(&req.header_bytes, strip_header);
    let content_length = reverse::extract_content_length(&req.header_bytes);
    let body = match reverse::read_request_body(tls_stream, content_length, &req.buffered).await? {
        Some(b) => b,
        None => return Ok(()),
    };

    let upstream_authority = reverse::format_host_header(UpstreamScheme::Https, ctx.host, ctx.port);
    let mut request = Zeroizing::new(format!(
        "{} {} {}\r\nHost: {}\r\n",
        method, path, req.version, upstream_authority
    ));
    if let (Some(value), Some(header)) = (&inject_value, &inject_header) {
        request.push_str(&format!("{}: {}\r\n", header, value));
    }
    for (name, value) in &filtered_headers {
        if let Some(header) = &inject_header
            && name.eq_ignore_ascii_case(header)
        {
            continue;
        }
        request.push_str(&format!("{}: {}\r\n", name, value));
    }
    request.push_str("Connection: close\r\n");
    if !body.is_empty() {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");

    let default_connector;
    let connector = if let Some(ref owned) = tls_connector_owned {
        owned
    } else {
        default_connector = route
            .tls_connector
            .as_ref()
            .unwrap_or(ctx.tls_connector)
            .clone();
        &default_connector
    };
    let strategy = select_upstream_strategy(&ctx.upstream_proxy, &resolved_addrs);
    let upstream_spec = UpstreamSpec {
        scheme: UpstreamScheme::Https,
        host: ctx.host,
        port: ctx.port,
        strategy,
        tls_connector: connector,
    };
    let audit_ctx = AuditCtx {
        log: ctx.audit_log,
        mode: audit::ProxyMode::ConnectIntercept,
        event_ctx: event_ctx.clone(),
        target: ctx.host,
        method,
        path,
    };
    if let Err(e) = forward::forward_request(
        tls_stream,
        request.as_bytes(),
        &body,
        upstream_spec,
        audit_ctx,
    )
    .await
    {
        warn!("tls_intercept: SPIFFE upstream forwarding failed: {}", e);
        audit::log_denied(
            ctx.audit_log,
            audit::ProxyMode::ConnectIntercept,
            &audit::EventContext {
                denial_category: Some(
                    nono::undo::NetworkAuditDenialCategory::UpstreamConnectFailed,
                ),
                ..event_ctx
            },
            ctx.host,
            ctx.port,
            &e.to_string(),
        );
        let _ = reverse::send_error_generic(tls_stream, 502, "Bad Gateway").await;
    }
    Ok(())
}

/// Scan a header value for a tool-sandbox broker nonce (`nono_<64hex>`) and,
/// if one is found and `resolver` admits `consumer`, return the header value
/// with the nonce replaced by the real credential bytes (UTF-8).
///
/// Only the first nonce found is substituted. Non-UTF-8 real values are
/// forwarded verbatim (fail-open for the substitution, not the request).
/// If no nonce is found, or the resolver returns `None`, the original value
/// is returned unchanged (fail-closed: the upstream sees the raw nonce and
/// will reject the request, not a silently wrong credential).
pub(crate) fn resolve_nonce_in_header_value(
    value: &str,
    consumer: &str,
    resolver: &dyn crate::token::NonceResolver,
) -> Option<String> {
    const NONCE_PREFIX: &str = "nono_";
    const NONCE_LEN: usize = 5 + 64; // "nono_" + 64 hex chars

    let start = value.find(NONCE_PREFIX)?;
    let end = start.checked_add(NONCE_LEN)?;
    if end > value.len() {
        return None;
    }
    let nonce = &value[start..end];
    if !nonce[NONCE_PREFIX.len()..]
        .bytes()
        .all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }
    let real = resolver.resolve(nonce, consumer)?;
    let real_str = std::str::from_utf8(&real).ok()?;
    Some(format!("{}{}{}", &value[..start], real_str, &value[end..]))
}

/// Handle the AWS SigV4 arm of an intercepted inner request.
///
/// Owns the full pipeline for that credential type: header stripping, body reading,
/// SigV4 signing, request assembly, filter check, and upstream forwarding.
async fn handle_inner_request_aws<S>(
    tls_stream: &mut S,
    ctx: &InterceptCtx<'_>,
    aws: &crate::aws::route::AwsRoute,
    route: Option<&crate::route::LoadedRoute>,
    service: Option<&str>,
    req: &ParsedRequest,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // Strip the five auth-bearing headers so the agent's dummy credentials are
    // never forwarded or included in the canonical request. All other
    // x-amz-* headers (X-Amz-Target, meta, etc.) are preserved and signed.
    let mut filtered_headers = reverse::filter_headers(&req.header_bytes, "");
    filtered_headers.retain(|(name, _)| !crate::aws::sign::is_aws_auth_header(name));

    let content_length = reverse::extract_content_length(&req.header_bytes);
    let body = match reverse::read_request_body(tls_stream, content_length, &req.buffered).await? {
        Some(b) => b,
        None => return Ok(()),
    };

    // --- Resolve upstream IPs (DNS-rebind-safe via filter) ---
    let resolved_addrs = match resolve_upstream_or_deny(
        tls_stream,
        ctx,
        audit::EventContext {
            route_id: service,
            managed_credential_active: Some(true),
            injection_mode: Some(nono::undo::NetworkAuditInjectionMode::Header),
            ..audit::EventContext::default()
        },
    )
    .await?
    {
        Some(addrs) => addrs,
        None => return Ok(()),
    };

    // --- Build upstream request bytes ---
    let upstream_authority = reverse::format_host_header(UpstreamScheme::Https, ctx.host, ctx.port);
    let mut request = Zeroizing::new(format!(
        "{} {} {}\r\nHost: {}\r\n",
        req.method, req.path, req.version, upstream_authority
    ));

    // SigV4 signing: resolve credentials via the route's provider and inject
    // Authorization, X-Amz-Date, X-Amz-Content-Sha256, and (if present)
    // X-Amz-Security-Token.
    let full_url = format!("https://{}{}", upstream_authority, req.path);
    debug!(
        "tls_intercept: signing AWS request: method={} url='{}' \
         service='{}' region='{}' body_len={} header_count={}",
        req.method,
        full_url,
        aws.service,
        aws.region,
        body.len(),
        filtered_headers.len(),
    );
    match crate::aws::sign::sign_request(aws, &req.method, &full_url, &filtered_headers, &body)
        .await
    {
        Ok(sign_headers) => {
            debug!(
                "tls_intercept: SigV4 signing succeeded; injecting {} headers",
                sign_headers.len(),
            );
            for (name, value) in &sign_headers {
                request.push_str(&format!("{}: {}\r\n", name, value));
            }
        }
        Err(e) => {
            let svc = service.unwrap_or("unknown");
            let reason = format!(
                "AWS credential resolution failed for route '{}': {}",
                svc, e
            );
            warn!("tls_intercept: {}", reason);
            audit::log_denied(
                ctx.audit_log,
                audit::ProxyMode::ConnectIntercept,
                &audit::EventContext {
                    route_id: service,
                    auth_mechanism: route.and_then(|r| r.managed_auth_mechanism.clone()),
                    auth_outcome: Some(nono::undo::NetworkAuditAuthOutcome::Failed),
                    managed_credential_active: Some(false),
                    injection_mode: route.and_then(|r| r.managed_injection_mode.clone()),
                    denial_category: Some(
                        nono::undo::NetworkAuditDenialCategory::ManagedCredentialUnavailable,
                    ),
                    ..audit::EventContext::default()
                },
                ctx.host,
                ctx.port,
                &reason,
            );
            reverse::send_error_generic(tls_stream, 502, "Bad Gateway").await?;
            return Ok(());
        }
    }

    for (name, value) in &filtered_headers {
        request.push_str(&format!("{}: {}\r\n", name, value));
    }
    request.push_str("Connection: close\r\n");
    if !body.is_empty() {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");

    // --- Forward via shared pipeline ---
    let connector = route
        .and_then(|r| r.tls_connector.as_ref())
        .unwrap_or(ctx.tls_connector);
    let strategy = select_upstream_strategy(&ctx.upstream_proxy, &resolved_addrs);
    let upstream_spec = UpstreamSpec {
        scheme: UpstreamScheme::Https,
        host: ctx.host,
        port: ctx.port,
        strategy,
        tls_connector: connector,
    };
    let event_ctx = audit::EventContext {
        route_id: service,
        auth_mechanism: Some(nono::undo::NetworkAuditAuthMechanism::PhantomHeader),
        auth_outcome: Some(nono::undo::NetworkAuditAuthOutcome::Succeeded),
        managed_credential_active: Some(true),
        injection_mode: Some(nono::undo::NetworkAuditInjectionMode::Header),
        denial_category: None,
        ..audit::EventContext::default()
    };
    let audit_ctx = AuditCtx {
        log: ctx.audit_log,
        mode: audit::ProxyMode::ConnectIntercept,
        event_ctx: event_ctx.clone(),
        target: ctx.host,
        method: &req.method,
        path: &req.path,
    };
    if let Err(e) = forward::forward_request(
        tls_stream,
        request.as_bytes(),
        &body,
        upstream_spec,
        audit_ctx,
    )
    .await
    {
        warn!("tls_intercept: upstream forwarding failed: {}", e);
        audit::log_denied(
            ctx.audit_log,
            audit::ProxyMode::ConnectIntercept,
            &audit::EventContext {
                denial_category: Some(
                    nono::undo::NetworkAuditDenialCategory::UpstreamConnectFailed,
                ),
                ..event_ctx
            },
            ctx.host,
            ctx.port,
            &e.to_string(),
        );
        let _ = reverse::send_error_generic(tls_stream, 502, "Bad Gateway").await;
    }
    Ok(())
}

/// Parse a request line into (method, path, version).
fn parse_request_line(line: &str) -> Result<(String, String, String)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 3 {
        return Err(ProxyError::HttpParse(format!(
            "malformed inner request line: {}",
            line
        )));
    }
    Ok((
        parts[0].to_string(),
        parts[1].to_string(),
        parts[2].to_string(),
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    #[test]
    fn parse_request_line_extracts_components() {
        let (m, p, v) = parse_request_line("GET /v1/models HTTP/1.1").unwrap();
        assert_eq!(m, "GET");
        assert_eq!(p, "/v1/models");
        assert_eq!(v, "HTTP/1.1");
    }

    #[test]
    fn parse_request_line_rejects_malformed() {
        assert!(parse_request_line("malformed").is_err());
        assert!(parse_request_line("").is_err());
    }

    #[test]
    fn upstream_strategy_selects_external_proxy_when_configured() {
        // When InterceptUpstreamProxy is set, the strategy must be
        // ExternalProxy, not Direct. Regression test for #1048.
        let proxy = InterceptUpstreamProxy {
            proxy_addr: "proxy.corp:80",
            proxy_auth_header: None,
        };
        let some_proxy = Some(proxy);
        let strategy = select_upstream_strategy(&some_proxy, &[]);
        match strategy {
            UpstreamStrategy::ExternalProxy {
                proxy_addr,
                proxy_auth_header,
            } => {
                assert_eq!(proxy_addr, "proxy.corp:80");
                assert!(proxy_auth_header.is_none());
            }
            UpstreamStrategy::Direct { .. } => {
                panic!("expected ExternalProxy strategy, got Direct");
            }
        }
    }

    #[test]
    fn upstream_strategy_selects_direct_when_no_proxy() {
        // When upstream_proxy is None, the strategy must fall back to
        // Direct (pre-existing behaviour).
        let addrs: Vec<std::net::SocketAddr> = vec![];
        let strategy = select_upstream_strategy(&None, &addrs);
        match strategy {
            UpstreamStrategy::Direct { resolved_addrs } => {
                assert!(resolved_addrs.is_empty());
            }
            UpstreamStrategy::ExternalProxy { .. } => {
                panic!("expected Direct strategy, got ExternalProxy");
            }
        }
    }

    #[test]
    fn upstream_strategy_external_proxy_with_auth_header() {
        // When auth header is provided, it must be carried through.
        let proxy = InterceptUpstreamProxy {
            proxy_addr: "proxy.corp:3128",
            proxy_auth_header: Some("Basic dXNlcjpwYXNz"),
        };
        let some_proxy = Some(proxy);
        let strategy = select_upstream_strategy(&some_proxy, &[]);
        match strategy {
            UpstreamStrategy::ExternalProxy {
                proxy_addr,
                proxy_auth_header,
            } => {
                assert_eq!(proxy_addr, "proxy.corp:3128");
                assert_eq!(proxy_auth_header, Some("Basic dXNlcjpwYXNz"));
            }
            UpstreamStrategy::Direct { .. } => {
                panic!("expected ExternalProxy strategy, got Direct");
            }
        }
    }

    #[tokio::test]
    async fn h2_tls_connector_for_target_uses_custom_route_config() {
        let ca = crate::tls_intercept::ca::EphemeralCa::generate().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("upstream-ca.pem");
        std::fs::write(&ca_path, ca.cert_pem()).unwrap();

        let routes = vec![route_config(
            "custom",
            "localhost",
            9443,
            Some(ca_path.to_string_lossy().as_ref()),
        )];
        let route_store = RouteStore::load(&routes).await.unwrap();
        let default_connector = test_default_h2_connector();

        let (_connector, key) =
            select_h2_tls_connector_for_target(&route_store, "localhost", 9443, &default_connector)
                .unwrap();

        assert!(
            key.starts_with("route:"),
            "custom route TLS config should be selected for h2"
        );
    }

    #[tokio::test]
    async fn h2_tls_connector_for_target_accepts_matching_custom_route_configs() {
        let ca = crate::tls_intercept::ca::EphemeralCa::generate().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("upstream-ca.pem");
        std::fs::write(&ca_path, ca.cert_pem()).unwrap();
        let ca_path = ca_path.to_string_lossy();

        let routes = vec![
            route_config("custom-a", "localhost", 9443, Some(ca_path.as_ref())),
            route_config("custom-b", "localhost", 9443, Some(ca_path.as_ref())),
        ];
        let route_store = RouteStore::load(&routes).await.unwrap();
        let default_connector = test_default_h2_connector();

        let (_connector, key) =
            select_h2_tls_connector_for_target(&route_store, "localhost", 9443, &default_connector)
                .unwrap();

        assert!(
            key.starts_with("route:"),
            "matching custom route TLS configs can share an h2 upstream"
        );
    }

    #[tokio::test]
    async fn h2_tls_connector_for_target_rejects_mixed_route_configs() {
        let ca = crate::tls_intercept::ca::EphemeralCa::generate().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("upstream-ca.pem");
        std::fs::write(&ca_path, ca.cert_pem()).unwrap();

        let routes = vec![
            route_config("default", "localhost", 9443, None),
            route_config(
                "custom",
                "localhost",
                9443,
                Some(ca_path.to_string_lossy().as_ref()),
            ),
        ];
        let route_store = RouteStore::load(&routes).await.unwrap();
        let default_connector = test_default_h2_connector();

        assert!(
            select_h2_tls_connector_for_target(
                &route_store,
                "localhost",
                9443,
                &default_connector,
            )
            .is_err(),
            "h2 should not guess between incompatible route TLS configs"
        );
    }

    fn route_config(
        prefix: &str,
        host: &str,
        port: u16,
        tls_ca: Option<&str>,
    ) -> crate::config::RouteConfig {
        crate::config::RouteConfig {
            prefix: prefix.to_string(),
            upstream: format!("https://{}:{}", host, port),
            credential_key: Some(format!("env://{}_TOKEN", prefix.to_uppercase())),
            inject_mode: crate::config::InjectMode::Header,
            inject_header: "Authorization".to_string(),
            credential_format: Some("Bearer {}".to_string()),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: None,
            endpoint_rules: vec![crate::config::EndpointRule {
                method: "*".to_string(),
                path: "/**".to_string(),
            }],
            tls_ca: tls_ca.map(str::to_string),
            tls_client_cert: None,
            tls_client_key: None,
            oauth2: None,
            aws_auth: None,
            endpoint_policy: None,
            spiffe: None,
        }
    }

    /// Two managed-credential routes sharing one upstream with disjoint
    /// `endpoint_rules` must each authorize their own path and inject their own
    /// credential; a path covered by neither is an un-credentialed passthrough.
    /// Regression test: a sibling route's legacy default-deny must not
    /// hard-deny (403) a request another route on the same upstream allows.
    #[tokio::test]
    async fn select_intercept_route_disjoint_credential_routes_do_not_cross_deny() {
        fn cred_route(prefix: &str, path: &str) -> crate::config::RouteConfig {
            crate::config::RouteConfig {
                prefix: prefix.to_string(),
                upstream: "https://example.com".to_string(),
                credential_key: Some(format!("env://{}_TOKEN", prefix.to_uppercase())),
                inject_mode: crate::config::InjectMode::Header,
                inject_header: "Authorization".to_string(),
                credential_format: Some("Bearer {}".to_string()),
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                proxy: None,
                env_var: None,
                endpoint_rules: vec![crate::config::EndpointRule {
                    method: "GET".to_string(),
                    path: path.to_string(),
                }],
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
                aws_auth: None,
                endpoint_policy: None,
                spiffe: None,
            }
        }

        let routes = vec![cred_route("foo", "/foo"), cred_route("bar", "/bar")];
        let store = RouteStore::load(&routes).await.unwrap();

        // Each path selects its own route; the sibling route's default-deny must
        // not turn this into a 403.
        match select_intercept_route(&store, "example.com", 443, "GET", "/foo", None, None).await {
            RouteSelection::Selected(Some((svc, _))) => assert_eq!(svc, "foo"),
            RouteSelection::Selected(None) => {
                panic!("/foo must select the foo route, not passthrough")
            }
            RouteSelection::Rejected(status) => {
                panic!("/foo must be allowed, got rejection with status {status}")
            }
        }
        match select_intercept_route(&store, "example.com", 443, "GET", "/bar", None, None).await {
            RouteSelection::Selected(Some((svc, _))) => assert_eq!(svc, "bar"),
            RouteSelection::Selected(None) => {
                panic!("/bar must select the bar route, not passthrough")
            }
            RouteSelection::Rejected(status) => {
                panic!("/bar must be allowed, got rejection with status {status}")
            }
        }
        // A path covered by neither route: passthrough without credentials, not a 403.
        match select_intercept_route(&store, "example.com", 443, "GET", "/other", None, None).await
        {
            RouteSelection::Selected(None) => {}
            RouteSelection::Selected(Some((svc, _))) => {
                panic!("/other must not inject a credential, selected route '{svc}'")
            }
            RouteSelection::Rejected(status) => {
                panic!("/other must pass through, got rejection with status {status}")
            }
        }
    }

    fn test_default_h2_connector() -> tokio_rustls::TlsConnector {
        let mut config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];
        tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
    }

    // --- resolve_nonce_in_header_value tests ---

    struct TestResolver {
        nonce: String,
        real: Vec<u8>,
        admitted_consumer: String,
    }

    impl crate::token::NonceResolver for TestResolver {
        fn resolve(&self, nonce: &str, consumer: &str) -> Option<Zeroizing<Vec<u8>>> {
            if nonce == self.nonce && consumer == self.admitted_consumer {
                Some(Zeroizing::new(self.real.clone()))
            } else {
                None
            }
        }
    }

    fn make_nonce() -> String {
        format!("nono_{}", "a".repeat(64))
    }

    #[test]
    fn resolves_bearer_nonce() {
        let nonce = make_nonce();
        let resolver = TestResolver {
            nonce: nonce.clone(),
            real: b"sk-ant-real".to_vec(),
            admitted_consumer: "proxy.anthropic".to_string(),
        };
        let value = format!("Bearer {nonce}");
        let result = resolve_nonce_in_header_value(&value, "proxy.anthropic", &resolver);
        assert_eq!(result, Some("Bearer sk-ant-real".to_string()));
    }

    #[test]
    fn returns_none_for_unadmitted_consumer() {
        let nonce = make_nonce();
        let resolver = TestResolver {
            nonce: nonce.clone(),
            real: b"sk-ant-real".to_vec(),
            admitted_consumer: "proxy.anthropic".to_string(),
        };
        let value = format!("Bearer {nonce}");
        let result = resolve_nonce_in_header_value(&value, "proxy.other", &resolver);
        assert!(result.is_none(), "unadmitted consumer must not resolve");
    }

    #[test]
    fn returns_none_when_no_nonce_present() {
        let resolver = TestResolver {
            nonce: make_nonce(),
            real: b"secret".to_vec(),
            admitted_consumer: "proxy.anthropic".to_string(),
        };
        let result =
            resolve_nonce_in_header_value("Bearer plain-token", "proxy.anthropic", &resolver);
        assert!(result.is_none());
    }

    #[test]
    fn preserves_prefix_and_suffix_around_nonce() {
        let nonce = make_nonce();
        let resolver = TestResolver {
            nonce: nonce.clone(),
            real: b"REAL".to_vec(),
            admitted_consumer: "proxy.svc".to_string(),
        };
        let value = format!("prefix-{nonce}-suffix");
        let result = resolve_nonce_in_header_value(&value, "proxy.svc", &resolver);
        assert_eq!(result, Some("prefix-REAL-suffix".to_string()));
    }
}
