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
use crate::config::InjectMode;
use crate::credential::CredentialStore;
use crate::error::{ProxyError, Result};
use crate::filter::ProxyFilter;
use crate::forward::{self, AuditCtx, UpstreamScheme, UpstreamSpec, UpstreamStrategy};
use crate::reverse;
use crate::route::RouteStore;
use crate::tls_intercept::acceptor;
use crate::tls_intercept::cert_cache::CertCache;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, warn};
use zeroize::Zeroizing;

/// Header byte cap matching the outer proxy's `MAX_HEADER_SIZE` to keep the
/// memory ceiling consistent.
const MAX_HEADER_SIZE: usize = 64 * 1024;

/// Per-connection context passed to [`handle_intercept_connect`].
pub struct InterceptCtx<'a> {
    pub route_id: Option<&'a str>,
    pub host: &'a str,
    pub port: u16,
    pub route_store: &'a RouteStore,
    pub credential_store: &'a CredentialStore,
    pub session_token: &'a Zeroizing<String>,
    pub cert_cache: Arc<CertCache>,
    pub tls_connector: &'a tokio_rustls::TlsConnector,
    pub filter: &'a ProxyFilter,
    pub audit_log: Option<&'a audit::SharedAuditLog>,
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

    let server_config = acceptor::build_server_config(Arc::clone(&ctx.cert_cache))?;
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

    if let Err(e) = forward_inner_request(&mut tls_stream, &ctx).await {
        debug!(
            "tls_intercept: inner-request handling failed for {}:{}: {}",
            ctx.host, ctx.port, e
        );
    }
    Ok(())
}

/// Read one inner HTTP/1.1 request, select the matching route, inject
/// credentials if matched, and forward upstream.
async fn forward_inner_request<S>(tls_stream: &mut S, ctx: &InterceptCtx<'_>) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut buf_reader = BufReader::new(&mut *tls_stream);
    let mut first_line = String::new();
    buf_reader.read_line(&mut first_line).await?;
    if first_line.is_empty() {
        return Ok(());
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
            let buffered = buf_reader.buffer().to_vec();
            drop(buf_reader);
            tls_stream
                .write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n")
                .await?;
            let _ = buffered;
            return Ok(());
        }
    }
    let buffered = buf_reader.buffer().to_vec();
    drop(buf_reader);

    let first_line = first_line.trim_end();
    let (method, path, version) = parse_request_line(first_line)?;
    debug!("tls_intercept: inner request {} {}", method, path);

    // Route selection: 1 match → cred, 0 → passthrough, 2+ → 403.
    let host_port = format!("{}:{}", ctx.host.to_lowercase(), ctx.port);
    let candidates = ctx.route_store.lookup_all_by_upstream(&host_port);
    if candidates.is_empty() {
        warn!(
            "tls_intercept: no route for {} after intercept handshake",
            host_port
        );
        reverse::send_error_generic(tls_stream, 502, "Bad Gateway").await?;
        return Ok(());
    }

    let mut matches: Vec<(&str, &crate::route::LoadedRoute)> = Vec::new();
    let mut catch_all: Option<(&str, &crate::route::LoadedRoute)> = None;
    let mut has_endpoint_only_route = false;
    let mut endpoint_authorized = false;
    for (prefix, route) in &candidates {
        if route.endpoint_rules.is_empty() {
            if catch_all.is_none() {
                catch_all = Some((prefix, route));
            }
        } else if route.endpoint_rules.is_allowed(&method, &path) {
            matches.push((prefix, route));
            if !route.requires_managed_credential {
                endpoint_authorized = true;
            }
        } else if !route.requires_managed_credential {
            has_endpoint_only_route = true;
        }
    }

    // Endpoint-only authorization layer (from allow_domain with endpoints):
    // if any _ep_ route exists for this upstream, the request must match at
    // least one of their endpoint rules. This gates access BEFORE credential
    // selection — a credential catch-all cannot bypass endpoint restrictions.
    if has_endpoint_only_route && !endpoint_authorized {
        let reason = format!(
            "endpoint rules denied {} {}: no rule matched on {}:{}",
            method, path, ctx.host, ctx.port
        );
        warn!("tls_intercept: {}", reason);
        audit::log_denied(
            ctx.audit_log,
            audit::ProxyMode::ConnectIntercept,
            &audit::EventContext {
                denial_category: Some(nono::undo::NetworkAuditDenialCategory::EndpointPolicy),
                ..audit::EventContext::default()
            },
            ctx.host,
            ctx.port,
            &reason,
        );
        reverse::send_error_generic(tls_stream, 403, "Forbidden").await?;
        return Ok(());
    }

    // Ambiguous route check only applies to credential-injection routes.
    // Multiple endpoint-only authorization routes matching the same request
    // is fine (they all just allow it); ambiguity is a problem only when the
    // proxy must choose which credential to inject.
    let credential_matches: Vec<_> = matches
        .iter()
        .filter(|(_, route)| route.requires_managed_credential)
        .collect();
    if credential_matches.len() > 1 {
        let names: Vec<_> = credential_matches.iter().map(|(p, _)| *p).collect();
        let reason = format!(
            "ambiguous route: {} {} matched {} credential routes: {:?}. \
             Narrow endpoint_rules so each request matches exactly one route.",
            method,
            path,
            credential_matches.len(),
            names
        );
        warn!("tls_intercept: {}", reason);
        audit::log_denied(
            ctx.audit_log,
            audit::ProxyMode::ConnectIntercept,
            &audit::EventContext {
                denial_category: Some(nono::undo::NetworkAuditDenialCategory::EndpointPolicy),
                ..audit::EventContext::default()
            },
            ctx.host,
            ctx.port,
            &reason,
        );
        reverse::send_error_generic(tls_stream, 403, "Forbidden").await?;
        return Ok(());
    }

    // Prefer the credential route over endpoint-only authorization routes.
    let selected = matches
        .iter()
        .find(|(_, route)| route.requires_managed_credential)
        .or(matches.first())
        .copied()
        .or(catch_all);
    let service: Option<&str> = selected.map(|(s, _)| s);
    let route: Option<&crate::route::LoadedRoute> = selected.map(|(_, r)| r);
    match service {
        Some(svc) => debug!(
            "tls_intercept: selected route '{}' for {} {}",
            svc, method, path
        ),
        None => debug!(
            "tls_intercept: no endpoint_rules matched {} {}, forwarding without credentials",
            method, path
        ),
    }

    let cred = service.and_then(|s| ctx.credential_store.get(s));
    let oauth2_route = service.and_then(|s| ctx.credential_store.get_oauth2(s));

    if let Some(rt) = route
        && rt.missing_managed_credential(cred.is_some(), oauth2_route.is_some())
    {
        let svc = service.unwrap_or("unknown");
        let reason = format!(
            "managed credential unavailable for route '{}': intercepted request requires proxy-supplied auth",
            svc
        );
        warn!("tls_intercept: {}", reason);
        audit::log_denied(
            ctx.audit_log,
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
            },
            ctx.host,
            ctx.port,
            &reason,
        );
        reverse::send_error_generic(tls_stream, 503, "Service Unavailable").await?;
        return Ok(());
    }

    let transformed_path = if let Some(cred) = cred {
        let cleaned = reverse::strip_proxy_artifacts(
            &path,
            &cred.proxy_inject_mode,
            &cred.inject_mode,
            cred.proxy_path_pattern.as_deref(),
            cred.proxy_query_param_name.as_deref(),
        );
        reverse::transform_path_for_mode(
            &cred.inject_mode,
            &cleaned,
            cred.path_pattern.as_deref(),
            cred.path_replacement.as_deref(),
            cred.query_param_name.as_deref(),
            &cred.raw_credential,
        )?
    } else {
        path.clone()
    };

    let check = ctx.filter.check_host(ctx.host, ctx.port).await?;
    if !check.result.is_allowed() {
        let reason = check.result.reason();
        warn!("tls_intercept: upstream host denied by filter: {}", reason);
        audit::log_denied(
            ctx.audit_log,
            audit::ProxyMode::ConnectIntercept,
            &audit::EventContext {
                route_id: service,
                managed_credential_active: Some(cred.is_some() || oauth2_route.is_some()),
                injection_mode: cred.map(|c| match c.inject_mode {
                    InjectMode::Header => nono::undo::NetworkAuditInjectionMode::Header,
                    InjectMode::UrlPath => nono::undo::NetworkAuditInjectionMode::UrlPath,
                    InjectMode::QueryParam => nono::undo::NetworkAuditInjectionMode::QueryParam,
                    InjectMode::BasicAuth => nono::undo::NetworkAuditInjectionMode::BasicAuth,
                }),
                denial_category: Some(nono::undo::NetworkAuditDenialCategory::HostDenied),
                ..audit::EventContext::default()
            },
            ctx.host,
            ctx.port,
            &reason,
        );
        reverse::send_error_generic(tls_stream, 403, "Forbidden").await?;
        return Ok(());
    }

    // --- Read body (Content-Length only; chunked is rare in API requests
    // and matches the existing reverse-proxy contract). ---
    let strip_header = cred.map(|c| c.proxy_header_name.as_str()).unwrap_or("");
    let filtered_headers = reverse::filter_headers(&header_bytes, strip_header);
    let content_length = reverse::extract_content_length(&header_bytes);
    let body = match reverse::read_request_body(tls_stream, content_length, &buffered).await? {
        Some(b) => b,
        None => return Ok(()),
    };

    let upstream_authority = reverse::format_host_header(UpstreamScheme::Https, ctx.host, ctx.port);
    let mut request = Zeroizing::new(format!(
        "{} {} {}\r\nHost: {}\r\n",
        method, transformed_path, version, upstream_authority
    ));
    if let Some(cred) = cred {
        reverse::inject_credential_for_mode(cred, &mut request);
    }
    let auth_header_lower = cred.map(|c| c.header_name.to_lowercase());
    for (name, value) in &filtered_headers {
        if let (Some(cred), Some(hdr)) = (cred, auth_header_lower.as_ref())
            && matches!(cred.inject_mode, InjectMode::Header | InjectMode::BasicAuth)
            && name.to_lowercase() == *hdr
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

    let connector = route
        .and_then(|r| r.tls_connector.as_ref())
        .unwrap_or(ctx.tls_connector);
    let upstream_spec = UpstreamSpec {
        scheme: UpstreamScheme::Https,
        host: ctx.host,
        port: ctx.port,
        strategy: UpstreamStrategy::Direct {
            resolved_addrs: &check.resolved_addrs,
        },
        tls_connector: connector,
    };
    let audit_ctx = AuditCtx {
        log: ctx.audit_log,
        mode: audit::ProxyMode::ConnectIntercept,
        event_ctx: audit::EventContext {
            route_id: service,
            auth_mechanism: cred.map(|c| match c.proxy_inject_mode {
                InjectMode::Header | InjectMode::BasicAuth => {
                    nono::undo::NetworkAuditAuthMechanism::PhantomHeader
                }
                InjectMode::UrlPath => nono::undo::NetworkAuditAuthMechanism::PhantomPath,
                InjectMode::QueryParam => nono::undo::NetworkAuditAuthMechanism::PhantomQuery,
            }),
            auth_outcome: cred.map(|_| nono::undo::NetworkAuditAuthOutcome::Succeeded),
            managed_credential_active: Some(cred.is_some() || oauth2_route.is_some()),
            injection_mode: cred.map(|c| match c.inject_mode {
                InjectMode::Header => nono::undo::NetworkAuditInjectionMode::Header,
                InjectMode::UrlPath => nono::undo::NetworkAuditInjectionMode::UrlPath,
                InjectMode::QueryParam => nono::undo::NetworkAuditInjectionMode::QueryParam,
                InjectMode::BasicAuth => nono::undo::NetworkAuditInjectionMode::BasicAuth,
            }),
            denial_category: None,
        },
        target: ctx.host,
        method: &method,
        path: &path,
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
                route_id: service,
                auth_mechanism: cred.map(|c| match c.proxy_inject_mode {
                    InjectMode::Header | InjectMode::BasicAuth => {
                        nono::undo::NetworkAuditAuthMechanism::PhantomHeader
                    }
                    InjectMode::UrlPath => nono::undo::NetworkAuditAuthMechanism::PhantomPath,
                    InjectMode::QueryParam => nono::undo::NetworkAuditAuthMechanism::PhantomQuery,
                }),
                auth_outcome: cred.map(|_| nono::undo::NetworkAuditAuthOutcome::Succeeded),
                managed_credential_active: Some(cred.is_some() || oauth2_route.is_some()),
                injection_mode: cred.map(|c| match c.inject_mode {
                    InjectMode::Header => nono::undo::NetworkAuditInjectionMode::Header,
                    InjectMode::UrlPath => nono::undo::NetworkAuditInjectionMode::UrlPath,
                    InjectMode::QueryParam => nono::undo::NetworkAuditInjectionMode::QueryParam,
                    InjectMode::BasicAuth => nono::undo::NetworkAuditInjectionMode::BasicAuth,
                }),
                denial_category: Some(
                    nono::undo::NetworkAuditDenialCategory::UpstreamConnectFailed,
                ),
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
}
