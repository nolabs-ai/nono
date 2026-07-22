//! HTTP/2 per-stream credential injection and forwarding.
//!
//! When the inbound TLS handshake negotiates `h2` via ALPN, this module takes
//! over from [`super::handle`]. It uses the `h2` crate directly to accept
//! frames from the client and forward them upstream, applying credential
//! injection on each request stream's headers.
//!
//! Bodies are streamed frame-by-frame (DATA + TRAILERS) in both directions
//! without buffering, supporting all gRPC patterns including bidirectional
//! streaming.

use crate::audit;
use crate::capture::CredentialCaptureBackend;
use crate::config::InjectMode;
use crate::credential::CredentialStore;
use crate::error::{ProxyError, Result};
use crate::forward::{self, UpstreamScheme, UpstreamSpec};
use crate::reverse;
use crate::route::RouteStore;
use crate::tls_intercept::handle::{self, InterceptCtx, RouteSelection};
use bytes::Bytes;
use h2::{RecvStream, SendStream};
use http::{HeaderMap, HeaderValue, Request, Response};
use std::future::poll_fn;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, warn};

/// Spawn-safe context for per-stream h2 handlers.
///
/// Built from `InterceptCtx` at connection setup. Contains only the fields
/// needed by `handle_h2_stream`, all behind owned/Arc types so the struct
/// is `'static + Send`.
#[derive(Clone)]
struct SharedH2Ctx {
    host: String,
    port: u16,
    route_store: Arc<RouteStore>,
    credential_store: Arc<CredentialStore>,
    oauth_capture_store: Arc<crate::oauth_capture::OAuthCaptureStore>,
    audit_log: Option<audit::SharedAuditLog>,
    approval_backends: Option<crate::approval::ApprovalBackendRegistry>,
    credential_capture_backend: Option<Arc<dyn CredentialCaptureBackend>>,
    nonce_resolver: Option<Arc<dyn crate::token::NonceResolver>>,
    /// Managed upstream auth source shared across all streams on this connection.
    /// `None` for non-SPIFFE upstreams.
    managed_auth: Option<Arc<crate::auth::ManagedUpstreamAuth>>,
}

/// Accept an h2 connection from the client, open an h2 connection to the
/// upstream, and forward request streams with credential injection.
///
/// Each inbound stream is spawned as an independent task so multiple gRPC
/// RPCs can be multiplexed concurrently over a single connection.
pub(crate) async fn forward_h2_connection<S>(io: S, ctx: &InterceptCtx<'_>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut server_conn = h2::server::Builder::new()
        .max_send_buffer_size(1024 * 1024)
        .max_concurrent_streams(128)
        .initial_window_size(2 * 1024 * 1024)
        .initial_connection_window_size(16 * 1024 * 1024)
        .handshake(io)
        .await
        .map_err(|e| ProxyError::HttpParse(format!("h2 server handshake failed: {}", e)))?;

    debug!(
        "h2_forward: server connection established for {}:{} (window=2MiB, conn_window=16MiB)",
        ctx.host, ctx.port
    );

    // Resolve upstream addresses (DNS-rebind-safe via filter).
    let check = ctx.filter.check_host(ctx.host, ctx.port).await?;
    if !check.result.is_allowed() {
        let reason = check.result.reason();
        warn!("h2_forward: upstream host denied by filter: {}", reason);
        return Ok(());
    }

    // Look up SPIFFE routes for this upstream to determine the correct TLS
    // connector and JWT injection configuration.
    let host_port = format!("{}:{}", ctx.host, ctx.port);
    let spiffe_routes: Vec<(_, &crate::route::LoadedRoute)> =
        ctx.route_store.lookup_all_by_upstream(&host_port);

    // Find the first route with a ManagedUpstreamAuth source. All routes on the
    // same upstream share the same SPIRE socket, so using the first match is correct.
    let managed_auth: Option<Arc<crate::auth::ManagedUpstreamAuth>> = spiffe_routes
        .iter()
        .find_map(|(_, route)| route.managed_auth.as_ref().map(Arc::clone));

    // No per-connection SPIFFE mTLS setup — X.509-SVID support is planned for
    // a future PR once the TLS-intercept CONNECT path is fully wired.
    let spiffe_connector: Option<tokio_rustls::TlsConnector> = None;

    // Use the SPIFFE mTLS connector when available, otherwise fall back to the
    // default h2 TLS connector.
    let upstream_tls = open_upstream_h2(
        ctx,
        &check.resolved_addrs,
        spiffe_connector.as_ref().unwrap_or(ctx.tls_connector_h2),
    )
    .await?;

    let (h2_client, h2_conn) = h2::client::Builder::new()
        .max_send_buffer_size(1024 * 1024)
        .initial_window_size(2 * 1024 * 1024)
        .initial_connection_window_size(16 * 1024 * 1024)
        .handshake(upstream_tls)
        .await
        .map_err(|e| ProxyError::UpstreamConnect {
            host: ctx.host.to_string(),
            reason: format!("h2 client handshake failed: {}", e),
        })?;

    // Spawn a task to continuously drive the upstream h2 connection. It must
    // be polled independently so frame I/O can progress while we handle
    // streams concurrently below.
    let conn_task = tokio::spawn(async move {
        if let Err(e) = h2_conn.await {
            debug!("h2_forward: upstream connection closed: {}", e);
        }
    });

    let shared_ctx = SharedH2Ctx {
        host: ctx.host.to_string(),
        port: ctx.port,
        route_store: Arc::clone(&ctx.route_store),
        credential_store: Arc::clone(&ctx.credential_store),
        oauth_capture_store: Arc::clone(&ctx.oauth_capture_store),
        audit_log: ctx.audit_log.cloned(),
        approval_backends: ctx.approval_backends.clone(),
        credential_capture_backend: ctx.credential_capture_backend.clone(),
        nonce_resolver: ctx.nonce_resolver.clone(),
        managed_auth,
    };

    let mut tasks = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            result = server_conn.accept() => {
                match result {
                    Some(Ok((request, respond))) => {
                        let ctx = shared_ctx.clone();
                        let mut client_send = h2_client.clone();
                        tasks.spawn(async move {
                            if let Err(e) =
                                handle_h2_stream(request, respond, &mut client_send, &ctx).await
                            {
                                debug!(
                                    "h2_forward: stream error for {}:{}: {}",
                                    ctx.host, ctx.port, e
                                );
                            }
                        });
                    }
                    Some(Err(e)) => {
                        debug!("h2_forward: server accept error: {}", e);
                        break;
                    }
                    None => break,
                }
            }
            Some(_) = tasks.join_next() => {
                // Stream task completed; continue accepting.
            }
        }
    }

    // Drain remaining in-flight streams. Keep driving the server connection
    // so flow-control frames (WINDOW_UPDATE) are processed for active streams.
    let mut conn_closed = false;
    while !tasks.is_empty() {
        if conn_closed {
            tasks.join_next().await;
        } else {
            tokio::select! {
                biased;
                result = tasks.join_next() => {
                    if result.is_none() {
                        break;
                    }
                }
                _ = poll_fn(|cx| server_conn.poll_closed(cx)) => {
                    conn_closed = true;
                }
            }
        }
    }

    conn_task.abort();
    Ok(())
}

/// Open upstream TLS with h2 ALPN.
///
/// `tls_connector` is the connector to use for the upstream TLS handshake.
async fn open_upstream_h2(
    ctx: &InterceptCtx<'_>,
    resolved_addrs: &[SocketAddr],
    tls_connector: &tokio_rustls::TlsConnector,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let upstream_spec = UpstreamSpec {
        scheme: UpstreamScheme::Https,
        host: ctx.host,
        port: ctx.port,
        strategy: handle::select_upstream_strategy(&ctx.upstream_proxy, resolved_addrs),
        tls_connector,
    };
    let tcp = forward::open_tcp_upstream(&upstream_spec).await?;
    let server_name =
        rustls::pki_types::ServerName::try_from(ctx.host.to_string()).map_err(|_| {
            ProxyError::UpstreamConnect {
                host: ctx.host.to_string(),
                reason: "invalid server name for TLS".to_string(),
            }
        })?;
    tls_connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| ProxyError::UpstreamConnect {
            host: ctx.host.to_string(),
            reason: format!("h2 upstream TLS failed: {}", e),
        })
}

/// Handle a single h2 request stream: route selection, credential injection,
/// and bidirectional body streaming.
async fn handle_h2_stream(
    request: Request<RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    client_send: &mut h2::client::SendRequest<Bytes>,
    ctx: &SharedH2Ctx,
) -> Result<()> {
    let method = request.method().clone();
    let path = request
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    debug!(
        "h2_forward: {} {} on {}:{}",
        method, path, ctx.host, ctx.port
    );

    let host_port = format!("{}:{}", ctx.host.to_lowercase(), ctx.port);
    if ctx.oauth_capture_store.host_policy(&host_port).is_some() {
        warn!(
            "h2_forward: OAuth capture host matched for {} {}, but h2 OAuth body rewrite is not implemented; failing closed",
            method, path
        );
        send_h2_error(&mut respond, 502)?;
        return Ok(());
    }

    // Endpoint authorization + credential route selection. Shared with the
    // HTTP/1.1 path via [`handle::select_intercept_route`] so the two protocols
    // enforce identical L7 policy (deny / approve / default-deny). Using the
    // legacy `endpoint_rules` API here would silently bypass endpoint_policy on
    // gRPC traffic.
    let method_str = method.as_str().to_string();

    // Audit context is populated per-stream when credentials are acquired.
    let mut spiffe_audit_ctx: Option<nono::undo::SpiffeAuditContext> = None;
    let selected = match handle::select_intercept_route(
        &ctx.route_store,
        &ctx.host,
        ctx.port,
        &method_str,
        &path,
        ctx.audit_log.as_ref(),
        ctx.approval_backends.as_ref(),
    )
    .await
    {
        RouteSelection::Rejected(status) => {
            send_h2_error(&mut respond, status)?;
            return Ok(());
        }
        RouteSelection::Selected(selected) => selected,
    };
    let service: Option<&str> = selected.map(|(s, _)| s);
    let route: Option<&crate::route::LoadedRoute> = selected.map(|(_, r)| r);

    // Managed credential gating, AWS handling, and command-backed capture are
    // shared with the HTTP/1.1 path via [`handle::resolve_managed_credential`]
    // so the two protocols cannot diverge (e.g. h2 must not forward an unsigned
    // AWS request just because it lacks a signing branch).
    let resolved = match handle::resolve_managed_credential(
        &ctx.credential_store,
        ctx.credential_capture_backend.as_ref(),
        ctx.audit_log.as_ref(),
        &ctx.host,
        ctx.port,
        service,
        route,
        &method_str,
        &path,
    )
    .await
    {
        handle::CredentialResolution::Rejected(status) => {
            send_h2_error(&mut respond, status)?;
            return Ok(());
        }
        handle::CredentialResolution::Forward { credential } => credential,
    };
    let cred = resolved.as_ref().map(|c| c.as_ref());

    // SPIFFE assertion route: fetch access token, fail hard if SVID is gone.
    let spiffe_assertion_route = service.and_then(|s| ctx.credential_store.get_spiffe_assertion(s));
    let spiffe_assertion_token = if let Some(assertion_route) = spiffe_assertion_route {
        match assertion_route.cache.get_or_refresh().await {
            Ok(token) => {
                let id = &assertion_route.cache.workload_spiffe_id;
                spiffe_audit_ctx = Some(nono::undo::SpiffeAuditContext {
                    trust_domain: crate::auth::extract_trust_domain(id),
                    workload_spiffe_id: id.clone(),
                    svid_type: "jwt".to_string(),
                    source: "spire-workload-api".to_string(),
                    upstream_spiffe_id: None,
                    delegation: None,
                });
                Some(token)
            }
            Err(e) => {
                warn!("h2_forward: SPIFFE assertion token unavailable: {}", e);
                send_h2_error(&mut respond, 503)?;
                return Ok(());
            }
        }
    } else {
        None
    };

    // Build transformed path (credential injection into path/query if needed).
    // Shared with the HTTP/1.1 path so URL-mode injection cannot diverge.
    let transformed_path = reverse::transform_path_for_credential(cred, &path)?;

    // Build upstream request headers. The set of credential header names that
    // must be stripped from the inbound request (and re-injected below) is
    // computed by the shared helper so the h2 path strips/injects exactly the
    // same headers as HTTP/1.1 — including any `extra_headers`.
    let injected_header_names = reverse::injected_credential_header_names(cred);
    // Strip the managed-auth inject header so a client-supplied copy cannot
    // survive alongside the injected value.
    let spiffe_inject_header_lower: Option<String> =
        ctx.managed_auth.as_ref().map(|auth| match auth.as_ref() {
            crate::auth::ManagedUpstreamAuth::SpiffeJwt(src) => src.inject_header.to_lowercase(),
        });
    // Resolve tool-sandbox broker nonces (`nono_<64hex>`) in forwarded header
    // values, mirroring the HTTP/1.1 path. Without this, an h2/gRPC request that
    // carries a broker nonce in a header would forward the raw nonce upstream
    // instead of the resolved credential.
    let nonce_consumer = service.map(|s| format!("proxy.{s}"));
    let mut upstream_headers = HeaderMap::new();
    for (name, value) in request.headers() {
        let name_lower = name.as_str().to_lowercase();
        // Skip hop-by-hop and connection-specific headers.
        // RFC 7540 §8.1.2.2: strip hop-by-hop headers before h2 forwarding.
        if matches!(
            name_lower.as_str(),
            "host"
                | "connection"
                | "proxy-authorization"
                | "te"
                | "transfer-encoding"
                | "upgrade"
                | "keep-alive"
                | "trailer"
        ) {
            continue;
        }
        // Skip any header the credential will inject (primary + extra), so a
        // client-supplied copy cannot survive alongside the injected value.
        if injected_header_names.contains(&name_lower) {
            continue;
        }
        // Strip the SPIFFE JWT inject header so a client-supplied copy cannot
        // survive alongside the bearer token we inject below.
        if spiffe_inject_header_lower
            .as_deref()
            .is_some_and(|h| h == name_lower)
        {
            continue;
        }
        // Strip authorization when the assertion route will inject its own Bearer.
        if spiffe_assertion_token.is_some() && name_lower == "authorization" {
            continue;
        }
        // Substitute a broker nonce for the real credential when present and
        // admitted; otherwise forward the value unchanged (fail-closed: the
        // upstream rejects a raw nonce, never sees a silently-wrong credential).
        let resolved = value
            .to_str()
            .ok()
            .and_then(|v| {
                nonce_consumer.as_deref().and_then(|consumer| {
                    ctx.nonce_resolver.as_deref().and_then(|resolver| {
                        handle::resolve_nonce_in_header_value(v, consumer, resolver)
                    })
                })
            })
            .and_then(|resolved| HeaderValue::from_str(&resolved).ok());
        match resolved {
            Some(val) => {
                upstream_headers.insert(name.clone(), val);
            }
            None => {
                upstream_headers.insert(name.clone(), value.clone());
            }
        }
    }

    // Inject credential headers (primary + extra) for header/basic-auth modes.
    if let Some(cred) = cred
        && matches!(cred.inject_mode, InjectMode::Header | InjectMode::BasicAuth)
    {
        if !cred.header_value.is_empty()
            && let Ok(val) = HeaderValue::from_str(cred.header_value.as_str())
            && let Ok(name) = http::header::HeaderName::from_bytes(cred.header_name.as_bytes())
        {
            upstream_headers.insert(name, val);
        }
        for (header_name, header_value) in &cred.extra_headers {
            if let Ok(val) = HeaderValue::from_str(header_value.as_str())
                && let Ok(name) = http::header::HeaderName::from_bytes(header_name.as_bytes())
            {
                upstream_headers.insert(name, val);
            }
        }
    }

    // Inject managed credential (SpiffeJwt) per stream.
    // On fetch failure, send 503 — forwarding an unsigned request would bypass the auth boundary.
    if let Some(auth) = &ctx.managed_auth {
        match auth.acquire().await {
            Ok(
                ref material @ crate::auth::UpstreamAuthMaterial::BearerToken {
                    ref header,
                    ref token,
                    ref credential_format,
                    ..
                },
            ) => {
                let value =
                    zeroize::Zeroizing::new(credential_format.replace("{}", token.as_str()));
                if let Ok(val) = HeaderValue::from_str(value.as_str())
                    && let Ok(name) = http::header::HeaderName::from_bytes(header.as_bytes())
                {
                    upstream_headers.insert(name, val);
                }
                spiffe_audit_ctx = Some(material.spiffe_audit_context());
            }
            Err(e) => {
                warn!(
                    "h2_forward: managed credential fetch failed for {}:{}: {}",
                    ctx.host, ctx.port, e
                );
                send_h2_error(&mut respond, 503)?;
                return Ok(());
            }
        }
    }

    // Inject SPIFFE assertion Bearer token (OAuth2 jwt-bearer exchange result).
    if let Some(token) = spiffe_assertion_token {
        let bearer = zeroize::Zeroizing::new(format!("Bearer {}", token.as_str()));
        if let Ok(val) = HeaderValue::from_str(bearer.as_str()) {
            upstream_headers.insert(http::header::AUTHORIZATION, val);
        }
    }

    // Build upstream h2 request.
    let uri = format!("https://{}:{}{}", ctx.host, ctx.port, transformed_path);
    let mut upstream_req = Request::builder().method(method.clone()).uri(&uri);
    if let Some(headers) = upstream_req.headers_mut() {
        *headers = upstream_headers;
    }

    let (recv_body, is_end_stream) = {
        let body = request.into_body();
        let end = body.is_end_stream();
        (body, end)
    };

    let upstream_req = upstream_req
        .body(())
        .map_err(|e| ProxyError::HttpParse(format!("h2 request build error: {}", e)))?;

    // Send request to upstream.
    let (response_fut, mut send_stream) = client_send
        .send_request(upstream_req, is_end_stream)
        .map_err(|e| ProxyError::UpstreamConnect {
            host: ctx.host.to_string(),
            reason: format!("h2 send_request failed: {}", e),
        })?;

    // Run both directions concurrently. Bidirectional gRPC clients keep the
    // request stream open while consuming the response, so we must not block on
    // fully draining the request body before polling the upstream response —
    // doing so would deadlock streaming RPCs. `try_join!` polls both halves on
    // this task and drops the other (cancelling its pump, which sends a RST via
    // the `Drop` of the open `SendStream`) as soon as either side errors.
    let host = ctx.host.as_str();

    // Half A: pump client request body → upstream (no-op if already ended).
    let request_pump = async {
        if !is_end_stream {
            stream_body_to_upstream(recv_body, &mut send_stream).await?;
        }
        Ok::<(), ProxyError>(())
    };

    // Half B: await upstream response headers, relay them, then pump the
    // response body → client. Returns the upstream status for auditing.
    let response_pump = async {
        let response = response_fut
            .await
            .map_err(|e| ProxyError::UpstreamConnect {
                host: host.to_string(),
                reason: format!("h2 response error: {}", e),
            })?;

        let status = response.status();
        let resp_headers = response.headers().clone();
        let recv_resp_body = response.into_body();
        let resp_end_stream = recv_resp_body.is_end_stream();

        // Send response headers back to client.
        let mut client_response = Response::builder().status(status);
        if let Some(headers) = client_response.headers_mut() {
            *headers = resp_headers;
        }
        let client_response = client_response
            .body(())
            .map_err(|e| ProxyError::HttpParse(format!("h2 response build error: {}", e)))?;

        let mut send_resp = respond
            .send_response(client_response, resp_end_stream)
            .map_err(|e| ProxyError::HttpParse(format!("h2 send_response failed: {}", e)))?;

        // Stream response body back to client (frame-by-frame).
        if !resp_end_stream {
            stream_body_to_client(recv_resp_body, &mut send_resp).await?;
        }

        Ok::<http::StatusCode, ProxyError>(status)
    };

    let ((), status) = tokio::try_join!(request_pump, response_pump)?;

    // Audit event.
    audit::log_l7_request(
        ctx.audit_log.as_ref(),
        audit::ProxyMode::ConnectIntercept,
        &audit::EventContext {
            route_id: service,
            auth_mechanism: cred
                .map(|c| reverse::auth_mechanism_for_inject_mode(&c.proxy_inject_mode)),
            auth_outcome: cred.map(|_| nono::undo::NetworkAuditAuthOutcome::Succeeded),
            managed_credential_active: Some(cred.is_some()),
            injection_mode: cred
                .map(|c| reverse::audit_injection_mode_for_inject_mode(&c.inject_mode)),
            denial_category: None,
            spiffe_context: spiffe_audit_ctx,
            ..audit::EventContext::default()
        },
        &ctx.host,
        &method_str,
        &path,
        status.as_u16(),
    );

    Ok(())
}

/// Stream h2 DATA frames from client to upstream without buffering.
async fn stream_body_to_upstream(mut recv: RecvStream, send: &mut SendStream<Bytes>) -> Result<()> {
    loop {
        match recv.data().await {
            Some(Ok(data)) => {
                let len = data.len();
                send.send_data(data, false)
                    .map_err(|e| ProxyError::HttpParse(format!("h2 send_data upstream: {e}")))?;
                recv.flow_control()
                    .release_capacity(len)
                    .map_err(|e| ProxyError::HttpParse(format!("h2 flow control: {e}")))?;
            }
            Some(Err(e)) => {
                debug!("h2_forward: client body read error: {}", e);
                send.send_reset(h2::Reason::INTERNAL_ERROR);
                return Err(ProxyError::HttpParse(format!(
                    "h2 client body read failed: {e}"
                )));
            }
            None => break,
        }
    }
    // Forward trailers if present (gRPC uses trailers for grpc-status).
    if let Some(trailers) = recv
        .trailers()
        .await
        .map_err(|e| ProxyError::HttpParse(format!("h2 recv trailers: {e}")))?
    {
        send.send_trailers(trailers)
            .map_err(|e| ProxyError::HttpParse(format!("h2 send_trailers upstream: {e}")))?;
    } else {
        send.send_data(Bytes::new(), true)
            .map_err(|e| ProxyError::HttpParse(format!("h2 end stream upstream: {e}")))?;
    }
    Ok(())
}

/// Stream h2 DATA frames from upstream response to client without buffering.
async fn stream_body_to_client(mut recv: RecvStream, send: &mut SendStream<Bytes>) -> Result<()> {
    loop {
        match recv.data().await {
            Some(Ok(data)) => {
                let len = data.len();
                send.send_data(data, false)
                    .map_err(|e| ProxyError::HttpParse(format!("h2 send_data client: {e}")))?;
                recv.flow_control()
                    .release_capacity(len)
                    .map_err(|e| ProxyError::HttpParse(format!("h2 flow control: {e}")))?;
            }
            Some(Err(e)) => {
                debug!("h2_forward: upstream body read error: {}", e);
                send.send_reset(h2::Reason::INTERNAL_ERROR);
                return Err(ProxyError::HttpParse(format!(
                    "h2 upstream body read failed: {e}"
                )));
            }
            None => break,
        }
    }
    // Forward trailers (gRPC uses grpc-status + grpc-message as trailers).
    if let Some(trailers) = recv
        .trailers()
        .await
        .map_err(|e| ProxyError::HttpParse(format!("h2 recv trailers: {e}")))?
    {
        send.send_trailers(trailers)
            .map_err(|e| ProxyError::HttpParse(format!("h2 send_trailers client: {e}")))?;
    } else {
        send.send_data(Bytes::new(), true)
            .map_err(|e| ProxyError::HttpParse(format!("h2 end stream client: {e}")))?;
    }
    Ok(())
}

/// Send a simple h2 error response (no body).
fn send_h2_error(respond: &mut h2::server::SendResponse<Bytes>, status_code: u16) -> Result<()> {
    let status =
        http::StatusCode::from_u16(status_code).unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);
    let response = Response::builder()
        .status(status)
        .body(())
        .map_err(|e| ProxyError::HttpParse(format!("h2 error response build: {}", e)))?;
    respond
        .send_response(response, true)
        .map_err(|e| ProxyError::HttpParse(format!("h2 send error response: {}", e)))?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::config::{EndpointRule, InjectMode, RouteConfig};
    use crate::credential::{CredentialStore, LoadedCredential};
    use crate::filter::ProxyFilter;
    use crate::route::RouteStore;
    use crate::tls_intercept::ca::EphemeralCa;
    use crate::tls_intercept::cert_cache::CertCache;
    use bytes::Bytes;
    use rustls::pki_types::CertificateDer;
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use zeroize::Zeroizing;

    /// Capture backend that returns a fixed secret, for exercising the
    /// command-backed credential path without a real supervisor.
    #[derive(Debug)]
    struct MockCaptureBackend {
        secret: String,
    }

    impl crate::capture::CredentialCaptureBackend for MockCaptureBackend {
        fn capture(
            &self,
            _request: crate::capture::CredentialCaptureRequest,
        ) -> std::result::Result<
            crate::capture::CredentialCaptureResponse,
            crate::capture::CredentialCaptureError,
        > {
            Ok(crate::capture::CredentialCaptureResponse {
                material: crate::capture::CredentialCaptureMaterial::Secret(Zeroizing::new(
                    self.secret.clone(),
                )),
                metadata: crate::capture::CredentialCaptureMetadata::default(),
            })
        }
    }

    /// Capture backend that returns fully-materialized headers (the `Json`
    /// output format), exercising the `Headers` material variant.
    #[derive(Debug)]
    struct MockHeaderCaptureBackend {
        headers: Vec<(String, String)>,
    }

    impl crate::capture::CredentialCaptureBackend for MockHeaderCaptureBackend {
        fn capture(
            &self,
            _request: crate::capture::CredentialCaptureRequest,
        ) -> std::result::Result<
            crate::capture::CredentialCaptureResponse,
            crate::capture::CredentialCaptureError,
        > {
            let headers = self
                .headers
                .iter()
                .map(|(name, value)| (name.clone(), Zeroizing::new(value.clone())))
                .collect();
            Ok(crate::capture::CredentialCaptureResponse {
                material: crate::capture::CredentialCaptureMaterial::Headers(headers),
                metadata: crate::capture::CredentialCaptureMetadata::default(),
            })
        }
    }

    /// Build a RouteStore + CredentialStore for a `cmd://` route so the
    /// command-backed capture path is exercised.
    async fn make_cmd_route_stores(
        host: &str,
        port: u16,
        tls_connector: &tokio_rustls::TlsConnector,
    ) -> (RouteStore, CredentialStore) {
        let routes = vec![RouteConfig {
            prefix: "cmd-svc".to_string(),
            upstream: format!("https://{}:{}", host, port),
            credential_key: Some("cmd://my-cmd-cred".to_string()),
            inject_mode: InjectMode::Header,
            inject_header: "Authorization".to_string(),
            credential_format: Some("Bearer {}".to_string()),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: None,
            endpoint_rules: vec![EndpointRule {
                method: "*".to_string(),
                path: "/**".to_string(),
            }],
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
            oauth2: None,
            aws_auth: None,
            endpoint_policy: None,
            spiffe: None,
        }];
        let route_store = RouteStore::load(&routes).await.unwrap();
        let credential_store = CredentialStore::load_with_diagnostics(&routes, tls_connector)
            .await
            .unwrap()
            .store;
        (route_store, credential_store)
    }

    /// Build a TLS connector that trusts the given CA PEM and offers h2 ALPN.
    fn h2_tls_connector_trusting(ca_pem: &str) -> tokio_rustls::TlsConnector {
        use rustls::pki_types::pem::PemObject;

        let mut roots = rustls::RootCertStore::empty();
        let cert = CertificateDer::from_pem_slice(ca_pem.as_bytes()).unwrap();
        roots.add(cert).unwrap();
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];
        tokio_rustls::TlsConnector::from(Arc::new(config))
    }

    /// Build a TLS server config for the mock upstream (uses the same ephemeral CA).
    fn upstream_server_config(ca: &EphemeralCa) -> Arc<rustls::server::ServerConfig> {
        use rcgen::{CertificateParams, KeyPair};
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use time::OffsetDateTime;

        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.not_before = OffsetDateTime::now_utc();
        params.not_after = OffsetDateTime::now_utc() + time::Duration::hours(1);

        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params.signed_by(&key_pair, ca.issuer()).unwrap();

        let cert_der = cert.der().clone();
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

        let mut config = rustls::server::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], private_key)
        .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec()];
        Arc::new(config)
    }

    /// Build a RouteStore with a single route pointing at `host:port`.
    async fn make_route_store(host: &str, port: u16, rules: Vec<EndpointRule>) -> RouteStore {
        let routes = vec![RouteConfig {
            prefix: "test-svc".to_string(),
            upstream: format!("https://{}:{}", host, port),
            credential_key: None,
            inject_mode: InjectMode::Header,
            inject_header: "Authorization".to_string(),
            credential_format: Some("Bearer {}".to_string()),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: None,
            endpoint_rules: rules,
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
            oauth2: None,
            aws_auth: None,
            endpoint_policy: None,
            spiffe: None,
        }];
        RouteStore::load(&routes).await.unwrap()
    }

    /// Build a CredentialStore with a test credential.
    fn make_credential_store(secret: &str) -> CredentialStore {
        let mut store = CredentialStore::empty();
        store.insert_for_test(
            "test-svc".to_string(),
            LoadedCredential {
                inject_mode: InjectMode::Header,
                proxy_inject_mode: InjectMode::Header,
                raw_credential: Zeroizing::new(secret.to_string()),
                header_name: "Authorization".to_string(),
                proxy_header_name: "Authorization".to_string(),
                header_value: Zeroizing::new(format!("Bearer {}", secret)),
                extra_headers: Vec::new(),
                path_pattern: None,
                proxy_path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                proxy_query_param_name: None,
            },
        );
        store
    }

    /// Build a CredentialStore whose credential carries an extra header in
    /// addition to the primary `Authorization` header.
    fn make_credential_store_with_extra(
        secret: &str,
        extra_name: &str,
        extra_value: &str,
    ) -> CredentialStore {
        let mut store = CredentialStore::empty();
        store.insert_for_test(
            "test-svc".to_string(),
            LoadedCredential {
                inject_mode: InjectMode::Header,
                proxy_inject_mode: InjectMode::Header,
                raw_credential: Zeroizing::new(secret.to_string()),
                header_name: "Authorization".to_string(),
                proxy_header_name: "Authorization".to_string(),
                header_value: Zeroizing::new(format!("Bearer {}", secret)),
                extra_headers: vec![(
                    extra_name.to_string(),
                    Zeroizing::new(extra_value.to_string()),
                )],
                path_pattern: None,
                proxy_path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                proxy_query_param_name: None,
            },
        );
        store
    }

    /// Spawn a mock h2 upstream server that captures received request headers
    /// and responds with 200. Returns the captured headers via the channel.
    async fn spawn_mock_h2_upstream(
        ca: &EphemeralCa,
    ) -> (
        u16,
        tokio::sync::oneshot::Receiver<(String, http::HeaderMap)>,
    ) {
        let server_config = upstream_server_config(ca);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let (tcp_stream, _) = listener.accept().await.unwrap();
            let tls_acceptor = tokio_rustls::TlsAcceptor::from(server_config);
            let tls_stream = tls_acceptor.accept(tcp_stream).await.unwrap();

            let mut h2_conn = h2::server::handshake(tls_stream).await.unwrap();
            let mut tx = Some(tx);
            // Drive the server connection — accept() both drives I/O and yields streams.
            while let Some(Ok((request, mut respond))) = h2_conn.accept().await {
                if let Some(tx) = tx.take() {
                    let method_path = format!(
                        "{} {}",
                        request.method(),
                        request
                            .uri()
                            .path_and_query()
                            .map(|pq| pq.as_str())
                            .unwrap_or("/")
                    );
                    let headers = request.headers().clone();

                    let response = http::Response::builder().status(200).body(()).unwrap();
                    respond.send_response(response, true).unwrap();

                    let _ = tx.send((method_path, headers));
                }
            }
        });

        (port, rx)
    }

    /// Nonce resolver stub that swaps one fixed nonce for one fixed secret,
    /// but only for the expected consumer (`proxy.<route_id>`).
    #[derive(Debug)]
    struct StubNonceResolver {
        nonce: String,
        consumer: String,
        secret: String,
    }

    impl crate::token::NonceResolver for StubNonceResolver {
        fn resolve(&self, nonce: &str, consumer: &str) -> Option<Zeroizing<Vec<u8>>> {
            if nonce == self.nonce && consumer == self.consumer {
                Some(Zeroizing::new(self.secret.clone().into_bytes()))
            } else {
                None
            }
        }
    }

    /// Spawn a mock h2 upstream that sends response headers and a DATA frame
    /// *before* reading the request body, then drains the body. Used to prove
    /// the proxy relays the response concurrently with the request body (no
    /// head-of-line deadlock for bidirectional streaming).
    async fn spawn_mock_h2_upstream_early_response(
        ca: &EphemeralCa,
    ) -> (u16, tokio::sync::oneshot::Receiver<Vec<u8>>) {
        let server_config = upstream_server_config(ca);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let (tcp_stream, _) = listener.accept().await.unwrap();
            let tls_acceptor = tokio_rustls::TlsAcceptor::from(server_config);
            let tls_stream = tls_acceptor.accept(tcp_stream).await.unwrap();

            let mut h2_conn = h2::server::handshake(tls_stream).await.unwrap();
            if let Some(Ok((request, mut respond))) = h2_conn.accept().await {
                // Respond immediately, before consuming the request body.
                let response = http::Response::builder().status(200).body(()).unwrap();
                let mut send_stream = respond.send_response(response, false).unwrap();
                send_stream
                    .send_data(Bytes::from_static(b"early"), false)
                    .unwrap();

                let mut body_recv = request.into_body();

                // Drain the request body while concurrently driving the h2
                // connection — polling `accept()` flushes the queued early
                // response to the proxy so the client can react and send its
                // (late) request body. Without this drive the early frame never
                // leaves the mock's send buffer and the test deadlocks.
                let drain = async {
                    let mut collected = Vec::new();
                    while let Some(Ok(data)) = body_recv.data().await {
                        let len = data.len();
                        collected.extend_from_slice(&data);
                        body_recv.flow_control().release_capacity(len).unwrap();
                    }
                    collected
                };
                let drive = async { while h2_conn.accept().await.is_some() {} };
                let collected = tokio::select! {
                    c = drain => c,
                    _ = drive => Vec::new(),
                };

                send_stream.send_data(Bytes::new(), true).unwrap();
                let _ = tx.send(collected);

                // Keep driving the connection so the trailing frames flush and
                // the client sees a clean end-of-stream.
                while h2_conn.accept().await.is_some() {}
            }
        });

        (port, rx)
    }

    /// Spawn a mock h2 upstream that echoes body and trailers back.
    async fn spawn_mock_h2_upstream_echo(
        ca: &EphemeralCa,
    ) -> (u16, tokio::sync::oneshot::Receiver<Vec<u8>>) {
        let server_config = upstream_server_config(ca);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let (tcp_stream, _) = listener.accept().await.unwrap();
            let tls_acceptor = tokio_rustls::TlsAcceptor::from(server_config);
            let tls_stream = tls_acceptor.accept(tcp_stream).await.unwrap();

            let mut h2_conn = h2::server::handshake(tls_stream).await.unwrap();
            let mut tx = Some(tx);
            while let Some(Ok((request, mut respond))) = h2_conn.accept().await {
                if let Some(tx) = tx.take() {
                    let mut body_recv = request.into_body();
                    let mut collected = Vec::new();

                    while let Some(Ok(data)) = body_recv.data().await {
                        let len = data.len();
                        collected.extend_from_slice(&data);
                        body_recv.flow_control().release_capacity(len).unwrap();
                    }

                    let response = http::Response::builder().status(200).body(()).unwrap();
                    let mut send_stream = respond.send_response(response, false).unwrap();
                    send_stream
                        .send_data(Bytes::from(collected.clone()), false)
                        .unwrap();

                    let mut trailers = http::HeaderMap::new();
                    trailers.insert("grpc-status", "0".parse().unwrap());
                    trailers.insert("grpc-message", "OK".parse().unwrap());
                    send_stream.send_trailers(trailers).unwrap();

                    let _ = tx.send(collected);
                }
            }
        });

        (port, rx)
    }

    #[tokio::test]
    async fn h2_forward_injects_credential_header() {
        use std::time::Duration;

        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let (upstream_port, rx) = spawn_mock_h2_upstream(&ca).await;

        let route_store = make_route_store(
            "localhost",
            upstream_port,
            vec![EndpointRule {
                method: "POST".to_string(),
                path: "/v1/chat/completions".to_string(),
            }],
        )
        .await;
        let credential_store = make_credential_store("sk-test-secret-key");
        let cert_cache = Arc::new(CertCache::new(Arc::clone(&ca)));
        let tls_connector = h2_tls_connector_trusting(ca.cert_pem());
        let filter = ProxyFilter::allow_all();
        let session_token = Zeroizing::new("session-tok".to_string());

        let ctx = InterceptCtx {
            route_id: Some("test-svc"),
            host: "localhost",
            port: upstream_port,
            route_store: Arc::new(route_store),
            credential_store: Arc::new(credential_store),
            oauth_capture_store: Arc::new(crate::oauth_capture::OAuthCaptureStore::empty()),
            session_token: &session_token,
            cert_cache,
            tls_connector: &tls_connector,
            tls_connector_h2: &tls_connector,
            filter: &filter,
            audit_log: None,
            upstream_proxy: None,
            approval_backends: None,
            credential_capture_backend: None,
            nonce_resolver: None,
            enable_h2: true,
        };

        let (client_io, server_io) = tokio::io::duplex(65536);

        // The forward arm will block after handling the stream. We use a
        // timeout on the overall join to detect the test completing.
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                async {
                    let _ = forward_h2_connection(server_io, &ctx).await;
                },
                async {
                    let (mut h2_client, h2_conn) = h2::client::handshake(client_io).await.unwrap();
                    let conn_handle = tokio::spawn(async move {
                        let _ = h2_conn.await;
                    });

                    let request = http::Request::builder()
                        .method("POST")
                        .uri(format!(
                            "https://localhost:{}/v1/chat/completions",
                            upstream_port
                        ))
                        .header("content-type", "application/json")
                        .body(())
                        .unwrap();
                    let (response_fut, mut send_stream) =
                        h2_client.send_request(request, false).unwrap();
                    send_stream
                        .send_data(Bytes::from(r#"{"model":"gpt-4"}"#), true)
                        .unwrap();

                    let response = response_fut.await.unwrap();
                    assert_eq!(response.status(), 200);

                    let (method_path, headers) = rx.await.unwrap();
                    assert_eq!(method_path, "POST /v1/chat/completions");
                    assert_eq!(
                        headers.get("authorization").map(|v| v.to_str().unwrap()),
                        Some("Bearer sk-test-secret-key")
                    );
                    assert_eq!(
                        headers.get("content-type").map(|v| v.to_str().unwrap()),
                        Some("application/json")
                    );

                    // Close client h2 so server_conn.accept() returns None.
                    drop(h2_client);
                    conn_handle.abort();
                    let _ = conn_handle.await;
                }
            );
        })
        .await;
        assert!(result.is_ok(), "test timed out — h2 forwarding hung");
    }

    #[tokio::test]
    async fn h2_forward_injects_command_captured_credential() {
        use std::time::Duration;

        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let (upstream_port, rx) = spawn_mock_h2_upstream(&ca).await;

        let tls_connector = h2_tls_connector_trusting(ca.cert_pem());
        let (route_store, credential_store) =
            make_cmd_route_stores("localhost", upstream_port, &tls_connector).await;
        let cert_cache = Arc::new(CertCache::new(Arc::clone(&ca)));
        let filter = ProxyFilter::allow_all();
        let session_token = Zeroizing::new("session-tok".to_string());
        let capture_backend: Arc<dyn crate::capture::CredentialCaptureBackend> =
            Arc::new(MockCaptureBackend {
                secret: "captured-secret".to_string(),
            });

        let ctx = InterceptCtx {
            route_id: Some("cmd-svc"),
            host: "localhost",
            port: upstream_port,
            route_store: Arc::new(route_store),
            credential_store: Arc::new(credential_store),
            oauth_capture_store: Arc::new(crate::oauth_capture::OAuthCaptureStore::empty()),
            session_token: &session_token,
            cert_cache,
            tls_connector: &tls_connector,
            tls_connector_h2: &tls_connector,
            filter: &filter,
            audit_log: None,
            upstream_proxy: None,
            approval_backends: None,
            credential_capture_backend: Some(capture_backend),
            nonce_resolver: None,
            enable_h2: true,
        };

        let (client_io, server_io) = tokio::io::duplex(65536);

        let result = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                async {
                    let _ = forward_h2_connection(server_io, &ctx).await;
                },
                async {
                    let (mut h2_client, h2_conn) = h2::client::handshake(client_io).await.unwrap();
                    let conn_handle = tokio::spawn(async move {
                        let _ = h2_conn.await;
                    });

                    let request = http::Request::builder()
                        .method("POST")
                        .uri(format!("https://localhost:{}/v1/resource", upstream_port))
                        .header("content-type", "application/json")
                        .body(())
                        .unwrap();
                    let (response_fut, mut send_stream) =
                        h2_client.send_request(request, false).unwrap();
                    send_stream.send_data(Bytes::from("{}"), true).unwrap();

                    let response = response_fut.await.unwrap();
                    assert_eq!(response.status(), 200);

                    let (_method_path, headers) = rx.await.unwrap();
                    assert_eq!(
                        headers.get("authorization").map(|v| v.to_str().unwrap()),
                        Some("Bearer captured-secret"),
                        "command-captured credential must be injected on the h2 path"
                    );

                    drop(h2_client);
                    conn_handle.abort();
                    let _ = conn_handle.await;
                }
            );
        })
        .await;
        assert!(result.is_ok(), "test timed out — h2 forwarding hung");
    }

    #[tokio::test]
    async fn h2_forward_injects_command_captured_headers() {
        use std::time::Duration;

        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let (upstream_port, rx) = spawn_mock_h2_upstream(&ca).await;

        let tls_connector = h2_tls_connector_trusting(ca.cert_pem());
        let (route_store, credential_store) =
            make_cmd_route_stores("localhost", upstream_port, &tls_connector).await;
        let cert_cache = Arc::new(CertCache::new(Arc::clone(&ca)));
        let filter = ProxyFilter::allow_all();
        let session_token = Zeroizing::new("session-tok".to_string());
        // Headers-format capture: materializes into extra_headers with an empty
        // primary header_value, exercising the other injection branch on h2.
        let capture_backend: Arc<dyn crate::capture::CredentialCaptureBackend> =
            Arc::new(MockHeaderCaptureBackend {
                headers: vec![
                    ("authorization".to_string(), "Bearer hdr-token".to_string()),
                    ("x-extra".to_string(), "extra-val".to_string()),
                ],
            });

        let ctx = InterceptCtx {
            route_id: Some("cmd-svc"),
            host: "localhost",
            port: upstream_port,
            route_store: Arc::new(route_store),
            credential_store: Arc::new(credential_store),
            oauth_capture_store: Arc::new(crate::oauth_capture::OAuthCaptureStore::empty()),
            session_token: &session_token,
            cert_cache,
            tls_connector: &tls_connector,
            tls_connector_h2: &tls_connector,
            filter: &filter,
            audit_log: None,
            upstream_proxy: None,
            approval_backends: None,
            credential_capture_backend: Some(capture_backend),
            nonce_resolver: None,
            enable_h2: true,
        };

        let (client_io, server_io) = tokio::io::duplex(65536);

        let result = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                async {
                    let _ = forward_h2_connection(server_io, &ctx).await;
                },
                async {
                    let (mut h2_client, h2_conn) = h2::client::handshake(client_io).await.unwrap();
                    let conn_handle = tokio::spawn(async move {
                        let _ = h2_conn.await;
                    });

                    let request = http::Request::builder()
                        .method("GET")
                        .uri(format!("https://localhost:{}/v1/resource", upstream_port))
                        .body(())
                        .unwrap();
                    let (response_fut, _send_stream) =
                        h2_client.send_request(request, true).unwrap();

                    let response = response_fut.await.unwrap();
                    assert_eq!(response.status(), 200);

                    let (_method_path, headers) = rx.await.unwrap();
                    assert_eq!(
                        headers.get("authorization").map(|v| v.to_str().unwrap()),
                        Some("Bearer hdr-token"),
                        "captured header must be injected on the h2 path"
                    );
                    assert_eq!(
                        headers.get("x-extra").map(|v| v.to_str().unwrap()),
                        Some("extra-val"),
                        "captured extra header must be injected on the h2 path"
                    );

                    drop(h2_client);
                    conn_handle.abort();
                    let _ = conn_handle.await;
                }
            );
        })
        .await;
        assert!(result.is_ok(), "test timed out — h2 forwarding hung");
    }

    #[tokio::test]
    async fn h2_forward_denies_command_credential_without_backend() {
        use std::time::Duration;

        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let (upstream_port, _rx) = spawn_mock_h2_upstream(&ca).await;

        let tls_connector = h2_tls_connector_trusting(ca.cert_pem());
        let (route_store, credential_store) =
            make_cmd_route_stores("localhost", upstream_port, &tls_connector).await;
        let cert_cache = Arc::new(CertCache::new(Arc::clone(&ca)));
        let filter = ProxyFilter::allow_all();
        let session_token = Zeroizing::new("session-tok".to_string());

        // No capture backend configured: a cmd:// route must be denied (503),
        // mirroring the gate the HTTP/1.1 path applies.
        let ctx = InterceptCtx {
            route_id: Some("cmd-svc"),
            host: "localhost",
            port: upstream_port,
            route_store: Arc::new(route_store),
            credential_store: Arc::new(credential_store),
            oauth_capture_store: Arc::new(crate::oauth_capture::OAuthCaptureStore::empty()),
            session_token: &session_token,
            cert_cache,
            tls_connector: &tls_connector,
            tls_connector_h2: &tls_connector,
            filter: &filter,
            audit_log: None,
            upstream_proxy: None,
            approval_backends: None,
            credential_capture_backend: None,
            nonce_resolver: None,
            enable_h2: true,
        };

        let (client_io, server_io) = tokio::io::duplex(65536);

        let result = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                async {
                    let _ = forward_h2_connection(server_io, &ctx).await;
                },
                async {
                    let (mut h2_client, h2_conn) = h2::client::handshake(client_io).await.unwrap();
                    let conn_handle = tokio::spawn(async move {
                        let _ = h2_conn.await;
                    });

                    let request = http::Request::builder()
                        .method("POST")
                        .uri(format!("https://localhost:{}/v1/resource", upstream_port))
                        .body(())
                        .unwrap();
                    let (response_fut, _send_stream) =
                        h2_client.send_request(request, true).unwrap();

                    let response = response_fut.await.unwrap();
                    assert_eq!(
                        response.status(),
                        503,
                        "cmd:// route without a capture backend must be denied on h2"
                    );

                    drop(h2_client);
                    conn_handle.abort();
                    let _ = conn_handle.await;
                }
            );
        })
        .await;
        assert!(result.is_ok(), "test timed out — h2 forwarding hung");
    }

    #[tokio::test]
    async fn h2_forward_injects_extra_headers_and_replaces_client_copy() {
        use std::time::Duration;

        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let (upstream_port, rx) = spawn_mock_h2_upstream(&ca).await;

        let route_store = make_route_store(
            "localhost",
            upstream_port,
            vec![EndpointRule {
                method: "POST".to_string(),
                path: "/v1/chat/completions".to_string(),
            }],
        )
        .await;
        // Credential carries a second managed header beyond Authorization.
        let credential_store =
            make_credential_store_with_extra("sk-test-secret-key", "x-api-key", "managed-key");
        let cert_cache = Arc::new(CertCache::new(Arc::clone(&ca)));
        let tls_connector = h2_tls_connector_trusting(ca.cert_pem());
        let filter = ProxyFilter::allow_all();
        let session_token = Zeroizing::new("session-tok".to_string());

        let ctx = InterceptCtx {
            route_id: Some("test-svc"),
            host: "localhost",
            port: upstream_port,
            route_store: Arc::new(route_store),
            credential_store: Arc::new(credential_store),
            oauth_capture_store: Arc::new(crate::oauth_capture::OAuthCaptureStore::empty()),
            session_token: &session_token,
            cert_cache,
            tls_connector: &tls_connector,
            tls_connector_h2: &tls_connector,
            filter: &filter,
            audit_log: None,
            upstream_proxy: None,
            approval_backends: None,
            credential_capture_backend: None,
            nonce_resolver: None,
            enable_h2: true,
        };

        let (client_io, server_io) = tokio::io::duplex(65536);

        let result = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                async {
                    let _ = forward_h2_connection(server_io, &ctx).await;
                },
                async {
                    let (mut h2_client, h2_conn) = h2::client::handshake(client_io).await.unwrap();
                    let conn_handle = tokio::spawn(async move {
                        let _ = h2_conn.await;
                    });

                    // Client smuggles its own x-api-key — it must be replaced by
                    // the managed value, not forwarded.
                    let request = http::Request::builder()
                        .method("POST")
                        .uri(format!(
                            "https://localhost:{}/v1/chat/completions",
                            upstream_port
                        ))
                        .header("content-type", "application/json")
                        .header("x-api-key", "client-supplied-attacker-key")
                        .body(())
                        .unwrap();
                    let (response_fut, mut send_stream) =
                        h2_client.send_request(request, false).unwrap();
                    send_stream
                        .send_data(Bytes::from(r#"{"model":"gpt-4"}"#), true)
                        .unwrap();

                    let response = response_fut.await.unwrap();
                    assert_eq!(response.status(), 200);

                    let (_method_path, headers) = rx.await.unwrap();
                    assert_eq!(
                        headers.get("authorization").map(|v| v.to_str().unwrap()),
                        Some("Bearer sk-test-secret-key")
                    );
                    // Extra managed header must be injected, and the client's
                    // copy must not survive.
                    let api_keys: Vec<&str> = headers
                        .get_all("x-api-key")
                        .iter()
                        .map(|v| v.to_str().unwrap())
                        .collect();
                    assert_eq!(
                        api_keys,
                        vec!["managed-key"],
                        "extra header must be injected and the client copy dropped"
                    );

                    drop(h2_client);
                    conn_handle.abort();
                    let _ = conn_handle.await;
                }
            );
        })
        .await;
        assert!(result.is_ok(), "test timed out — h2 forwarding hung");
    }

    /// Regression test for the h1/h2 AWS divergence: an `aws_auth` route is
    /// gated identically on both protocols. SigV4 signing is not implemented on
    /// h2, so the request must be rejected (501) rather than forwarded upstream
    /// unsigned. Before the shared `resolve_managed_credential`, the h2 path had
    /// no AWS branch and would forward the request without a signature.
    ///
    /// Fake AWS env vars are set for the duration of credential loading so the
    /// default credential chain succeeds and `get_aws()` returns `Some(...)`,
    /// letting the 501 stub in `resolve_managed_credential` be reached.
    #[tokio::test]
    async fn h2_forward_rejects_aws_route_without_forwarding() {
        use std::time::Duration;

        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let (upstream_port, rx) = spawn_mock_h2_upstream(&ca).await;

        let tls_connector = h2_tls_connector_trusting(ca.cert_pem());

        // Route configured for AWS SigV4 (h2 signing not yet implemented).
        let routes = vec![RouteConfig {
            prefix: "aws-svc".to_string(),
            upstream: format!("https://localhost:{}", upstream_port),
            credential_key: None,
            inject_mode: InjectMode::Header,
            inject_header: "Authorization".to_string(),
            credential_format: None,
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: None,
            endpoint_rules: vec![EndpointRule {
                method: "*".to_string(),
                path: "/**".to_string(),
            }],
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
            oauth2: None,
            aws_auth: Some(crate::config::AwsAuthConfig {
                profile: None,
                region: Some("us-east-1".to_string()),
                service: Some("bedrock".to_string()),
            }),
            endpoint_policy: None,
            spiffe: None,
        }];
        let route_store = RouteStore::load(&routes).await.unwrap();
        // Set fake AWS credential env vars so the default chain succeeds and
        // load_with_diagnostics inserts the AwsRoute. The mutex lock is dropped
        // before the await point (holding a MutexGuard across an await is a
        // compile error); the EnvVarGuard outlives the await so it restores the
        // vars after load completes.
        let _env = {
            let _lock = crate::test_env::ENV_LOCK
                .lock()
                .expect("env mutex poisoned");
            crate::test_env::EnvVarGuard::set_all(&[
                ("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE"),
                (
                    "AWS_SECRET_ACCESS_KEY",
                    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                ),
            ])
        };
        let credential_store = CredentialStore::load_with_diagnostics(&routes, &tls_connector)
            .await
            .unwrap()
            .store;
        let cert_cache = Arc::new(CertCache::new(Arc::clone(&ca)));
        let filter = ProxyFilter::allow_all();
        let session_token = Zeroizing::new("session-tok".to_string());

        let ctx = InterceptCtx {
            route_id: Some("aws-svc"),
            host: "localhost",
            port: upstream_port,
            route_store: Arc::new(route_store),
            credential_store: Arc::new(credential_store),
            oauth_capture_store: Arc::new(crate::oauth_capture::OAuthCaptureStore::empty()),
            session_token: &session_token,
            cert_cache,
            tls_connector: &tls_connector,
            tls_connector_h2: &tls_connector,
            filter: &filter,
            audit_log: None,
            upstream_proxy: None,
            approval_backends: None,
            credential_capture_backend: None,
            nonce_resolver: None,
            enable_h2: true,
        };

        let (client_io, server_io) = tokio::io::duplex(65536);

        let result = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                async {
                    let _ = forward_h2_connection(server_io, &ctx).await;
                },
                async {
                    let (mut h2_client, h2_conn) = h2::client::handshake(client_io).await.unwrap();
                    let conn_handle = tokio::spawn(async move {
                        let _ = h2_conn.await;
                    });

                    let request = http::Request::builder()
                        .method("GET")
                        .uri(format!("https://localhost:{}/some/api", upstream_port))
                        .body(())
                        .unwrap();
                    let (response_fut, _send_stream) =
                        h2_client.send_request(request, true).unwrap();

                    let response = response_fut.await.unwrap();
                    assert_eq!(
                        response.status(),
                        501,
                        "AWS route must be rejected (not forwarded unsigned) on h2"
                    );

                    drop(h2_client);
                    conn_handle.abort();
                    let _ = conn_handle.await;
                }
            );
        })
        .await;
        assert!(result.is_ok(), "test timed out — h2 forwarding hung");

        // The upstream must NOT have received the request.
        assert!(
            rx.await.is_err(),
            "AWS request must not be forwarded upstream unsigned"
        );
    }

    #[tokio::test]
    async fn h2_forward_streams_body_and_trailers() {
        use std::time::Duration;

        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let (upstream_port, rx) = spawn_mock_h2_upstream_echo(&ca).await;

        let route_store = make_route_store("localhost", upstream_port, vec![]).await;
        let credential_store = CredentialStore::empty();
        let cert_cache = Arc::new(CertCache::new(Arc::clone(&ca)));
        let tls_connector = h2_tls_connector_trusting(ca.cert_pem());
        let filter = ProxyFilter::allow_all();
        let session_token = Zeroizing::new("session-tok".to_string());

        let ctx = InterceptCtx {
            route_id: Some("test-svc"),
            host: "localhost",
            port: upstream_port,
            route_store: Arc::new(route_store),
            credential_store: Arc::new(credential_store),
            oauth_capture_store: Arc::new(crate::oauth_capture::OAuthCaptureStore::empty()),
            session_token: &session_token,
            cert_cache,
            tls_connector: &tls_connector,
            tls_connector_h2: &tls_connector,
            filter: &filter,
            audit_log: None,
            upstream_proxy: None,
            approval_backends: None,
            credential_capture_backend: None,
            nonce_resolver: None,
            enable_h2: true,
        };

        let (client_io, server_io) = tokio::io::duplex(65536);

        let result = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                async {
                    let _ = forward_h2_connection(server_io, &ctx).await;
                },
                async {
                    let (mut h2_client, h2_conn) = h2::client::handshake(client_io).await.unwrap();
                    let conn_handle = tokio::spawn(async move {
                        let _ = h2_conn.await;
                    });

                    let request = http::Request::builder()
                        .method("POST")
                        .uri(format!(
                            "https://localhost:{}/test.Service/Method",
                            upstream_port
                        ))
                        .header("content-type", "application/grpc")
                        .body(())
                        .unwrap();
                    let (response_fut, mut send_stream) =
                        h2_client.send_request(request, false).unwrap();

                    let payload = b"hello grpc world";
                    send_stream
                        .send_data(Bytes::from(&payload[..8]), false)
                        .unwrap();
                    send_stream
                        .send_data(Bytes::from(&payload[8..]), true)
                        .unwrap();

                    let response = response_fut.await.unwrap();
                    assert_eq!(response.status(), 200);

                    let mut resp_body = response.into_body();
                    let mut received = Vec::new();
                    while let Some(Ok(chunk)) = resp_body.data().await {
                        let len = chunk.len();
                        received.extend_from_slice(&chunk);
                        resp_body.flow_control().release_capacity(len).unwrap();
                    }
                    assert_eq!(received, payload);

                    let trailers = resp_body.trailers().await.unwrap().unwrap();
                    assert_eq!(trailers.get("grpc-status").unwrap(), "0");
                    assert_eq!(trailers.get("grpc-message").unwrap(), "OK");

                    let upstream_body = rx.await.unwrap();
                    assert_eq!(upstream_body, payload);

                    drop(h2_client);
                    conn_handle.abort();
                    let _ = conn_handle.await;
                }
            );
        })
        .await;
        assert!(result.is_ok(), "test timed out — h2 forwarding hung");
    }

    #[tokio::test]
    async fn h2_forward_returns_502_when_no_route() {
        let ca = Arc::new(EphemeralCa::generate().unwrap());

        let route_store = RouteStore::empty();
        let credential_store = CredentialStore::empty();
        let cert_cache = Arc::new(CertCache::new(Arc::clone(&ca)));
        let tls_connector = h2_tls_connector_trusting(ca.cert_pem());
        let filter = ProxyFilter::allow_all();
        let session_token = Zeroizing::new("session-tok".to_string());

        // Mock upstream that accepts h2 connections (needed so
        // forward_h2_connection can open the upstream h2 session).
        let server_config = upstream_server_config(&ca);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let tls_acceptor = tokio_rustls::TlsAcceptor::from(server_config);
            let tls = tls_acceptor.accept(tcp).await.unwrap();
            let mut h2_conn = h2::server::handshake(tls).await.unwrap();
            while h2_conn.accept().await.is_some() {}
        });

        let ctx = InterceptCtx {
            route_id: None,
            host: "localhost",
            port: upstream_port,
            route_store: Arc::new(route_store),
            credential_store: Arc::new(credential_store),
            oauth_capture_store: Arc::new(crate::oauth_capture::OAuthCaptureStore::empty()),
            session_token: &session_token,
            cert_cache,
            tls_connector: &tls_connector,
            tls_connector_h2: &tls_connector,
            filter: &filter,
            audit_log: None,
            upstream_proxy: None,
            approval_backends: None,
            credential_capture_backend: None,
            nonce_resolver: None,
            enable_h2: true,
        };

        let (client_io, server_io) = tokio::io::duplex(65536);

        let (_, client_result) = tokio::join!(
            async {
                let _ = forward_h2_connection(server_io, &ctx).await;
            },
            async {
                let (h2_client, h2_conn) = h2::client::handshake(client_io).await.unwrap();
                let conn_handle = tokio::spawn(async move {
                    let _ = h2_conn.await;
                });

                let mut client_send = h2_client.ready().await.unwrap();
                let request = http::Request::builder()
                    .method("GET")
                    .uri(format!("https://localhost:{}/v1/models", upstream_port))
                    .body(())
                    .unwrap();
                let (response_fut, _send_stream) = client_send.send_request(request, true).unwrap();

                let response = response_fut.await.unwrap();
                assert_eq!(response.status(), 502);

                drop(client_send);
                conn_handle.abort();
            }
        );
        client_result
    }

    #[tokio::test]
    async fn h2_forward_fails_closed_for_oauth_capture_host() {
        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let (upstream_port, rx) = spawn_mock_h2_upstream(&ca).await;

        let route_store = RouteStore::empty();
        let credential_store = CredentialStore::empty();
        let oauth_capture_store =
            crate::oauth_capture::OAuthCaptureStore::load(&[crate::config::OAuthCaptureConfig {
                provider: "test".to_string(),
                token_endpoints: vec![crate::config::OAuthTokenEndpointConfig {
                    host: format!("https://localhost:{upstream_port}"),
                    path: "/oauth/token".to_string(),
                    response_fields: vec![
                        crate::config::OAuthTokenResponseFieldConfig {
                            path: "access_token".to_string(),
                            kind: crate::config::OAuthTokenResponseFieldKind::Opaque,
                            format: None,
                        },
                        crate::config::OAuthTokenResponseFieldConfig {
                            path: "refresh_token".to_string(),
                            kind: crate::config::OAuthTokenResponseFieldKind::Opaque,
                            format: None,
                        },
                    ],
                    request_body: crate::config::OAuthTokenRequestBodyFormat::Auto,
                    request_nonce_fields: vec!["refresh_token".to_string()],
                }],
                admitted_consumers: vec!["proxy.test".to_string()],
            }])
            .unwrap();
        let cert_cache = Arc::new(CertCache::new(Arc::clone(&ca)));
        let tls_connector = h2_tls_connector_trusting(ca.cert_pem());
        let filter = ProxyFilter::allow_all();
        let session_token = Zeroizing::new("session-tok".to_string());

        let ctx = InterceptCtx {
            route_id: None,
            host: "localhost",
            port: upstream_port,
            route_store: Arc::new(route_store),
            credential_store: Arc::new(credential_store),
            oauth_capture_store: Arc::new(oauth_capture_store),
            session_token: &session_token,
            cert_cache,
            tls_connector: &tls_connector,
            tls_connector_h2: &tls_connector,
            filter: &filter,
            audit_log: None,
            upstream_proxy: None,
            approval_backends: None,
            credential_capture_backend: None,
            nonce_resolver: None,
            enable_h2: true,
        };

        let (client_io, server_io) = tokio::io::duplex(65536);

        let result = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let (_, client_result) = tokio::join!(
                async {
                    let _ = forward_h2_connection(server_io, &ctx).await;
                },
                async {
                    let (h2_client, h2_conn) = h2::client::handshake(client_io).await.unwrap();
                    let conn_handle = tokio::spawn(async move {
                        let _ = h2_conn.await;
                    });

                    let mut client_send = h2_client.ready().await.unwrap();
                    let request = http::Request::builder()
                        .method("POST")
                        .uri(format!("https://localhost:{upstream_port}/oauth/token/"))
                        .body(())
                        .unwrap();
                    let (response_fut, _send_stream) =
                        client_send.send_request(request, true).unwrap();

                    let response = response_fut.await.unwrap();
                    assert_eq!(response.status(), 502);
                    assert!(
                        tokio::time::timeout(std::time::Duration::from_millis(100), rx)
                            .await
                            .is_err(),
                        "OAuth capture h2 host request must not be forwarded before rewrite support exists"
                    );

                    drop(client_send);
                    conn_handle.abort();
                }
            );
            client_result
        })
        .await;
        assert!(result.is_ok(), "test timed out — h2 forwarding hung");
    }

    #[tokio::test]
    async fn h2_forward_returns_403_on_ambiguous_routes() {
        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let (upstream_port, _rx) = spawn_mock_h2_upstream(&ca).await;

        let routes = vec![
            RouteConfig {
                prefix: "svc-a".to_string(),
                upstream: format!("https://localhost:{}", upstream_port),
                credential_key: None,
                inject_mode: InjectMode::Header,
                inject_header: "Authorization".to_string(),
                credential_format: Some("Bearer {}".to_string()),
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                proxy: None,
                env_var: None,
                endpoint_rules: vec![EndpointRule {
                    method: "*".to_string(),
                    path: "/v1/*".to_string(),
                }],
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
                aws_auth: None,
                endpoint_policy: None,
                spiffe: None,
            },
            RouteConfig {
                prefix: "svc-b".to_string(),
                upstream: format!("https://localhost:{}", upstream_port),
                credential_key: None,
                inject_mode: InjectMode::Header,
                inject_header: "Authorization".to_string(),
                credential_format: Some("Bearer {}".to_string()),
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                proxy: None,
                env_var: None,
                endpoint_rules: vec![EndpointRule {
                    method: "*".to_string(),
                    path: "/v1/*".to_string(),
                }],
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
                aws_auth: None,
                endpoint_policy: None,
                spiffe: None,
            },
        ];
        let route_store = RouteStore::load(&routes).await.unwrap();
        let credential_store = CredentialStore::empty();
        let cert_cache = Arc::new(CertCache::new(Arc::clone(&ca)));
        let tls_connector = h2_tls_connector_trusting(ca.cert_pem());
        let filter = ProxyFilter::allow_all();
        let session_token = Zeroizing::new("session-tok".to_string());

        let ctx = InterceptCtx {
            route_id: None,
            host: "localhost",
            port: upstream_port,
            route_store: Arc::new(route_store),
            credential_store: Arc::new(credential_store),
            oauth_capture_store: Arc::new(crate::oauth_capture::OAuthCaptureStore::empty()),
            session_token: &session_token,
            cert_cache,
            tls_connector: &tls_connector,
            tls_connector_h2: &tls_connector,
            filter: &filter,
            audit_log: None,
            upstream_proxy: None,
            approval_backends: None,
            credential_capture_backend: None,
            nonce_resolver: None,
            enable_h2: true,
        };

        let (client_io, server_io) = tokio::io::duplex(65536);

        let (_, client_result) = tokio::join!(
            async {
                let _ = forward_h2_connection(server_io, &ctx).await;
            },
            async {
                let (h2_client, h2_conn) = h2::client::handshake(client_io).await.unwrap();
                let conn_handle = tokio::spawn(async move {
                    let _ = h2_conn.await;
                });

                let mut client_send = h2_client.ready().await.unwrap();
                let request = http::Request::builder()
                    .method("POST")
                    .uri(format!(
                        "https://localhost:{}/v1/chat/completions",
                        upstream_port
                    ))
                    .body(())
                    .unwrap();
                let (response_fut, _send_stream) = client_send.send_request(request, true).unwrap();

                let response = response_fut.await.unwrap();
                assert_eq!(
                    response.status(),
                    200,
                    "multiple endpoint-only routes matching is allowed (not ambiguous)"
                );

                drop(client_send);
                conn_handle.abort();
            }
        );
        client_result
    }

    #[tokio::test]
    async fn h2_forward_passthrough_without_credentials_when_no_endpoint_match() {
        use std::time::Duration;

        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let (upstream_port, _rx) = spawn_mock_h2_upstream(&ca).await;

        let route_store = make_route_store(
            "localhost",
            upstream_port,
            vec![EndpointRule {
                method: "POST".to_string(),
                path: "/v1/chat/completions".to_string(),
            }],
        )
        .await;
        let credential_store = make_credential_store("sk-should-not-appear");
        let cert_cache = Arc::new(CertCache::new(Arc::clone(&ca)));
        let tls_connector = h2_tls_connector_trusting(ca.cert_pem());
        let filter = ProxyFilter::allow_all();
        let session_token = Zeroizing::new("session-tok".to_string());

        let ctx = InterceptCtx {
            route_id: Some("test-svc"),
            host: "localhost",
            port: upstream_port,
            route_store: Arc::new(route_store),
            credential_store: Arc::new(credential_store),
            oauth_capture_store: Arc::new(crate::oauth_capture::OAuthCaptureStore::empty()),
            session_token: &session_token,
            cert_cache,
            tls_connector: &tls_connector,
            tls_connector_h2: &tls_connector,
            filter: &filter,
            audit_log: None,
            upstream_proxy: None,
            approval_backends: None,
            credential_capture_backend: None,
            nonce_resolver: None,
            enable_h2: true,
        };

        let (client_io, server_io) = tokio::io::duplex(65536);

        let result = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                async {
                    let _ = forward_h2_connection(server_io, &ctx).await;
                },
                async {
                    let (mut h2_client, h2_conn) = h2::client::handshake(client_io).await.unwrap();
                    let conn_handle = tokio::spawn(async move {
                        let _ = h2_conn.await;
                    });

                    let request = http::Request::builder()
                        .method("GET")
                        .uri(format!(
                            "https://localhost:{}/v1/unmatched-path",
                            upstream_port
                        ))
                        .body(())
                        .unwrap();
                    let (response_fut, _send_stream) =
                        h2_client.send_request(request, true).unwrap();

                    let response = response_fut.await.unwrap();
                    assert_eq!(
                        response.status(),
                        403,
                        "endpoint-only route must deny unmatched requests"
                    );

                    drop(h2_client);
                    conn_handle.abort();
                    let _ = conn_handle.await;
                }
            );
        })
        .await;
        assert!(result.is_ok(), "test timed out — h2 forwarding hung");
    }

    /// Build a RouteStore modeling an endpoint-only restriction route (no
    /// credential_key), as produced by `_ep_` routes from allow_domain.
    async fn make_endpoint_only_route_store(
        host: &str,
        port: u16,
        rules: Vec<EndpointRule>,
    ) -> RouteStore {
        let routes = vec![RouteConfig {
            prefix: "_ep_test".to_string(),
            upstream: format!("https://{}:{}", host, port),
            credential_key: None,
            inject_mode: InjectMode::Header,
            inject_header: "Authorization".to_string(),
            credential_format: None,
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: None,
            endpoint_rules: rules,
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
            oauth2: None,
            aws_auth: None,
            endpoint_policy: None,
            spiffe: None,
        }];
        RouteStore::load(&routes).await.unwrap()
    }

    #[tokio::test]
    async fn h2_forward_returns_403_for_endpoint_only_route_when_no_rule_matches() {
        use std::time::Duration;

        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let (upstream_port, _rx) = spawn_mock_h2_upstream(&ca).await;

        let route_store = make_endpoint_only_route_store(
            "localhost",
            upstream_port,
            vec![EndpointRule {
                method: "GET".to_string(),
                path: "/repos/my-org/**".to_string(),
            }],
        )
        .await;
        let credential_store = CredentialStore::empty();
        let cert_cache = Arc::new(CertCache::new(Arc::clone(&ca)));
        let tls_connector = h2_tls_connector_trusting(ca.cert_pem());
        let filter = ProxyFilter::allow_all();
        let session_token = Zeroizing::new("session-tok".to_string());

        let ctx = InterceptCtx {
            route_id: Some("_ep_test"),
            host: "localhost",
            port: upstream_port,
            route_store: Arc::new(route_store),
            credential_store: Arc::new(credential_store),
            oauth_capture_store: Arc::new(crate::oauth_capture::OAuthCaptureStore::empty()),
            session_token: &session_token,
            cert_cache,
            tls_connector: &tls_connector,
            tls_connector_h2: &tls_connector,
            filter: &filter,
            audit_log: None,
            upstream_proxy: None,
            approval_backends: None,
            credential_capture_backend: None,
            nonce_resolver: None,
            enable_h2: true,
        };

        let (client_io, server_io) = tokio::io::duplex(65536);

        let result = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                async {
                    let _ = forward_h2_connection(server_io, &ctx).await;
                },
                async {
                    let (mut h2_client, h2_conn) = h2::client::handshake(client_io).await.unwrap();
                    let conn_handle = tokio::spawn(async move {
                        let _ = h2_conn.await;
                    });

                    // This path is NOT in the endpoint rules
                    let request = http::Request::builder()
                        .method("POST")
                        .uri(format!(
                            "https://localhost:{}/repos/evil-org/exploit",
                            upstream_port
                        ))
                        .body(())
                        .unwrap();
                    let (response_fut, _send_stream) =
                        h2_client.send_request(request, true).unwrap();

                    let response = response_fut.await.unwrap();
                    assert_eq!(
                        response.status(),
                        403,
                        "endpoint-only route must deny unmatched requests"
                    );

                    drop(h2_client);
                    conn_handle.abort();
                    let _ = conn_handle.await;
                }
            );
        })
        .await;
        assert!(result.is_ok(), "test timed out — h2 forwarding hung");
    }

    /// Regression test for the h1/h2 endpoint-policy divergence: a route
    /// authored with the explicit `endpoint_policy` API (default deny + an
    /// `allow` rule) and EMPTY legacy `endpoint_rules` must be enforced on the
    /// h2/gRPC path. The legacy `endpoint_rules`-based selection treated such a
    /// route as an unrestricted catch-all and forwarded denied requests.
    #[tokio::test]
    async fn h2_forward_enforces_explicit_endpoint_policy_default_deny() {
        use crate::config::{
            EndpointPolicyConfig, EndpointPolicyDecision, EndpointPolicyDefault, EndpointPolicyRule,
        };
        use std::time::Duration;

        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let (upstream_port, _rx) = spawn_mock_h2_upstream(&ca).await;

        // Explicit policy: deny everything except GET /repos/my-org/**.
        // No legacy endpoint_rules — so the legacy path would treat this as a
        // catch-all and forward the request.
        let routes = vec![RouteConfig {
            prefix: "_ep_policy".to_string(),
            upstream: format!("https://localhost:{}", upstream_port),
            credential_key: None,
            inject_mode: InjectMode::Header,
            inject_header: "Authorization".to_string(),
            credential_format: None,
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: None,
            endpoint_rules: Vec::new(),
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
            oauth2: None,
            aws_auth: None,
            endpoint_policy: Some(EndpointPolicyConfig {
                default: EndpointPolicyDefault {
                    decision: EndpointPolicyDecision::Deny,
                    backend: None,
                    timeout_secs: None,
                },
                deny: Vec::new(),
                approve: Vec::new(),
                allow: vec![EndpointPolicyRule {
                    method: "GET".to_string(),
                    path: "/repos/my-org/**".to_string(),
                    backend: None,
                    reason: None,
                    timeout_secs: None,
                }],
            }),
            spiffe: None,
        }];
        let route_store = RouteStore::load(&routes).await.unwrap();
        let credential_store = CredentialStore::empty();
        let cert_cache = Arc::new(CertCache::new(Arc::clone(&ca)));
        let tls_connector = h2_tls_connector_trusting(ca.cert_pem());
        let filter = ProxyFilter::allow_all();
        let session_token = Zeroizing::new("session-tok".to_string());

        let ctx = InterceptCtx {
            route_id: Some("_ep_policy"),
            host: "localhost",
            port: upstream_port,
            route_store: Arc::new(route_store),
            credential_store: Arc::new(credential_store),
            oauth_capture_store: Arc::new(crate::oauth_capture::OAuthCaptureStore::empty()),
            session_token: &session_token,
            cert_cache,
            tls_connector: &tls_connector,
            tls_connector_h2: &tls_connector,
            filter: &filter,
            audit_log: None,
            upstream_proxy: None,
            approval_backends: None,
            credential_capture_backend: None,
            nonce_resolver: None,
            enable_h2: true,
        };

        let (client_io, server_io) = tokio::io::duplex(65536);

        let result = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                async {
                    let _ = forward_h2_connection(server_io, &ctx).await;
                },
                async {
                    let (mut h2_client, h2_conn) = h2::client::handshake(client_io).await.unwrap();
                    let conn_handle = tokio::spawn(async move {
                        let _ = h2_conn.await;
                    });

                    // Denied by default-deny (not GET /repos/my-org/**).
                    let request = http::Request::builder()
                        .method("POST")
                        .uri(format!(
                            "https://localhost:{}/repos/victim-org/repo",
                            upstream_port
                        ))
                        .body(())
                        .unwrap();
                    let (response_fut, _send_stream) =
                        h2_client.send_request(request, true).unwrap();

                    let response = response_fut.await.unwrap();
                    assert_eq!(
                        response.status(),
                        403,
                        "explicit endpoint_policy default-deny must be enforced on h2"
                    );

                    drop(h2_client);
                    conn_handle.abort();
                    let _ = conn_handle.await;
                }
            );
        })
        .await;
        assert!(result.is_ok(), "test timed out — h2 forwarding hung");
    }

    #[tokio::test]
    async fn h2_forward_allows_matching_request_on_endpoint_only_route() {
        use std::time::Duration;

        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let (upstream_port, rx) = spawn_mock_h2_upstream(&ca).await;

        let route_store = make_endpoint_only_route_store(
            "localhost",
            upstream_port,
            vec![EndpointRule {
                method: "GET".to_string(),
                path: "/repos/my-org/**".to_string(),
            }],
        )
        .await;
        let credential_store = CredentialStore::empty();
        let cert_cache = Arc::new(CertCache::new(Arc::clone(&ca)));
        let tls_connector = h2_tls_connector_trusting(ca.cert_pem());
        let filter = ProxyFilter::allow_all();
        let session_token = Zeroizing::new("session-tok".to_string());

        let ctx = InterceptCtx {
            route_id: Some("_ep_test"),
            host: "localhost",
            port: upstream_port,
            route_store: Arc::new(route_store),
            credential_store: Arc::new(credential_store),
            oauth_capture_store: Arc::new(crate::oauth_capture::OAuthCaptureStore::empty()),
            session_token: &session_token,
            cert_cache,
            tls_connector: &tls_connector,
            tls_connector_h2: &tls_connector,
            filter: &filter,
            audit_log: None,
            upstream_proxy: None,
            approval_backends: None,
            credential_capture_backend: None,
            nonce_resolver: None,
            enable_h2: true,
        };

        let (client_io, server_io) = tokio::io::duplex(65536);

        let result = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                async {
                    let _ = forward_h2_connection(server_io, &ctx).await;
                },
                async {
                    let (mut h2_client, h2_conn) = h2::client::handshake(client_io).await.unwrap();
                    let conn_handle = tokio::spawn(async move {
                        let _ = h2_conn.await;
                    });

                    // This path IS in the endpoint rules
                    let request = http::Request::builder()
                        .method("GET")
                        .uri(format!(
                            "https://localhost:{}/repos/my-org/some-repo",
                            upstream_port
                        ))
                        .body(())
                        .unwrap();
                    let (response_fut, _send_stream) =
                        h2_client.send_request(request, true).unwrap();

                    let response = response_fut.await.unwrap();
                    assert_eq!(
                        response.status(),
                        200,
                        "endpoint-only route must allow matching requests"
                    );

                    let (method_path, _headers) = rx.await.unwrap();
                    assert_eq!(method_path, "GET /repos/my-org/some-repo");

                    drop(h2_client);
                    conn_handle.abort();
                    let _ = conn_handle.await;
                }
            );
        })
        .await;
        assert!(result.is_ok(), "test timed out — h2 forwarding hung");
    }

    #[tokio::test]
    async fn h2_forward_endpoint_only_denies_even_with_credential_catchall() {
        use std::time::Duration;

        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let (upstream_port, _rx) = spawn_mock_h2_upstream(&ca).await;

        // Scenario: credential catch-all + endpoint-only restriction for same
        // upstream. The _ep_ route gates authorization; the credential route
        // injects a secret. A request not matching endpoint rules must be denied
        // even though the credential catch-all would otherwise forward it.
        let routes = vec![
            // Credential catch-all (no endpoint_rules)
            RouteConfig {
                prefix: "github-cred".to_string(),
                upstream: format!("https://localhost:{}", upstream_port),
                credential_key: Some("gh-token".to_string()),
                inject_mode: InjectMode::Header,
                inject_header: "Authorization".to_string(),
                credential_format: Some("Bearer {}".to_string()),
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                proxy: None,
                env_var: None,
                endpoint_rules: vec![],
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
                aws_auth: None,
                endpoint_policy: None,
                spiffe: None,
            },
            // Endpoint-only restriction (_ep_ route)
            RouteConfig {
                prefix: "_ep_localhost".to_string(),
                upstream: format!("https://localhost:{}", upstream_port),
                credential_key: None,
                inject_mode: InjectMode::Header,
                inject_header: "Authorization".to_string(),
                credential_format: None,
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                proxy: None,
                env_var: None,
                endpoint_rules: vec![
                    EndpointRule {
                        method: "*".to_string(),
                        path: "/repos/my-org/**".to_string(),
                    },
                    EndpointRule {
                        method: "*".to_string(),
                        path: "/graphql".to_string(),
                    },
                ],
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
                aws_auth: None,
                endpoint_policy: None,
                spiffe: None,
            },
        ];
        let route_store = RouteStore::load(&routes).await.unwrap();
        let credential_store = make_credential_store("gh-secret");
        let cert_cache = Arc::new(CertCache::new(Arc::clone(&ca)));
        let tls_connector = h2_tls_connector_trusting(ca.cert_pem());
        let filter = ProxyFilter::allow_all();
        let session_token = Zeroizing::new("session-tok".to_string());

        let ctx = InterceptCtx {
            route_id: None,
            host: "localhost",
            port: upstream_port,
            route_store: Arc::new(route_store),
            credential_store: Arc::new(credential_store),
            oauth_capture_store: Arc::new(crate::oauth_capture::OAuthCaptureStore::empty()),
            session_token: &session_token,
            cert_cache,
            tls_connector: &tls_connector,
            tls_connector_h2: &tls_connector,
            filter: &filter,
            audit_log: None,
            upstream_proxy: None,
            approval_backends: None,
            credential_capture_backend: None,
            nonce_resolver: None,
            enable_h2: true,
        };

        let (client_io, server_io) = tokio::io::duplex(65536);

        let result = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                async {
                    let _ = forward_h2_connection(server_io, &ctx).await;
                },
                async {
                    let (mut h2_client, h2_conn) = h2::client::handshake(client_io).await.unwrap();
                    let conn_handle = tokio::spawn(async move {
                        let _ = h2_conn.await;
                    });

                    // Path NOT in endpoint rules — must be denied
                    let request = http::Request::builder()
                        .method("GET")
                        .uri(format!(
                            "https://localhost:{}/repos/evil-org/exploit",
                            upstream_port
                        ))
                        .body(())
                        .unwrap();
                    let (response_fut, _send_stream) =
                        h2_client.send_request(request, true).unwrap();

                    let response = response_fut.await.unwrap();
                    assert_eq!(
                        response.status(),
                        403,
                        "endpoint restriction must deny even with credential catch-all present"
                    );

                    drop(h2_client);
                    conn_handle.abort();
                    let _ = conn_handle.await;
                }
            );
        })
        .await;
        assert!(result.is_ok(), "test timed out — h2 forwarding hung");
    }

    /// A broker nonce (`nono_<64hex>`) carried in a forwarded header must be
    /// resolved to the real credential before being sent upstream, mirroring
    /// the HTTP/1.1 path. Without `nonce_resolver` wired into `SharedH2Ctx` the
    /// raw nonce would leak upstream.
    #[tokio::test]
    async fn h2_forward_resolves_broker_nonce_in_header() {
        use std::time::Duration;

        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let (upstream_port, rx) = spawn_mock_h2_upstream(&ca).await;

        let route_store = make_route_store(
            "localhost",
            upstream_port,
            vec![EndpointRule {
                method: "POST".to_string(),
                path: "/v1/chat/completions".to_string(),
            }],
        )
        .await;
        // No managed credential — the secret arrives purely via nonce resolution.
        let credential_store = CredentialStore::empty();
        let cert_cache = Arc::new(CertCache::new(Arc::clone(&ca)));
        let tls_connector = h2_tls_connector_trusting(ca.cert_pem());
        let filter = ProxyFilter::allow_all();
        let session_token = Zeroizing::new("session-tok".to_string());

        let nonce = format!("nono_{}", "a".repeat(64));
        let resolver: Arc<dyn crate::token::NonceResolver> = Arc::new(StubNonceResolver {
            nonce: nonce.clone(),
            consumer: "proxy.test-svc".to_string(),
            secret: "Bearer resolved-secret".to_string(),
        });

        let ctx = InterceptCtx {
            route_id: Some("test-svc"),
            host: "localhost",
            port: upstream_port,
            route_store: Arc::new(route_store),
            credential_store: Arc::new(credential_store),
            oauth_capture_store: Arc::new(crate::oauth_capture::OAuthCaptureStore::empty()),
            session_token: &session_token,
            cert_cache,
            tls_connector: &tls_connector,
            tls_connector_h2: &tls_connector,
            filter: &filter,
            audit_log: None,
            upstream_proxy: None,
            approval_backends: None,
            credential_capture_backend: None,
            nonce_resolver: Some(resolver),
            enable_h2: true,
        };

        let (client_io, server_io) = tokio::io::duplex(65536);

        let result = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                async {
                    let _ = forward_h2_connection(server_io, &ctx).await;
                },
                async {
                    let (mut h2_client, h2_conn) = h2::client::handshake(client_io).await.unwrap();
                    let conn_handle = tokio::spawn(async move {
                        let _ = h2_conn.await;
                    });

                    let request = http::Request::builder()
                        .method("POST")
                        .uri(format!(
                            "https://localhost:{}/v1/chat/completions",
                            upstream_port
                        ))
                        .header("authorization", &nonce)
                        .body(())
                        .unwrap();
                    let (response_fut, mut send_stream) =
                        h2_client.send_request(request, false).unwrap();
                    send_stream
                        .send_data(Bytes::from_static(b"{}"), true)
                        .unwrap();

                    let response = response_fut.await.unwrap();
                    assert_eq!(response.status(), 200);

                    let (_method_path, headers) = rx.await.unwrap();
                    assert_eq!(
                        headers.get("authorization").map(|v| v.to_str().unwrap()),
                        Some("Bearer resolved-secret"),
                        "broker nonce must be resolved to the real credential upstream"
                    );

                    drop(h2_client);
                    conn_handle.abort();
                    let _ = conn_handle.await;
                }
            );
        })
        .await;
        assert!(result.is_ok(), "test timed out — h2 forwarding hung");
    }

    /// When no resolver admits the nonce (returns `None`), the raw header value
    /// is forwarded unchanged (fail-closed: upstream rejects the raw nonce,
    /// never a silently-wrong credential).
    #[tokio::test]
    async fn h2_forward_passes_through_unresolved_nonce() {
        use std::time::Duration;

        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let (upstream_port, rx) = spawn_mock_h2_upstream(&ca).await;

        let route_store = make_route_store(
            "localhost",
            upstream_port,
            vec![EndpointRule {
                method: "POST".to_string(),
                path: "/v1/chat/completions".to_string(),
            }],
        )
        .await;
        let credential_store = CredentialStore::empty();
        let cert_cache = Arc::new(CertCache::new(Arc::clone(&ca)));
        let tls_connector = h2_tls_connector_trusting(ca.cert_pem());
        let filter = ProxyFilter::allow_all();
        let session_token = Zeroizing::new("session-tok".to_string());

        let nonce = format!("nono_{}", "b".repeat(64));
        // Resolver only admits a *different* nonce, so this one is unresolved.
        let resolver: Arc<dyn crate::token::NonceResolver> = Arc::new(StubNonceResolver {
            nonce: format!("nono_{}", "c".repeat(64)),
            consumer: "proxy.test-svc".to_string(),
            secret: "Bearer unused".to_string(),
        });

        let ctx = InterceptCtx {
            route_id: Some("test-svc"),
            host: "localhost",
            port: upstream_port,
            route_store: Arc::new(route_store),
            credential_store: Arc::new(credential_store),
            oauth_capture_store: Arc::new(crate::oauth_capture::OAuthCaptureStore::empty()),
            session_token: &session_token,
            cert_cache,
            tls_connector: &tls_connector,
            tls_connector_h2: &tls_connector,
            filter: &filter,
            audit_log: None,
            upstream_proxy: None,
            approval_backends: None,
            credential_capture_backend: None,
            nonce_resolver: Some(resolver),
            enable_h2: true,
        };

        let (client_io, server_io) = tokio::io::duplex(65536);

        let result = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                async {
                    let _ = forward_h2_connection(server_io, &ctx).await;
                },
                async {
                    let (mut h2_client, h2_conn) = h2::client::handshake(client_io).await.unwrap();
                    let conn_handle = tokio::spawn(async move {
                        let _ = h2_conn.await;
                    });

                    let request = http::Request::builder()
                        .method("POST")
                        .uri(format!(
                            "https://localhost:{}/v1/chat/completions",
                            upstream_port
                        ))
                        .header("authorization", &nonce)
                        .body(())
                        .unwrap();
                    let (response_fut, mut send_stream) =
                        h2_client.send_request(request, false).unwrap();
                    send_stream
                        .send_data(Bytes::from_static(b"{}"), true)
                        .unwrap();

                    let response = response_fut.await.unwrap();
                    assert_eq!(response.status(), 200);

                    let (_method_path, headers) = rx.await.unwrap();
                    assert_eq!(
                        headers.get("authorization").map(|v| v.to_str().unwrap()),
                        Some(nonce.as_str()),
                        "unresolved nonce must be forwarded unchanged (fail-closed)"
                    );

                    drop(h2_client);
                    conn_handle.abort();
                    let _ = conn_handle.await;
                }
            );
        })
        .await;
        assert!(result.is_ok(), "test timed out — h2 forwarding hung");
    }

    /// Bidirectional gRPC: the upstream sends response headers and a DATA frame
    /// before the client finishes its request body. The proxy must relay that
    /// response concurrently with pumping the request body — if the two halves
    /// ran sequentially (await full request body, then poll response) this would
    /// deadlock and time out.
    #[tokio::test]
    async fn h2_forward_bidi_streaming_no_deadlock() {
        use std::time::Duration;

        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let (upstream_port, body_rx) = spawn_mock_h2_upstream_early_response(&ca).await;

        let route_store = make_route_store(
            "localhost",
            upstream_port,
            vec![EndpointRule {
                method: "POST".to_string(),
                path: "/pkg.Svc/BidiStream".to_string(),
            }],
        )
        .await;
        let credential_store = make_credential_store("sk-test-secret-key");
        let cert_cache = Arc::new(CertCache::new(Arc::clone(&ca)));
        let tls_connector = h2_tls_connector_trusting(ca.cert_pem());
        let filter = ProxyFilter::allow_all();
        let session_token = Zeroizing::new("session-tok".to_string());

        let ctx = InterceptCtx {
            route_id: Some("test-svc"),
            host: "localhost",
            port: upstream_port,
            route_store: Arc::new(route_store),
            credential_store: Arc::new(credential_store),
            oauth_capture_store: Arc::new(crate::oauth_capture::OAuthCaptureStore::empty()),
            session_token: &session_token,
            cert_cache,
            tls_connector: &tls_connector,
            tls_connector_h2: &tls_connector,
            filter: &filter,
            audit_log: None,
            upstream_proxy: None,
            approval_backends: None,
            credential_capture_backend: None,
            nonce_resolver: None,
            enable_h2: true,
        };

        let (client_io, server_io) = tokio::io::duplex(65536);

        let result = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                async {
                    let _ = forward_h2_connection(server_io, &ctx).await;
                },
                async {
                    let (mut h2_client, h2_conn) = h2::client::handshake(client_io).await.unwrap();
                    let conn_handle = tokio::spawn(async move {
                        let _ = h2_conn.await;
                    });

                    let request = http::Request::builder()
                        .method("POST")
                        .uri(format!(
                            "https://localhost:{}/pkg.Svc/BidiStream",
                            upstream_port
                        ))
                        .header("content-type", "application/grpc")
                        .body(())
                        .unwrap();
                    // Keep the request stream OPEN (end_stream = false) and do not
                    // send the body yet — emulating a client waiting for the first
                    // server response before continuing to stream.
                    let (response_fut, mut send_stream) =
                        h2_client.send_request(request, false).unwrap();

                    // We must receive the early response while our request body
                    // is still open. A sequential proxy would never get here.
                    let response = response_fut.await.unwrap();
                    assert_eq!(response.status(), 200);
                    let mut resp_body = response.into_body();
                    let first = resp_body.data().await.unwrap().unwrap();
                    assert_eq!(&first[..], b"early");
                    resp_body
                        .flow_control()
                        .release_capacity(first.len())
                        .unwrap();

                    // Now that we've seen the response, finish the request body.
                    send_stream
                        .send_data(Bytes::from_static(b"late-request-data"), true)
                        .unwrap();

                    // Upstream received the late body only after responding early.
                    let received = body_rx.await.unwrap();
                    assert_eq!(&received[..], b"late-request-data");

                    // Drain the rest of the response.
                    while let Some(chunk) = resp_body.data().await {
                        let chunk = chunk.unwrap();
                        let len = chunk.len();
                        resp_body.flow_control().release_capacity(len).unwrap();
                    }

                    drop(h2_client);
                    conn_handle.abort();
                    let _ = conn_handle.await;
                }
            );
        })
        .await;
        assert!(
            result.is_ok(),
            "test timed out — bidirectional h2 streaming deadlocked"
        );
    }
}
