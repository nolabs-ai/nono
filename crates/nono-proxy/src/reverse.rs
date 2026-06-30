//! Reverse proxy handler (Mode 2 — Credential Injection).
//!
//! Routes requests by path prefix to upstream APIs, injecting credentials
//! from the keystore. The agent uses `http://localhost:PORT/openai/v1/chat`
//! and the proxy rewrites to `https://api.openai.com/v1/chat` with the
//! real credential injected.
//!
//! Supports multiple injection modes:
//! - `header`: Inject into HTTP header (e.g., `Authorization: Bearer ...`)
//! - `url_path`: Replace pattern in URL path (e.g., Telegram `/bot{}/`)
//! - `query_param`: Add/replace query parameter (e.g., `?api_key=...`)
//! - `basic_auth`: HTTP Basic Authentication
//!
//! Streaming responses (SSE, MCP Streamable HTTP, A2A JSON-RPC) are
//! forwarded without buffering.

use crate::audit;
use crate::capture::{CredentialCaptureBackend, CredentialCaptureRequest};
use crate::config::{EndpointPolicyOutcome, InjectMode};
use crate::credential::{CmdCredentialRoute, CredentialStore, LoadedCredential};
use crate::error::{ProxyError, Result};
use crate::filter::ProxyFilter;
use crate::forward::UpstreamScheme;
use crate::route::RouteStore;
use crate::token;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};
use zeroize::Zeroizing;

/// Maximum request body size (16 MiB). Prevents DoS from malicious Content-Length.
const MAX_REQUEST_BODY: usize = 16 * 1024 * 1024;

pub(crate) fn auth_mechanism_for_inject_mode(
    mode: &InjectMode,
) -> nono::undo::NetworkAuditAuthMechanism {
    match mode {
        InjectMode::Header | InjectMode::BasicAuth => {
            nono::undo::NetworkAuditAuthMechanism::PhantomHeader
        }
        InjectMode::UrlPath => nono::undo::NetworkAuditAuthMechanism::PhantomPath,
        InjectMode::QueryParam => nono::undo::NetworkAuditAuthMechanism::PhantomQuery,
    }
}

pub(crate) fn audit_injection_mode_for_inject_mode(
    mode: &InjectMode,
) -> nono::undo::NetworkAuditInjectionMode {
    match mode {
        InjectMode::Header => nono::undo::NetworkAuditInjectionMode::Header,
        InjectMode::UrlPath => nono::undo::NetworkAuditInjectionMode::UrlPath,
        InjectMode::QueryParam => nono::undo::NetworkAuditInjectionMode::QueryParam,
        InjectMode::BasicAuth => nono::undo::NetworkAuditInjectionMode::BasicAuth,
    }
}

fn proxy_auth_event_ctx<'a>(route_id: &'a str) -> audit::EventContext<'a> {
    audit::EventContext {
        route_id: Some(route_id),
        auth_mechanism: Some(nono::undo::NetworkAuditAuthMechanism::ProxyAuthorization),
        ..audit::EventContext::default()
    }
}

fn managed_credential_event_ctx<'a>(
    route_id: &'a str,
    proxy_mode: &InjectMode,
    inject_mode: nono::undo::NetworkAuditInjectionMode,
) -> audit::EventContext<'a> {
    audit::EventContext {
        route_id: Some(route_id),
        auth_mechanism: Some(auth_mechanism_for_inject_mode(proxy_mode)),
        managed_credential_active: Some(true),
        injection_mode: Some(inject_mode),
        ..audit::EventContext::default()
    }
}

/// Handle a non-CONNECT HTTP request (reverse proxy mode).
///
/// Reads the full HTTP request from the client, matches path prefix to
/// a configured route, injects credentials, and forwards to the upstream.
/// Shared context passed from the server to the reverse proxy handler.
pub struct ReverseProxyCtx<'a> {
    /// Route store for upstream URL, L7 filtering, and per-route TLS
    pub route_store: &'a RouteStore,
    /// Credential store for service lookups (optional injection)
    pub credential_store: &'a CredentialStore,
    /// Session token for authentication
    pub session_token: &'a Zeroizing<String>,
    /// Host filter for upstream validation
    pub filter: &'a ProxyFilter,
    /// Shared TLS connector
    pub tls_connector: &'a TlsConnector,
    /// Default TLS client config (for routes without custom CA)
    pub default_tls_config: &'a std::sync::Arc<rustls::ClientConfig>,
    /// Upstream connection pool (HTTP/1.1 keep-alive + HTTP/2 multiplexing)
    pub upstream_pool: &'a crate::pool::UpstreamPool,
    /// Shared network audit sink for session metadata capture
    pub audit_log: Option<&'a audit::SharedAuditLog>,
    /// Optional approval backend registry for endpoint-policy approve decisions.
    pub approval_backends: Option<crate::approval::ApprovalBackendRegistry>,
    /// Optional supervisor capture backend for command-backed credentials.
    pub credential_capture_backend: Option<Arc<dyn CredentialCaptureBackend>>,
}

/// Handle a non-CONNECT HTTP request (reverse proxy mode).
///
/// `buffered_body` contains any bytes the BufReader read ahead beyond the
/// headers. These are prepended to the body read from the stream to prevent
/// data loss.
///
/// ## Phantom Token Pattern
///
/// The client (SDK) sends the session token as its "API key". The proxy:
/// 1. Extracts the service from the path (e.g., `/openai/v1/chat` → `openai`)
/// 2. Looks up which header that service uses (e.g., `Authorization` or `x-api-key`)
/// 3. Validates the phantom token from that header
/// 4. Replaces it with the real credential from keyring
pub async fn handle_reverse_proxy(
    first_line: &str,
    stream: &mut TcpStream,
    remaining_header: &[u8],
    ctx: &ReverseProxyCtx<'_>,
    buffered_body: &[u8],
) -> Result<()> {
    // Parse method, path, and HTTP version
    let (method, path, version) = parse_request_line(first_line)?;
    debug!("Reverse proxy: {} {}", method, path);

    // Extract service prefix from path (e.g., "/openai/v1/chat" -> ("openai", "/v1/chat"))
    let (service, upstream_path) = parse_service_prefix(&path)?;
    let route = ctx
        .route_store
        .get(&service)
        .ok_or_else(|| ProxyError::UnknownService {
            prefix: service.clone(),
        })?;
    let static_cred = ctx.credential_store.get(&service);
    let cmd_route = ctx.credential_store.get_cmd(&service);
    let oauth2_route = ctx.credential_store.get_oauth2(&service);
    let aws_route = ctx.credential_store.get_aws(&service);
    let managed_ctx = static_cred
        .map(|cred| {
            managed_credential_event_ctx(
                &service,
                &cred.proxy_inject_mode,
                audit_injection_mode_for_inject_mode(&cred.inject_mode),
            )
        })
        .or_else(|| {
            cmd_route.map(|cmd| {
                managed_credential_event_ctx(
                    &service,
                    &cmd.proxy_inject_mode,
                    audit_injection_mode_for_inject_mode(&cmd.inject_mode),
                )
            })
        });
    let oauth2_ctx = oauth2_route.map(|_| audit::EventContext {
        route_id: Some(&service),
        auth_mechanism: Some(nono::undo::NetworkAuditAuthMechanism::PhantomHeader),
        managed_credential_active: Some(true),
        injection_mode: Some(nono::undo::NetworkAuditInjectionMode::OAuth2),
        ..audit::EventContext::default()
    });
    let route_ctx = managed_ctx
        .clone()
        .or_else(|| oauth2_ctx.clone())
        .unwrap_or_else(|| audit::EventContext {
            route_id: Some(&service),
            managed_credential_active: Some(false),
            ..audit::EventContext::default()
        });

    let cmd_available = cmd_route.is_some() && ctx.credential_capture_backend.is_some();
    if route.missing_managed_credential(
        static_cred.is_some() || cmd_available,
        oauth2_route.is_some(),
        aws_route.is_some(),
    ) {
        let reason = format!(
            "managed credential unavailable for service '{}': route is configured for proxy-supplied auth",
            service
        );
        warn!("{}", reason);
        let deny_ctx = audit::EventContext {
            route_id: Some(&service),
            auth_mechanism: route.managed_auth_mechanism.clone(),
            auth_outcome: Some(nono::undo::NetworkAuditAuthOutcome::Failed),
            managed_credential_active: Some(false),
            injection_mode: route.managed_injection_mode.clone(),
            denial_category: Some(
                nono::undo::NetworkAuditDenialCategory::ManagedCredentialUnavailable,
            ),
            ..audit::EventContext::default()
        };
        audit::log_denied(
            ctx.audit_log,
            audit::ProxyMode::Reverse,
            &deny_ctx,
            &service,
            0,
            &reason,
        );
        send_error(stream, 503, "Service Unavailable").await?;
        return Ok(());
    }

    if !enforce_endpoint_policy(
        route,
        &service,
        &method,
        &upstream_path,
        &route_ctx,
        ctx,
        stream,
    )
    .await?
    {
        return Ok(());
    }

    if let Some(oauth2_route) = oauth2_route {
        return handle_oauth2_credential(
            oauth2_route,
            route,
            &service,
            &upstream_path,
            &method,
            &version,
            stream,
            remaining_header,
            buffered_body,
            ctx,
        )
        .await;
    }

    // AWS SigV4 signing is not yet implemented. Return 501 so the caller
    // knows the route exists but is not functional. This branch will be
    // replaced with real SigV4 signing in a follow-up.
    if aws_route.is_some() {
        send_error(stream, 501, "Not Implemented").await?;
        return Ok(());
    }

    let cred = static_cred;

    // Authenticate the request. Every reverse proxy request must prove
    // possession of the session token, regardless of whether a credential
    // is configured — this is the localhost auth boundary.
    if let Some(cred) = cred {
        if let Err(e) = validate_phantom_token_for_mode(
            &cred.proxy_inject_mode,
            remaining_header,
            &upstream_path,
            &cred.proxy_header_name,
            cred.proxy_path_pattern.as_deref(),
            cred.proxy_query_param_name.as_deref(),
            ctx.session_token,
        ) {
            let deny_ctx = audit::EventContext {
                auth_outcome: Some(nono::undo::NetworkAuditAuthOutcome::Failed),
                denial_category: Some(nono::undo::NetworkAuditDenialCategory::AuthenticationFailed),
                ..managed_ctx.clone().unwrap_or_else(|| route_ctx.clone())
            };
            audit::log_denied(
                ctx.audit_log,
                audit::ProxyMode::Reverse,
                &deny_ctx,
                &service,
                0,
                &e.to_string(),
            );
            send_error(stream, 401, "Unauthorized").await?;
            return Ok(());
        }
    } else if let Some(cmd) = cmd_route {
        if let Err(e) = validate_phantom_token_for_mode(
            &cmd.proxy_inject_mode,
            remaining_header,
            &upstream_path,
            &cmd.proxy_header_name,
            cmd.proxy_path_pattern.as_deref(),
            cmd.proxy_query_param_name.as_deref(),
            ctx.session_token,
        ) {
            let deny_ctx = audit::EventContext {
                auth_outcome: Some(nono::undo::NetworkAuditAuthOutcome::Failed),
                denial_category: Some(nono::undo::NetworkAuditDenialCategory::AuthenticationFailed),
                ..managed_ctx.clone().unwrap_or_else(|| route_ctx.clone())
            };
            audit::log_denied(
                ctx.audit_log,
                audit::ProxyMode::Reverse,
                &deny_ctx,
                &service,
                0,
                &e.to_string(),
            );
            send_error(stream, 401, "Unauthorized").await?;
            return Ok(());
        }
    } else if let Err(e) = token::validate_proxy_auth(remaining_header, ctx.session_token) {
        let deny_ctx = audit::EventContext {
            auth_outcome: Some(nono::undo::NetworkAuditAuthOutcome::Failed),
            denial_category: Some(nono::undo::NetworkAuditDenialCategory::AuthenticationFailed),
            ..proxy_auth_event_ctx(&service)
        };
        audit::log_denied(
            ctx.audit_log,
            audit::ProxyMode::Reverse,
            &deny_ctx,
            &service,
            0,
            &e.to_string(),
        );
        send_error(stream, 407, "Proxy Authentication Required").await?;
        return Ok(());
    }

    let captured_credential = if let Some(cmd) = cmd_route
        && cred.is_none()
    {
        match capture_cmd_credential(
            cmd,
            &service,
            &route.upstream,
            &upstream_path,
            &method,
            &service,
            0,
            audit::ProxyMode::Reverse,
            ctx.audit_log,
            ctx.credential_capture_backend.clone(),
        )
        .await
        {
            Ok(credential) => Some(credential),
            Err(err) => {
                warn!("{}", err);
                let deny_ctx = audit::EventContext {
                    route_id: Some(&service),
                    auth_mechanism: route.managed_auth_mechanism.clone(),
                    auth_outcome: Some(nono::undo::NetworkAuditAuthOutcome::Failed),
                    managed_credential_active: Some(false),
                    injection_mode: route.managed_injection_mode.clone(),
                    denial_category: Some(
                        nono::undo::NetworkAuditDenialCategory::ManagedCredentialUnavailable,
                    ),
                    ..audit::EventContext::default()
                };
                audit::log_denied(
                    ctx.audit_log,
                    audit::ProxyMode::Reverse,
                    &deny_ctx,
                    &service,
                    0,
                    &err.to_string(),
                );
                send_error(stream, 503, "Service Unavailable").await?;
                return Ok(());
            }
        }
    } else {
        None
    };
    let cred = cred.or(captured_credential.as_ref());

    let transformed_path = if let Some(cred) = cred {
        let cleaned_path = strip_proxy_artifacts(
            &upstream_path,
            &cred.proxy_inject_mode,
            &cred.inject_mode,
            cred.proxy_path_pattern.as_deref(),
            cred.proxy_query_param_name.as_deref(),
        );
        transform_path_for_mode(
            &cred.inject_mode,
            &cleaned_path,
            cred.path_pattern.as_deref(),
            cred.path_replacement.as_deref(),
            cred.query_param_name.as_deref(),
            &cred.raw_credential,
        )?
    } else {
        upstream_path.clone()
    };

    let upstream_url = format!(
        "{}{}",
        route.upstream.trim_end_matches('/'),
        transformed_path
    );
    debug!("Forwarding to upstream: {} {}", method, upstream_url);

    let (upstream_scheme, upstream_host, upstream_port, upstream_path_full) =
        parse_upstream_url(&upstream_url)?;
    let check = ctx.filter.check_host(&upstream_host, upstream_port).await?;
    if !check.result.is_allowed() {
        let reason = check.result.reason();
        warn!("Upstream host denied by filter: {}", reason);
        send_error(stream, 403, "Forbidden").await?;
        let deny_ctx = audit::EventContext {
            denial_category: Some(nono::undo::NetworkAuditDenialCategory::HostDenied),
            ..route_ctx.clone()
        };
        audit::log_denied(
            ctx.audit_log,
            audit::ProxyMode::Reverse,
            &deny_ctx,
            &service,
            0,
            &reason,
        );
        return Ok(());
    }
    if let Err(reason) =
        validate_http_upstream_target(upstream_scheme, &upstream_host, &check.resolved_addrs)
    {
        warn!("{}", reason);
        send_error(stream, 502, "Bad Gateway").await?;
        let deny_ctx = audit::EventContext {
            denial_category: Some(nono::undo::NetworkAuditDenialCategory::UpstreamConnectFailed),
            ..route_ctx.clone()
        };
        audit::log_denied(
            ctx.audit_log,
            audit::ProxyMode::Reverse,
            &deny_ctx,
            &service,
            0,
            &reason,
        );
        return Ok(());
    }

    let success_ctx = if let Some(ctx) = managed_ctx.clone() {
        audit::EventContext {
            auth_outcome: Some(nono::undo::NetworkAuditAuthOutcome::Succeeded),
            ..ctx
        }
    } else if oauth2_ctx.is_some() {
        audit::EventContext {
            auth_outcome: Some(nono::undo::NetworkAuditAuthOutcome::Succeeded),
            ..oauth2_ctx.clone().unwrap_or_default()
        }
    } else {
        audit::EventContext {
            auth_outcome: Some(nono::undo::NetworkAuditAuthOutcome::Succeeded),
            managed_credential_active: Some(false),
            ..proxy_auth_event_ctx(&service)
        }
    };

    let strip_header = cred.map(|c| c.proxy_header_name.as_str()).unwrap_or("");
    let filtered_headers = filter_headers(remaining_header, strip_header);
    let content_length = extract_content_length(remaining_header);
    let body = match read_request_body(stream, content_length, buffered_body).await? {
        Some(body) => body,
        None => return Ok(()),
    };

    let upstream_authority = format_host_header(upstream_scheme, &upstream_host, upstream_port);
    let scheme_str = match upstream_scheme {
        UpstreamScheme::Https => "https",
        UpstreamScheme::Http => "http",
    };
    let uri = format!(
        "{}://{}{}",
        scheme_str, upstream_authority, upstream_path_full
    );

    let mut req_builder = http::Request::builder()
        .method(method.as_str())
        .uri(&uri)
        .header("Host", &upstream_authority);

    // Inject credential header
    if let Some(cred) = cred {
        req_builder = inject_credential_structured(cred, req_builder);
    }

    let injected_header_names = injected_credential_header_names(cred);
    for (name, value) in &filtered_headers {
        if injected_header_names
            .iter()
            .any(|header| name.eq_ignore_ascii_case(header))
        {
            continue;
        }
        req_builder = req_builder.header(name.as_str(), value.as_str());
    }

    let req = req_builder
        .body(http_body_util::Full::new(bytes::Bytes::from(body)))
        .map_err(|e| ProxyError::HttpParse(format!("request build error: {}", e)))?;

    let tls_config = route
        .tls_client_config
        .as_ref()
        .unwrap_or(ctx.default_tls_config);

    ctx.upstream_pool
        .pin_host(&upstream_host, &check.resolved_addrs);

    match pool_forward(ctx.upstream_pool, tls_config, req, stream).await {
        Ok(status) => {
            audit::log_l7_request(
                ctx.audit_log,
                audit::ProxyMode::Reverse,
                &success_ctx,
                &service,
                &method,
                &upstream_path,
                status,
            );
        }
        Err(e) => {
            warn!("Upstream connection failed: {}", e);
            send_error(stream, 502, "Bad Gateway").await?;
            let deny_ctx = audit::EventContext {
                denial_category: Some(
                    nono::undo::NetworkAuditDenialCategory::UpstreamConnectFailed,
                ),
                ..success_ctx.clone()
            };
            audit::log_denied(
                ctx.audit_log,
                audit::ProxyMode::Reverse,
                &deny_ctx,
                &service,
                0,
                &e.to_string(),
            );
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn capture_cmd_credential(
    cmd: &CmdCredentialRoute,
    route_id: &str,
    upstream: &str,
    request_path: &str,
    request_method: &str,
    request_host: &str,
    request_port: u16,
    proxy_mode: audit::ProxyMode,
    audit_log: Option<&audit::SharedAuditLog>,
    backend: Option<Arc<dyn CredentialCaptureBackend>>,
) -> Result<LoadedCredential> {
    let Some(backend) = backend else {
        let reason = format!(
            "credential '{}' requires supervisor capture but no capture backend is configured",
            cmd.credential_name
        );
        audit::log_credential_capture(
            audit_log,
            proxy_mode,
            audit::CredentialCaptureAudit {
                route_id,
                credential_name: &cmd.credential_name,
                action: "denied",
                decision: nono::undo::NetworkAuditDecision::Deny,
                command: None,
                argv: None,
                exit_status: None,
                duration_ms: Some(0),
                stdout_bytes: None,
                stderr_redacted: None,
                cache_scope: None,
                output_format: None,
                header_names: None,
                stdin_mode: None,
                interactive: None,
                upstream: Some(upstream),
                request_host,
                request_port: Some(request_port),
                request_method,
                request_path,
                reason: Some(&reason),
            },
        );
        return Err(ProxyError::Credential(reason));
    };

    let request = CredentialCaptureRequest {
        credential_name: cmd.credential_name.clone(),
        route_id: route_id.to_string(),
        request_host: request_host.to_string(),
        request_path: request_path.to_string(),
        request_method: request_method.to_string(),
        session_id: String::new(),
        cache_scope: String::new(),
    };
    let result = tokio::task::spawn_blocking(move || backend.capture(request))
        .await
        .map_err(|err| ProxyError::Credential(format!("credential capture task failed: {err}")))?;

    match result {
        Ok(response) => {
            audit::log_credential_capture(
                audit_log,
                proxy_mode,
                audit::CredentialCaptureAudit {
                    route_id,
                    credential_name: &cmd.credential_name,
                    action: &response.metadata.cache_action,
                    decision: nono::undo::NetworkAuditDecision::Allow,
                    command: response.metadata.command.as_deref(),
                    argv: Some(&response.metadata.argv),
                    exit_status: response.metadata.exit_status,
                    duration_ms: Some(response.metadata.duration_ms),
                    stdout_bytes: response.metadata.stdout_bytes,
                    stderr_redacted: response.metadata.stderr_redacted.as_deref(),
                    cache_scope: response.metadata.cache_scope.as_deref(),
                    output_format: response.metadata.output_format.as_deref(),
                    header_names: Some(&response.metadata.header_names),
                    stdin_mode: response.metadata.stdin_mode.as_deref(),
                    interactive: response.metadata.interactive,
                    upstream: Some(upstream),
                    request_host,
                    request_port: Some(request_port),
                    request_method,
                    request_path,
                    reason: None,
                },
            );
            Ok(cmd.materialize(response.material))
        }
        Err(err) => {
            audit::log_credential_capture(
                audit_log,
                proxy_mode,
                audit::CredentialCaptureAudit {
                    route_id,
                    credential_name: &cmd.credential_name,
                    action: &err.metadata.cache_action,
                    decision: nono::undo::NetworkAuditDecision::Deny,
                    command: err.metadata.command.as_deref(),
                    argv: Some(&err.metadata.argv),
                    exit_status: err.metadata.exit_status,
                    duration_ms: Some(err.metadata.duration_ms),
                    stdout_bytes: err.metadata.stdout_bytes,
                    stderr_redacted: err.metadata.stderr_redacted.as_deref(),
                    cache_scope: err.metadata.cache_scope.as_deref(),
                    output_format: err.metadata.output_format.as_deref(),
                    header_names: Some(&err.metadata.header_names),
                    stdin_mode: err.metadata.stdin_mode.as_deref(),
                    interactive: err.metadata.interactive,
                    upstream: Some(upstream),
                    request_host,
                    request_port: Some(request_port),
                    request_method,
                    request_path,
                    reason: Some(&err.reason),
                },
            );
            Err(ProxyError::Credential(err.reason))
        }
    }
}

async fn enforce_endpoint_policy(
    route: &crate::route::LoadedRoute,
    service: &str,
    method: &str,
    upstream_path: &str,
    route_ctx: &audit::EventContext<'_>,
    ctx: &ReverseProxyCtx<'_>,
    stream: &mut TcpStream,
) -> Result<bool> {
    match route.endpoint_policy.evaluate(method, upstream_path) {
        EndpointPolicyOutcome::Allow { rule_label } => {
            let policy_ctx = audit::EventContext {
                endpoint_policy_action: Some("allow"),
                endpoint_policy_rule: Some(&rule_label),
                upstream: Some(&route.upstream),
                ..route_ctx.clone()
            };
            audit::log_l7_policy_decision(
                ctx.audit_log,
                audit::ProxyMode::Reverse,
                &policy_ctx,
                service,
                None,
                method,
                upstream_path,
                nono::undo::NetworkAuditDecision::Allow,
                "allow",
                &rule_label,
                None,
            );
            Ok(true)
        }
        EndpointPolicyOutcome::Deny { reason, rule_label } => {
            let reason = reason.map(str::to_string).unwrap_or_else(|| {
                format!(
                    "endpoint denied by {}: {} {} on service '{}'",
                    rule_label, method, upstream_path, service
                )
            });
            warn!("{}", reason);
            let deny_ctx = audit::EventContext {
                denial_category: Some(nono::undo::NetworkAuditDenialCategory::EndpointPolicy),
                endpoint_policy_action: Some("deny"),
                endpoint_policy_rule: Some(&rule_label),
                upstream: Some(&route.upstream),
                ..route_ctx.clone()
            };
            audit::log_l7_policy_decision(
                ctx.audit_log,
                audit::ProxyMode::Reverse,
                &deny_ctx,
                service,
                None,
                method,
                upstream_path,
                nono::undo::NetworkAuditDecision::Deny,
                "deny",
                &rule_label,
                Some(&reason),
            );
            send_error(stream, 403, "Forbidden").await?;
            Ok(false)
        }
        EndpointPolicyOutcome::Approve {
            backend,
            reason,
            timeout_secs,
            rule_label,
        } => {
            let Some(approval_backends) = ctx.approval_backends.clone() else {
                let deny_reason = format!(
                    "endpoint approval required by {} but no approval backend is configured",
                    rule_label
                );
                warn!("{}", deny_reason);
                let deny_ctx = audit::EventContext {
                    denial_category: Some(nono::undo::NetworkAuditDenialCategory::EndpointPolicy),
                    endpoint_policy_action: Some("approve"),
                    endpoint_policy_rule: Some(&rule_label),
                    upstream: Some(&route.upstream),
                    ..route_ctx.clone()
                };
                audit::log_l7_policy_decision(
                    ctx.audit_log,
                    audit::ProxyMode::Reverse,
                    &deny_ctx,
                    service,
                    None,
                    method,
                    upstream_path,
                    nono::undo::NetworkAuditDecision::ApproveError,
                    "approve",
                    &rule_label,
                    Some(&deny_reason),
                );
                send_error(stream, 403, "Forbidden").await?;
                return Ok(false);
            };
            let (backend_name, backend) = match approval_backends.resolve(backend) {
                Ok(resolved) => resolved,
                Err(err) => {
                    let deny_reason = format!("endpoint approval backend resolution failed: {err}");
                    warn!("{}", deny_reason);
                    let deny_ctx = audit::EventContext {
                        denial_category: Some(
                            nono::undo::NetworkAuditDenialCategory::EndpointPolicy,
                        ),
                        endpoint_policy_action: Some("approve"),
                        endpoint_policy_rule: Some(&rule_label),
                        upstream: Some(&route.upstream),
                        ..route_ctx.clone()
                    };
                    audit::log_l7_policy_decision(
                        ctx.audit_log,
                        audit::ProxyMode::Reverse,
                        &deny_ctx,
                        service,
                        None,
                        method,
                        upstream_path,
                        nono::undo::NetworkAuditDecision::ApproveError,
                        "approve",
                        &rule_label,
                        Some(&deny_reason),
                    );
                    send_error(stream, 403, "Forbidden").await?;
                    return Ok(false);
                }
            };
            let request_reason = reason.map(str::to_string).unwrap_or_else(|| {
                format!(
                    "endpoint approval required by {} for {} {}",
                    rule_label, method, upstream_path
                )
            });
            let approval_ctx = audit::EventContext {
                endpoint_policy_action: Some("approve"),
                endpoint_policy_rule: Some(&rule_label),
                approval_backend: Some(&backend_name),
                upstream: Some(&route.upstream),
                ..route_ctx.clone()
            };
            audit::log_l7_policy_decision(
                ctx.audit_log,
                audit::ProxyMode::Reverse,
                &approval_ctx,
                service,
                None,
                method,
                upstream_path,
                nono::undo::NetworkAuditDecision::ApproveRequested,
                "approve",
                &rule_label,
                Some(&request_reason),
            );
            let request = nono::supervisor::ApprovalRequest::Endpoint {
                request_id: endpoint_approval_request_id(service),
                route_id: service.to_string(),
                upstream: route.upstream.clone(),
                method: method.to_string(),
                path: upstream_path.to_string(),
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
                        ctx.audit_log,
                        audit::ProxyMode::Reverse,
                        &approval_ctx,
                        service,
                        None,
                        method,
                        upstream_path,
                        nono::undo::NetworkAuditDecision::ApproveGranted,
                        "approve",
                        &rule_label,
                        None,
                    );
                    return Ok(true);
                }
                Ok(Ok(Ok(_))) => {}
                Ok(Ok(Err(err))) => {
                    let deny_reason = format!("endpoint approval backend error: {err}");
                    audit::log_l7_policy_decision(
                        ctx.audit_log,
                        audit::ProxyMode::Reverse,
                        &approval_ctx,
                        service,
                        None,
                        method,
                        upstream_path,
                        nono::undo::NetworkAuditDecision::ApproveError,
                        "approve",
                        &rule_label,
                        Some(&deny_reason),
                    );
                    warn!("{}", deny_reason);
                    send_error(stream, 403, "Forbidden").await?;
                    return Ok(false);
                }
                Ok(Err(err)) => {
                    let deny_reason = format!("endpoint approval task failed: {err}");
                    audit::log_l7_policy_decision(
                        ctx.audit_log,
                        audit::ProxyMode::Reverse,
                        &approval_ctx,
                        service,
                        None,
                        method,
                        upstream_path,
                        nono::undo::NetworkAuditDecision::ApproveError,
                        "approve",
                        &rule_label,
                        Some(&deny_reason),
                    );
                    warn!("{}", deny_reason);
                    send_error(stream, 403, "Forbidden").await?;
                    return Ok(false);
                }
                Err(_) => {
                    let deny_reason = format!(
                        "endpoint approval timed out by {}: {} {} on service '{}'",
                        rule_label, method, upstream_path, service
                    );
                    audit::log_l7_policy_decision(
                        ctx.audit_log,
                        audit::ProxyMode::Reverse,
                        &approval_ctx,
                        service,
                        None,
                        method,
                        upstream_path,
                        nono::undo::NetworkAuditDecision::ApproveTimeout,
                        "approve",
                        &rule_label,
                        Some(&deny_reason),
                    );
                    warn!("{}", deny_reason);
                    send_error(stream, 403, "Forbidden").await?;
                    return Ok(false);
                }
            }
            let deny_reason = format!(
                "endpoint approval denied by {}: {} {} on service '{}'",
                rule_label, method, upstream_path, service
            );
            warn!("{}", deny_reason);
            audit::log_l7_policy_decision(
                ctx.audit_log,
                audit::ProxyMode::Reverse,
                &approval_ctx,
                service,
                None,
                method,
                upstream_path,
                nono::undo::NetworkAuditDecision::ApproveDenied,
                "approve",
                &rule_label,
                Some(&deny_reason),
            );
            send_error(stream, 403, "Forbidden").await?;
            Ok(false)
        }
    }
}

fn endpoint_approval_request_id(service: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("proxy-endpoint-approval-{service}-{nanos}")
}

/// Handle a reverse proxy request using an OAuth2 token cache.
///
/// Retrieves a (possibly refreshed) access token from the cache and injects
/// it as `Authorization: Bearer <token>`. The agent authenticates with the
/// session token via the `Authorization: Bearer <phantom>` header, which is
/// validated and then replaced with the real OAuth2 access token.
#[allow(clippy::too_many_arguments)]
async fn handle_oauth2_credential(
    oauth2_route: &crate::credential::OAuth2Route,
    route: &crate::route::LoadedRoute,
    service: &str,
    upstream_path: &str,
    method: &str,
    _version: &str,
    stream: &mut TcpStream,
    remaining_header: &[u8],
    buffered_body: &[u8],
    ctx: &ReverseProxyCtx<'_>,
) -> Result<()> {
    // Get (possibly refreshed) OAuth2 access token
    let access_token = oauth2_route.cache.get_or_refresh().await;

    // Validate session token from Authorization header (phantom token pattern).
    // OAuth2 routes still require the agent to authenticate with the session
    // token — this prevents unauthorized access to the token-exchanged credential.
    if let Err(e) = validate_phantom_token(remaining_header, "Authorization", ctx.session_token) {
        let deny_ctx = audit::EventContext {
            route_id: Some(service),
            auth_mechanism: Some(nono::undo::NetworkAuditAuthMechanism::PhantomHeader),
            auth_outcome: Some(nono::undo::NetworkAuditAuthOutcome::Failed),
            managed_credential_active: Some(true),
            injection_mode: Some(nono::undo::NetworkAuditInjectionMode::OAuth2),
            denial_category: Some(nono::undo::NetworkAuditDenialCategory::AuthenticationFailed),
            ..audit::EventContext::default()
        };
        audit::log_denied(
            ctx.audit_log,
            audit::ProxyMode::Reverse,
            &deny_ctx,
            service,
            0,
            &e.to_string(),
        );
        send_error(stream, 401, "Unauthorized").await?;
        return Ok(());
    }

    let upstream_url = format!(
        "{}{}",
        oauth2_route.upstream.trim_end_matches('/'),
        upstream_path
    );
    debug!("OAuth2 forwarding to upstream: {} {}", method, upstream_url);

    let (upstream_scheme, upstream_host, upstream_port, upstream_path_full) =
        parse_upstream_url(&upstream_url)?;
    // DNS resolve + host check via the filter
    let check = ctx.filter.check_host(&upstream_host, upstream_port).await?;
    if !check.result.is_allowed() {
        let reason = check.result.reason();
        warn!("Upstream host denied by filter: {}", reason);
        send_error(stream, 403, "Forbidden").await?;
        let route_ctx = audit::EventContext {
            route_id: Some(service),
            managed_credential_active: Some(true),
            injection_mode: Some(nono::undo::NetworkAuditInjectionMode::OAuth2),
            denial_category: Some(nono::undo::NetworkAuditDenialCategory::HostDenied),
            ..audit::EventContext::default()
        };
        audit::log_denied(
            ctx.audit_log,
            audit::ProxyMode::Reverse,
            &route_ctx,
            service,
            0,
            &reason,
        );
        return Ok(());
    }
    if let Err(reason) =
        validate_http_upstream_target(upstream_scheme, &upstream_host, &check.resolved_addrs)
    {
        warn!("{}", reason);
        send_error(stream, 502, "Bad Gateway").await?;
        let route_ctx = audit::EventContext {
            route_id: Some(service),
            managed_credential_active: Some(true),
            injection_mode: Some(nono::undo::NetworkAuditInjectionMode::OAuth2),
            denial_category: Some(nono::undo::NetworkAuditDenialCategory::UpstreamConnectFailed),
            ..audit::EventContext::default()
        };
        audit::log_denied(
            ctx.audit_log,
            audit::ProxyMode::Reverse,
            &route_ctx,
            service,
            0,
            &reason,
        );
        return Ok(());
    }

    // Collect remaining request headers, stripping the client-supplied
    // Authorization header that carries the phantom token.
    let filtered_headers = filter_headers(remaining_header, "Authorization");
    let content_length = extract_content_length(remaining_header);

    // Read request body
    let body = match read_request_body(stream, content_length, buffered_body).await? {
        Some(body) => body,
        None => return Ok(()),
    };

    // Build upstream request with Bearer token injection
    let upstream_authority = format_host_header(upstream_scheme, &upstream_host, upstream_port);
    let scheme_str = match upstream_scheme {
        UpstreamScheme::Https => "https",
        UpstreamScheme::Http => "http",
    };
    let uri = format!(
        "{}://{}{}",
        scheme_str, upstream_authority, upstream_path_full
    );

    let bearer_value = Zeroizing::new(format!("Bearer {}", access_token.as_str()));
    let mut req_builder = http::Request::builder()
        .method(method)
        .uri(&uri)
        .header("Host", &upstream_authority)
        .header("Authorization", bearer_value.as_str());

    for (name, value) in &filtered_headers {
        req_builder = req_builder.header(name.as_str(), value.as_str());
    }

    let req = req_builder
        .body(http_body_util::Full::new(bytes::Bytes::from(body)))
        .map_err(|e| ProxyError::HttpParse(format!("request build error: {}", e)))?;

    let tls_config = route
        .tls_client_config
        .as_ref()
        .unwrap_or(ctx.default_tls_config);

    ctx.upstream_pool
        .pin_host(&upstream_host, &check.resolved_addrs);

    let success_event = audit::EventContext {
        route_id: Some(service),
        auth_mechanism: Some(nono::undo::NetworkAuditAuthMechanism::PhantomHeader),
        auth_outcome: Some(nono::undo::NetworkAuditAuthOutcome::Succeeded),
        managed_credential_active: Some(true),
        injection_mode: Some(nono::undo::NetworkAuditInjectionMode::OAuth2),
        denial_category: None,
        ..audit::EventContext::default()
    };

    match pool_forward(ctx.upstream_pool, tls_config, req, stream).await {
        Ok(status) => {
            audit::log_l7_request(
                ctx.audit_log,
                audit::ProxyMode::Reverse,
                &success_event,
                service,
                method,
                upstream_path,
                status,
            );
        }
        Err(e) => {
            warn!("Upstream connection failed: {}", e);
            send_error(stream, 502, "Bad Gateway").await?;
            audit::log_denied(
                ctx.audit_log,
                audit::ProxyMode::Reverse,
                &audit::EventContext {
                    denial_category: Some(
                        nono::undo::NetworkAuditDenialCategory::UpstreamConnectFailed,
                    ),
                    ..success_event
                },
                service,
                0,
                &e.to_string(),
            );
        }
    }
    Ok(())
}

/// Read request body from the client stream with size limit.
///
/// `buffered_body` contains bytes the BufReader read ahead beyond headers.
/// Generic over the inbound stream so the TLS-intercept handler can reuse
/// it on a `TlsStream<…>` without duplication.
pub(crate) async fn read_request_body<S>(
    stream: &mut S,
    content_length: Option<usize>,
    buffered_body: &[u8],
) -> Result<Option<Vec<u8>>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if let Some(len) = content_length {
        if len > MAX_REQUEST_BODY {
            send_error_generic(stream, 413, "Payload Too Large").await?;
            return Ok(None);
        }
        let mut buf = Vec::with_capacity(len);
        let pre = buffered_body.len().min(len);
        buf.extend_from_slice(&buffered_body[..pre]);
        let remaining = len - pre;
        if remaining > 0 {
            let mut rest = vec![0u8; remaining];
            stream.read_exact(&mut rest).await?;
            buf.extend_from_slice(&rest);
        }
        Ok(Some(buf))
    } else {
        Ok(Some(Vec::new()))
    }
}

/// Generic equivalent of `send_error` used by [`read_request_body`].
pub(crate) async fn send_error_generic<S>(stream: &mut S, status: u16, reason: &str) -> Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let body = format!("{{\"error\":\"{}\"}}", reason);
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        status,
        reason,
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

/// Forward a request through the upstream pool and stream the response back
/// to the inbound client as HTTP/1.1.
///
/// Handles both the pool send and writing the full HTTP/1.1 response (status
/// line, headers, body) back to the raw TCP stream. Returns the response
/// status code on success.
async fn pool_forward(
    pool: &crate::pool::UpstreamPool,
    tls_config: &std::sync::Arc<rustls::ClientConfig>,
    req: http::Request<http_body_util::Full<bytes::Bytes>>,
    inbound: &mut TcpStream,
) -> Result<u16> {
    use http_body_util::BodyExt;

    let response = pool.send(tls_config, req).await?;

    let status = response.status().as_u16();
    let version = response.version();

    debug!("pool: upstream responded {} via {:?}", status, version);

    // Write HTTP/1.1 status line
    let reason = response.status().canonical_reason().unwrap_or("OK");
    let status_line = format!("HTTP/1.1 {} {}\r\n", status, reason);
    inbound.write_all(status_line.as_bytes()).await?;

    // Write response headers
    for (name, value) in response.headers() {
        // Skip h2-specific pseudo-headers and connection-level headers
        let name_str = name.as_str();
        if name_str == "transfer-encoding" || name_str == "connection" {
            continue;
        }
        inbound
            .write_all(format!("{}: {}\r\n", name, value.to_str().unwrap_or("")).as_bytes())
            .await?;
    }
    inbound.write_all(b"\r\n").await?;

    // Stream body frames without buffering
    let mut body = response.into_body();
    loop {
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Some(data) = frame.data_ref() {
                    inbound.write_all(data).await?;
                }
            }
            Some(Err(e)) => {
                debug!("pool: response body read error: {}", e);
                break;
            }
            None => break,
        }
    }
    inbound.flush().await?;

    Ok(status)
}

/// Parse an HTTP request line into (method, path, version).
fn parse_request_line(line: &str) -> Result<(String, String, String)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 3 {
        return Err(ProxyError::HttpParse(format!(
            "malformed request line: {}",
            line
        )));
    }
    Ok((
        parts[0].to_string(),
        parts[1].to_string(),
        parts[2].to_string(),
    ))
}

/// Extract service prefix from path.
///
/// "/openai/v1/chat/completions" -> ("openai", "/v1/chat/completions")
/// "/anthropic/v1/messages" -> ("anthropic", "/v1/messages")
fn parse_service_prefix(path: &str) -> Result<(String, String)> {
    let trimmed = path.strip_prefix('/').unwrap_or(path);
    if let Some((prefix, rest)) = trimmed.split_once('/') {
        Ok((prefix.to_string(), format!("/{}", rest)))
    } else {
        // No sub-path, just the prefix
        Ok((trimmed.to_string(), "/".to_string()))
    }
}

/// Validate the phantom token from the service's auth header.
///
/// The SDK sends the session token as its "API key" in the standard auth header
/// for that service (e.g., `Authorization: Bearer <token>` for OpenAI,
/// `x-api-key: <token>` for Anthropic). We validate the token matches the
/// session token before swapping in the real credential.
fn validate_phantom_token(
    header_bytes: &[u8],
    header_name: &str,
    session_token: &Zeroizing<String>,
) -> Result<()> {
    let header_str = std::str::from_utf8(header_bytes).map_err(|_| ProxyError::InvalidToken)?;
    let header_name_lower = header_name.to_lowercase();

    for line in header_str.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with(&format!("{}:", header_name_lower)) {
            let value = line.split_once(':').map(|(_, v)| v.trim()).unwrap_or("");

            // Handle "Bearer <token>" format (strip "Bearer " prefix if present)
            // Use case-insensitive check, then slice original value by length
            let value_lower = value.to_lowercase();
            let token_value = if value_lower.starts_with("bearer ") {
                // "bearer ".len() == 7
                value[7..].trim()
            } else {
                value
            };

            if token::constant_time_eq(token_value.as_bytes(), session_token.as_bytes()) {
                return Ok(());
            }
            warn!("Invalid phantom token in {} header", header_name);
            return Err(ProxyError::InvalidToken);
        }
    }

    warn!(
        "Missing {} header for phantom token validation",
        header_name
    );
    Err(ProxyError::InvalidToken)
}

/// Filter headers, removing hop-by-hop and proxy-internal headers.
///
/// Always strips:
/// - `Host` (rewritten to upstream)
/// - `Content-Length` (re-added after body is read)
/// - `Proxy-Authorization` (hop-by-hop, contains session token)
///
/// When `cred_header` is non-empty, also strips that header (it contains
/// the phantom token that must not be forwarded alongside the real credential).
/// When `cred_header` is empty (no-credential route), all other headers
/// including `Authorization` are passed through to the upstream.
pub(crate) fn filter_headers(header_bytes: &[u8], cred_header: &str) -> Vec<(String, String)> {
    let header_str = std::str::from_utf8(header_bytes).unwrap_or("");
    let cred_header_lower = if cred_header.is_empty() {
        String::new()
    } else {
        format!("{}:", cred_header.to_lowercase())
    };
    let mut headers = Vec::new();

    for line in header_str.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("host:")
            || lower.starts_with("content-length:")
            || lower.starts_with("connection:")
            || lower.starts_with("proxy-authorization:")
            || (!cred_header_lower.is_empty() && lower.starts_with(&cred_header_lower))
            || line.trim().is_empty()
        {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }

    headers
}

/// Extract Content-Length value from raw headers.
pub(crate) fn extract_content_length(header_bytes: &[u8]) -> Option<usize> {
    let header_str = std::str::from_utf8(header_bytes).ok()?;
    for line in header_str.lines() {
        if line.to_lowercase().starts_with("content-length:") {
            let value = line.split_once(':')?.1.trim();
            return value.parse().ok();
        }
    }
    None
}

fn validate_http_upstream_target(
    scheme: UpstreamScheme,
    host: &str,
    resolved_addrs: &[SocketAddr],
) -> std::result::Result<(), String> {
    if matches!(scheme, UpstreamScheme::Https) {
        return Ok(());
    }

    if is_local_only_target(host, resolved_addrs) {
        Ok(())
    } else {
        Err(format!(
            "refusing insecure http upstream for non-local host '{}'; http is only allowed for loopback addresses",
            host
        ))
    }
}

fn is_local_only_target(host: &str, resolved_addrs: &[SocketAddr]) -> bool {
    if !resolved_addrs.is_empty() {
        return resolved_addrs.iter().all(|addr| addr.ip().is_loopback());
    }

    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => ip.is_loopback(),
        Ok(std::net::IpAddr::V6(ip)) => ip.is_loopback(),
        Err(_) => false,
    }
}

pub(crate) fn format_host_header(scheme: UpstreamScheme, host: &str, port: u16) -> String {
    let default_port = match scheme {
        UpstreamScheme::Http => 80,
        UpstreamScheme::Https => 443,
    };
    let bracketed_host = if host.contains(':') && !host.starts_with('[') {
        format!("[{}]", host)
    } else {
        host.to_string()
    };

    if port == default_port {
        bracketed_host
    } else {
        format!("{}:{}", bracketed_host, port)
    }
}

fn parse_upstream_url(url_str: &str) -> Result<(UpstreamScheme, String, u16, String)> {
    let parsed = url::Url::parse(url_str)
        .map_err(|e| ProxyError::HttpParse(format!("invalid upstream URL '{}': {}", url_str, e)))?;

    let scheme = match parsed.scheme() {
        "https" => UpstreamScheme::Https,
        "http" => UpstreamScheme::Http,
        _ => {
            return Err(ProxyError::HttpParse(format!(
                "unsupported URL scheme: {}",
                url_str
            )));
        }
    };

    let host = parsed
        .host_str()
        .ok_or_else(|| ProxyError::HttpParse(format!("missing host in URL: {}", url_str)))?
        .to_string();

    let default_port = if matches!(scheme, UpstreamScheme::Https) {
        443
    } else {
        80
    };
    let port = parsed.port().unwrap_or(default_port);

    let path = parsed.path().to_string();
    let path = if path.is_empty() {
        "/".to_string()
    } else {
        path
    };

    // Include query string if present
    let path_with_query = if let Some(query) = parsed.query() {
        format!("{}?{}", path, query)
    } else {
        path
    };

    Ok((scheme, host, port, path_with_query))
}

/// Send an HTTP error response.
async fn send_error(stream: &mut TcpStream, status: u16, reason: &str) -> Result<()> {
    let body = format!("{{\"error\":\"{}\"}}", reason);
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        status,
        reason,
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

// ============================================================================
// Injection mode helpers
// ============================================================================

/// Validate phantom token based on injection mode.
///
/// Different modes extract the phantom token from different locations:
/// - `Header`/`BasicAuth`: From the auth header (Authorization, x-api-key, etc.)
/// - `UrlPath`: From the URL path pattern (e.g., `/bot<token>/getMe`)
/// - `QueryParam`: From the query parameter (e.g., `?api_key=<token>`)
pub(crate) fn validate_phantom_token_for_mode(
    mode: &InjectMode,
    header_bytes: &[u8],
    path: &str,
    header_name: &str,
    path_pattern: Option<&str>,
    query_param_name: Option<&str>,
    session_token: &Zeroizing<String>,
) -> Result<()> {
    match mode {
        InjectMode::Header | InjectMode::BasicAuth => {
            // Validate from header (existing behavior)
            validate_phantom_token(header_bytes, header_name, session_token)
        }
        InjectMode::UrlPath => {
            // Validate from URL path
            let pattern = path_pattern.ok_or_else(|| {
                ProxyError::HttpParse("url_path mode requires path_pattern".to_string())
            })?;
            validate_phantom_token_in_path(path, pattern, session_token)
        }
        InjectMode::QueryParam => {
            // Validate from query parameter
            let param_name = query_param_name.ok_or_else(|| {
                ProxyError::HttpParse("query_param mode requires query_param_name".to_string())
            })?;
            validate_phantom_token_in_query(path, param_name, session_token)
        }
    }
}

/// Validate phantom token embedded in URL path.
///
/// Extracts the token from the path using the pattern (e.g., `/bot{}/` matches
/// `/bot<token>/getMe` and extracts `<token>`).
fn validate_phantom_token_in_path(
    path: &str,
    pattern: &str,
    session_token: &Zeroizing<String>,
) -> Result<()> {
    // Split pattern on {} to get prefix and suffix
    let parts: Vec<&str> = pattern.split("{}").collect();
    if parts.len() != 2 {
        return Err(ProxyError::HttpParse(format!(
            "invalid path_pattern '{}': must contain exactly one {{}}",
            pattern
        )));
    }
    let (prefix, suffix) = (parts[0], parts[1]);

    // Find the token in the path
    if let Some(start) = path.find(prefix) {
        let after_prefix = start + prefix.len();

        // Handle empty suffix case (token extends to end of path or next '/' or '?')
        let end_offset = if suffix.is_empty() {
            path[after_prefix..]
                .find(['/', '?'])
                .unwrap_or(path[after_prefix..].len())
        } else {
            match path[after_prefix..].find(suffix) {
                Some(offset) => offset,
                None => {
                    warn!("Missing phantom token in URL path (pattern: {})", pattern);
                    return Err(ProxyError::InvalidToken);
                }
            }
        };

        let token = &path[after_prefix..after_prefix + end_offset];
        if token::constant_time_eq(token.as_bytes(), session_token.as_bytes()) {
            return Ok(());
        }
        warn!("Invalid phantom token in URL path");
        return Err(ProxyError::InvalidToken);
    }

    warn!("Missing phantom token in URL path (pattern: {})", pattern);
    Err(ProxyError::InvalidToken)
}

/// Validate phantom token in query parameter.
fn validate_phantom_token_in_query(
    path: &str,
    param_name: &str,
    session_token: &Zeroizing<String>,
) -> Result<()> {
    // Parse query string from path
    if let Some(query_start) = path.find('?') {
        let query = &path[query_start + 1..];
        for pair in query.split('&') {
            if let Some((name, value)) = pair.split_once('=')
                && name == param_name
            {
                let decoded = urlencoding::decode(value).unwrap_or_else(|_| value.into());
                if token::constant_time_eq(decoded.as_bytes(), session_token.as_bytes()) {
                    return Ok(());
                }
                warn!("Invalid phantom token in query parameter '{}'", param_name);
                return Err(ProxyError::InvalidToken);
            }
        }
    }

    warn!("Missing phantom token in query parameter '{}'", param_name);
    Err(ProxyError::InvalidToken)
}

/// Transform URL path based on injection mode.
///
/// - `UrlPath`: Replace phantom token with real credential in path
/// - `QueryParam`: Add/replace query parameter with real credential
/// - `Header`/`BasicAuth`: No path transformation needed
pub(crate) fn transform_path_for_mode(
    mode: &InjectMode,
    path: &str,
    path_pattern: Option<&str>,
    path_replacement: Option<&str>,
    query_param_name: Option<&str>,
    credential: &Zeroizing<String>,
) -> Result<String> {
    match mode {
        InjectMode::Header | InjectMode::BasicAuth => {
            // No path transformation needed
            Ok(path.to_string())
        }
        InjectMode::UrlPath => {
            let pattern = path_pattern.ok_or_else(|| {
                ProxyError::HttpParse("url_path mode requires path_pattern".to_string())
            })?;
            let replacement = path_replacement.unwrap_or(pattern);
            transform_url_path(path, pattern, replacement, credential)
        }
        InjectMode::QueryParam => {
            let param_name = query_param_name.ok_or_else(|| {
                ProxyError::HttpParse("query_param mode requires query_param_name".to_string())
            })?;
            transform_query_param(path, param_name, credential)
        }
    }
}

/// Transform URL path by replacing phantom token pattern with real credential.
///
/// Example: `/bot<phantom>/getMe` with pattern `/bot{}/` becomes `/bot<real>/getMe`
fn transform_url_path(
    path: &str,
    pattern: &str,
    replacement: &str,
    credential: &Zeroizing<String>,
) -> Result<String> {
    // Split pattern on {} to get prefix and suffix
    let parts: Vec<&str> = pattern.split("{}").collect();
    if parts.len() != 2 {
        return Err(ProxyError::HttpParse(format!(
            "invalid path_pattern '{}': must contain exactly one {{}}",
            pattern
        )));
    }
    let (pattern_prefix, pattern_suffix) = (parts[0], parts[1]);

    // Split replacement on {}
    let repl_parts: Vec<&str> = replacement.split("{}").collect();
    if repl_parts.len() != 2 {
        return Err(ProxyError::HttpParse(format!(
            "invalid path_replacement '{}': must contain exactly one {{}}",
            replacement
        )));
    }
    let (repl_prefix, repl_suffix) = (repl_parts[0], repl_parts[1]);

    // Find and replace the token in the path
    if let Some(start) = path.find(pattern_prefix) {
        let after_prefix = start + pattern_prefix.len();

        // Handle empty suffix case (token extends to end of path or next '/' or '?')
        let end_offset = if pattern_suffix.is_empty() {
            // Find the next path segment delimiter or end of path
            path[after_prefix..]
                .find(['/', '?'])
                .unwrap_or(path[after_prefix..].len())
        } else {
            // Find the suffix in the remaining path
            match path[after_prefix..].find(pattern_suffix) {
                Some(offset) => offset,
                None => {
                    return Err(ProxyError::HttpParse(format!(
                        "path '{}' does not match pattern '{}'",
                        path, pattern
                    )));
                }
            }
        };

        let before = &path[..start];
        let after = &path[after_prefix + end_offset + pattern_suffix.len()..];
        return Ok(format!(
            "{}{}{}{}{}",
            before,
            repl_prefix,
            credential.as_str(),
            repl_suffix,
            after
        ));
    }

    Err(ProxyError::HttpParse(format!(
        "path '{}' does not match pattern '{}'",
        path, pattern
    )))
}

/// Transform query string by adding or replacing a parameter with the credential.
fn transform_query_param(
    path: &str,
    param_name: &str,
    credential: &Zeroizing<String>,
) -> Result<String> {
    let encoded_value = urlencoding::encode(credential.as_str());

    if let Some(query_start) = path.find('?') {
        let base_path = &path[..query_start];
        let query = &path[query_start + 1..];

        // Check if parameter already exists
        let mut found = false;
        let new_query: Vec<String> = query
            .split('&')
            .map(|pair| {
                if let Some((name, _)) = pair.split_once('=')
                    && name == param_name
                {
                    found = true;
                    return format!("{}={}", param_name, encoded_value);
                }
                pair.to_string()
            })
            .collect();

        if found {
            Ok(format!("{}?{}", base_path, new_query.join("&")))
        } else {
            // Append the parameter
            Ok(format!(
                "{}?{}&{}={}",
                base_path, query, param_name, encoded_value
            ))
        }
    } else {
        // No query string, add one
        Ok(format!("{}?{}={}", path, param_name, encoded_value))
    }
}

/// Strip proxy-side artifacts from the path when proxy and upstream modes differ.
///
/// When the proxy validates the phantom token using a different injection mode
/// than the upstream (e.g., proxy uses `url_path` or `query_param` while upstream
/// uses `header`), the proxy-side token is embedded in the URL. This function
/// removes it before the path is forwarded to the upstream, preventing phantom
/// token leakage.
///
/// When both modes are the same, the upstream transform handles replacement
/// (phantom → real credential), so no stripping is needed.
pub(crate) fn strip_proxy_artifacts(
    path: &str,
    proxy_mode: &InjectMode,
    upstream_mode: &InjectMode,
    proxy_path_pattern: Option<&str>,
    proxy_query_param_name: Option<&str>,
) -> String {
    // Only strip when modes differ — same-mode cases are handled by the
    // upstream transform which replaces the phantom token with the real one.
    if proxy_mode == upstream_mode {
        return path.to_string();
    }

    match proxy_mode {
        InjectMode::UrlPath => {
            if let Some(pattern) = proxy_path_pattern {
                strip_proxy_path_token(path, pattern)
            } else {
                path.to_string()
            }
        }
        InjectMode::QueryParam => {
            if let Some(param_name) = proxy_query_param_name {
                strip_proxy_query_param(path, param_name)
            } else {
                path.to_string()
            }
        }
        // Header and BasicAuth modes don't embed artifacts in the URL path.
        InjectMode::Header | InjectMode::BasicAuth => path.to_string(),
    }
}

/// Remove a phantom token path segment matched by the given pattern.
///
/// Example: path `/TOKEN123/api/v1/pods` with pattern `/{}/` → `/api/v1/pods`
fn strip_proxy_path_token(path: &str, pattern: &str) -> String {
    let parts: Vec<&str> = pattern.split("{}").collect();
    if parts.len() != 2 {
        return path.to_string();
    }
    let (prefix, suffix) = (parts[0], parts[1]);

    // Prefer matching at the start of the path to avoid false hits on
    // common prefixes like "/" that would otherwise match at position 0
    // even if the intended token is in a later segment.
    let start = if path.starts_with(prefix) {
        Some(0)
    } else {
        path.find(prefix)
    };

    if let Some(start) = start {
        let after_prefix = start + prefix.len();
        let end_offset = if suffix.is_empty() {
            path[after_prefix..]
                .find(['/', '?'])
                .unwrap_or(path[after_prefix..].len())
        } else {
            match path[after_prefix..].find(suffix) {
                Some(offset) => offset,
                None => return path.to_string(),
            }
        };

        let before = &path[..start];
        let after = &path[after_prefix + end_offset + suffix.len()..];

        // Join before and after with exactly one separator to avoid
        // malformed paths: "/prefixapi" (missing slash) or "/api//v1"
        // (double slash) when the stripped segment was mid-path.
        let joined = match (before.ends_with('/'), after.starts_with('/')) {
            (true, true) => format!("{}{}", before, &after[1..]),
            (false, false) if !before.is_empty() && !after.is_empty() => {
                format!("{}/{}", before, after)
            }
            _ => format!("{}{}", before, after),
        };

        if joined.is_empty() || !joined.starts_with('/') {
            format!("/{}", joined)
        } else {
            joined
        }
    } else {
        path.to_string()
    }
}

/// Remove a phantom token query parameter from the URL.
///
/// Example: path `/api/v1/pods?token=XXX&limit=10` → `/api/v1/pods?limit=10`
fn strip_proxy_query_param(path: &str, param_name: &str) -> String {
    if let Some(query_start) = path.find('?') {
        let base_path = &path[..query_start];
        let query = &path[query_start + 1..];

        let remaining: Vec<&str> = query
            .split('&')
            .filter(|pair| {
                pair.split_once('=')
                    .map(|(name, _)| name != param_name)
                    .unwrap_or(true)
            })
            .collect();

        if remaining.is_empty() {
            base_path.to_string()
        } else {
            format!("{}?{}", base_path, remaining.join("&"))
        }
    } else {
        path.to_string()
    }
}

/// Inject credential into request based on mode.
///
/// For header/basic_auth modes, adds the credential header.
/// For url_path/query_param modes, the credential is already in the path.
/// Inject credential into a structured `http::Request` builder.
fn inject_credential_structured(
    cred: &LoadedCredential,
    builder: http::request::Builder,
) -> http::request::Builder {
    match cred.inject_mode {
        InjectMode::Header | InjectMode::BasicAuth => {
            // Mirror `inject_credential_for_mode` (the HTTP/1.1 raw-string path):
            // inject the primary header plus every materialized extra header.
            // `injected_credential_header_names` strips client-supplied copies of
            // all these names, so they must be re-added here or be lost entirely.
            let mut builder = builder;
            if !cred.header_value.is_empty() {
                builder = builder.header(cred.header_name.as_str(), cred.header_value.as_str());
            }
            for (name, value) in &cred.extra_headers {
                builder = builder.header(name.as_str(), value.as_str());
            }
            builder
        }
        InjectMode::UrlPath | InjectMode::QueryParam => builder,
    }
}

/// Apply proxy-artifact stripping and upstream credential injection to a
/// request path for the given credential.
///
/// Combines [`strip_proxy_artifacts`] and [`transform_path_for_mode`] into the
/// single transformation both the HTTP/1.1 and HTTP/2 CONNECT-intercept paths
/// need, so they cannot diverge. When `cred` is `None` the path is returned
/// unchanged (passthrough).
pub(crate) fn transform_path_for_credential(
    cred: Option<&LoadedCredential>,
    path: &str,
) -> Result<String> {
    let Some(cred) = cred else {
        return Ok(path.to_string());
    };
    let cleaned = strip_proxy_artifacts(
        path,
        &cred.proxy_inject_mode,
        &cred.inject_mode,
        cred.proxy_path_pattern.as_deref(),
        cred.proxy_query_param_name.as_deref(),
    );
    transform_path_for_mode(
        &cred.inject_mode,
        &cleaned,
        cred.path_pattern.as_deref(),
        cred.path_replacement.as_deref(),
        cred.query_param_name.as_deref(),
        &cred.raw_credential,
    )
}

pub(crate) fn inject_credential_for_mode(cred: &LoadedCredential, request: &mut Zeroizing<String>) {
    match cred.inject_mode {
        InjectMode::Header | InjectMode::BasicAuth => {
            // Inject credential header
            if !cred.header_value.is_empty() {
                request.push_str(&format!(
                    "{}: {}\r\n",
                    cred.header_name,
                    cred.header_value.as_str()
                ));
            }
            for (name, value) in &cred.extra_headers {
                request.push_str(&format!("{}: {}\r\n", name, value.as_str()));
            }
        }
        InjectMode::UrlPath | InjectMode::QueryParam => {
            // Credential is already injected into the URL path/query
            // No header injection needed
        }
    }
}

pub(crate) fn injected_credential_header_names(cred: Option<&LoadedCredential>) -> Vec<String> {
    cred.filter(|c| matches!(c.inject_mode, InjectMode::Header | InjectMode::BasicAuth))
        .map(|c| {
            let mut names = vec![c.header_name.to_lowercase()];
            names.extend(c.extra_headers.iter().map(|(name, _)| name.to_lowercase()));
            names
        })
        .unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_request_line() {
        let (method, path, version) = parse_request_line("POST /openai/v1/chat HTTP/1.1").unwrap();
        assert_eq!(method, "POST");
        assert_eq!(path, "/openai/v1/chat");
        assert_eq!(version, "HTTP/1.1");
    }

    #[test]
    fn test_parse_request_line_malformed() {
        assert!(parse_request_line("GET").is_err());
    }

    #[test]
    fn test_parse_service_prefix() {
        let (service, path) = parse_service_prefix("/openai/v1/chat/completions").unwrap();
        assert_eq!(service, "openai");
        assert_eq!(path, "/v1/chat/completions");
    }

    #[test]
    fn test_parse_service_prefix_no_subpath() {
        let (service, path) = parse_service_prefix("/anthropic").unwrap();
        assert_eq!(service, "anthropic");
        assert_eq!(path, "/");
    }

    #[test]
    fn test_validate_phantom_token_bearer_valid() {
        let token = Zeroizing::new("secret123".to_string());
        let header = b"Authorization: Bearer secret123\r\nContent-Type: application/json\r\n\r\n";
        assert!(validate_phantom_token(header, "Authorization", &token).is_ok());
    }

    #[test]
    fn test_validate_phantom_token_bearer_invalid() {
        let token = Zeroizing::new("secret123".to_string());
        let header = b"Authorization: Bearer wrong\r\n\r\n";
        assert!(validate_phantom_token(header, "Authorization", &token).is_err());
    }

    #[test]
    fn test_validate_phantom_token_x_api_key_valid() {
        let token = Zeroizing::new("secret123".to_string());
        let header = b"x-api-key: secret123\r\nContent-Type: application/json\r\n\r\n";
        assert!(validate_phantom_token(header, "x-api-key", &token).is_ok());
    }

    #[test]
    fn test_validate_phantom_token_x_goog_api_key_valid() {
        let token = Zeroizing::new("secret123".to_string());
        let header = b"x-goog-api-key: secret123\r\nContent-Type: application/json\r\n\r\n";
        assert!(validate_phantom_token(header, "x-goog-api-key", &token).is_ok());
    }

    #[test]
    fn test_validate_phantom_token_missing() {
        let token = Zeroizing::new("secret123".to_string());
        let header = b"Content-Type: application/json\r\n\r\n";
        assert!(validate_phantom_token(header, "Authorization", &token).is_err());
    }

    #[test]
    fn test_validate_phantom_token_case_insensitive_header() {
        let token = Zeroizing::new("secret123".to_string());
        let header = b"AUTHORIZATION: Bearer secret123\r\n\r\n";
        assert!(validate_phantom_token(header, "Authorization", &token).is_ok());
    }

    #[test]
    fn test_filter_headers_removes_host_auth() {
        let header = b"Host: localhost:8080\r\nAuthorization: Bearer old\r\nContent-Type: application/json\r\nAccept: */*\r\n\r\n";
        let filtered = filter_headers(header, "Authorization");
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].0, "Content-Type");
        assert_eq!(filtered[1].0, "Accept");
    }

    #[test]
    fn test_filter_headers_removes_x_api_key() {
        let header = b"x-api-key: sk-old\r\nContent-Type: application/json\r\n\r\n";
        let filtered = filter_headers(header, "x-api-key");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].0, "Content-Type");
    }

    #[test]
    fn test_filter_headers_removes_custom_header() {
        let header = b"PRIVATE-TOKEN: phantom123\r\nContent-Type: application/json\r\n\r\n";
        let filtered = filter_headers(header, "PRIVATE-TOKEN");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].0, "Content-Type");
    }

    #[test]
    fn test_injected_credential_header_names_include_extra_headers() {
        let cred = LoadedCredential {
            inject_mode: InjectMode::Header,
            proxy_inject_mode: InjectMode::Header,
            raw_credential: Zeroizing::new(String::new()),
            header_name: "Authorization".to_string(),
            proxy_header_name: "Authorization".to_string(),
            header_value: Zeroizing::new("Bearer real".to_string()),
            extra_headers: vec![(
                "X-Gateway-Key".to_string(),
                Zeroizing::new("gateway-real".to_string()),
            )],
            path_pattern: None,
            proxy_path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy_query_param_name: None,
        };

        let names = injected_credential_header_names(Some(&cred));
        assert_eq!(
            names,
            vec!["authorization".to_string(), "x-gateway-key".to_string()]
        );
    }

    #[test]
    fn test_inject_credential_structured_includes_extra_headers() {
        // Regression: `inject_credential_structured` must re-add `extra_headers`
        // on the reverse-proxy path. `injected_credential_header_names` strips
        // client-supplied copies of these names, so if they are not re-injected
        // here the managed extra header is lost entirely.
        let cred = LoadedCredential {
            inject_mode: InjectMode::Header,
            proxy_inject_mode: InjectMode::Header,
            raw_credential: Zeroizing::new(String::new()),
            header_name: "Authorization".to_string(),
            proxy_header_name: "Authorization".to_string(),
            header_value: Zeroizing::new("Bearer real".to_string()),
            extra_headers: vec![(
                "X-Gateway-Key".to_string(),
                Zeroizing::new("gateway-real".to_string()),
            )],
            path_pattern: None,
            proxy_path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy_query_param_name: None,
        };

        let builder = http::Request::builder().method("POST").uri("https://x/y");
        let req = inject_credential_structured(&cred, builder)
            .body(())
            .unwrap();

        assert_eq!(
            req.headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok()),
            Some("Bearer real")
        );
        assert_eq!(
            req.headers()
                .get("x-gateway-key")
                .and_then(|v| v.to_str().ok()),
            Some("gateway-real"),
            "extra managed header must be injected on the reverse-proxy path"
        );
    }

    #[test]
    fn test_inject_credential_structured_skips_empty_primary_value() {
        // A credential with only extra headers (empty primary value) must not
        // emit an empty `Authorization` header, matching `inject_credential_for_mode`.
        let cred = LoadedCredential {
            inject_mode: InjectMode::Header,
            proxy_inject_mode: InjectMode::Header,
            raw_credential: Zeroizing::new(String::new()),
            header_name: "Authorization".to_string(),
            proxy_header_name: "Authorization".to_string(),
            header_value: Zeroizing::new(String::new()),
            extra_headers: vec![(
                "X-Gateway-Key".to_string(),
                Zeroizing::new("gateway-real".to_string()),
            )],
            path_pattern: None,
            proxy_path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy_query_param_name: None,
        };

        let builder = http::Request::builder().method("POST").uri("https://x/y");
        let req = inject_credential_structured(&cred, builder)
            .body(())
            .unwrap();

        assert!(
            req.headers().get("authorization").is_none(),
            "empty primary credential value must not be injected"
        );
        assert_eq!(
            req.headers()
                .get("x-gateway-key")
                .and_then(|v| v.to_str().ok()),
            Some("gateway-real")
        );
    }

    #[test]
    fn test_extract_content_length() {
        let header = b"Content-Type: application/json\r\nContent-Length: 42\r\n\r\n";
        assert_eq!(extract_content_length(header), Some(42));
    }

    #[test]
    fn test_extract_content_length_missing() {
        let header = b"Content-Type: application/json\r\n\r\n";
        assert_eq!(extract_content_length(header), None);
    }

    #[test]
    fn test_parse_upstream_url_https() {
        let (scheme, host, port, path) =
            parse_upstream_url("https://api.openai.com/v1/chat/completions").unwrap();
        assert_eq!(scheme, UpstreamScheme::Https);
        assert_eq!(host, "api.openai.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/v1/chat/completions");
    }

    #[test]
    fn test_parse_upstream_url_http_with_port() {
        let (scheme, host, port, path) = parse_upstream_url("http://localhost:8080/api").unwrap();
        assert_eq!(scheme, UpstreamScheme::Http);
        assert_eq!(host, "localhost");
        assert_eq!(port, 8080);
        assert_eq!(path, "/api");
    }

    #[test]
    fn test_parse_upstream_url_no_path() {
        let (scheme, host, port, path) = parse_upstream_url("https://api.anthropic.com").unwrap();
        assert_eq!(scheme, UpstreamScheme::Https);
        assert_eq!(host, "api.anthropic.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/");
    }

    #[test]
    fn test_parse_upstream_url_invalid_scheme() {
        assert!(parse_upstream_url("ftp://example.com").is_err());
    }

    #[test]
    fn test_validate_http_upstream_target_rejects_non_local_host() {
        let err = validate_http_upstream_target(UpstreamScheme::Http, "api.example.com", &[])
            .expect_err("non-local http upstream should be rejected");
        assert!(err.contains("refusing insecure http upstream"));
    }

    #[test]
    fn test_validate_http_upstream_target_allows_loopback() {
        let loopback = [SocketAddr::from(([127, 0, 0, 1], 8080))];
        assert!(validate_http_upstream_target(UpstreamScheme::Http, "127.0.0.1", &[]).is_ok());
        assert!(validate_http_upstream_target(UpstreamScheme::Http, "::1", &[]).is_ok());
        assert!(
            validate_http_upstream_target(UpstreamScheme::Http, "localhost", &loopback).is_ok()
        );
    }

    #[test]
    fn test_validate_http_upstream_target_rejects_unspecified_addresses() {
        let unspecified = [SocketAddr::from(([0, 0, 0, 0], 8080))];
        let err = validate_http_upstream_target(UpstreamScheme::Http, "0.0.0.0", &[])
            .expect_err("unspecified http upstream should be rejected");
        assert!(err.contains("loopback addresses"));

        let err = validate_http_upstream_target(UpstreamScheme::Http, "localhost", &unspecified)
            .expect_err("localhost resolving to unspecified should be rejected");
        assert!(err.contains("loopback addresses"));
    }

    #[test]
    fn test_validate_http_upstream_target_rejects_localhost_resolving_non_loopback() {
        let poisoned = [SocketAddr::from(([203, 0, 113, 10], 8080))];
        let err = validate_http_upstream_target(UpstreamScheme::Http, "localhost", &poisoned)
            .expect_err("localhost resolving off-host should be rejected");
        assert!(err.contains("refusing insecure http upstream"));
    }

    #[test]
    fn test_format_host_header_uses_port_for_non_default_http() {
        assert_eq!(
            format_host_header(UpstreamScheme::Http, "localhost", 8080),
            "localhost:8080"
        );
    }

    #[test]
    fn test_format_host_header_omits_default_https_port() {
        assert_eq!(
            format_host_header(UpstreamScheme::Https, "api.openai.com", 443),
            "api.openai.com"
        );
    }

    #[test]
    fn test_format_host_header_brackets_ipv6() {
        assert_eq!(
            format_host_header(UpstreamScheme::Http, "::1", 8080),
            "[::1]:8080"
        );
    }

    // Status-line parsing moved to `crate::forward` along with the upstream
    // response-streaming pipeline; coverage continues there.

    // ============================================================================
    // URL Path Injection Mode Tests
    // ============================================================================

    #[test]
    fn test_validate_phantom_token_in_path_valid() {
        let token = Zeroizing::new("session123".to_string());
        let path = "/bot/session123/getMe";
        let pattern = "/bot/{}/";
        assert!(validate_phantom_token_in_path(path, pattern, &token).is_ok());
    }

    #[test]
    fn test_validate_phantom_token_in_path_invalid() {
        let token = Zeroizing::new("session123".to_string());
        let path = "/bot/wrong_token/getMe";
        let pattern = "/bot/{}/";
        assert!(validate_phantom_token_in_path(path, pattern, &token).is_err());
    }

    #[test]
    fn test_validate_phantom_token_in_path_missing() {
        let token = Zeroizing::new("session123".to_string());
        let path = "/api/getMe";
        let pattern = "/bot/{}/";
        assert!(validate_phantom_token_in_path(path, pattern, &token).is_err());
    }

    #[test]
    fn test_transform_url_path_basic() {
        let credential = Zeroizing::new("real_token".to_string());
        let path = "/bot/phantom_token/getMe";
        let pattern = "/bot/{}/";
        let replacement = "/bot/{}/";
        let result = transform_url_path(path, pattern, replacement, &credential).unwrap();
        assert_eq!(result, "/bot/real_token/getMe");
    }

    #[test]
    fn test_transform_url_path_different_replacement() {
        let credential = Zeroizing::new("real_token".to_string());
        let path = "/api/v1/phantom_token/chat";
        let pattern = "/api/v1/{}/";
        let replacement = "/v2/bot/{}/";
        let result = transform_url_path(path, pattern, replacement, &credential).unwrap();
        assert_eq!(result, "/v2/bot/real_token/chat");
    }

    #[test]
    fn test_transform_url_path_no_trailing_slash() {
        let credential = Zeroizing::new("real_token".to_string());
        let path = "/bot/phantom_token";
        let pattern = "/bot/{}";
        let replacement = "/bot/{}";
        let result = transform_url_path(path, pattern, replacement, &credential).unwrap();
        assert_eq!(result, "/bot/real_token");
    }

    // ============================================================================
    // Query Param Injection Mode Tests
    // ============================================================================

    #[test]
    fn test_validate_phantom_token_in_query_valid() {
        let token = Zeroizing::new("session123".to_string());
        let path = "/api/data?api_key=session123&other=value";
        assert!(validate_phantom_token_in_query(path, "api_key", &token).is_ok());
    }

    #[test]
    fn test_validate_phantom_token_in_query_invalid() {
        let token = Zeroizing::new("session123".to_string());
        let path = "/api/data?api_key=wrong_token";
        assert!(validate_phantom_token_in_query(path, "api_key", &token).is_err());
    }

    #[test]
    fn test_validate_phantom_token_in_query_missing_param() {
        let token = Zeroizing::new("session123".to_string());
        let path = "/api/data?other=value";
        assert!(validate_phantom_token_in_query(path, "api_key", &token).is_err());
    }

    #[test]
    fn test_validate_phantom_token_in_query_no_query_string() {
        let token = Zeroizing::new("session123".to_string());
        let path = "/api/data";
        assert!(validate_phantom_token_in_query(path, "api_key", &token).is_err());
    }

    #[test]
    fn test_validate_phantom_token_in_query_url_encoded() {
        let token = Zeroizing::new("token with spaces".to_string());
        let path = "/api/data?api_key=token%20with%20spaces";
        assert!(validate_phantom_token_in_query(path, "api_key", &token).is_ok());
    }

    #[test]
    fn test_transform_query_param_add_to_no_query() {
        let credential = Zeroizing::new("real_key".to_string());
        let path = "/api/data";
        let result = transform_query_param(path, "api_key", &credential).unwrap();
        assert_eq!(result, "/api/data?api_key=real_key");
    }

    #[test]
    fn test_transform_query_param_add_to_existing_query() {
        let credential = Zeroizing::new("real_key".to_string());
        let path = "/api/data?other=value";
        let result = transform_query_param(path, "api_key", &credential).unwrap();
        assert_eq!(result, "/api/data?other=value&api_key=real_key");
    }

    #[test]
    fn test_transform_query_param_replace_existing() {
        let credential = Zeroizing::new("real_key".to_string());
        let path = "/api/data?api_key=phantom&other=value";
        let result = transform_query_param(path, "api_key", &credential).unwrap();
        assert_eq!(result, "/api/data?api_key=real_key&other=value");
    }

    #[test]
    fn test_transform_query_param_url_encodes_special_chars() {
        let credential = Zeroizing::new("key with spaces".to_string());
        let path = "/api/data";
        let result = transform_query_param(path, "api_key", &credential).unwrap();
        assert_eq!(result, "/api/data?api_key=key%20with%20spaces");
    }

    #[test]
    fn test_validate_phantom_token_uses_proxy_mode_over_upstream_mode() {
        let token = Zeroizing::new("session123".to_string());
        let header = b"Authorization: Bearer session123\r\n\r\n";
        let path = "/api/data?api_key=wrong";

        // Simulate split config where proxy-side mode is header while upstream
        // mode might be query_param.
        let result = validate_phantom_token_for_mode(
            &InjectMode::Header,
            header,
            path,
            "Authorization",
            None,
            Some("api_key"),
            &token,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_transform_path_uses_upstream_mode_independently() {
        let credential = Zeroizing::new("real_key".to_string());
        let path = "/api/data?api_key=phantom";

        // Simulate split config where upstream mode is query_param.
        let transformed = transform_path_for_mode(
            &InjectMode::QueryParam,
            path,
            None,
            None,
            Some("api_key"),
            &credential,
        )
        .expect("query-param transform should succeed");

        assert_eq!(transformed, "/api/data?api_key=real_key");
    }

    // ========================================================================
    // Proxy artifact stripping tests
    // ========================================================================

    #[test]
    fn test_strip_proxy_path_token_basic() {
        // Pattern: /{}/  — token is the first path segment
        let result = strip_proxy_path_token("/PHANTOM123/api/v1/pods", "/{}/");
        assert_eq!(result, "/api/v1/pods");
    }

    #[test]
    fn test_strip_proxy_path_token_nested_pattern() {
        // Pattern: /auth/{}/  — token is in a nested segment
        let result = strip_proxy_path_token("/auth/PHANTOM123/api/v1/pods", "/auth/{}/");
        assert_eq!(result, "/api/v1/pods");
    }

    #[test]
    fn test_strip_proxy_path_token_no_trailing_slash() {
        // Pattern: /{}  — token at end of path with no trailing content
        let result = strip_proxy_path_token("/PHANTOM123", "/{}");
        assert_eq!(result, "/");
    }

    #[test]
    fn test_strip_proxy_path_token_preserves_query() {
        // Pattern: /{}/  — should preserve query string after stripping
        let result = strip_proxy_path_token("/PHANTOM123/api?limit=10", "/{}/");
        assert_eq!(result, "/api?limit=10");
    }

    #[test]
    fn test_strip_proxy_path_token_no_match() {
        // Pattern doesn't match — return path unchanged
        let result = strip_proxy_path_token("/api/v1/pods", "/auth/{}/");
        assert_eq!(result, "/api/v1/pods");
    }

    #[test]
    fn test_strip_proxy_path_token_mid_path_slash_join() {
        // Token in the middle: before="/api" after="data" must join with "/"
        let result = strip_proxy_path_token("/api/k8s/PHANTOM/data", "/k8s/{}/");
        assert_eq!(result, "/api/data");
    }

    #[test]
    fn test_strip_proxy_path_token_no_double_slash() {
        // Before ends with "/" and after starts with "/" — collapse to one
        let result = strip_proxy_path_token("/prefix/PHANTOM//suffix", "/prefix/{}/");
        assert_eq!(result, "/suffix");
    }

    #[test]
    fn test_strip_proxy_query_param_only_param() {
        let result = strip_proxy_query_param("/api/v1/pods?token=PHANTOM123", "token");
        assert_eq!(result, "/api/v1/pods");
    }

    #[test]
    fn test_strip_proxy_query_param_with_other_params() {
        let result = strip_proxy_query_param("/api/v1/pods?token=PHANTOM123&limit=10", "token");
        assert_eq!(result, "/api/v1/pods?limit=10");
    }

    #[test]
    fn test_strip_proxy_query_param_middle() {
        let result =
            strip_proxy_query_param("/api/v1/pods?limit=10&token=PHANTOM123&watch=true", "token");
        assert_eq!(result, "/api/v1/pods?limit=10&watch=true");
    }

    #[test]
    fn test_strip_proxy_query_param_no_match() {
        let result = strip_proxy_query_param("/api/v1/pods?limit=10", "token");
        assert_eq!(result, "/api/v1/pods?limit=10");
    }

    #[test]
    fn test_strip_proxy_query_param_no_query_string() {
        let result = strip_proxy_query_param("/api/v1/pods", "token");
        assert_eq!(result, "/api/v1/pods");
    }

    #[test]
    fn test_strip_proxy_artifacts_same_mode_noop() {
        // When proxy and upstream use the same mode, no stripping (upstream transform handles it)
        let path = "/PHANTOM123/api/v1/pods";
        let result = strip_proxy_artifacts(
            path,
            &InjectMode::UrlPath,
            &InjectMode::UrlPath,
            Some("/{}/"),
            None,
        );
        assert_eq!(result, path);
    }

    #[test]
    fn test_strip_proxy_artifacts_url_path_to_header() {
        // Proxy uses url_path, upstream uses header — must strip path token
        let result = strip_proxy_artifacts(
            "/PHANTOM123/api/v1/pods",
            &InjectMode::UrlPath,
            &InjectMode::Header,
            Some("/{}/"),
            None,
        );
        assert_eq!(result, "/api/v1/pods");
    }

    #[test]
    fn test_strip_proxy_artifacts_query_param_to_header() {
        // Proxy uses query_param, upstream uses header — must strip query param
        let result = strip_proxy_artifacts(
            "/api/v1/pods?token=PHANTOM123",
            &InjectMode::QueryParam,
            &InjectMode::Header,
            None,
            Some("token"),
        );
        assert_eq!(result, "/api/v1/pods");
    }

    #[test]
    fn test_strip_proxy_artifacts_header_to_query_param() {
        // Proxy uses header, upstream uses query_param — no URL artifacts to strip
        let path = "/api/v1/pods";
        let result = strip_proxy_artifacts(
            path,
            &InjectMode::Header,
            &InjectMode::QueryParam,
            None,
            None,
        );
        assert_eq!(result, path);
    }

    #[test]
    fn test_end_to_end_url_path_proxy_header_upstream() {
        // Full flow: proxy validates via url_path, upstream injects via header.
        // The path token must be stripped before forwarding.
        let token = Zeroizing::new("session456".to_string());
        let credential = Zeroizing::new("real_bearer_token".to_string());
        let path = "/session456/api/v1/namespaces";

        // 1. Proxy-side validation succeeds
        assert!(
            validate_phantom_token_for_mode(
                &InjectMode::UrlPath,
                b"\r\n\r\n", // no auth header needed for url_path mode
                path,
                "Authorization",
                Some("/{}/"),
                None,
                &token,
            )
            .is_ok()
        );

        // 2. Strip proxy artifacts
        let cleaned = strip_proxy_artifacts(
            path,
            &InjectMode::UrlPath,
            &InjectMode::Header,
            Some("/{}/"),
            None,
        );
        assert_eq!(cleaned, "/api/v1/namespaces");

        // 3. Upstream transform (header mode = no path change)
        let transformed =
            transform_path_for_mode(&InjectMode::Header, &cleaned, None, None, None, &credential)
                .unwrap();
        assert_eq!(transformed, "/api/v1/namespaces");
    }

    #[test]
    fn test_end_to_end_query_param_proxy_header_upstream() {
        // Full flow: proxy validates via query_param, upstream injects via header.
        let token = Zeroizing::new("session789".to_string());
        let credential = Zeroizing::new("real_bearer_token".to_string());
        let path = "/api/v1/pods?token=session789&limit=100";

        // 1. Proxy-side validation succeeds
        assert!(
            validate_phantom_token_for_mode(
                &InjectMode::QueryParam,
                b"\r\n\r\n",
                path,
                "Authorization",
                None,
                Some("token"),
                &token,
            )
            .is_ok()
        );

        // 2. Strip proxy artifacts
        let cleaned = strip_proxy_artifacts(
            path,
            &InjectMode::QueryParam,
            &InjectMode::Header,
            None,
            Some("token"),
        );
        assert_eq!(cleaned, "/api/v1/pods?limit=100");

        // 3. Upstream transform (header mode = no path change)
        let transformed =
            transform_path_for_mode(&InjectMode::Header, &cleaned, None, None, None, &credential)
                .unwrap();
        assert_eq!(transformed, "/api/v1/pods?limit=100");
    }
}
