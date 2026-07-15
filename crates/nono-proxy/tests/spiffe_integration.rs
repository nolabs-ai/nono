//! SPIFFE/SPIRE proxy integration tests.
//!
//! Fail-closed tests run everywhere (no SPIRE needed).
//! Live tests run only when SPIRE_AGENT_SOCKET is set — the CI job sets it.
#![allow(clippy::unwrap_used)]

use nono_proxy::config::{ProxyConfig, RouteConfig, SpiffeAuthConfig};
use nono_proxy::server;
use nono_proxy::spiffe::SpiffeJwtSource;

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn make_jwt_route(socket: &str) -> RouteConfig {
    RouteConfig {
        prefix: "testapi".to_string(),
        upstream: "http://127.0.0.1:1".to_string(),
        credential_key: None,
        inject_mode: nono_proxy::config::InjectMode::Header,
        inject_header: "Authorization".to_string(),
        credential_format: None,
        path_pattern: None,
        path_replacement: None,
        query_param_name: None,
        proxy: None,
        env_var: None,
        endpoint_rules: vec![],
        endpoint_policy: None,
        tls_ca: None,
        tls_client_cert: None,
        tls_client_key: None,
        oauth2: None,
        aws_auth: None,
        spiffe: Some(SpiffeAuthConfig::Jwt {
            workload_api_socket: socket.to_string(),
            audience: vec!["test-audience".to_string()],
            inject_header: "Authorization".to_string(),
            credential_format: None,
            svid_hint: None,
        }),
        rate_limit: None,
    }
}

/// Returns the SPIRE agent socket path, or `None` if `SPIRE_AGENT_SOCKET` is unset.
fn live_socket() -> Option<String> {
    std::env::var("SPIRE_AGENT_SOCKET").ok()
}

fn live_audience() -> Vec<String> {
    let td = std::env::var("SPIRE_TRUST_DOMAIN").unwrap_or_else(|_| "test.nono".to_string());
    vec![format!("spiffe://{td}")]
}

fn live_expected_spiffe_id() -> String {
    std::env::var("SPIRE_WORKLOAD_SPIFFE_ID")
        .unwrap_or_else(|_| "spiffe://test.nono/nono-proxy".to_string())
}

// ─── Fail-closed tests (no SPIRE needed) ────────────────────────────────────

#[tokio::test]
async fn test_spiffe_jwt_fails_closed_on_missing_socket() {
    let route = make_jwt_route("/tmp/nono-test-nonexistent-spire-socket.sock");
    let result = server::start(ProxyConfig {
        routes: vec![route],
        ..ProxyConfig::default()
    })
    .await;
    let err = result.err().map(|e| e.to_string()).unwrap_or_default();
    assert!(
        err.contains("SPIFFE") || err.contains("spiffe") || err.contains("socket"),
        "unexpected error: {}",
        err
    );
}

// ─── Live tests (require SPIRE_AGENT_SOCKET) ────────────────────────────────

#[tokio::test]
async fn test_spiffe_jwt_live_fetch() {
    let socket = match live_socket() {
        Some(s) => s,
        None => return,
    };
    let audience = live_audience();
    let expected_id = live_expected_spiffe_id();

    let src = SpiffeJwtSource::connect(
        &socket,
        audience.clone(),
        "Authorization".to_string(),
        None,
        None,
    )
    .await
    .expect("should connect to live SPIRE agent");

    let (token, spiffe_id) = src
        .fetch_token(&audience)
        .await
        .expect("should fetch JWT-SVID from live agent");

    let parts: Vec<&str> = token.as_str().split('.').collect();
    assert_eq!(parts.len(), 3, "JWT-SVID should have three parts");
    assert!(!parts[0].is_empty() && !parts[1].is_empty() && !parts[2].is_empty());

    assert_eq!(
        spiffe_id, expected_id,
        "workload SPIFFE ID should match the registered entry"
    );
}

#[tokio::test]
async fn test_spiffe_jwt_live_delegation_none_on_plain_svid() {
    let socket = match live_socket() {
        Some(s) => s,
        None => return,
    };
    let audience = live_audience();

    let src = SpiffeJwtSource::connect(
        &socket,
        audience.clone(),
        "Authorization".to_string(),
        None,
        None,
    )
    .await
    .expect("should connect to live SPIRE agent");

    let (token, _) = src
        .fetch_token(&audience)
        .await
        .expect("should fetch JWT-SVID");

    // A plain SPIRE JWT-SVID has no `act` claim, so delegation must be None.
    let delegation = nono_proxy::spiffe::delegation_from_jwt(token.as_str());
    assert!(
        delegation.is_none(),
        "plain SPIRE JWT-SVID should not have delegation context"
    );
}

#[tokio::test]
async fn test_spiffe_jwt_live_proxy_startup() {
    let socket = match live_socket() {
        Some(s) => s,
        None => return,
    };
    let audience = live_audience();

    let route = RouteConfig {
        prefix: "testapi".to_string(),
        upstream: "http://127.0.0.1:1".to_string(),
        credential_key: None,
        inject_mode: nono_proxy::config::InjectMode::Header,
        inject_header: "Authorization".to_string(),
        credential_format: None,
        path_pattern: None,
        path_replacement: None,
        query_param_name: None,
        proxy: None,
        env_var: None,
        endpoint_rules: vec![],
        endpoint_policy: None,
        tls_ca: None,
        tls_client_cert: None,
        tls_client_key: None,
        oauth2: None,
        aws_auth: None,
        spiffe: Some(SpiffeAuthConfig::Jwt {
            workload_api_socket: socket,
            audience,
            inject_header: "Authorization".to_string(),
            credential_format: None,
            svid_hint: None,
        }),
        rate_limit: None,
    };
    let result = server::start(ProxyConfig {
        routes: vec![route],
        ..ProxyConfig::default()
    })
    .await;
    assert!(
        result.is_ok(),
        "proxy should start with a live SPIRE agent: {:?}",
        result.err()
    );
}
