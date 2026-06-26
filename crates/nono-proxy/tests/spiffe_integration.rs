//! SPIFFE/SPIRE proxy startup tests.
#![allow(clippy::unwrap_used)]

use nono_proxy::config::{ProxyConfig, RouteConfig, SpiffeAuthConfig};
use nono_proxy::server;

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
        }),
    }
}

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

#[tokio::test]
async fn test_spiffe_x509_fails_closed_on_missing_socket() {
    let route = RouteConfig {
        prefix: "mtls".to_string(),
        upstream: "https://example.com".to_string(),
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
        spiffe: Some(SpiffeAuthConfig::X509 {
            workload_api_socket: "/tmp/nono-test-nonexistent-spire-socket.sock".to_string(),
            svid_hint: None,
            expected_upstream_spiffe_id: None,
        }),
    };
    let result = server::start(ProxyConfig {
        routes: vec![route],
        ..ProxyConfig::default()
    })
    .await;
    assert!(result.is_err());
}
