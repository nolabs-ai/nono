//! Command-backed credential capture interface.
//!
//! The proxy owns the trigger (`cmd://` route needs a credential), while the
//! CLI/supervisor owns command execution. This module defines the narrow
//! boundary between those crates.

use zeroize::Zeroizing;

/// Safe client-facing diagnostic shared by all proxy transports. Never include
/// helper output, command arguments, credential references, or backend errors.
pub(crate) const CAPTURE_FAILED_BODY: &str = concat!(
    r#"{"error":"credential_capture_failed","message":"nono could not obtain host credentials. "#,
    r#"Check the host credential helper and proxy logs."}"#,
);

/// Request context for a command-backed credential capture.
#[derive(Debug, Clone)]
pub struct CredentialCaptureRequest {
    /// Logical credential name from `cmd://<name>`.
    pub credential_name: String,
    /// Route prefix that triggered capture.
    pub route_id: String,
    /// Upstream host for the request.
    pub request_host: String,
    /// Upstream request path.
    pub request_path: String,
    /// HTTP method that triggered capture.
    pub request_method: String,
    /// Stable supervisor/proxy session identifier.
    pub session_id: String,
    /// Cache scope derived from request context.
    pub cache_scope: String,
}

/// Metadata about a capture attempt. Secret stdout is intentionally excluded.
#[derive(Debug, Clone, Default)]
pub struct CredentialCaptureMetadata {
    pub cache_action: String,
    pub command: Option<String>,
    pub argv: Vec<String>,
    pub exit_status: Option<i32>,
    pub duration_ms: u64,
    pub stdout_bytes: Option<usize>,
    pub stderr_redacted: Option<String>,
    pub cache_scope: Option<String>,
    pub output_format: Option<String>,
    pub header_names: Vec<String>,
    pub stdin_mode: Option<String>,
    pub interactive: Option<bool>,
}

/// Captured material that can be injected into the upstream request.
#[derive(Debug, Clone)]
pub enum CredentialCaptureMaterial {
    /// A single credential value, formatted later by the route config.
    Secret(Zeroizing<String>),
    /// Fully materialized headers produced by the capture command.
    Headers(Vec<(String, Zeroizing<String>)>),
}

/// Result of a capture attempt.
#[derive(Debug, Clone)]
pub struct CredentialCaptureResponse {
    pub material: CredentialCaptureMaterial,
    pub metadata: CredentialCaptureMetadata,
}

/// Error returned by a capture backend. It contains only redacted diagnostics.
#[derive(Debug, Clone)]
pub struct CredentialCaptureError {
    pub reason: String,
    pub metadata: Box<CredentialCaptureMetadata>,
}

impl CredentialCaptureError {
    pub fn new(reason: String, metadata: CredentialCaptureMetadata) -> Self {
        Self {
            reason,
            metadata: Box::new(metadata),
        }
    }
}

impl std::fmt::Display for CredentialCaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for CredentialCaptureError {}

/// Supervisor-provided backend for command-backed proxy credentials.
pub trait CredentialCaptureBackend: Send + Sync + std::fmt::Debug {
    fn capture(
        &self,
        request: CredentialCaptureRequest,
    ) -> std::result::Result<CredentialCaptureResponse, CredentialCaptureError>;
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod tests {
    use super::*;
    use crate::{config::RouteConfig, credential::CredentialStore, route::RouteStore};
    use std::sync::Arc;

    #[derive(Debug)]
    pub(crate) struct FailingCaptureBackend;

    impl CredentialCaptureBackend for FailingCaptureBackend {
        fn capture(
            &self,
            _request: CredentialCaptureRequest,
        ) -> std::result::Result<CredentialCaptureResponse, CredentialCaptureError> {
            Err(CredentialCaptureError::new(
                "private-backend-detail".to_string(),
                CredentialCaptureMetadata {
                    command: Some("/private/helper".to_string()),
                    argv: vec!["private-command-argument".to_string()],
                    stderr_redacted: Some("private-helper-diagnostic".to_string()),
                    exit_status: Some(1),
                    ..Default::default()
                },
            ))
        }
    }

    pub(crate) struct FailureFixture {
        pub route_store: Arc<RouteStore>,
        pub credential_store: Arc<CredentialStore>,
        pub connector: tokio_rustls::TlsConnector,
        pub tls_config: Arc<rustls::ClientConfig>,
        pub upstream: std::net::TcpListener,
    }

    impl FailureFixture {
        pub async fn new() -> Self {
            let upstream = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            upstream.set_nonblocking(true).unwrap();
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
            let tls_config = Arc::new(config);
            let connector = tokio_rustls::TlsConnector::from(Arc::clone(&tls_config));
            let route: RouteConfig = serde_json::from_value(serde_json::json!({
                "prefix": "capture",
                "upstream": format!("https://127.0.0.1:{}", upstream.local_addr().unwrap().port()),
                "credential_key": "cmd://private-credential-reference",
                "inject_header": "Authorization",
                "credential_format": "Bearer {}",
                "endpoint_rules": [{"method": "POST", "path": "/mcp"}]
            }))
            .unwrap();
            let routes = [route];
            let route_store = Arc::new(RouteStore::load(&routes).await.unwrap());
            let credential_store = Arc::new(
                CredentialStore::load_with_diagnostics(&routes, &connector, None)
                    .await
                    .unwrap()
                    .store,
            );
            Self {
                route_store,
                credential_store,
                connector,
                tls_config,
                upstream,
            }
        }

        pub fn port(&self) -> u16 {
            self.upstream.local_addr().unwrap().port()
        }

        pub fn assert_no_upstream_connection(&self) {
            assert!(matches!(self.upstream.accept(), Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock));
        }
    }

    pub(crate) fn assert_failure_body(body: &[u8]) {
        let value: serde_json::Value = serde_json::from_slice(body).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "error": "credential_capture_failed",
                "message": "nono could not obtain host credentials. Check the host credential helper and proxy logs."
            })
        );
    }

    pub(crate) fn assert_http1_failure(response: &str) {
        let (headers, body) = response.split_once("\r\n\r\n").unwrap();
        assert!(headers.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
        assert!(headers.contains("Content-Type: application/json\r\n"));
        assert!(headers.ends_with(&format!("Content-Length: {}", body.len())));
        assert!(!headers.to_ascii_lowercase().contains("www-authenticate"));
        assert_failure_body(body.as_bytes());
    }
}
