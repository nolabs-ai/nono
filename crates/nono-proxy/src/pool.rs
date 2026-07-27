//! Upstream connection pool for the reverse proxy path.
//!
//! Uses `hyper_util::client::legacy::Client` to provide:
//! - Connection pooling (TCP + TLS reuse across requests)
//! - Automatic ALPN negotiation (h2 when upstream supports it)
//! - HTTP/2 multiplexing (many requests over one connection)
//! - Adaptive flow-control window sizing
//!
//! Per-route TLS connectors (custom CAs) are isolated: routes with different
//! `rustls::ClientConfig` instances get separate pool entries and never share
//! connections.
//!
//! ## DNS Rebinding Protection
//!
//! The pool uses a [`PinnedResolver`] that returns pre-validated addresses from
//! `check_host()` instead of performing live DNS resolution. This prevents
//! TOCTOU attacks where DNS could be rebinded between validation and connection.

use crate::error::{ProxyError, Result};
use bytes::Bytes;
use http::{Request, Response};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::connect::dns::Name;
use hyper_util::rt::TokioExecutor;
use std::collections::HashMap;
use std::future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tracing::debug;

type PinnedHttpsConnector = hyper_rustls::HttpsConnector<HttpConnector<PinnedResolver>>;
type PooledClient = Client<PinnedHttpsConnector, Full<Bytes>>;

/// DNS resolver that returns pre-validated socket addresses.
///
/// Before each request, the caller registers (host → addresses) via
/// `pin()`. When hyper's connector needs to resolve a hostname, it
/// receives the pinned addresses instead of performing real DNS — preventing
/// DNS rebinding between the filter check and the actual connection.
#[derive(Clone)]
pub struct PinnedResolver {
    pins: Arc<Mutex<HashMap<String, Vec<SocketAddr>>>>,
}

impl PinnedResolver {
    fn new() -> Self {
        Self {
            pins: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Register pre-resolved addresses for a hostname.
    pub fn pin(&self, host: &str, addrs: Vec<SocketAddr>) {
        let mut pins = self.pins.lock().unwrap_or_else(|e| e.into_inner());
        pins.insert(host.to_lowercase(), addrs);
    }
}

impl tower_service::Service<Name> for PinnedResolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = std::io::Error;
    type Future = future::Ready<std::result::Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        let host = name.as_str().to_lowercase();
        let pins = self.pins.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(addrs) = pins.get(&host) {
            debug!(
                "pool: resolving {} via pinned addresses ({} addrs)",
                host,
                addrs.len()
            );
            future::ready(Ok(addrs.clone().into_iter()))
        } else {
            debug!("pool: no pinned addresses for {}, denying", host);
            future::ready(Err(std::io::Error::other(format!(
                "no pinned DNS for host: {}",
                host
            ))))
        }
    }
}

/// Upstream connection pool shared across all reverse proxy requests.
///
/// Maintains a default client (using the shared TLS config) and lazily creates
/// per-route clients when routes specify custom CA certificates.
pub struct UpstreamPool {
    default_client: PooledClient,
    default_config_ptr: usize,
    resolver: PinnedResolver,
    enable_h2: bool,
    route_clients: Mutex<HashMap<usize, PooledClient>>,
}

impl UpstreamPool {
    /// Create a new pool. `default_tls_config` is the shared TLS config
    /// created at proxy startup (system roots, no custom CA).
    /// `enable_h2` controls whether HTTP/2 is negotiated via ALPN.
    pub fn new(default_tls_config: Arc<rustls::ClientConfig>, enable_h2: bool) -> Self {
        let ptr = Arc::as_ptr(&default_tls_config) as usize;
        let resolver = PinnedResolver::new();
        let client =
            build_pooled_client((*default_tls_config).clone(), resolver.clone(), enable_h2);
        Self {
            default_client: client,
            default_config_ptr: ptr,
            resolver,
            enable_h2,
            route_clients: Mutex::new(HashMap::new()),
        }
    }

    /// Register pre-resolved addresses for a hostname before sending a request.
    ///
    /// Must be called after `check_host()` succeeds and before `send()`.
    /// The pinned addresses are used instead of live DNS resolution,
    /// preventing DNS rebinding attacks.
    pub fn pin_host(&self, host: &str, addrs: &[SocketAddr]) {
        self.resolver.pin(host, addrs.to_vec());
    }

    /// Send a request through the pool.
    ///
    /// `tls_config` determines which pooled client handles the request.
    /// Routes sharing the same `Arc<ClientConfig>` reuse the same pool;
    /// routes with custom CAs get isolated clients.
    ///
    /// **Caller must call `pin_host()` before this** with the pre-resolved
    /// addresses from `check_host()`.
    pub async fn send(
        &self,
        tls_config: &Arc<rustls::ClientConfig>,
        req: Request<Full<Bytes>>,
    ) -> Result<Response<Incoming>> {
        let client = self.client_for(tls_config);
        let uri = req.uri().clone();
        let resp = client
            .request(req)
            .await
            .map_err(|e| ProxyError::UpstreamConnect {
                host: uri.host().unwrap_or("unknown").to_string(),
                reason: format!("pool request failed: {}", e),
            })?;

        debug!(
            "pool: {} {} via {:?}",
            resp.status(),
            uri.path(),
            resp.version()
        );

        Ok(resp)
    }

    /// Get or create the appropriate client for a given TLS config.
    fn client_for(&self, tls_config: &Arc<rustls::ClientConfig>) -> PooledClient {
        let ptr = Arc::as_ptr(tls_config) as usize;
        if ptr == self.default_config_ptr {
            return self.default_client.clone();
        }

        let mut clients = self.route_clients.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(client) = clients.get(&ptr) {
            return client.clone();
        }

        debug!("pool: creating new pooled client for TLS config {:x}", ptr);
        let client = build_pooled_client(
            (**tls_config).clone(),
            self.resolver.clone(),
            self.enable_h2,
        );
        clients.insert(ptr, client.clone());
        client
    }
}

fn build_pooled_client(
    tls_config: rustls::ClientConfig,
    resolver: PinnedResolver,
    enable_h2: bool,
) -> PooledClient {
    let mut tls_config = tls_config;
    // hyper-rustls manages ALPN internally — clear any pre-existing ALPN
    // to avoid its assertion.
    tls_config.alpn_protocols.clear();

    let mut http = HttpConnector::new_with_resolver(resolver);
    http.enforce_http(false);

    let builder = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http();

    let https_connector = if enable_h2 {
        builder.enable_all_versions().wrap_connector(http)
    } else {
        builder.enable_http1().wrap_connector(http)
    };

    let mut client_builder = Client::builder(TokioExecutor::new());
    client_builder
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(4);

    if enable_h2 {
        client_builder
            .http2_initial_stream_window_size(2 * 1024 * 1024)
            .http2_initial_connection_window_size(16 * 1024 * 1024)
            .http2_adaptive_window(true)
            .http2_max_frame_size(32 * 1024);
    }

    client_builder.build(https_connector)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tower_service::Service;

    #[tokio::test]
    async fn pinned_resolver_returns_pinned_addrs() {
        let resolver = PinnedResolver::new();
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 443));
        resolver.pin("example.com", vec![addr]);

        let mut resolver_clone = resolver.clone();
        let name = "example.com".parse::<Name>().unwrap();
        let result = resolver_clone.call(name).await.unwrap();
        let addrs: Vec<SocketAddr> = result.collect();
        assert_eq!(addrs, vec![addr]);
    }

    #[tokio::test]
    async fn pinned_resolver_is_case_insensitive() {
        let resolver = PinnedResolver::new();
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 443));
        resolver.pin("EXAMPLE.COM", vec![addr]);

        let mut resolver_clone = resolver.clone();
        let name = "example.com".parse::<Name>().unwrap();
        let result = resolver_clone.call(name).await.unwrap();
        let addrs: Vec<SocketAddr> = result.collect();
        assert_eq!(addrs, vec![addr]);
    }

    #[tokio::test]
    async fn pinned_resolver_denies_unknown_host() {
        let resolver = PinnedResolver::new();
        let mut resolver_clone = resolver.clone();
        let name = "evil.com".parse::<Name>().unwrap();
        let result = resolver_clone.call(name).await;
        assert!(result.is_err());
    }

    #[test]
    fn pool_uses_separate_clients_for_different_configs() {
        let config1 = Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth(),
        );
        let config2 = Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth(),
        );

        let pool = UpstreamPool::new(Arc::clone(&config1), false);

        // Default config should return the pre-built default client
        let c1 = pool.client_for(&config1);
        let c2 = pool.client_for(&config2);

        // config2 should have been lazily created and stored in route_clients
        let route_clients = pool.route_clients.lock().unwrap();
        let ptr2 = Arc::as_ptr(&config2) as usize;
        assert!(route_clients.contains_key(&ptr2));
        drop(route_clients);

        // Both should be usable (not panicking)
        drop(c1);
        drop(c2);
    }

    #[tokio::test]
    async fn pool_send_to_pinned_http_server() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        // Start a mock HTTP server
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _n = stream.read(&mut buf).await.unwrap();
            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
            stream.write_all(response).await.unwrap();
            stream.flush().await.unwrap();
        });

        let tls_config = Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth(),
        );

        let pool = UpstreamPool::new(Arc::clone(&tls_config), false);
        pool.pin_host("127.0.0.1", &[addr]);

        let req = Request::builder()
            .method("GET")
            .uri(format!("http://127.0.0.1:{}/test", addr.port()))
            .body(Full::new(Bytes::new()))
            .unwrap();

        let resp = pool.send(&tls_config, req).await.unwrap();
        assert_eq!(resp.status(), 200);

        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn pin_host_overwrites_previous_entry() {
        let resolver = PinnedResolver::new();
        let addr1 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 443));
        let addr2 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 443));

        resolver.pin("host.com", vec![addr1]);
        resolver.pin("host.com", vec![addr2]);

        let mut resolver_clone = resolver.clone();
        let name = "host.com".parse::<Name>().unwrap();
        let result = resolver_clone.call(name).await.unwrap();
        let addrs: Vec<SocketAddr> = result.collect();
        assert_eq!(addrs, vec![addr2]);
    }
}
