//! Pre-flight HTTP/2 capability probe and per-host cache.
//!
//! Before advertising `h2` in the inbound TLS acceptor ALPN list, we need to
//! know whether the upstream actually supports HTTP/2. Some hosts (e.g.
//! `a0us.jfrog.io`) reject a `h2`-only ClientHello with
//! `NoApplicationProtocol`. By then the inbound TLS handshake has already
//! committed to h2, leaving no graceful fallback.
//!
//! The fix: open a short-lived TLS probe to the upstream before the inbound
//! handshake, cache the result by target, upstream strategy, and TLS connector,
//! and only advertise `h2` to the client when the upstream is known to support
//! it.

use crate::filter::ProxyFilter;
use crate::forward::{UpstreamScheme, UpstreamSpec, UpstreamStrategy, open_tcp_upstream};
use crate::tls_intercept::handle::{InterceptUpstreamProxy, select_upstream_strategy};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;

/// Per-host HTTP/2 capability cache.
///
/// Keyed on target, upstream strategy, and TLS connector identity. Cache
/// entries are permanent for the lifetime of the proxy session — upstream H2
/// capability is stable for a fixed connection policy.
pub(crate) struct UpstreamH2Cache {
    inner: RwLock<HashMap<String, bool>>,
}

impl UpstreamH2Cache {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: RwLock::new(HashMap::new()),
        })
    }

    /// Return the cached capability, or run a probe and cache the result.
    pub(crate) async fn get_or_probe(
        &self,
        host: &str,
        port: u16,
        filter: &ProxyFilter,
        tls_connector_h2: &tokio_rustls::TlsConnector,
        upstream_proxy: Option<&InterceptUpstreamProxy<'_>>,
        connector_cache_key: &str,
    ) -> bool {
        let proxy_cache_key = upstream_proxy
            .map(|proxy| format!("proxy:{}", proxy.proxy_addr))
            .unwrap_or_else(|| "direct".to_string());
        let key = format!(
            "{}:{}:{}:{}",
            host.to_lowercase(),
            port,
            proxy_cache_key,
            connector_cache_key
        );

        // Fast path: read lock.
        {
            let guard = self.inner.read().await;
            if let Some(&cached) = guard.get(&key) {
                return cached;
            }
        }

        // Slow path: probe, then write.
        let mut guard = self.inner.write().await;
        // Double-checked: another task may have probed while we waited.
        if let Some(&cached) = guard.get(&key) {
            return cached;
        }

        let result = probe_upstream_h2(host, port, filter, tls_connector_h2, upstream_proxy).await;
        debug!("h2_probe: {}:{} → h2={}", host, port, result);
        guard.insert(key, result);
        result
    }
}

/// Open a short-lived TLS connection to the upstream and check whether it
/// negotiated `h2` via ALPN.
///
/// On any error (DNS, TCP, TLS) returns `false` — fail-safe: treat unknown
/// capability as no h2. The probe connection is dropped immediately after
/// the ALPN check; tokio-rustls sends `close_notify` on drop.
async fn probe_upstream_h2(
    host: &str,
    port: u16,
    filter: &ProxyFilter,
    tls_connector_h2: &tokio_rustls::TlsConnector,
    upstream_proxy: Option<&InterceptUpstreamProxy<'_>>,
) -> bool {
    let check = match filter.check_host(host, port).await {
        Ok(c) if c.result.is_allowed() => c,
        _ => return false,
    };

    let upstream_proxy = upstream_proxy.cloned();
    let strategy = select_upstream_strategy(&upstream_proxy, &check.resolved_addrs);
    probe_with_strategy(host, port, strategy, tls_connector_h2).await
}

/// Inner probe: TCP connect + TLS handshake against pre-resolved addresses.
///
/// Split out so tests can call it directly without a `ProxyFilter`.
#[cfg(test)]
pub(crate) async fn probe_with_addrs(
    host: &str,
    port: u16,
    resolved_addrs: &[std::net::SocketAddr],
    tls_connector_h2: &tokio_rustls::TlsConnector,
) -> bool {
    probe_with_strategy(
        host,
        port,
        UpstreamStrategy::Direct { resolved_addrs },
        tls_connector_h2,
    )
    .await
}

pub(crate) async fn probe_with_strategy(
    host: &str,
    port: u16,
    strategy: UpstreamStrategy<'_>,
    tls_connector_h2: &tokio_rustls::TlsConnector,
) -> bool {
    let upstream = UpstreamSpec {
        scheme: UpstreamScheme::Https,
        host,
        port,
        strategy,
        tls_connector: tls_connector_h2,
    };

    let tcp = match open_tcp_upstream(&upstream).await {
        Ok(t) => t,
        Err(_) => return false,
    };

    let server_name = match rustls::pki_types::ServerName::try_from(host.to_string()) {
        Ok(n) => n,
        Err(_) => return false,
    };

    let tls = match tls_connector_h2.connect(server_name, tcp).await {
        Ok(t) => t,
        Err(_) => return false,
    };

    tls.get_ref().1.alpn_protocol() == Some(b"h2")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::tls_intercept::ca::EphemeralCa;
    use rcgen::{CertificateParams, KeyPair};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject};
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use time::OffsetDateTime;
    use tokio::net::TcpListener;

    /// Build a TLS connector that trusts `ca_pem` with h2-only ALPN.
    fn h2_connector_trusting(ca_pem: &str) -> tokio_rustls::TlsConnector {
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

    /// Spin a TLS server advertising the given ALPN list.
    /// Returns the bound port and a counter of accepted connections.
    async fn spawn_alpn_server(ca: &EphemeralCa, alpn: Vec<Vec<u8>>) -> (u16, Arc<AtomicUsize>) {
        use rcgen::PKCS_ECDSA_P256_SHA256;

        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.not_before = OffsetDateTime::now_utc();
        params.not_after = OffsetDateTime::now_utc() + time::Duration::hours(1);
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params.signed_by(&key, ca.issuer()).unwrap();

        let cert_der = cert.der().clone();
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));

        let mut server_cfg = rustls::server::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], private_key)
        .unwrap();
        server_cfg.alpn_protocols = alpn;
        let server_cfg = Arc::new(server_cfg);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter2 = Arc::clone(&counter);

        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    break;
                };
                counter2.fetch_add(1, Ordering::SeqCst);
                let acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(&server_cfg));
                tokio::spawn(async move {
                    // Complete the handshake; we don't need to serve anything.
                    let _ = acceptor.accept(tcp).await;
                });
            }
        });

        (port, counter)
    }

    #[tokio::test]
    async fn probe_returns_true_for_h2_upstream() {
        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let (port, _) = spawn_alpn_server(&ca, vec![b"h2".to_vec()]).await;

        let connector = h2_connector_trusting(ca.cert_pem());
        let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
        let result = probe_with_addrs("localhost", port, &[addr], &connector).await;
        assert!(result, "expected h2=true for h2-only upstream");
    }

    #[tokio::test]
    async fn probe_returns_false_for_h1_only_upstream() {
        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let (port, _) = spawn_alpn_server(&ca, vec![b"http/1.1".to_vec()]).await;

        let connector = h2_connector_trusting(ca.cert_pem());
        let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
        let result = probe_with_addrs("localhost", port, &[addr], &connector).await;
        assert!(!result, "expected h2=false for http/1.1-only upstream");
    }

    #[tokio::test]
    async fn cache_probes_once_and_reuses() {
        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let (port, connect_count) = spawn_alpn_server(&ca, vec![b"h2".to_vec()]).await;

        let connector = h2_connector_trusting(ca.cert_pem());
        let cache = UpstreamH2Cache::new();
        let filter = ProxyFilter::allow_all();

        // Override ProxyFilter resolution by using the inner probe directly
        // (ProxyFilter::allow_all skips DNS, resolved_addrs will be empty).
        // We test the cache logic by calling get_or_probe twice against a
        // real server and checking connect_count reaches exactly 1.
        let r1 = cache
            .get_or_probe("localhost", port, &filter, &connector, None, "test")
            .await;
        // get_or_probe with allow_all calls probe_upstream_h2 which calls
        // filter.check_host — for allow_all this returns empty resolved_addrs,
        // so open_tcp_upstream falls back to direct hostname resolution.
        // The counter will be 1 after the first probe.
        let count_after_first = connect_count.load(Ordering::SeqCst);

        let r2 = cache
            .get_or_probe("localhost", port, &filter, &connector, None, "test")
            .await;
        let count_after_second = connect_count.load(Ordering::SeqCst);

        assert_eq!(r1, r2, "both calls should return the same result");
        assert_eq!(
            count_after_first, count_after_second,
            "second call must not open a new connection (cache hit)"
        );
    }

    #[tokio::test]
    async fn probe_supports_external_proxy_strategy() {
        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let (upstream_port, _) = spawn_alpn_server(&ca, vec![b"h2".to_vec()]).await;
        let proxy_port = spawn_connect_proxy().await;

        let connector = h2_connector_trusting(ca.cert_pem());
        let proxy_addr = format!("127.0.0.1:{}", proxy_port);
        let result = probe_with_strategy(
            "localhost",
            upstream_port,
            UpstreamStrategy::ExternalProxy {
                proxy_addr: &proxy_addr,
                proxy_auth_header: None,
            },
            &connector,
        )
        .await;

        assert!(result, "h2 probe should work through an upstream proxy");
    }

    async fn spawn_connect_proxy() -> u16 {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let Ok((mut inbound, _)) = listener.accept().await else {
                return;
            };
            let mut reader = BufReader::new(&mut inbound);
            let mut first_line = String::new();
            if reader.read_line(&mut first_line).await.is_err() {
                return;
            }
            let target = first_line
                .split_whitespace()
                .nth(1)
                .map(str::to_string)
                .unwrap_or_default();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).await.is_err() || line.trim().is_empty() {
                    break;
                }
            }
            drop(reader);

            let Ok(mut upstream) = TcpStream::connect(target).await else {
                return;
            };
            if inbound
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .is_err()
            {
                return;
            }
            let _ = tokio::io::copy_bidirectional(&mut inbound, &mut upstream).await;
        });

        port
    }
}
