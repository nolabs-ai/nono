//! TLS acceptor configuration for intercepted CONNECT streams.
//!
//! The acceptor uses [`super::CertCache`] as its `ResolvesServerCert` so each
//! intercepted handshake is answered with a fresh-or-cached leaf certificate
//! matching the SNI hostname.
//!
//! ## ALPN
//!
//! We advertise both `h2` and `http/1.1` in ALPN. After the handshake the
//! caller inspects the negotiated protocol and dispatches to the appropriate
//! forwarding path:
//!
//! * `h2` — [`super::h2_forward`] handles HTTP/2 framing with per-stream
//!   credential injection (required for gRPC clients).
//! * `http/1.1` — the existing [`super::handle`] request parser forwards a
//!   single HTTP/1.1 request with credential injection.

use crate::error::{ProxyError, Result};
use crate::tls_intercept::cert_cache::CertCache;
use rustls::server::ServerConfig;
use std::sync::Arc;

/// Build a [`ServerConfig`] suitable for terminating an intercepted CONNECT.
///
/// The config:
/// * uses the `ring` crypto provider explicitly (matching the rest of the
///   proxy crate; the process-level default is intentionally not set so that
///   embedders can choose);
/// * has no client-cert authentication (the OUTER CONNECT auth has already
///   established caller identity at the TCP layer);
/// * resolves server certs via the supplied [`CertCache`];
/// * advertises `h2` and `http/1.1` in ALPN.
pub fn build_server_config(
    cert_cache: Arc<CertCache>,
    enable_h2: bool,
) -> Result<Arc<ServerConfig>> {
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| ProxyError::Config(format!("tls_intercept TLS config error: {}", e)))?
            .with_no_client_auth()
            .with_cert_resolver(cert_cache);
    config.alpn_protocols = if enable_h2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };
    Ok(Arc::new(config))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::tls_intercept::ca::EphemeralCa;
    use rustls::pki_types::{CertificateDer, ServerName};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn alpn_offers_h2_and_h1() {
        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let cache = Arc::new(CertCache::new(ca));
        let config = build_server_config(cache, true).unwrap();
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    /// Helper: build a rustls client `ClientConfig` that trusts `ca_pem`.
    fn client_config_trusting(ca_pem: &str) -> Arc<rustls::ClientConfig> {
        use rustls::pki_types::pem::PemObject;

        let mut roots = rustls::RootCertStore::empty();
        let cert = CertificateDer::from_pem_slice(ca_pem.as_bytes()).unwrap();
        roots.add(cert).unwrap();
        Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
        )
    }

    /// Helper: build a rustls client `ClientConfig` with an empty trust
    /// store — used to simulate cert pinning / hard-coded trust lists.
    fn client_config_empty_trust() -> Arc<rustls::ClientConfig> {
        Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth(),
        )
    }

    #[tokio::test]
    async fn handshake_succeeds_when_client_trusts_ephemeral_ca() {
        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let cache = Arc::new(CertCache::new(Arc::clone(&ca)));
        let server_config = build_server_config(Arc::clone(&cache), true).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
            let mut tls = acceptor.accept(stream).await.unwrap();
            // Echo the bytes the client sends so the test can validate
            // the encrypted channel actually flows.
            let mut buf = [0u8; 64];
            let n = tls.read(&mut buf).await.unwrap();
            tls.write_all(&buf[..n]).await.unwrap();
            tls.flush().await.unwrap();
        });

        let client_config = client_config_trusting(ca.cert_pem());
        let connector = tokio_rustls::TlsConnector::from(client_config);
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let server_name = ServerName::try_from("api.example.com").unwrap();
        let mut tls = connector.connect(server_name, tcp).await.unwrap();
        tls.write_all(b"hello").await.unwrap();
        tls.flush().await.unwrap();
        let mut buf = [0u8; 5];
        tls.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handshake_fails_when_client_pins_other_cert() {
        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let cache = Arc::new(CertCache::new(Arc::clone(&ca)));
        let server_config = build_server_config(Arc::clone(&cache), true).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
            // Expect the handshake to fail because the client trusts no roots.
            assert!(acceptor.accept(stream).await.is_err());
        });

        let client_config = client_config_empty_trust();
        let connector = tokio_rustls::TlsConnector::from(client_config);
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let server_name = ServerName::try_from("api.example.com").unwrap();
        // Client should refuse to complete the handshake because our
        // ephemeral CA isn't in its (empty) trust store. This is the
        // cert-pinning hard-fail behaviour the design constraint demands.
        assert!(connector.connect(server_name, tcp).await.is_err());

        server_task.await.unwrap();
    }

    /// Helper: build a client config that trusts `ca_pem` with a specific ALPN preference.
    fn client_config_trusting_with_alpn(
        ca_pem: &str,
        alpn: Vec<Vec<u8>>,
    ) -> Arc<rustls::ClientConfig> {
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
        config.alpn_protocols = alpn;
        Arc::new(config)
    }

    #[tokio::test]
    async fn alpn_negotiates_h2_when_client_prefers_h2() {
        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let cache = Arc::new(CertCache::new(Arc::clone(&ca)));
        let server_config = build_server_config(Arc::clone(&cache), true).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
            let tls = acceptor.accept(stream).await.unwrap();
            let negotiated = tls.get_ref().1.alpn_protocol().map(|p| p.to_vec());
            assert_eq!(negotiated, Some(b"h2".to_vec()));
        });

        let client_config = client_config_trusting_with_alpn(
            ca.cert_pem(),
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        );
        let connector = tokio_rustls::TlsConnector::from(client_config);
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let server_name = ServerName::try_from("api.example.com").unwrap();
        let tls = connector.connect(server_name, tcp).await.unwrap();
        let negotiated = tls.get_ref().1.alpn_protocol().map(|p| p.to_vec());
        assert_eq!(negotiated, Some(b"h2".to_vec()));

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn alpn_negotiates_h1_when_client_only_offers_h1() {
        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let cache = Arc::new(CertCache::new(Arc::clone(&ca)));
        let server_config = build_server_config(Arc::clone(&cache), true).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
            let tls = acceptor.accept(stream).await.unwrap();
            let negotiated = tls.get_ref().1.alpn_protocol().map(|p| p.to_vec());
            assert_eq!(negotiated, Some(b"http/1.1".to_vec()));
        });

        let client_config =
            client_config_trusting_with_alpn(ca.cert_pem(), vec![b"http/1.1".to_vec()]);
        let connector = tokio_rustls::TlsConnector::from(client_config);
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let server_name = ServerName::try_from("api.example.com").unwrap();
        let tls = connector.connect(server_name, tcp).await.unwrap();
        let negotiated = tls.get_ref().1.alpn_protocol().map(|p| p.to_vec());
        assert_eq!(negotiated, Some(b"http/1.1".to_vec()));

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn alpn_negotiates_h2_when_client_only_offers_h2() {
        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let cache = Arc::new(CertCache::new(Arc::clone(&ca)));
        let server_config = build_server_config(Arc::clone(&cache), true).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
            let tls = acceptor.accept(stream).await.unwrap();
            let negotiated = tls.get_ref().1.alpn_protocol().map(|p| p.to_vec());
            assert_eq!(negotiated, Some(b"h2".to_vec()));
        });

        let client_config = client_config_trusting_with_alpn(ca.cert_pem(), vec![b"h2".to_vec()]);
        let connector = tokio_rustls::TlsConnector::from(client_config);
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let server_name = ServerName::try_from("api.example.com").unwrap();
        let tls = connector.connect(server_name, tcp).await.unwrap();
        let negotiated = tls.get_ref().1.alpn_protocol().map(|p| p.to_vec());
        assert_eq!(negotiated, Some(b"h2".to_vec()));

        server_task.await.unwrap();
    }
}
