//! Loopback restriction integration tests (issue #605).
//!
//! These drive a real proxy against a real loopback listener. The bypass under
//! test: when the proxy is active the OS sandbox pins the sandboxed child to
//! `loopback:<proxy port>`, which makes the proxy the only route off the
//! child's loopback interface — but the child can still ask that proxy to
//! `CONNECT` to a *different* local service (a Kind cluster's API server on
//! 6443, say) and reach it directly, skipping the credential-injecting route
//! that was meant to mediate it.
#![allow(clippy::unwrap_used)]

use nono_proxy::config::{ProxyConfig, RouteConfig};
use nono_proxy::server;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

/// Upper bound on how long a test waits for the proxy's response line. The
/// filter decides before any upstream dial, so a denial always lands well
/// inside this; an allow that has to dial an unreachable host may not, which
/// the callers account for.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

/// Stand-in for a local service the sandboxed process must not reach directly
/// (e.g. a Kind cluster's Kubernetes API server). Returns its bound port and
/// keeps serving until the test drops the listener.
fn spawn_local_service() -> (u16, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        // A single accept is enough: the tests only need the connection to be
        // establishable for the "allowed" cases.
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        }
    });
    (port, handle)
}

/// A TLS loopback service standing in for a local HTTPS API server. Returns the
/// port and the PEM the proxy should trust for it.
///
/// The proxy mints its interception leaf from the upstream's real chain, so the
/// upstream has to complete a TLS handshake before the request ever reaches the
/// upstream-dial check this test is about.
fn spawn_tls_local_service() -> (u16, String, std::thread::JoinHandle<()>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_der = cert.signing_key.serialize_der();
    let cert_der = cert.cert.der().clone();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let handle = std::thread::spawn(move || {
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert_der],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into()),
            )
            .unwrap();
        let config = std::sync::Arc::new(config);
        while let Ok((stream, _)) = listener.accept() {
            let config = std::sync::Arc::clone(&config);
            std::thread::spawn(move || {
                let mut conn = match rustls::ServerConnection::new(config) {
                    Ok(c) => c,
                    Err(_) => return,
                };
                let mut stream = stream;
                let mut tls = rustls::Stream::new(&mut conn, &mut stream);
                let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            });
        }
    });
    (port, cert_pem, handle)
}

/// Issue a raw `CONNECT host:port` to the proxy and return the status line,
/// or the empty string if the proxy did not answer within [`RESPONSE_TIMEOUT`].
fn connect_through_proxy(proxy_port: u16, token: &str, target: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    stream.set_read_timeout(Some(RESPONSE_TIMEOUT)).unwrap();
    let request = format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Bearer {token}\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).unwrap();
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).unwrap_or(0);
    String::from_utf8_lossy(&buf[..n])
        .lines()
        .next()
        .unwrap_or("")
        .to_string()
}

/// Without the restriction, the proxy happily tunnels to another local
/// service. This is the current behaviour and the hole reported in #605.
// Multi-threaded: the client below uses blocking sockets, which would
// otherwise starve the proxy's accept loop on a current-thread runtime.
#[tokio::test(flavor = "multi_thread")]
async fn loopback_reachable_through_proxy_by_default() {
    let (service_port, _service) = spawn_local_service();
    let handle = server::start(ProxyConfig::default()).await.unwrap();

    let status = connect_through_proxy(
        handle.port,
        &handle.token,
        &format!("127.0.0.1:{service_port}"),
    );

    assert!(
        status.starts_with("HTTP/1.1 200"),
        "default config must keep loopback reachable, got: {status:?}"
    );
}

/// With `block_loopback`, the same tunnel is refused.
// Multi-threaded: the client below uses blocking sockets, which would
// otherwise starve the proxy's accept loop on a current-thread runtime.
#[tokio::test(flavor = "multi_thread")]
async fn block_loopback_refuses_connect_to_local_service() {
    let (service_port, _service) = spawn_local_service();
    let config = ProxyConfig {
        block_loopback: true,
        ..ProxyConfig::default()
    };
    let handle = server::start(config).await.unwrap();

    let status = connect_through_proxy(
        handle.port,
        &handle.token,
        &format!("127.0.0.1:{service_port}"),
    );

    assert!(
        status.starts_with("HTTP/1.1 403"),
        "block_loopback must refuse a CONNECT to another local service, got: {status:?}"
    );
}

/// Spelling the destination `localhost` instead of `127.0.0.1` must not help.
// Multi-threaded: the client below uses blocking sockets, which would
// otherwise starve the proxy's accept loop on a current-thread runtime.
#[tokio::test(flavor = "multi_thread")]
async fn block_loopback_refuses_localhost_spelling() {
    let (service_port, _service) = spawn_local_service();
    let config = ProxyConfig {
        block_loopback: true,
        ..ProxyConfig::default()
    };
    let handle = server::start(config).await.unwrap();

    let status = connect_through_proxy(
        handle.port,
        &handle.token,
        &format!("localhost:{service_port}"),
    );

    assert!(
        status.starts_with("HTTP/1.1 403"),
        "block_loopback must refuse the localhost spelling too, got: {status:?}"
    );
}

/// An operator-declared port stays reachable, so a deliberate localhost IPC
/// dependency can be kept while everything else on loopback is refused.
// Multi-threaded: the client below uses blocking sockets, which would
// otherwise starve the proxy's accept loop on a current-thread runtime.
#[tokio::test(flavor = "multi_thread")]
async fn loopback_allow_permits_declared_port_only() {
    let (allowed_port, _allowed) = spawn_local_service();
    let (denied_port, _denied) = spawn_local_service();
    let config = ProxyConfig {
        block_loopback: true,
        loopback_allow: vec![allowed_port],
        ..ProxyConfig::default()
    };
    let handle = server::start(config).await.unwrap();

    let allowed = connect_through_proxy(
        handle.port,
        &handle.token,
        &format!("127.0.0.1:{allowed_port}"),
    );
    assert!(
        allowed.starts_with("HTTP/1.1 200"),
        "a port in loopback_allow must stay reachable, got: {allowed:?}"
    );

    let denied = connect_through_proxy(
        handle.port,
        &handle.token,
        &format!("127.0.0.1:{denied_port}"),
    );
    assert!(
        denied.starts_with("HTTP/1.1 403"),
        "a port outside loopback_allow must be refused, got: {denied:?}"
    );
}

/// The restriction must not touch non-loopback egress.
// Multi-threaded: the client below uses blocking sockets, which would
// otherwise starve the proxy's accept loop on a current-thread runtime.
#[tokio::test(flavor = "multi_thread")]
async fn block_loopback_leaves_external_hosts_alone() {
    let config = ProxyConfig {
        block_loopback: true,
        ..ProxyConfig::default()
    };
    let handle = server::start(config).await.unwrap();

    // `.invalid` is reserved by RFC 2606 and never resolves, so this fails
    // fast upstream (502) instead of stalling on a TCP connect to a
    // blackholed address. What matters is that the loopback policy — which
    // decides before any dial — did not reject it.
    let status = connect_through_proxy(handle.port, &handle.token, "not-a-real-host.invalid:443");

    // Assert the positive outcome, not merely "not 403": an empty status (proxy
    // hung or dropped the connection) would satisfy a negative assertion and
    // hide a regression on the non-loopback path.
    assert!(
        status.starts_with("HTTP/1.1 502"),
        "a non-loopback destination must reach the upstream dial and fail there, \
         not be rejected by the loopback policy, got: {status:?}"
    );
}

/// The point of the whole feature: the sanctioned path must survive. A
/// credential route whose upstream *is* a loopback service stays reachable
/// under `block_loopback` — otherwise turning the restriction on would break
/// the very setup it protects — while a raw CONNECT to that same service is
/// still refused.
#[tokio::test(flavor = "multi_thread")]
async fn block_loopback_exempts_configured_route_upstream() {
    let (service_port, _service) = spawn_local_service();
    let config = ProxyConfig {
        block_loopback: true,
        routes: vec![RouteConfig {
            prefix: "k8s".to_string(),
            upstream: format!("http://127.0.0.1:{service_port}"),
            ..RouteConfig::default()
        }],
        ..ProxyConfig::default()
    };
    let handle = server::start(config).await.unwrap();

    // The raw tunnel to the same service is still refused. This is the heart
    // of the design: the exemption follows the caller (the proxy dialling for
    // a route), not the address. Exempting `127.0.0.1:<service_port>` itself
    // would let a client ask for it directly and skip the route's
    // endpoint_policy and credential injection.
    let status = connect_through_proxy(
        handle.port,
        &handle.token,
        &format!("127.0.0.1:{service_port}"),
    );
    assert!(
        status.starts_with("HTTP/1.1 403"),
        "a raw CONNECT to a routed upstream must still be refused, got: {status:?}"
    );

    // The route itself resolves past the loopback policy and reaches the
    // upstream. Without the route exemption this is a 403 and the credential
    // path is broken — which is exactly the trade-off this test pins down.
    let via_route = reverse_request(handle.port, &handle.token, "/k8s/healthz");
    assert!(
        via_route.starts_with("HTTP/1.1 200"),
        "the configured route upstream must stay reachable, got: {via_route:?}"
    );
}

/// Issue a plain reverse-proxy request and return the status line.
fn reverse_request(proxy_port: u16, token: &str, path: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    stream.set_read_timeout(Some(RESPONSE_TIMEOUT)).unwrap();
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{proxy_port}\r\nProxy-Authorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).unwrap();
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).unwrap_or(0);
    String::from_utf8_lossy(&buf[..n])
        .lines()
        .next()
        .unwrap_or("")
        .to_string()
}

/// Regression: a route carrying a credential requires TLS interception
/// (`route.rs` marks any `credential_key` route `requires_intercept`), and the
/// intercept path dials the upstream through its own code — not `reverse.rs`.
/// That dial must use the route-scoped check, or `block_loopback` makes every
/// credential route to a local service unreachable, which is exactly the
/// documented `https://localhost:6443` example.
///
/// This has to complete the inner TLS request, because the upstream dial
/// happens well after the CONNECT: stopping at the `200` tunnel response
/// passes whether or not the bug is present.
///
/// Discriminator: the loopback policy is consulted *before* the upstream dial,
/// so a `403` means the policy rejected it (the bug) while a `502` means it got
/// through to the dial and failed there against the plain-TCP stub (correct).
#[tokio::test(flavor = "multi_thread")]
async fn block_loopback_allows_intercepted_credential_route_upstream() {
    use rustls::pki_types::pem::PemObject;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // rustls needs a process-wide provider before any config is built.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Credential comes from a `file://` source, not an env var: mutating the
    // environment is not thread-safe across parallel tests (and is disallowed
    // by the workspace lint).
    const CRED_ENV: &str = "NONO_TEST_LOOPBACK_INTERCEPT_CRED";

    // `localhost`, not `127.0.0.1`: the interception cert cache refuses to mint
    // a leaf for an IP literal (`is_plausible_dns_name`), so an IP-literal
    // upstream never reaches the dial this test is about.
    let (service_port, upstream_ca_pem, _service) = spawn_tls_local_service();
    let ca_dir = tempfile::tempdir().unwrap();
    // `tls_ca` is a path, not inline PEM.
    let upstream_ca_path = ca_dir.path().join("upstream-ca.pem");
    std::fs::write(&upstream_ca_path, &upstream_ca_pem).unwrap();
    let cred_path = ca_dir.path().join("credential");
    std::fs::write(&cred_path, "test-credential-value").unwrap();
    let config = ProxyConfig {
        block_loopback: true,
        intercept_ca_dir: Some(ca_dir.path().to_path_buf()),
        routes: vec![RouteConfig {
            prefix: "k8s".to_string(),
            upstream: format!("https://localhost:{service_port}"),
            credential_key: Some(format!("file://{}", cred_path.display())),
            env_var: Some(CRED_ENV.to_string()),
            tls_ca: Some(upstream_ca_path.to_string_lossy().into_owned()),
            ..RouteConfig::default()
        }],
        ..ProxyConfig::default()
    };
    let config_for_env = config.clone();
    let handle = server::start(config).await.unwrap();
    let ca_path = handle
        .intercept_ca_path()
        .expect("interception must be active for this test to mean anything")
        .to_path_buf();

    // Open the tunnel to the route's own upstream address.
    let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", handle.port))
        .await
        .unwrap();
    let target = format!("localhost:{service_port}");
    sock.write_all(
        format!(
            "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Bearer {}\r\n\r\n",
            *handle.token
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut buf = [0u8; 128];
    let n = sock.read(&mut buf).await.unwrap();
    let connect_status = String::from_utf8_lossy(&buf[..n])
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    assert!(
        connect_status.starts_with("HTTP/1.1 200"),
        "CONNECT to a routed upstream must enter the intercept path, got: {connect_status:?}"
    );

    // Speak TLS to the proxy's interception CA, then send the inner request —
    // this is what drives the upstream dial.
    let mut roots = rustls::RootCertStore::empty();
    let bundle = std::fs::read(&ca_path).unwrap();
    for cert in rustls::pki_types::CertificateDer::pem_slice_iter(&bundle).flatten() {
        let _ = roots.add(cert);
    }
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls_config));
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();

    let mut tls = match connector.connect(server_name, sock).await {
        Ok(stream) => stream,
        Err(e) => panic!("inner TLS handshake against the intercept CA failed: {e}"),
    };
    // The route swaps a phantom for the real credential, so the client has to
    // present the phantom it was issued — same contract the sandboxed child has.
    let phantom = handle
        .credential_env_vars(&config_for_env)
        .into_iter()
        .find(|(k, _)| k == CRED_ENV)
        .map(|(_, v)| v)
        .expect("route must issue a phantom credential");

    tls.write_all(
        format!(
            "GET /api/v1/namespaces HTTP/1.1\r\nHost: {target}\r\nAuthorization: Bearer {phantom}\r\nProxy-Authorization: Bearer {}\r\nConnection: close\r\n\r\n",
            *handle.token
        )
        .as_bytes(),
    )
    .await
    .unwrap();

    let mut resp = Vec::new();
    let _ = tls.read_to_end(&mut resp).await;

    // Assert on the audit trail rather than the response body. The loopback
    // policy records its denial before the upstream dial, so this is decisive
    // regardless of how the exchange ends — and it stays decisive if some later
    // stage of the intercept pipeline changes.
    // On this path `HostDenied` can only come from the proxy filter, and the
    // filter would otherwise allow (non-strict, empty allowlist) — so its
    // presence means the loopback policy rejected the route's own upstream.
    let host_denials: Vec<_> = handle
        .drain_audit_events()
        .into_iter()
        .filter(|e| e.denial_category == Some(nono::undo::NetworkAuditDenialCategory::HostDenied))
        .map(|e| (e.mode, e.denial_category))
        .collect();

    assert!(
        host_denials.is_empty(),
        "the intercept path's upstream dial must not be refused by the loopback \
         policy — a credential route to a local service has to keep working, but \
         the proxy recorded: {host_denials:?}"
    );
}

/// Through an upstream (enterprise) proxy, the proxy normally forwards the
/// client's hostname and lets the upstream proxy resolve it. Under
/// `block_loopback` that second resolution could land on loopback (rebinding),
/// so the target is pinned to the locally checked IP. If the name does not
/// resolve locally there is nothing to pin, and the request must be refused
/// before anything reaches the upstream proxy.
// Multi-threaded: the client below uses blocking sockets, which would
// otherwise starve the proxy's accept loop on a current-thread runtime.
#[tokio::test(flavor = "multi_thread")]
async fn block_loopback_refuses_unresolvable_target_via_upstream_proxy() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    // Stand-in enterprise proxy that only records whether anything connected.
    let upstream_proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_proxy_addr = upstream_proxy.local_addr().unwrap();
    upstream_proxy.set_nonblocking(true).unwrap();
    let contacted = Arc::new(AtomicBool::new(false));
    let contacted_flag = Arc::clone(&contacted);
    let _upstream = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + RESPONSE_TIMEOUT;
        while std::time::Instant::now() < deadline {
            if upstream_proxy.accept().is_ok() {
                contacted_flag.store(true, Ordering::SeqCst);
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    });

    let config = ProxyConfig {
        block_loopback: true,
        external_proxy: Some(nono_proxy::config::ExternalProxyConfig {
            address: upstream_proxy_addr.to_string(),
            auth: None,
            bypass_hosts: Vec::new(),
        }),
        ..ProxyConfig::default()
    };
    let handle = server::start(config).await.unwrap();

    // `.invalid` (RFC 2606) never resolves.
    let status = connect_through_proxy(handle.port, &handle.token, "unresolvable.invalid:443");

    assert!(
        status.starts_with("HTTP/1.1 502"),
        "an unresolvable target must be refused under block_loopback, got: {status:?}"
    );
    assert!(
        !contacted.load(Ordering::SeqCst),
        "the upstream proxy must not be contacted when there is no checked IP to pin to"
    );
}
