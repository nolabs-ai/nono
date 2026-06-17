#![allow(clippy::unwrap_used)]

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use nono_proxy::config::{ExternalProxyAuth, ExternalProxyConfig, ProxyConfig};

static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct EnvGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    key: &'static str,
}

impl EnvGuard {
    #[allow(clippy::disallowed_methods)]
    fn set(key: &'static str, value: &str) -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var(key, value) };
        Self { _lock: lock, key }
    }
}

#[allow(clippy::disallowed_methods)]
impl Drop for EnvGuard {
    fn drop(&mut self) {
        unsafe { std::env::remove_var(self.key) };
    }
}

/// TCP listener that records the first CONNECT request and replies 200.
async fn fake_proxy() -> (String, Arc<Mutex<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    let captured: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_clone = Arc::clone(&captured);
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            *captured_clone.lock().await = buf[..n].to_vec();
            let _ = stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await;
        }
    });
    (addr, captured)
}

async fn connect_through_proxy(proxy_port: u16, proxy_token: &str, target: &str) -> Vec<u8> {
    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
        .await
        .unwrap();
    let request = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: Bearer {}\r\n\r\n",
        target, target, proxy_token
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut resp = vec![0u8; 1024];
    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        stream.read(&mut resp),
    )
    .await;
    resp
}

#[tokio::test]
async fn external_connect_sends_basic_auth_header() {
    let _guard = EnvGuard::set("NONO_TEST_CORP_PASS", "s3cr3t");

    let (fake_addr, captured) = fake_proxy().await;
    let config = ProxyConfig {
        external_proxy: Some(ExternalProxyConfig {
            address: fake_addr,
            auth: Some(ExternalProxyAuth {
                username: "alice".to_string(),
                keyring_account: "env://NONO_TEST_CORP_PASS".to_string(),
                scheme: "basic".to_string(),
            }),
            bypass_hosts: vec![],
        }),
        ..Default::default()
    };

    let handle = nono_proxy::start(config).await.unwrap();
    connect_through_proxy(handle.port, handle.token.as_str(), "example.com:443").await;
    handle.shutdown();

    let raw = captured.lock().await;
    let request = String::from_utf8_lossy(&raw);
    println!("Fake proxy received:\n{}", request);

    // "alice:s3cr3t" base64 = "YWxpY2U6czNjcjN0"
    assert!(
        request.contains("Proxy-Authorization: Basic YWxpY2U6czNjcjN0"),
        "expected Basic auth header, got:\n{}",
        request
    );
    assert!(request.contains("CONNECT example.com:443"));
}

#[tokio::test]
async fn external_connect_missing_credential_returns_502() {
    let (fake_addr, _) = fake_proxy().await;
    let config = ProxyConfig {
        external_proxy: Some(ExternalProxyConfig {
            address: fake_addr,
            auth: Some(ExternalProxyAuth {
                username: "alice".to_string(),
                keyring_account: "env://NONO_TEST_CORP_PASS_MISSING_XYZ_123".to_string(),
                scheme: "basic".to_string(),
            }),
            bypass_hosts: vec![],
        }),
        ..Default::default()
    };

    let handle = nono_proxy::start(config).await.unwrap();
    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", handle.port))
        .await
        .unwrap();
    let request = format!(
        "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Bearer {}\r\n\r\n",
        handle.token.as_str()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut resp = vec![0u8; 1024];
    let n = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        stream.read(&mut resp),
    )
    .await
    .unwrap()
    .unwrap_or(0);
    let response = String::from_utf8_lossy(&resp[..n]);
    println!("Response for missing credential:\n{}", response);
    handle.shutdown();

    assert!(response.contains("502"), "expected 502, got:\n{}", response);
    assert!(
        !response.contains("s3cr3t"),
        "password must not appear in response"
    );
}

#[tokio::test]
async fn external_connect_unsupported_scheme_returns_502() {
    let _guard = EnvGuard::set("NONO_TEST_CORP_PASS2", "s3cr3t");

    let (fake_addr, _) = fake_proxy().await;
    let config = ProxyConfig {
        external_proxy: Some(ExternalProxyConfig {
            address: fake_addr,
            auth: Some(ExternalProxyAuth {
                username: "alice".to_string(),
                keyring_account: "env://NONO_TEST_CORP_PASS2".to_string(),
                scheme: "ntlm".to_string(),
            }),
            bypass_hosts: vec![],
        }),
        ..Default::default()
    };

    let handle = nono_proxy::start(config).await.unwrap();
    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", handle.port))
        .await
        .unwrap();
    let request = format!(
        "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Bearer {}\r\n\r\n",
        handle.token.as_str()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut resp = vec![0u8; 1024];
    let n = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        stream.read(&mut resp),
    )
    .await
    .unwrap()
    .unwrap_or(0);
    let response = String::from_utf8_lossy(&resp[..n]);
    println!("Response for unsupported scheme:\n{}", response);
    handle.shutdown();

    assert!(response.contains("502"), "expected 502, got:\n{}", response);
    assert!(
        !response.contains("s3cr3t"),
        "password must not appear in response"
    );
}
