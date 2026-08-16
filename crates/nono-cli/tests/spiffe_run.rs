//! End-to-end SPIFFE/SPIRE tests using the real `nono` binary.
//!
//! These tests only run when `SPIRE_AGENT_SOCKET` is set (the CI job sets it).
//! Without it every test returns immediately, so they are safe to include in
//! the normal test suite without requiring a running SPIRE agent.
//!
//! Each test:
//!   1. Binds a mock HTTP server on a random loopback port.
//!   2. Writes a hermetic profile pointing the SPIFFE credential at that port.
//!   3. Runs `nono run -- curl http://127.0.0.1:<port>/` through the real binary.
//!   4. Asserts the mock server received the expected injected credential.
//!
//! Because the upstream is on loopback, nono removes it from NO_PROXY so curl
//! routes through the nono proxy, which fetches the SVID and injects the header.
#![allow(clippy::unwrap_used)]

use nono_test_support::{Argv, nono_test};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

/// Returns the SPIRE agent socket path, or `None` to skip the test.
fn live_socket() -> Option<String> {
    std::env::var("SPIRE_AGENT_SOCKET").ok()
}

// ─── Mock HTTP server ─────────────────────────────────────────────────────────

/// A minimal HTTP/1.1 server that accepts one connection, records request
/// headers, and returns 200 OK. Runs on a background thread.
struct MockHttpServer {
    port: u16,
    /// Headers captured from the first accepted request.
    headers: Arc<Mutex<Vec<String>>>,
}

impl MockHttpServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let port = listener.local_addr().expect("local_addr").port();
        let headers: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let headers_bg = Arc::clone(&headers);

        thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let captured = read_request_headers(stream);
                *headers_bg.lock().expect("lock") = captured;
            }
        });

        Self { port, headers }
    }

    /// Blocks until the background thread has captured request headers, or `timeout` elapses.
    fn wait_for_headers(&self, timeout: std::time::Duration) -> Vec<String> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            {
                let guard = self.headers.lock().expect("lock");
                if !guard.is_empty() {
                    return guard.clone();
                }
            }
            if std::time::Instant::now() > deadline {
                return vec![];
            }
            thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}

fn read_request_headers(stream: TcpStream) -> Vec<String> {
    let mut reader = BufReader::new(&stream);
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
                if trimmed.is_empty() {
                    break; // blank line = end of headers
                }
                headers.push(trimmed);
            }
        }
    }
    // Send a minimal HTTP response so curl exits cleanly.
    let _ = (&stream).write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    headers
}

// ─── Tests ────────────────────────────────────────────────────────────────────

/// JWT-SVID: the nono proxy fetches a JWT-SVID and injects it as
/// `Authorization: Bearer <token>` into the upstream request.
#[test]
fn spiffe_jwt_credential_injected_end_to_end() {
    let socket = match live_socket() {
        Some(s) => s,
        None => return,
    };

    let t = nono_test!("spiffe-jwt-inject");
    let mock = MockHttpServer::start();
    let upstream = format!("http://127.0.0.1:{}", mock.port);

    // Credential name must be hyphen-free: it becomes MOCKAPI_BASE_URL / MOCKAPI_API_KEY
    // in the child environment. The proxy routes by URL path prefix (/mockapi/...) and
    // strips it before forwarding to the upstream.
    let profile = t.write_profile(
        "spiffe-jwt",
        &format!(
            r#"{{
                "meta": {{ "name": "spiffe-jwt-test" }},
                "network": {{
                    "credentials": ["mockapi"],
                    "custom_credentials": {{
                        "mockapi": {{
                            "upstream": "{upstream}",
                            "spiffe": {{
                                "type": "jwt",
                                "workload_api_socket": "{socket}",
                                "audience": ["https://test.nono"],
                                "inject_header": "Authorization"
                            }}
                        }}
                    }}
                }}
            }}"#
        ),
    );

    // curl routes $MOCKAPI_BASE_URL through HTTP_PROXY (127.0.0.1 is removed from
    // NO_PROXY because the upstream is loopback). The proxy normalises the absolute
    // URL, matches the mockapi route, fetches a JWT-SVID, and injects it.
    let completed = t.run().profile(&profile).no_rollback().exec(
        Argv::new("sh")
            .arg("-c")
            .arg("curl --silent --show-error \"$MOCKAPI_BASE_URL/\""),
    );

    let headers = mock.wait_for_headers(std::time::Duration::from_secs(10));

    let stderr = completed.stderr().into_owned();
    completed.assert_success("nono run with a SPIFFE credential completes");

    let auth_header = headers
        .iter()
        .find(|h| h.to_lowercase().starts_with("authorization:"));

    assert!(
        auth_header.is_some(),
        "mock upstream should have received an Authorization header\nheaders: {headers:?}\nstderr: {stderr}"
    );

    let auth = auth_header.unwrap();
    assert!(
        auth.to_lowercase().contains("bearer "),
        "Authorization header should be a Bearer token\ngot: {auth}\nstderr: {stderr}"
    );

    let token = auth.split_once(' ').map(|x| x.1).unwrap_or("").trim();
    assert_eq!(
        token.split('.').count(),
        3,
        "Bearer value should be a JWT with three parts\ngot: {token}"
    );
}

/// Catches profile-load or SVID-fetch failures that would be silent at request time.
#[test]
fn spiffe_jwt_proxy_starts_with_live_agent() {
    let socket = match live_socket() {
        Some(s) => s,
        None => return,
    };

    let t = nono_test!("spiffe-jwt-start");

    let profile = t.write_profile(
        "spiffe-jwt-start",
        &format!(
            r#"{{
                "meta": {{ "name": "spiffe-jwt-start-test" }},
                "network": {{
                    "credentials": ["mockapi"],
                    "custom_credentials": {{
                        "mockapi": {{
                            "upstream": "https://test.nono",
                            "spiffe": {{
                                "type": "jwt",
                                "workload_api_socket": "{socket}",
                                "audience": ["https://test.nono"],
                                "inject_header": "Authorization"
                            }}
                        }}
                    }}
                }}
            }}"#
        ),
    );

    t.run()
        .profile(&profile)
        .no_rollback()
        .exec("true")
        .assert_success("nono run starts cleanly with a live SPIRE agent");
}
