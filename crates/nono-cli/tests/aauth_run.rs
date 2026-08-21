//! End-to-end aauth tests using the real `nono` binary.
//!
//! The "resource" side is a real `aauth_core::resource::RequestVerifier`
//! running inline in a background thread — not a separate process — so
//! these tests have no dependency on a live network or a second binary,
//! while still exercising the exact wire format and crypto a real resource
//! server would use.
//!
//! Each signing test:
//!   1. Generates a real Ed25519 key and writes it as `nono aauth keygen`
//!      would (base64 PKCS#8 DER).
//!   2. Binds a mock verifying server on a random loopback port.
//!   3. Writes a hermetic profile pointing an aauth-signed route at it.
//!   4. Runs `nono run -- curl ...` through the real binary.
//!   5. Asserts the mock server actually verified the signature.
//!
//! The isolation tests prove the two exfiltration paths found during review
//! stay closed: a `file://` key under a granted path, and an `env://` key's
//! value leaking into the sandboxed child's environment.
#![allow(clippy::unwrap_used)]

use aauth_core::keys::{PrivateKey, generate_ed25519_keypair, generate_jwks, public_key_to_jwk};
use aauth_core::resource::RequestVerifier;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use nono_test_support::{Argv, nono_test};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

/// What the mock server saw once it received and verified one request.
#[derive(Debug, Clone)]
struct Verified {
    valid: bool,
    agent_id: Option<String>,
}

/// A loopback server that reads one HTTP request, verifies it as an aauth
/// signature, and responds 200 (verified) or 401 (not) — the same shape as
/// aauth-rs's own `examples/demo_resource_server.rs`, inlined here.
struct MockAauthServer {
    port: u16,
    verified: Arc<Mutex<Option<Verified>>>,
}

impl MockAauthServer {
    /// `jwks_uri` is `Some((jwks_document, expected_issuer))` for jwks_uri-scheme
    /// tests, or `None` for hwk (no discovery needed).
    fn start(jwks_uri: Option<(serde_json::Value, String)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let port = listener.local_addr().expect("local_addr").port();
        let authority = format!("127.0.0.1:{port}");
        let verified: Arc<Mutex<Option<Verified>>> = Arc::new(Mutex::new(None));
        let verified_bg = Arc::clone(&verified);

        thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let (method, path, headers, body) = read_request(&mut stream);
            let target_uri = format!("http://{authority}{path}");
            let body_opt = if body.is_empty() {
                None
            } else {
                Some(body.as_slice())
            };

            let verifier = RequestVerifier::new(vec![authority.clone()]);
            let result = match &jwks_uri {
                Some((jwks, expected_issuer)) => {
                    let jwks = jwks.clone();
                    let expected_issuer = expected_issuer.clone();
                    let resolver = move |id: &str, _dwk: Option<&str>, _kid: Option<&str>| {
                        (id == expected_issuer).then(|| jwks.clone())
                    };
                    verifier.with_jwks_resolver(&resolver).verify_request(
                        &method,
                        &target_uri,
                        &headers,
                        body_opt,
                        false,
                        false,
                    )
                }
                None => {
                    verifier.verify_request(&method, &target_uri, &headers, body_opt, false, false)
                }
            };

            *verified_bg.lock().expect("lock") = Some(Verified {
                valid: result.valid,
                agent_id: result.agent_id,
            });

            let status = if result.valid {
                "200 OK"
            } else {
                "401 Unauthorized"
            };
            let _ = (&stream)
                .write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n").as_bytes());
        });

        Self { port, verified }
    }

    fn wait_for_result(&self, timeout: std::time::Duration) -> Option<Verified> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some(v) = self.verified.lock().expect("lock").clone() {
                return Some(v);
            }
            if std::time::Instant::now() > deadline {
                return None;
            }
            thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}

/// Reads one HTTP/1.1 request's method, path, headers (lowercased), and body.
fn read_request(stream: &mut TcpStream) -> (String, String, HashMap<String, String>, Vec<u8>) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .expect("read request line");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let path = parts.next().unwrap_or("/").to_string();

    let mut headers = HashMap::new();
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).expect("read header line");
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim().to_string();
            if name == "content-length" {
                content_length = value.parse().unwrap_or(0);
            }
            headers.insert(name, value);
        }
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).expect("read body");
    }
    (method, path, headers, body)
}

/// Writes a fresh Ed25519 key at `path`, base64-PKCS#8 encoded exactly as
/// `nono aauth keygen` writes it, and returns the keypair for building a
/// matching JWKS document.
fn write_aauth_key(path: &std::path::Path) -> (PrivateKey, aauth_core::keys::PublicKey) {
    let (private_key, public_key) = generate_ed25519_keypair();
    let der = private_key.to_pkcs8_der().expect("encode key");
    std::fs::write(path, BASE64.encode(&*der)).expect("write key file");
    (private_key, public_key)
}

#[test]
fn aauth_hwk_signs_and_verifies_end_to_end() {
    let t = nono_test!("aauth-hwk");
    let key_path = t.root().join("aauth-key.pem");
    write_aauth_key(&key_path);

    let server = MockAauthServer::start(None);
    let upstream = format!("http://127.0.0.1:{}", server.port);

    let profile = t.write_profile(
        "aauth-hwk",
        &format!(
            r#"{{
                "meta": {{ "name": "aauth-hwk-test" }},
                "network": {{
                    "credentials": ["aauthapi"],
                    "aauth_identity": {{ "key_ref": "file://{}" }},
                    "custom_credentials": {{
                        "aauthapi": {{ "upstream": "{upstream}", "aauth": true }}
                    }}
                }}
            }}"#,
            key_path.display()
        ),
    );

    t.run()
        .profile(&profile)
        .no_rollback()
        .exec(
            Argv::new("sh")
                .arg("-c")
                .arg("curl --silent --show-error \"$AAUTHAPI_BASE_URL/widgets\""),
        )
        .assert_success("nono run with an aauth hwk route completes");

    let result = server
        .wait_for_result(std::time::Duration::from_secs(10))
        .expect("mock server should have received a request");
    assert!(result.valid, "hwk-signed request should verify: {result:?}");
    assert_eq!(
        result.agent_id, None,
        "hwk is pseudonymous — no identity to recover"
    );
}

#[test]
fn aauth_jwks_uri_signs_and_verifies_end_to_end() {
    let t = nono_test!("aauth-jwksuri");
    let key_path = t.root().join("aauth-key.pem");
    let (_private_key, public_key) = write_aauth_key(&key_path);
    let kid = aauth_core::keys::calculate_jwk_thumbprint(&public_key_to_jwk(&public_key, None))
        .expect("thumbprint");
    let jwks = generate_jwks(&[public_key_to_jwk(&public_key, Some(&kid))]);
    let issuer = "https://demo-agent.nono.local".to_string();

    let server = MockAauthServer::start(Some((jwks, issuer.clone())));
    let upstream = format!("http://127.0.0.1:{}", server.port);

    let profile = t.write_profile(
        "aauth-jwksuri",
        &format!(
            r#"{{
                "meta": {{ "name": "aauth-jwksuri-test" }},
                "network": {{
                    "credentials": ["aauthapi"],
                    "aauth_identity": {{
                        "key_ref": "file://{}",
                        "scheme": {{ "type": "jwks_uri", "issuer": "{issuer}" }}
                    }},
                    "custom_credentials": {{
                        "aauthapi": {{ "upstream": "{upstream}", "aauth": true }}
                    }}
                }}
            }}"#,
            key_path.display()
        ),
    );

    t.run()
        .profile(&profile)
        .no_rollback()
        .exec(
            Argv::new("sh")
                .arg("-c")
                .arg("curl --silent --show-error \"$AAUTHAPI_BASE_URL/widgets\""),
        )
        .assert_success("nono run with an aauth jwks_uri route completes");

    let result = server
        .wait_for_result(std::time::Duration::from_secs(10))
        .expect("mock server should have received a request");
    assert!(
        result.valid,
        "jwks_uri-signed request should verify: {result:?}"
    );
    assert_eq!(
        result.agent_id.as_deref(),
        Some(issuer.as_str()),
        "jwks_uri recovers the issuer as the agent identity"
    );
}

/// Regression test for the file-path exfiltration fix: a `file://` aauth key
/// under a directory the sandboxed process is granted must be rejected
/// before the sandbox even starts.
#[test]
fn aauth_file_key_under_granted_path_is_rejected() {
    let t = nono_test!("aauth-key-overlap");
    let key_path = t.workspace().join("aauth-key.pem");
    write_aauth_key(&key_path);

    let profile = t.write_profile(
        "aauth-overlap",
        &format!(
            r#"{{
                "meta": {{ "name": "aauth-overlap-test" }},
                "network": {{
                    "credentials": ["aauthapi"],
                    "aauth_identity": {{ "key_ref": "file://{}" }},
                    "custom_credentials": {{
                        "aauthapi": {{ "upstream": "https://example.com", "aauth": true }}
                    }}
                }}
            }}"#,
            key_path.display()
        ),
    );

    t.run()
        .profile(&profile)
        .allow(t.workspace())
        .no_rollback()
        .exec("true")
        .assert_failure("aauth key under a granted read path must be rejected")
        .assert_stderr_contains("filesystem capability");
}

/// Regression test for the same fix from the other direction: a key outside
/// every granted path must load and sign successfully, and the sandboxed
/// child must not be able to read it directly.
#[test]
fn aauth_file_key_outside_granted_paths_cannot_be_read_by_child() {
    let t = nono_test!("aauth-key-isolated");
    let key_path = t.root().join("aauth-key.pem");
    write_aauth_key(&key_path);

    let server = MockAauthServer::start(None);
    let upstream = format!("http://127.0.0.1:{}", server.port);

    let profile = t.write_profile(
        "aauth-isolated",
        &format!(
            r#"{{
                "meta": {{ "name": "aauth-isolated-test" }},
                "network": {{
                    "credentials": ["aauthapi"],
                    "aauth_identity": {{ "key_ref": "file://{}" }},
                    "custom_credentials": {{
                        "aauthapi": {{ "upstream": "{upstream}", "aauth": true }}
                    }}
                }}
            }}"#,
            key_path.display()
        ),
    );

    let key_contents = std::fs::read_to_string(&key_path).expect("read key file for comparison");

    // The sandboxed child only ever gets `workspace` — not the key's
    // directory — yet the proxy (a separate, unsandboxed process) can still
    // load and sign with it.
    // `cat` is expected to be denied, so the shell's own exit code reflects
    // that failure — assert on content, not on overall process success.
    let outcome = t
        .run()
        .profile(&profile)
        .allow(t.workspace())
        .no_rollback()
        .exec(Argv::new("sh").arg("-c").arg(format!(
            "curl --silent --show-error \"$AAUTHAPI_BASE_URL/widgets\"; cat {} 2>&1",
            key_path.display()
        )));
    assert!(
        !outcome.stdout().contains(key_contents.trim()),
        "sandboxed child must never see the key's actual contents: {}",
        outcome.stdout()
    );

    let result = server
        .wait_for_result(std::time::Duration::from_secs(10))
        .expect("mock server should have received a request despite the child's denied read");
    assert!(result.valid, "signing must still succeed: {result:?}");
}

/// Regression test for the env-var exfiltration fix: nono's default
/// full-environment passthrough must not hand the sandboxed child the
/// contents of an `env://`-referenced aauth key.
#[test]
fn aauth_env_key_ref_not_leaked_to_sandboxed_child() {
    let t = nono_test!("aauth-env-key");
    let (private_key, _public_key) = generate_ed25519_keypair();
    let der = private_key.to_pkcs8_der().expect("encode key");
    let key_b64 = BASE64.encode(&der);

    let profile = t.write_profile(
        "aauth-env",
        r#"{
            "meta": { "name": "aauth-env-test" },
            "network": {
                "credentials": ["aauthapi"],
                "aauth_identity": { "key_ref": "env://NONO_TEST_AAUTH_ENV_KEY" },
                "custom_credentials": {
                    "aauthapi": { "upstream": "https://example.com", "aauth": true }
                }
            }
        }"#,
    );

    t.run()
        .profile(&profile)
        .env("NONO_TEST_AAUTH_ENV_KEY", &key_b64)
        .no_rollback()
        .exec(
            Argv::new("sh")
                .arg("-c")
                .arg("echo \"[$NONO_TEST_AAUTH_ENV_KEY]\""),
        )
        .assert_stdout_contains("[]");
}
