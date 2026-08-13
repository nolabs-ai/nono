//! End-to-end aauth tests using the real `nono` binary.
//!
//! The "resource" side is a real `aauth_core::resource::RequestVerifier`
//! running inline in a background thread — not a separate process — so
//! these tests have no dependency on a live network or a second binary,
//! while still exercising the exact wire format and crypto a real resource
//! server would use.
//!
//! Each signing test:
//!   1. Generates a real Ed25519 key in the supported legacy base64 DER
//!      format. Separate lifecycle tests exercise generated PEM and direct PEM/DER.
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
    body: Vec<u8>,
    has_bearer_headers: bool,
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
                body,
                has_bearer_headers: headers.contains_key("authorization")
                    || headers.contains_key("x-api-key"),
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
/// legacy file references accept it, and returns the keypair for building a
/// matching JWKS document.
fn write_aauth_key(path: &std::path::Path) -> (PrivateKey, aauth_core::keys::PublicKey) {
    let (private_key, public_key) = generate_ed25519_keypair();
    let der = private_key.to_pkcs8_der().expect("encode key");
    nono::store_secret_file(path, &BASE64.encode(&*der)).expect("write key file");
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

    for key_ref in [
        format!("file://{}", key_path.display()),
        key_path.to_string_lossy().into_owned(),
    ] {
        let profile = t.write_profile(
            "aauth-overlap",
            &serde_json::json!({
                "network": {
                    "credentials": ["aauthapi"],
                    "aauth_identity": {"key_ref": key_ref},
                    "custom_credentials": {
                        "aauthapi": {"upstream": "https://example.com", "aauth": true}
                    }
                }
            })
            .to_string(),
        );
        t.run()
            .profile(&profile)
            .allow(t.workspace())
            .no_rollback()
            .exec("true")
            .assert_failure("URI and absolute-path keys under a grant must both be rejected")
            .assert_stderr_contains("filesystem capability");
    }
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

#[test]
fn aauth_signs_fixed_length_and_chunked_request_bodies() {
    for chunked in [false, true] {
        let t = nono_test!("aauth-body");
        let key_path = t.root().join("aauth-key.pem");
        write_aauth_key(&key_path);
        let server = MockAauthServer::start(None);
        let profile = t.write_profile(
            "aauth-body",
            &serde_json::json!({
                "network": {
                    "credentials": ["aauthapi"],
                    "aauth_identity": {"key_ref": format!("file://{}", key_path.display())},
                    "aauth_sign_all_outbound": true,
                    "custom_credentials": {
                        "aauthapi": {"upstream": format!("http://127.0.0.1:{}", server.port)}
                    }
                }
            })
            .to_string(),
        );
        let transfer = if chunked {
            "-H 'Transfer-Encoding: chunked'"
        } else {
            ""
        };
        t.run()
            .profile(&profile)
            .no_rollback()
            .exec(Argv::new("sh").arg("-c").arg(format!(
                "curl --fail --silent --show-error {transfer} \
                 -H 'Content-Digest: forged' -H 'Signature: forged' \
                 --data-binary 'signed request body' \"$AAUTHAPI_BASE_URL/widgets?mode=test\""
            )))
            .assert_success("body upload through the aauth route verifies");
        let result = server
            .wait_for_result(std::time::Duration::from_secs(10))
            .expect("upstream received the signed upload");
        assert!(result.valid, "chunked={chunked}: {result:?}");
        assert_eq!(result.body, b"signed request body");
    }
}

#[test]
fn aauth_and_multiple_bearer_routes_work_concurrently() {
    for jwks_uri in [false, true] {
        for sign_all_outbound in [false, true] {
            let t = nono_test!("aauth-mixed-routes");
            let key_path = t.root().join("aauth-key.pem");
            let (_, public_key) = write_aauth_key(&key_path);
            let issuer = "https://mixed-agent.nono.local";
            let kid =
                aauth_core::keys::calculate_jwk_thumbprint(&public_key_to_jwk(&public_key, None))
                    .expect("thumbprint");
            let discovery = jwks_uri.then(|| {
                (
                    generate_jwks(&[public_key_to_jwk(&public_key, Some(&kid))]),
                    issuer.to_string(),
                )
            });
            let signed = MockAauthServer::start(discovery);
            let mut identity = serde_json::json!({
                "key_ref": format!("file://{}", key_path.display())
            });
            if jwks_uri {
                identity["scheme"] = serde_json::json!({"type": "jwks_uri", "issuer": issuer});
            }
            let mut network = serde_json::json!({
                "credentials": ["aauthapi", "regularapi", "secondapi"],
                "aauth_identity": identity,
                "custom_credentials": {
                    "aauthapi": {
                        "upstream": format!("http://127.0.0.1:{}/signed", signed.port),
                        "aauth": true
                    }
                }
            });
            if sign_all_outbound {
                network["aauth_sign_all_outbound"] = serde_json::json!(true);
            }

            let mut receivers = Vec::new();
            for name in ["regularapi", "secondapi"] {
                // Distinct listeners, paths, and secrets detect cross-route leakage.
                let token = format!("test-only-{name}-token");
                let token_path = t.root().join(format!("{name}.key"));
                let credential_key = if name == "regularapi" {
                    "env://REGULARAPI_API_KEY".to_string()
                } else {
                    std::fs::write(&token_path, &token).expect("write bearer credential");
                    format!("file://{}", token_path.display())
                };
                let listener = TcpListener::bind("127.0.0.1:0").expect("bind bearer server");
                let port = listener.local_addr().expect("bearer address").port();
                let (sender, receiver) = std::sync::mpsc::channel();
                thread::spawn(move || {
                    let (mut stream, _) = listener.accept().expect("accept bearer request");
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_secs(15)))
                        .expect("set bearer read timeout");
                    let (method, path, headers, body) = read_request(&mut stream);
                    let correct_auth =
                        headers.get("authorization") == Some(&format!("Bearer {token}"));
                    let unsigned = ["signature", "signature-input", "signature-key"]
                        .iter()
                        .all(|header| !headers.contains_key(*header));
                    let correct_route = method == "POST"
                        && path == format!("/{name}/widgets?route={name}")
                        && body == format!("payload for {name}").as_bytes();
                    let valid = correct_auth && unsigned && correct_route;
                    let status = if valid { "200 OK" } else { "401 Unauthorized" };
                    stream
                        .write_all(
                            format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n").as_bytes(),
                        )
                        .expect("respond to bearer request");
                    sender
                        .send((correct_auth, unsigned, correct_route))
                        .expect("report bearer request");
                });
                network["custom_credentials"][name] = serde_json::json!({
                    "upstream": format!("http://127.0.0.1:{port}/{name}"),
                    "credential_key": credential_key,
                    "env_var": format!("{}_API_KEY", name.to_ascii_uppercase()),
                    "inject_header": "Authorization",
                    "credential_format": "Bearer {}"
                });
                receivers.push((name, receiver));
            }
            let profile = t.write_profile(
                "mixed-routes",
                &serde_json::json!({"network": network}).to_string(),
            );
            t.run()
                .profile(&profile)
                .env("REGULARAPI_API_KEY", "test-only-regularapi-token")
                .no_rollback()
                .exec(Argv::new("sh").arg("-c").arg(
                    r#"
                    test -n "$REGULARAPI_API_KEY" || exit 1
                    test "$REGULARAPI_API_KEY" != 'test-only-regularapi-token' || exit 1
                    curl --fail --silent --show-error --max-time 15 \
                        --data-binary 'signed payload' "$AAUTHAPI_BASE_URL/widgets?route=signed" &
                    signed_pid=$!
                    curl --fail --silent --show-error --max-time 15 \
                        -H "Authorization: Bearer $REGULARAPI_API_KEY" \
                        --data-binary 'payload for regularapi' "$REGULARAPI_BASE_URL/widgets?route=regularapi" &
                    regular_pid=$!
                    curl --fail --silent --show-error --max-time 15 \
                        -H "Authorization: Bearer $SECONDAPI_API_KEY" \
                        --data-binary 'payload for secondapi' "$SECONDAPI_BASE_URL/widgets?route=secondapi" &
                    second_pid=$!
                    wait "$signed_pid" || exit 1
                    wait "$regular_pid" || exit 1
                    wait "$second_pid" || exit 1
                    "#,
                ))
                .assert_success("three custom credential routes work in one sandbox session");

            let result = signed
                .wait_for_result(std::time::Duration::from_secs(10))
                .expect("signed upstream received its request");
            assert!(result.valid, "aauth signature verifies");
            assert_eq!(result.body, b"signed payload");
            assert_eq!(result.agent_id.as_deref(), jwks_uri.then_some(issuer));
            assert!(
                !result.has_bearer_headers,
                "bearer auth must not reach signed route"
            );
            for (name, receiver) in receivers {
                let (correct_auth, unsigned, correct_route) = receiver
                    .recv_timeout(std::time::Duration::from_secs(10))
                    .expect("bearer upstream received its request");
                assert!(
                    correct_auth,
                    "{name} must receive only its own bearer credential"
                );
                assert!(unsigned, "{name} must not receive Aauth signatures");
                assert!(
                    correct_route,
                    "{name} must receive its own path, query, and body"
                );
            }
        }
    }
}

#[test]
fn existing_pem_and_der_keys_sign_directly_without_import() {
    for pem in [false, true] {
        let t = nono_test!("aauth-existing-key");
        let path = t
            .root()
            .join(if pem { "existing.pem" } else { "existing.der" });
        let (private, _) = generate_ed25519_keypair();
        let der = private.to_pkcs8_der().expect("DER");
        if pem {
            let b64 = BASE64.encode(&*der);
            let lines = b64
                .as_bytes()
                .chunks(64)
                .map(|line| std::str::from_utf8(line).expect("base64"))
                .collect::<Vec<_>>()
                .join("\n");
            nono::store_secret_file(
                &path,
                &format!("-----BEGIN PRIVATE KEY-----\n{lines}\n-----END PRIVATE KEY-----\n"),
            )
            .expect("write existing PEM");
        } else {
            std::fs::write(&path, &*der).expect("write DER");
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        }
        let original = std::fs::read(&path).expect("read original");
        let server = MockAauthServer::start(None);
        let profile = t.write_profile("existing-key", &serde_json::json!({
            "network": {
                "credentials": ["aauthapi"],
                "aauth_identity": {"key_ref": path},
                "custom_credentials": {
                    "aauthapi": {"upstream": format!("http://127.0.0.1:{}", server.port), "aauth": true}
                }
            }
        }).to_string());
        t.run()
            .profile(&profile)
            .no_rollback()
            .exec(
                Argv::new("sh")
                    .arg("-c")
                    .arg("curl -fsS --max-time 15 \"$AAUTHAPI_BASE_URL/widgets\""),
            )
            .assert_success("existing key signs without import or conversion");
        assert!(
            server
                .wait_for_result(std::time::Duration::from_secs(10))
                .expect("request")
                .valid
        );
        assert!(
            std::fs::read(&path).expect("read source") == original,
            "source key must remain unchanged"
        );
    }
}

#[test]
fn keygen_and_show_use_private_pem_without_mutating_existing_keys() {
    let t = nono_test!("aauth-key-lifecycle");
    let source = t.root().join("source.pem");
    let invoke = |args: &[&std::ffi::OsStr]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_nono"))
            .arg("aauth")
            .args(args)
            .env("HOME", t.home())
            .env("XDG_CONFIG_HOME", t.home().join(".config"))
            .env("XDG_STATE_HOME", t.state())
            .env("NONO_NO_UPDATE_CHECK", "1")
            .current_dir(t.workspace())
            .output()
            .expect("run key lifecycle command")
    };
    use std::ffi::OsStr;
    let generated = invoke(&[
        OsStr::new("keygen"),
        OsStr::new("--keyref"),
        source.as_os_str(),
    ]);
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let original = std::fs::read(&source).expect("read key");
    assert!(original.starts_with(b"-----BEGIN PRIVATE KEY-----"));
    use std::os::unix::fs::{PermissionsExt, symlink};
    assert_eq!(
        source.metadata().expect("metadata").permissions().mode() & 0o777,
        0o600
    );
    let show = |path: &std::path::Path| {
        invoke(&[
            OsStr::new("show"),
            OsStr::new("--jwks"),
            OsStr::new("--keyref"),
            path.as_os_str(),
        ])
    };
    let source_public = show(&source);
    assert!(source_public.status.success());
    let jwks: serde_json::Value =
        serde_json::from_slice(&source_public.stdout).expect("public JWKS");
    let key = &jwks["keys"][0];
    assert_eq!(key["kty"], "OKP");
    assert_eq!(key["crv"], "Ed25519");
    assert!(
        key.get("d").is_none(),
        "show must not export private key material"
    );
    assert!(std::fs::read(&source).expect("source remains") == original);
    assert!(
        !invoke(&[
            OsStr::new("keygen"),
            OsStr::new("--keyref"),
            source.as_os_str()
        ])
        .status
        .success()
    );
    let link = t.root().join("redirect.pem");
    let target = t.root().join("must-not-be-created.pem");
    symlink(&target, &link).expect("dangling symlink");
    for force in [false, true] {
        let mut args = vec![
            OsStr::new("keygen"),
            OsStr::new("--keyref"),
            link.as_os_str(),
        ];
        if force {
            args.push(OsStr::new("--force"));
        }
        assert!(!invoke(&args).status.success());
        assert!(!target.exists());
    }
}
