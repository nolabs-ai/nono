//! End-to-end tests of the OAuth client against an in-process mock
//! authorization server that verifies DPoP proofs like the platform must.

#![allow(clippy::unwrap_used)]

use super::client::{self, Grant, OAuthClient, TokenOutcome};
use super::dpop::DpopKey;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, UnparsedPublicKey,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

struct Request {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: String,
}

struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

fn json(status: u16, body: serde_json::Value) -> Response {
    Response {
        status,
        headers: vec![],
        body: body.to_string(),
    }
}

/// Serve requests on a loopback port until the handler has been called
/// `count` times. Returns the origin.
fn serve(
    count: usize,
    handler: impl Fn(&Request, &str) -> Response + Send + 'static,
) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let thread_origin = origin.clone();
    let handle = std::thread::spawn(move || {
        for _ in 0..count {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&mut stream);
            let response = handler(&request, &thread_origin);
            let mut head = format!(
                "HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                response.status,
                response.body.len()
            );
            if !response
                .headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            {
                head.push_str("Content-Type: application/json\r\n");
            }
            for (name, value) in &response.headers {
                head.push_str(&format!("{name}: {value}\r\n"));
            }
            head.push_str("\r\n");
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(response.body.as_bytes());
        }
    });
    (origin, handle)
}

fn read_request(stream: &mut std::net::TcpStream) -> Request {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut chunk).unwrap();
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let head = String::from_utf8(buffer[..header_end].to_vec()).unwrap();
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().unwrap().split(' ');
    let method = request_line.next().unwrap().to_string();
    let path = request_line.next().unwrap().to_string();
    let headers: HashMap<String, String> = lines
        .filter_map(|line| line.split_once(": "))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.to_string()))
        .collect();
    let length: usize = headers
        .get("content-length")
        .map(|value| value.parse().unwrap())
        .unwrap_or(0);
    while buffer.len() < header_end + length {
        let read = stream.read(&mut chunk).unwrap();
        buffer.extend_from_slice(&chunk[..read]);
    }
    let body = String::from_utf8(buffer[header_end..header_end + length].to_vec()).unwrap();
    Request {
        method,
        path,
        headers,
        body,
    }
}

fn metadata(origin: &str) -> serde_json::Value {
    serde_json::json!({
        "issuer": origin,
        "authorization_endpoint": format!("{origin}/oauth/authorize"),
        "token_endpoint": format!("{origin}/oauth/token"),
        "device_authorization_endpoint": format!("{origin}/oauth/device"),
        "revocation_endpoint": format!("{origin}/oauth/revoke"),
        "code_challenge_methods_supported": ["S256"],
        "dpop_signing_alg_values_supported": ["ES256"],
        "authorization_response_iss_parameter_supported": true,
    })
}

/// Verify a DPoP proof the way the authorization server must: signature by
/// the embedded JWK, method, URI and nonce. Returns the key's thumbprint.
fn verify_proof(proof: &str, method: &str, uri: &str, nonce: Option<&str>) -> String {
    let parts: Vec<_> = proof.split('.').collect();
    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    let claims: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    assert_eq!(header["typ"], "dpop+jwt");
    assert_eq!(claims["htm"], method);
    assert_eq!(claims["htu"], uri);
    assert_eq!(claims["nonce"].as_str(), nonce);
    let x = header["jwk"]["x"].as_str().unwrap();
    let y = header["jwk"]["y"].as_str().unwrap();
    let mut point = vec![0x04];
    point.extend(URL_SAFE_NO_PAD.decode(x).unwrap());
    point.extend(URL_SAFE_NO_PAD.decode(y).unwrap());
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &point)
        .verify(
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &URL_SAFE_NO_PAD.decode(parts[2]).unwrap(),
        )
        .expect("DPoP proof signature must verify");
    URL_SAFE_NO_PAD.encode(Sha256::digest(
        format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#).as_bytes(),
    ))
}

fn session_json() -> serde_json::Value {
    serde_json::json!({
        "tenant_id": "t-1",
        "console_url": "https://console.example.com",
        "organizations": [
            {"tenant_id": "t-1", "slug": "alice", "display_name": "Alice", "kind": "personal"},
            {"tenant_id": "t-2", "slug": "acme", "display_name": "Acme", "kind": "organization"}
        ]
    })
}

fn form(body: &str) -> HashMap<String, String> {
    url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect()
}

fn device_key() -> DpopKey {
    let pkcs8 =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
            .unwrap();
    DpopKey::new(
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref()).unwrap(),
    )
    .unwrap()
}

#[test]
fn refresh_grant_retries_with_a_dpop_nonce_and_binds_to_the_device_key() {
    let key = device_key();
    let expected_jkt = key.thumbprint().to_string();
    let seen_nonce_retry = Arc::new(Mutex::new(false));
    let seen = Arc::clone(&seen_nonce_retry);
    let (origin, server) = serve(3, move |request, origin| {
        if request.path == "/.well-known/oauth-authorization-server" {
            return json(200, metadata(origin));
        }
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/oauth/token");
        let proof = request.headers.get("dpop").expect("DPoP header");
        let token_uri = format!("{origin}/oauth/token");
        if !*seen.lock().unwrap() {
            verify_proof(proof, "POST", &token_uri, None);
            *seen.lock().unwrap() = true;
            return Response {
                status: 400,
                headers: vec![("DPoP-Nonce".to_string(), "server-nonce-1".to_string())],
                body: r#"{"error":"use_dpop_nonce"}"#.to_string(),
            };
        }
        let jkt = verify_proof(proof, "POST", &token_uri, Some("server-nonce-1"));
        assert_eq!(jkt, expected_jkt);
        let params = form(&request.body);
        assert_eq!(params["grant_type"], "refresh_token");
        assert_eq!(params["refresh_token"], "old-refresh");
        assert_eq!(params["client_id"], "nono-cli");
        assert_eq!(params["nono_tenant"], "t-2");
        let mut session = session_json();
        session["tenant_id"] = "t-2".into();
        json(
            200,
            serde_json::json!({
                "access_token": "new-access", "token_type": "DPoP", "expires_in": 300,
                "refresh_token": "rotated-refresh", "scope": "openid nono:connect nono:runs",
                "nono_session": session
            }),
        )
    });

    let authorization_server = client::discover(&origin).unwrap();
    let mut oauth = OAuthClient::new(&authorization_server, &key);
    let outcome = oauth
        .token(&Grant::RefreshToken {
            refresh_token: "old-refresh",
            tenant: Some("t-2"),
        })
        .unwrap();
    server.join().unwrap();
    match outcome {
        TokenOutcome::Issued(tokens) => {
            assert_eq!(tokens.access_token.as_str(), "new-access");
            assert_eq!(
                tokens.refresh_token.as_ref().map(|token| token.as_str()),
                Some("rotated-refresh")
            );
        }
        TokenOutcome::Error(error) => panic!("unexpected {error}"),
    }
    assert!(*seen_nonce_retry.lock().unwrap());
}

#[test]
fn device_grant_carries_the_proof_key_and_returns_the_session() {
    let key = device_key();
    let expected_jkt = key.thumbprint().to_string();
    let (origin, server) = serve(3, move |request, origin| match request.path.as_str() {
        "/.well-known/oauth-authorization-server" => json(200, metadata(origin)),
        "/oauth/device" => {
            let jkt = verify_proof(
                request.headers.get("dpop").unwrap(),
                "POST",
                &format!("{origin}/oauth/device"),
                None,
            );
            assert_eq!(jkt, expected_jkt);
            let params = form(&request.body);
            assert_eq!(params["scope"], "openid nono:connect nono:runs");
            assert_eq!(params["device_name"], "laptop");
            json(
                200,
                serde_json::json!({
                    "device_code": "dev-code", "user_code": "WDJB-MJHT",
                    "verification_uri": format!("{origin}/device"),
                    "verification_uri_complete": "https://phish.example/?code=WDJB-MJHT",
                    "expires_in": 600, "interval": 5
                }),
            )
        }
        "/oauth/token" => {
            let params = form(&request.body);
            assert_eq!(
                params["grant_type"],
                "urn:ietf:params:oauth:grant-type:device_code"
            );
            assert_eq!(params["device_code"], "dev-code");
            let jkt = verify_proof(
                request.headers.get("dpop").unwrap(),
                "POST",
                &format!("{origin}/oauth/token"),
                None,
            );
            assert_eq!(jkt, expected_jkt);
            json(
                200,
                serde_json::json!({
                    "access_token": "at", "token_type": "DPoP", "expires_in": 300,
                    "refresh_token": "rt", "id_token": "h.p.s",
                    "nono_session": session_json()
                }),
            )
        }
        other => panic!("unexpected path {other}"),
    });

    let authorization_server = client::discover(&origin).unwrap();
    let mut oauth = OAuthClient::new(&authorization_server, &key);
    let device = oauth
        .device_authorization("openid nono:connect nono:runs", Some("laptop"))
        .unwrap();
    assert_eq!(device.user_code, "WDJB-MJHT");
    // The phishing-prone verification_uri_complete is never surfaced.
    assert_eq!(device.verification_uri.as_str(), format!("{origin}/device"));
    let outcome = oauth
        .token(&Grant::DeviceCode {
            device_code: device.device_code.as_str(),
        })
        .unwrap();
    server.join().unwrap();
    let TokenOutcome::Issued(tokens) = outcome else {
        panic!("expected tokens");
    };
    assert_eq!(tokens.session.tenant_id, "t-1");
    assert_eq!(tokens.session.organizations.len(), 2);
    assert_eq!(
        tokens.session.console_url.as_ref().map(url::Url::as_str),
        Some("https://console.example.com/")
    );
}

#[test]
fn oauth_errors_and_bearer_downgrades_are_reported() {
    let key = device_key();
    let (origin, server) = serve(3, move |request, origin| match request.path.as_str() {
        "/.well-known/oauth-authorization-server" => json(200, metadata(origin)),
        "/oauth/token" if form(&request.body)["refresh_token"] == "revoked" => json(
            400,
            serde_json::json!({"error": "invalid_grant", "error_description": "revoked"}),
        ),
        "/oauth/token" => json(
            200,
            serde_json::json!({"access_token": "at", "token_type": "Bearer", "expires_in": 300}),
        ),
        other => panic!("unexpected path {other}"),
    });
    let authorization_server = client::discover(&origin).unwrap();
    let mut oauth = OAuthClient::new(&authorization_server, &key);
    match oauth
        .token(&Grant::RefreshToken {
            refresh_token: "revoked",
            tenant: None,
        })
        .unwrap()
    {
        TokenOutcome::Error(error) => assert_eq!(error.code, "invalid_grant"),
        TokenOutcome::Issued(_) => panic!("expected an OAuth error"),
    }
    assert!(
        oauth
            .token(&Grant::RefreshToken {
                refresh_token: "fine",
                tenant: None,
            })
            .is_err(),
        "a Bearer token must be refused"
    );
    server.join().unwrap();
}

#[test]
fn discovery_explains_a_site_that_is_not_a_platform() {
    let (origin, handle) = serve(1, |_, _| Response {
        status: 200,
        headers: vec![("Content-Type".into(), "text/html; charset=utf-8".into())],
        body: "<!doctype html><html></html>".into(),
    });
    let error = client::discover(&origin).unwrap_err().to_string();
    handle.join().unwrap();
    assert!(error.contains("got text/html"), "{error}");
    assert!(error.contains("--url"), "{error}");
}

#[test]
fn discovery_refuses_redirects_and_foreign_issuers() {
    let (origin, server) = serve(1, |request, _origin| match request.path.as_str() {
        "/.well-known/oauth-authorization-server" => Response {
            status: 302,
            headers: vec![(
                "Location".to_string(),
                "https://evil.example/.well-known/oauth-authorization-server".to_string(),
            )],
            body: String::new(),
        },
        _ => json(200, metadata("https://evil.example")),
    });
    assert!(client::discover(&origin).is_err());
    server.join().unwrap();
}

#[test]
fn a_refresh_for_another_organization_is_refused_but_the_rotation_is_kept() {
    let _env = crate::test_env::ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let state = tempfile::tempdir().unwrap();
    let _guard = crate::test_env::EnvVarGuard::set_all(&[(
        "XDG_STATE_HOME",
        state.path().to_str().unwrap(),
    )]);
    let key = device_key();
    // A platform that ignores `nono_tenant` and answers for the active one.
    let (origin, server) = serve(2, |request, origin| {
        if request.path == "/.well-known/oauth-authorization-server" {
            return json(200, metadata(origin));
        }
        assert_eq!(form(&request.body)["nono_tenant"], "t-2");
        json(
            200,
            serde_json::json!({
                "access_token": "access-for-t-1", "token_type": "DPoP", "expires_in": 300,
                "refresh_token": "rotated-refresh", "scope": "openid nono:connect nono:runs",
                "nono_session": session_json()
            }),
        )
    });
    let record = super::session::SessionRecord {
        protocol_version: "1".to_string(),
        platform_url: origin.clone(),
        issuer: origin.clone(),
        key_thumbprint: key.thumbprint().to_string(),
        user_subject: "u".to_string(),
        user_display: "Alice".to_string(),
        tenant_id: "t-1".to_string(),
        organizations: vec![],
        console_url: None,
        signed_in_at: "2026-11-02T00:00:00Z".to_string(),
    };
    let lock = super::session::lock().unwrap();
    let error = super::refresh(&lock, &record, &key, "old-refresh", Some("t-2"))
        .unwrap_err()
        .to_string();
    server.join().unwrap();
    assert!(error.contains("different organization"), "{error}");
    // The platform already rotated the token; keeping the new one keeps the
    // session alive instead of tripping reuse detection next time.
    assert_eq!(
        super::session::load_refresh_token()
            .unwrap()
            .unwrap()
            .as_str(),
        "rotated-refresh"
    );
}
