//! aauth request signing: RFC 9421 HTTP Message Signatures with a persistent
//! agent keypair, via the `aauth-core` crate.
//!
//! Unlike SPIFFE/OAuth2 (which produce a bearer credential to inject) this
//! signs the outbound request itself — method, URL, headers, and body — so
//! there is no secret to fetch or rotate at request time. Mirrors
//! `aws/sign.rs`'s shape: load once, sign per request, return headers to add.

use aauth_core::keys::{PrivateKey, calculate_jwk_thumbprint, private_key_to_jwk};
use aauth_core::signing::{
    SigScheme, build_signature_base, build_signature_header, build_signature_key_header,
    build_signature_params, calculate_content_digest, determine_covered_components,
};
#[cfg(test)]
use base64::Engine as _;
#[cfg(test)]
use base64::engine::general_purpose::STANDARD as BASE64;
use std::collections::HashMap;
mod key;
pub use key::{key_file_path, load_private_key};

use crate::config::{AauthIdentityConfig, AauthSigSchemeConfig};
use crate::error::{ProxyError, Result};

/// Well-known metadata document agent servers publish; also the `dwk`
/// parameter sent in a `jwks_uri`-scheme `Signature-Key` header.
const AGENT_METADATA_DOC: &str = "aauth-agent.json";

/// A loaded aauth identity, ready to sign outbound requests.
///
/// Built once at proxy startup from the profile's `aauth_identity` config
/// (fail-closed if the key can't be loaded), then shared across every route
/// that opts into aauth signing.
pub struct AauthSigner {
    /// Optional local label for hwk; other display labels are derived on demand.
    agent_id: Option<String>,
    private_key: PrivateKey,
    scheme: AauthSigSchemeConfig,
    /// JWK thumbprint of the public key — used as the `kid` under
    /// `jwks_uri`. Computed once at load so it's guaranteed to match
    /// whatever `nono aauth show --jwks` prints for the same key (both
    /// derive it the same way, from the same key).
    kid: String,
}

impl AauthSigner {
    /// Load an existing PEM/DER file by absolute path or file:// reference,
    /// or a keyring:// or env:// secret. Legacy base64 DER remains supported.
    pub fn load(identity: &AauthIdentityConfig) -> Result<Self> {
        let private_key = load_private_key(&identity.key_ref)?;
        let kid = jwk_thumbprint(&private_key).map_err(|e| {
            ProxyError::Credential(format!("aauth key '{}': {e}", identity.key_ref))
        })?;
        if let AauthSigSchemeConfig::JwksUri { issuer } = &identity.scheme
            && let Some(explicit) = &identity.agent_id
        {
            return Err(ProxyError::Credential(format!(
                "aauth identity: agent_id ('{explicit}') must not be set under jwks_uri \
                 — a verifying resource always recovers the issuer itself as the \
                 identity, so agent_id is always '{issuer}'; remove agent_id from the profile"
            )));
        }
        Ok(Self {
            agent_id: identity.agent_id.clone(),
            private_key,
            scheme: identity.scheme.clone(),
            kid,
        })
    }

    pub fn agent_id(&self) -> &str {
        match &self.scheme {
            AauthSigSchemeConfig::Hwk => self.agent_id.as_deref().unwrap_or(&self.kid),
            AauthSigSchemeConfig::JwksUri { issuer } => issuer,
        }
    }

    /// Build the audit context for a request signed by this identity —
    /// which scheme, which agent, which key, and (under `jwks_uri`) which
    /// issuer, so the audit log records the actual identity used, not just
    /// "aauth signature" with no further detail.
    pub fn audit_context(&self) -> nono::undo::AauthAuditContext {
        let (scheme, issuer, agent_id) = match &self.scheme {
            AauthSigSchemeConfig::Hwk => ("hwk".to_string(), None, self.agent_id.clone()),
            AauthSigSchemeConfig::JwksUri { issuer } => (
                "jwks_uri".to_string(),
                Some(issuer.clone()),
                Some(issuer.clone()),
            ),
        };
        nono::undo::AauthAuditContext {
            agent_id,
            scheme,
            issuer,
            key_thumbprint: self.kid.clone(),
        }
    }

    /// Convenience for signing tests without forwarded semantic headers.
    #[cfg(test)]
    fn sign(&self, method: &str, url: &str, body: &[u8]) -> Result<Vec<(String, String)>> {
        self.sign_with_headers(method, url, body, &[])
    }

    /// Sign the exact semantic headers that will be forwarded, plus a digest
    /// even for an empty body. Fresh signed nonce/expiry parameters let the
    /// resource enforce replay protection; it must retain consumed nonces.
    pub fn sign_with_headers(
        &self,
        method: &str,
        url: &str,
        body: &[u8],
        forwarded_headers: &[(String, String)],
    ) -> Result<Vec<(String, String)>> {
        let signing_error =
            |error| ProxyError::Credential(format!("aauth signing failed: {error}"));
        let parsed = url::Url::parse(url).map_err(|e| signing_error(e.to_string()))?;
        let host = match parsed.host() {
            Some(url::Host::Ipv6(host)) => format!("[{host}]"),
            Some(host) => host.to_string(),
            None => return Err(signing_error("target has no host".to_string())),
        };
        let authority = match parsed.port() {
            Some(port) => format!("{host}:{port}"),
            None => host,
        };
        let mut headers = HashMap::new();
        let mut additional = vec!["content-digest"];
        for component in [
            "content-type",
            "content-encoding",
            "idempotency-key",
            "aauth-mission",
        ] {
            let values: Vec<_> = forwarded_headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case(component))
                .collect();
            if values.len() > 1 {
                return Err(signing_error(format!("duplicate {component} headers")));
            }
            if let Some((_, value)) = values.first() {
                if value.contains(['\r', '\n']) {
                    return Err(signing_error(format!("invalid {component} header")));
                }
                headers.insert(component.to_string(), value.clone());
                additional.push(component);
            }
        }
        let content_digest = calculate_content_digest(body);
        headers.insert("Content-Digest".to_string(), content_digest.clone());
        let scheme = match &self.scheme {
            AauthSigSchemeConfig::Hwk => SigScheme::Hwk,
            AauthSigSchemeConfig::JwksUri { issuer } => SigScheme::JwksUri {
                id: issuer,
                dwk: AGENT_METADATA_DOC,
                kid: &self.kid,
            },
        };
        let signature_key = build_signature_key_header(&scheme, Some(&self.private_key), "sig")
            .map_err(|e| signing_error(e.to_string()))?;
        let components = determine_covered_components(parsed.query(), Some(&additional), false);
        let created = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|duration| i64::try_from(duration.as_secs()).ok())
            .ok_or_else(|| signing_error("invalid system clock".to_string()))?;
        let expires = created
            .checked_add(60)
            .ok_or_else(|| signing_error("expiry overflow".to_string()))?;
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce).map_err(|e| signing_error(e.to_string()))?;
        use base64::Engine as _;
        let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce);
        let params = format!(
            "{};expires={expires};nonce=\"{nonce}\"",
            build_signature_params(&components, created)
        );
        let signature_base = build_signature_base(
            method,
            &authority,
            parsed.path(),
            parsed.query(),
            &headers,
            Some(body),
            &signature_key,
            &components,
            &params,
        )
        .map_err(|e| signing_error(e.to_string()))?;
        let signature =
            build_signature_header(&self.private_key.sign(signature_base.as_bytes()), "sig");
        // Semantic headers are already in the forwarded set. Return only the
        // fields generated here so callers never send duplicate Content-Type.
        Ok(vec![
            ("Content-Digest".to_string(), content_digest),
            ("Signature-Key".to_string(), signature_key),
            ("Signature-Input".to_string(), format!("sig={params}")),
            ("Signature".to_string(), signature),
        ])
    }
}

/// The JWK thumbprint of a private key's public half — the same value
/// `nono aauth show --jwks` embeds as `kid` in the hosted JWKS document, so
/// a `jwks_uri`-scheme signature always references a `kid` the upstream can
/// actually find there.
pub fn jwk_thumbprint(private_key: &PrivateKey) -> Result<String> {
    let jwk = private_key_to_jwk(private_key, None);
    calculate_jwk_thumbprint(&jwk).map_err(|e| ProxyError::Credential(format!("thumbprint: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::{ENV_LOCK, EnvVarGuard};
    use aauth_core::keys::generate_ed25519_keypair;
    use aauth_core::resource::RequestVerifier;
    use std::collections::HashMap;

    #[test]
    fn signs_semantic_headers_and_nonce_and_rejects_tampering() {
        let root = tempfile::tempdir().expect("tempdir");
        let (private, _) = generate_ed25519_keypair();
        let path = root.path().join("key");
        nono::store_secret_file(
            &path,
            &BASE64.encode(&*private.to_pkcs8_der().expect("DER")),
        )
        .expect("store key");
        let signer = AauthSigner::load(&AauthIdentityConfig {
            agent_id: None,
            key_ref: path.to_string_lossy().into_owned(),
            scheme: AauthSigSchemeConfig::Hwk,
        })
        .expect("load");
        let forwarded = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Content-Encoding".to_string(), "identity".to_string()),
            ("Idempotency-Key".to_string(), "payment-123".to_string()),
        ];
        let url = "https://api.example.com/payments?account=1";
        let body = br#"{"amount":10}"#;
        let signed = signer
            .sign_with_headers("POST", url, body, &forwarded)
            .expect("sign");
        let headers: HashMap<_, _> = signed
            .into_iter()
            .chain(forwarded)
            .map(|(name, value)| (name.to_ascii_lowercase(), value))
            .collect();
        let input =
            aauth_core::signing::parse_signature_input(&headers["signature-input"]).expect("parse");
        assert_eq!(
            input.params["expires"].parse::<i64>().expect("expiry")
                - input.created().expect("created"),
            60
        );
        assert_eq!(input.params["nonce"].len(), 43);
        let second: HashMap<_, _> = signer
            .sign("POST", url, body)
            .expect("sign again")
            .into_iter()
            .collect();
        let second =
            aauth_core::signing::parse_signature_input(&second["Signature-Input"]).expect("parse");
        assert_ne!(input.params["nonce"], second.params["nonce"]);
        let verifier = RequestVerifier::new(vec!["api.example.com".to_string()]);
        assert!(
            verifier
                .verify_request("POST", url, &headers, Some(body), false, false)
                .valid
        );
        for field in ["content-type", "content-encoding", "idempotency-key"] {
            let mut tampered = headers.clone();
            tampered.insert(field.to_string(), "changed".to_string());
            assert!(
                !verifier
                    .verify_request("POST", url, &tampered, Some(body), false, false)
                    .valid,
                "changing signed {field} must invalidate the signature"
            );
        }
        let mut tampered = headers.clone();
        tampered.insert(
            "signature-input".to_string(),
            headers["signature-input"].replace(&input.params["nonce"], "replacement-nonce"),
        );
        assert!(
            !verifier
                .verify_request("POST", url, &tampered, Some(body), false, false)
                .valid
        );

        let empty: HashMap<_, _> = signer
            .sign("POST", url, b"")
            .expect("sign empty body")
            .into_iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value))
            .collect();
        assert!(
            verifier
                .verify_request("POST", url, &empty, None, false, false)
                .valid
        );
        assert!(
            !verifier
                .verify_request("POST", url, &empty, Some(b"injected"), false, false)
                .valid
        );
        let duplicate = vec![
            ("Content-Type".to_string(), "a".to_string()),
            ("content-type".to_string(), "b".to_string()),
        ];
        assert!(
            signer
                .sign_with_headers("POST", url, body, &duplicate)
                .is_err()
        );
    }

    /// Round-trips a key through the supported legacy base64-PKCS8 format,
    /// loads it as an `AauthSigner` via `env://`, signs a request, and verifies
    /// it with `aauth-core`'s
    /// own resource-side verifier — proving the proxy's signer and the
    /// library's verifier agree on the wire format end to end.
    #[test]
    fn signed_request_verifies_with_aauth_core() {
        let (private_key, _public_key) = generate_ed25519_keypair();
        let der = private_key.to_pkcs8_der().expect("encode key");
        let key_b64 = BASE64.encode(&der);

        const VAR: &str = "NONO_TEST_AAUTH_SIGNING_KEY";
        let _lock = ENV_LOCK.lock().expect("env mutex poisoned");
        let _guard = EnvVarGuard::set_all(&[(VAR, key_b64.as_str())]);
        let identity = AauthIdentityConfig {
            agent_id: Some("aauth:test-agent@nono.local".to_string()),
            key_ref: format!("env://{VAR}"),
            scheme: crate::config::AauthSigSchemeConfig::Hwk,
        };
        let signer = AauthSigner::load(&identity).expect("signer should load from env:// key");
        assert_eq!(signer.agent_id(), "aauth:test-agent@nono.local");

        let url = "https://api.example.com/v1/widgets";
        let body = br#"{"hello":"world"}"#;
        let signature_headers = signer.sign("POST", url, body).expect("sign request");

        let mut headers: HashMap<String, String> = signature_headers.into_iter().collect();
        assert!(headers.contains_key("Signature"));
        assert!(headers.contains_key("Signature-Input"));
        assert!(headers.contains_key("Signature-Key"));

        // aauth-core's verifier expects lowercase header names.
        let headers: HashMap<String, String> = headers
            .drain()
            .map(|(k, v)| (k.to_ascii_lowercase(), v))
            .collect();

        let verifier = RequestVerifier::new(vec!["api.example.com".to_string()]);
        let result = verifier.verify_request("POST", url, &headers, Some(body), false, false);
        assert!(result.valid, "verification failed: {:?}", result.error);
    }

    #[test]
    fn audit_context_reports_hwk_scheme_with_no_issuer() {
        let (private_key, _public_key) = generate_ed25519_keypair();
        let der = private_key.to_pkcs8_der().expect("encode key");
        let key_b64 = BASE64.encode(&der);

        const VAR: &str = "NONO_TEST_AAUTH_AUDIT_HWK_KEY";
        let _lock = ENV_LOCK.lock().expect("env mutex poisoned");
        let _guard = EnvVarGuard::set_all(&[(VAR, key_b64.as_str())]);
        let identity = AauthIdentityConfig {
            agent_id: Some("aauth:audit-test@nono.local".to_string()),
            key_ref: format!("env://{VAR}"),
            scheme: crate::config::AauthSigSchemeConfig::Hwk,
        };
        let signer = AauthSigner::load(&identity).expect("signer should load from env:// key");

        let ctx = signer.audit_context();
        assert_eq!(ctx.agent_id.as_deref(), Some("aauth:audit-test@nono.local"));
        assert_eq!(ctx.scheme, "hwk");
        assert_eq!(ctx.issuer, None);
        assert_eq!(
            ctx.key_thumbprint,
            jwk_thumbprint(&private_key).expect("thumbprint")
        );
    }

    #[test]
    fn audit_context_reports_jwks_uri_scheme_with_issuer_and_matching_kid() {
        let (private_key, _public_key) = generate_ed25519_keypair();
        let der = private_key.to_pkcs8_der().expect("encode key");
        let key_b64 = BASE64.encode(&der);

        const VAR: &str = "NONO_TEST_AAUTH_AUDIT_JWKS_URI_KEY";
        let _lock = ENV_LOCK.lock().expect("env mutex poisoned");
        let _guard = EnvVarGuard::set_all(&[(VAR, key_b64.as_str())]);
        let identity = AauthIdentityConfig {
            agent_id: None,
            key_ref: format!("env://{VAR}"),
            scheme: crate::config::AauthSigSchemeConfig::JwksUri {
                issuer: "https://demo-agent.nono.local".to_string(),
            },
        };
        let signer = AauthSigner::load(&identity).expect("signer should load from env:// key");

        let ctx = signer.audit_context();
        assert_eq!(ctx.scheme, "jwks_uri");
        assert_eq!(ctx.issuer.as_deref(), Some("https://demo-agent.nono.local"));
        // agent_id is derived from the issuer under jwks_uri — there's no
        // separate identity to set, so it must match exactly.
        assert_eq!(
            ctx.agent_id.as_deref(),
            Some("https://demo-agent.nono.local")
        );
        // The audited kid must be exactly the kid a real signed request uses,
        // not some independently-derived value that could drift from it.
        let signature_headers = signer
            .sign("POST", "https://resource.example/x", b"")
            .expect("sign request");
        let signature_key = signature_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Signature-Key"))
            .map(|(_, v)| v.clone())
            .expect("Signature-Key present");
        assert!(signature_key.contains(&format!("kid=\"{}\"", ctx.key_thumbprint)));
    }

    /// Same round trip as `signed_request_verifies_with_aauth_core`, but
    /// under `jwks_uri`: proves the signer emits `id`/`dwk`/`kid` correctly,
    /// that `kid` matches the thumbprint `nono aauth show --jwks` would
    /// print for the same key (so a hosted JWKS and a signed request always
    /// agree), and that discovery actually resolves and verifies — not just
    /// that the headers look right.
    #[test]
    fn jwks_uri_scheme_verifies_with_aauth_core() {
        let (private_key, public_key) = generate_ed25519_keypair();
        let der = private_key.to_pkcs8_der().expect("encode key");
        let key_b64 = BASE64.encode(&der);
        let kid = jwk_thumbprint(&private_key).expect("thumbprint");

        const VAR: &str = "NONO_TEST_AAUTH_JWKS_URI_KEY";
        let _lock = ENV_LOCK.lock().expect("env mutex poisoned");
        let _guard = EnvVarGuard::set_all(&[(VAR, key_b64.as_str())]);
        let issuer = "https://demo-agent.nono.local".to_string();
        let identity = AauthIdentityConfig {
            agent_id: None,
            key_ref: format!("env://{VAR}"),
            scheme: crate::config::AauthSigSchemeConfig::JwksUri {
                issuer: issuer.clone(),
            },
        };
        let signer = AauthSigner::load(&identity).expect("signer should load from env:// key");

        let url = "https://resource.example/v1/widgets";
        let body = br#"{"hello":"world"}"#;
        let signature_headers = signer.sign("POST", url, body).expect("sign request");
        let headers: HashMap<String, String> = signature_headers
            .into_iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v))
            .collect();

        let signature_key = headers.get("signature-key").expect("Signature-Key present");
        assert!(signature_key.starts_with("sig=jwks_uri;"));
        assert!(signature_key.contains(&format!("id=\"{issuer}\"")));
        assert!(signature_key.contains(&format!("kid=\"{kid}\"")));

        let jwks = aauth_core::keys::generate_jwks(&[aauth_core::keys::public_key_to_jwk(
            &public_key,
            Some(&kid),
        )]);
        let expected_issuer = issuer.clone();
        let resolver = move |id: &str, _dwk: Option<&str>, _kid: Option<&str>| {
            (id == expected_issuer).then(|| jwks.clone())
        };

        let verifier = RequestVerifier::new(vec!["resource.example".to_string()])
            .with_jwks_resolver(&resolver);
        let result = verifier.verify_request("POST", url, &headers, Some(body), false, false);
        assert!(result.valid, "verification failed: {:?}", result.error);
        assert_eq!(result.agent_id.as_deref(), Some(issuer.as_str()));
    }

    /// An issuer the resource doesn't recognize must fail closed rather than
    /// falling back to some other trust path.
    #[test]
    fn jwks_uri_scheme_rejects_unrecognized_issuer() {
        let (private_key, public_key) = generate_ed25519_keypair();
        let der = private_key.to_pkcs8_der().expect("encode key");
        let key_b64 = BASE64.encode(&der);
        let kid = jwk_thumbprint(&private_key).expect("thumbprint");

        const VAR: &str = "NONO_TEST_AAUTH_JWKS_URI_BAD_ISSUER_KEY";
        let _lock = ENV_LOCK.lock().expect("env mutex poisoned");
        let _guard = EnvVarGuard::set_all(&[(VAR, key_b64.as_str())]);
        let identity = AauthIdentityConfig {
            agent_id: None,
            key_ref: format!("env://{VAR}"),
            scheme: crate::config::AauthSigSchemeConfig::JwksUri {
                issuer: "https://signed-by-this-agent.example".to_string(),
            },
        };
        let signer = AauthSigner::load(&identity).expect("signer should load from env:// key");

        let url = "https://resource.example/v1/widgets";
        let body = br#"{"hello":"world"}"#;
        let signature_headers = signer.sign("POST", url, body).expect("sign request");
        let headers: HashMap<String, String> = signature_headers
            .into_iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v))
            .collect();

        // Resolver only recognizes a *different* issuer than the one that
        // actually signed the request.
        let jwks = aauth_core::keys::generate_jwks(&[aauth_core::keys::public_key_to_jwk(
            &public_key,
            Some(&kid),
        )]);
        let resolver = move |id: &str, _dwk: Option<&str>, _kid: Option<&str>| {
            (id == "https://some-other-agent.example").then(|| jwks.clone())
        };

        let verifier = RequestVerifier::new(vec!["resource.example".to_string()])
            .with_jwks_resolver(&resolver);
        let result = verifier.verify_request("POST", url, &headers, Some(body), false, false);
        assert!(!result.valid, "an unrecognized issuer must not verify");
    }

    /// Regression test: `sign()` must cover `content-digest` whenever a
    /// body is present. Without it, the signature authenticates only the
    /// request line and identity — a body swapped in flight while reusing
    /// the original headers would still verify successfully.
    #[test]
    fn signed_request_with_body_rejects_tampering() {
        let (private_key, _public_key) = generate_ed25519_keypair();
        let der = private_key.to_pkcs8_der().expect("encode key");
        let key_b64 = BASE64.encode(&der);

        const VAR: &str = "NONO_TEST_AAUTH_TAMPER_KEY";
        let _lock = ENV_LOCK.lock().expect("env mutex poisoned");
        let _guard = EnvVarGuard::set_all(&[(VAR, key_b64.as_str())]);
        let identity = AauthIdentityConfig {
            agent_id: Some("aauth:test-agent@nono.local".to_string()),
            key_ref: format!("env://{VAR}"),
            scheme: crate::config::AauthSigSchemeConfig::Hwk,
        };
        let signer = AauthSigner::load(&identity).expect("signer should load from env:// key");

        let url = "https://api.example.com/v1/widgets";
        let original_body = br#"{"amount":10}"#;
        let signature_headers = signer
            .sign("POST", url, original_body)
            .expect("sign request");
        let headers: HashMap<String, String> = signature_headers
            .into_iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v))
            .collect();
        assert!(
            headers.contains_key("content-digest"),
            "signing a request with a body must cover content-digest"
        );

        let verifier = RequestVerifier::new(vec!["api.example.com".to_string()]);

        let honest =
            verifier.verify_request("POST", url, &headers, Some(original_body), false, false);
        assert!(honest.valid, "honest body must verify: {:?}", honest.error);

        let tampered_body = br#"{"amount":999999}"#;
        let tampered =
            verifier.verify_request("POST", url, &headers, Some(tampered_body), false, false);
        assert!(
            !tampered.valid,
            "a tampered body under the same headers must be rejected"
        );
    }

    #[test]
    fn load_rejects_unparseable_key_material() {
        const VAR: &str = "NONO_TEST_AAUTH_BAD_KEY";
        let _lock = ENV_LOCK.lock().expect("env mutex poisoned");
        let _guard = EnvVarGuard::set_all(&[(VAR, "not-base64-pkcs8!!")]);
        let identity = AauthIdentityConfig {
            agent_id: Some("aauth:test-agent@nono.local".to_string()),
            key_ref: format!("env://{VAR}"),
            scheme: crate::config::AauthSigSchemeConfig::Hwk,
        };
        assert!(AauthSigner::load(&identity).is_err());
    }

    #[test]
    fn load_rejects_explicit_agent_id_under_jwks_uri() {
        let (private_key, _public_key) = generate_ed25519_keypair();
        let der = private_key.to_pkcs8_der().expect("encode key");
        let key_b64 = BASE64.encode(&der);

        const VAR: &str = "NONO_TEST_AAUTH_JWKS_URI_EXPLICIT_AGENT_ID_KEY";
        let _lock = ENV_LOCK.lock().expect("env mutex poisoned");
        let _guard = EnvVarGuard::set_all(&[(VAR, key_b64.as_str())]);
        let identity = AauthIdentityConfig {
            agent_id: Some("aauth:should-not-be-set@nono.local".to_string()),
            key_ref: format!("env://{VAR}"),
            scheme: crate::config::AauthSigSchemeConfig::JwksUri {
                issuer: "https://demo-agent.nono.local".to_string(),
            },
        };
        let result = AauthSigner::load(&identity);
        let Err(err) = result else {
            panic!("explicit agent_id under jwks_uri must be rejected");
        };
        assert!(err.to_string().contains("must not be set under jwks_uri"));
    }

    #[test]
    fn load_defaults_hwk_agent_id_to_key_thumbprint_when_unset() {
        let (private_key, _public_key) = generate_ed25519_keypair();
        let der = private_key.to_pkcs8_der().expect("encode key");
        let key_b64 = BASE64.encode(&der);
        let kid = jwk_thumbprint(&private_key).expect("thumbprint");

        const VAR: &str = "NONO_TEST_AAUTH_HWK_DEFAULT_AGENT_ID_KEY";
        let _lock = ENV_LOCK.lock().expect("env mutex poisoned");
        let _guard = EnvVarGuard::set_all(&[(VAR, key_b64.as_str())]);
        let identity = AauthIdentityConfig {
            agent_id: None,
            key_ref: format!("env://{VAR}"),
            scheme: crate::config::AauthSigSchemeConfig::Hwk,
        };
        let signer = AauthSigner::load(&identity).expect("signer should load from env:// key");
        assert_eq!(signer.agent_id(), kid);
    }

    #[test]
    fn audit_context_reports_no_agent_id_under_hwk_when_unset() {
        let (private_key, _public_key) = generate_ed25519_keypair();
        let der = private_key.to_pkcs8_der().expect("encode key");
        let key_b64 = BASE64.encode(&der);

        const VAR: &str = "NONO_TEST_AAUTH_AUDIT_HWK_NO_AGENT_ID_KEY";
        let _lock = ENV_LOCK.lock().expect("env mutex poisoned");
        let _guard = EnvVarGuard::set_all(&[(VAR, key_b64.as_str())]);
        let identity = AauthIdentityConfig {
            agent_id: None,
            key_ref: format!("env://{VAR}"),
            scheme: crate::config::AauthSigSchemeConfig::Hwk,
        };
        let signer = AauthSigner::load(&identity).expect("signer should load from env:// key");

        let ctx = signer.audit_context();
        assert_eq!(ctx.agent_id, None);
        assert_eq!(
            ctx.key_thumbprint,
            jwk_thumbprint(&private_key).expect("thumbprint")
        );
    }
}
