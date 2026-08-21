//! aauth request signing: RFC 9421 HTTP Message Signatures with a persistent
//! agent keypair, via the `aauth-core` crate.
//!
//! Unlike SPIFFE/OAuth2 (which produce a bearer credential to inject) this
//! signs the outbound request itself — method, URL, headers, and body — so
//! there is no secret to fetch or rotate at request time. Mirrors
//! `aws/sign.rs`'s shape: load once, sign per request, return headers to add.

use aauth_core::keys::{PrivateKey, calculate_jwk_thumbprint, private_key_to_jwk};
use aauth_core::signing::{SigScheme, SignOptions, sign_request};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use std::collections::HashMap;
use zeroize::Zeroizing;

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
    agent_id: String,
    /// `aauth_identity.agent_id` as configured, before the `hwk` default.
    explicit_agent_id: Option<String>,
    private_key: PrivateKey,
    scheme: AauthSigSchemeConfig,
    /// JWK thumbprint of the public key — used as the `kid` under
    /// `jwks_uri`. Computed once at load so it's guaranteed to match
    /// whatever `nono aauth show --jwks` prints for the same key (both
    /// derive it the same way, from the same key).
    kid: String,
}

impl AauthSigner {
    /// Load the identity's private key via `nono::keystore` (the same
    /// `file://`/`keyring://`/`env://` URI scheme used by `credential_key`).
    /// The stored secret is the key's PKCS#8 DER, base64-encoded — the same
    /// encoding `nono aauth keygen` uses for its own signing key.
    pub fn load(identity: &AauthIdentityConfig) -> Result<Self> {
        let secret =
            nono::keystore::load_secret_by_ref(nono::keystore::DEFAULT_SERVICE, &identity.key_ref)
                .map_err(|e| {
                    ProxyError::Credential(format!("aauth key '{}': {e}", identity.key_ref))
                })?;
        let der = Zeroizing::new(BASE64.decode(secret.trim()).map_err(|e| {
            ProxyError::Credential(format!(
                "aauth key '{}': not valid base64 PKCS#8: {e}",
                identity.key_ref
            ))
        })?);
        let private_key = PrivateKey::from_pkcs8_der(&der).map_err(|e| {
            ProxyError::Credential(format!("aauth key '{}': {e}", identity.key_ref))
        })?;
        let kid = jwk_thumbprint(&private_key).map_err(|e| {
            ProxyError::Credential(format!("aauth key '{}': {e}", identity.key_ref))
        })?;
        let agent_id = match &identity.scheme {
            // See AauthIdentityConfig's doc for why this is rejected rather
            // than just ignored.
            AauthSigSchemeConfig::JwksUri { issuer } => {
                if let Some(explicit) = &identity.agent_id {
                    return Err(ProxyError::Credential(format!(
                        "aauth identity: agent_id ('{explicit}') must not be set under jwks_uri \
                         — a verifying resource always recovers the issuer itself as the \
                         identity, so agent_id is always '{issuer}'; remove agent_id from the \
                         profile"
                    )));
                }
                issuer.clone()
            }
            // No protocol identity exists under hwk (the request is
            // pseudonymous), so this is purely a local label. Default to
            // the key's thumbprint so every audit entry is still
            // traceable to a specific key even when unnamed.
            AauthSigSchemeConfig::Hwk => identity.agent_id.clone().unwrap_or_else(|| kid.clone()),
        };
        Ok(Self {
            agent_id,
            explicit_agent_id: identity.agent_id.clone(),
            private_key,
            scheme: identity.scheme.clone(),
            kid,
        })
    }

    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// Build the audit context for a request signed by this identity —
    /// which scheme, which agent, which key, and (under `jwks_uri`) which
    /// issuer, so the audit log records the actual identity used, not just
    /// "aauth signature" with no further detail.
    pub fn audit_context(&self) -> nono::undo::AauthAuditContext {
        let (scheme, issuer, agent_id) = match &self.scheme {
            AauthSigSchemeConfig::Hwk => ("hwk".to_string(), None, self.explicit_agent_id.clone()),
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

    /// Sign `method`/`url`/`body` and return the headers to add to the
    /// outbound request (`Signature-Input`, `Signature`, `Signature-Key`,
    /// plus `Content-Digest` when there's a body).
    ///
    /// See [`AauthSigSchemeConfig`] for what `hwk` vs `jwks_uri` each put in
    /// `Signature-Key`.
    ///
    /// When a body is present, `content-digest` is explicitly requested as a
    /// covered component — `aauth_core::signing::sign_request` treats body
    /// coverage as opt-in, so without this the signature would authenticate
    /// only the request line and identity, leaving the body free to tamper
    /// with in flight without invalidating the signature.
    pub fn sign(&self, method: &str, url: &str, body: &[u8]) -> Result<Vec<(String, String)>> {
        let mut headers = HashMap::new();
        let body = if body.is_empty() { None } else { Some(body) };
        let options = SignOptions {
            additional_signature_components: body
                .is_some()
                .then(|| vec!["content-digest".to_string()]),
            ..SignOptions::default()
        };
        let scheme = match &self.scheme {
            AauthSigSchemeConfig::Hwk => SigScheme::Hwk,
            AauthSigSchemeConfig::JwksUri { issuer } => SigScheme::JwksUri {
                id: issuer,
                dwk: AGENT_METADATA_DOC,
                kid: &self.kid,
            },
        };
        sign_request(
            method,
            url,
            &mut headers,
            body,
            &self.private_key,
            &scheme,
            &options,
        )
        .map_err(|e| ProxyError::Credential(format!("aauth signing failed: {e}")))?;
        Ok(headers.into_iter().collect())
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

    /// Round-trips a generated key through the same base64-PKCS8 encoding
    /// `nono aauth keygen` would write, loads it as an `AauthSigner`
    /// via `env://`, signs a request, and verifies it with `aauth-core`'s
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
