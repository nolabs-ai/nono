//! DPoP proofs ([RFC 9449]) signed by the platform device key.
//!
//! Every OAuth token issued to `nono platform login` is bound to the CLI's P-256 device
//! key. The key's JWK thumbprint ([RFC 7638]) is sent as `dpop_jkt` at
//! authorization time, and every token-endpoint and resource request carries a
//! fresh proof JWT. A copied token is useless without the private key.
//!
//! [RFC 9449]: https://www.rfc-editor.org/rfc/rfc9449
//! [RFC 7638]: https://www.rfc-editor.org/rfc/rfc7638

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nono::{NonoError, Result};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

/// Upper bound on a server-supplied `DPoP-Nonce`, which is echoed back.
const MAX_NONCE_LEN: usize = 1024;

/// A device key prepared for DPoP: its public JWK coordinates and thumbprint.
pub(crate) struct DpopKey {
    key_pair: EcdsaKeyPair,
    x: String,
    y: String,
    thumbprint: String,
}

impl std::fmt::Debug for DpopKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpopKey")
            .field("thumbprint", &self.thumbprint)
            .finish_non_exhaustive()
    }
}

impl DpopKey {
    pub(crate) fn new(key_pair: EcdsaKeyPair) -> Result<Self> {
        let (x, y) = jwk_coordinates(key_pair.public_key().as_ref())?;
        let thumbprint = jwk_thumbprint(&x, &y);
        Ok(Self {
            key_pair,
            x,
            y,
            thumbprint,
        })
    }

    /// The base64url SHA-256 JWK thumbprint (`jkt`) of the public key.
    pub(crate) fn thumbprint(&self) -> &str {
        &self.thumbprint
    }

    /// A short, human-comparable key fingerprint shown in the terminal and on
    /// the platform consent screen: the first 16 thumbprint characters in
    /// four colon-separated groups.
    pub(crate) fn fingerprint(&self) -> String {
        fingerprint_of(&self.thumbprint)
    }

    /// Build a DPoP proof JWT for one request.
    ///
    /// `access_token` adds the `ath` claim required when presenting a token to
    /// a resource server. `nonce` echoes a server-supplied `DPoP-Nonce`.
    pub(crate) fn proof(
        &self,
        method: &str,
        target: &Url,
        nonce: Option<&str>,
        access_token: Option<&str>,
    ) -> Result<String> {
        let iat = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                NonoError::ConfigParse(format!("system clock is before Unix epoch: {error}"))
            })?
            .as_secs();
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": { "kty": "EC", "crv": "P-256", "x": self.x, "y": self.y },
        });
        let mut claims = serde_json::json!({
            "jti": super::random_token()?.as_str(),
            "htm": method,
            "htu": proof_target_uri(target)?,
            "iat": iat,
        });
        if let Some(nonce) = nonce {
            validate_nonce(nonce)?;
            claims["nonce"] = serde_json::Value::String(nonce.to_string());
        }
        if let Some(token) = access_token {
            claims["ath"] =
                serde_json::Value::String(URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes())));
        }
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        // ECDSA_P256_SHA256_FIXED produces the 64-byte r||s encoding that JWS
        // ES256 requires (RFC 7518 §3.4).
        let signature = self
            .key_pair
            .sign(&SystemRandom::new(), signing_input.as_bytes())
            .map_err(|_| NonoError::KeystoreAccess("failed to sign DPoP proof".to_string()))?;
        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.as_ref())
        ))
    }
}

/// The `htu` claim: the request URI without query or fragment. A WebSocket
/// URI is expressed as the HTTP(S) URI of its opening handshake, because that
/// handshake is the HTTP request the proof is attached to (cli-login-v1).
pub(crate) fn proof_target_uri(target: &Url) -> Result<String> {
    let mut url = target.clone();
    url.set_query(None);
    url.set_fragment(None);
    let scheme = match url.scheme() {
        "https" | "wss" => "https",
        "http" | "ws" => "http",
        other => {
            return Err(NonoError::ConfigParse(format!(
                "cannot create a DPoP proof for a {other}:// URL"
            )));
        }
    };
    // Url refuses to switch between "special" schemes with different default
    // ports, so rebuild the string instead of calling set_scheme.
    let rest = url
        .as_str()
        .split_once("://")
        .map(|(_, rest)| rest)
        .ok_or_else(|| NonoError::ConfigParse("invalid DPoP target URL".to_string()))?;
    Ok(format!("{scheme}://{rest}"))
}

/// Accept only the RFC 9449 NQCHAR nonce alphabet, so a server-supplied value
/// cannot inject anything into the proof or a retried request.
pub(crate) fn validate_nonce(nonce: &str) -> Result<()> {
    let valid = !nonce.is_empty()
        && nonce.len() <= MAX_NONCE_LEN
        && nonce
            .bytes()
            .all(|byte| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e));
    if valid {
        Ok(())
    } else {
        Err(NonoError::ConfigParse(
            "platform returned an invalid DPoP nonce".to_string(),
        ))
    }
}

fn jwk_coordinates(public_key: &[u8]) -> Result<(String, String)> {
    // Uncompressed SEC1 point: 0x04 || X (32 bytes) || Y (32 bytes).
    match public_key {
        [0x04, rest @ ..] if rest.len() == 64 => Ok((
            URL_SAFE_NO_PAD.encode(&rest[..32]),
            URL_SAFE_NO_PAD.encode(&rest[32..]),
        )),
        _ => Err(NonoError::KeystoreAccess(
            "platform key is not an uncompressed P-256 public key".to_string(),
        )),
    }
}

/// RFC 7638 thumbprint: SHA-256 over the required members in lexicographic
/// order with no whitespace.
fn jwk_thumbprint(x: &str, y: &str) -> String {
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

fn fingerprint_of(thumbprint: &str) -> String {
    thumbprint
        .chars()
        .take(16)
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::{
        ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, UnparsedPublicKey,
    };

    fn test_key() -> DpopKey {
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .unwrap();
        DpopKey::new(
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref()).unwrap(),
        )
        .unwrap()
    }

    fn decode_segment(segment: &str) -> serde_json::Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segment).unwrap()).unwrap()
    }

    #[test]
    fn thumbprint_and_fingerprint_match_the_cli_login_v1_fixture() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../../tests/fixtures/cli-login-v1.json"))
                .unwrap();
        let key = &fixture["dpop_key"];
        let jkt = jwk_thumbprint(
            key["jwk"]["x"].as_str().unwrap(),
            key["jwk"]["y"].as_str().unwrap(),
        );
        assert_eq!(jkt, key["jkt"].as_str().unwrap());
        assert_eq!(fingerprint_of(&jkt), key["fingerprint"].as_str().unwrap());
    }

    #[test]
    fn thumbprint_matches_rfc_9449_example_key() {
        // The ES256 public key and `dpop_jkt` from RFC 9449 §10.
        assert_eq!(
            jwk_thumbprint(
                "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
                "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"
            ),
            "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
        );
    }

    #[test]
    fn fingerprint_is_four_groups_of_the_thumbprint() {
        assert_eq!(
            fingerprint_of("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"),
            "0ZcO:CORZ:NYy-:DWpq"
        );
    }

    #[test]
    fn proof_is_a_verifiable_es256_jwt_with_the_required_claims() {
        let key = test_key();
        let target = Url::parse("https://nono.example.com/oauth/token?x=1#frag").unwrap();
        let proof = key
            .proof("POST", &target, Some("nonce-1"), Some("token-abc"))
            .unwrap();
        let parts: Vec<_> = proof.split('.').collect();
        assert_eq!(parts.len(), 3);

        let header = decode_segment(parts[0]);
        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["jwk"]["kty"], "EC");
        assert_eq!(header["jwk"]["crv"], "P-256");
        assert!(
            header["jwk"].get("d").is_none(),
            "private key must not leak"
        );

        let claims = decode_segment(parts[1]);
        assert_eq!(claims["htm"], "POST");
        assert_eq!(claims["htu"], "https://nono.example.com/oauth/token");
        assert_eq!(claims["nonce"], "nonce-1");
        assert_eq!(
            claims["ath"],
            URL_SAFE_NO_PAD.encode(Sha256::digest(b"token-abc"))
        );
        assert!(claims["jti"].as_str().is_some_and(|jti| !jti.is_empty()));
        assert!(claims["iat"].as_u64().is_some());

        // Verify with the public key reconstructed from the embedded JWK, as
        // the authorization server does, and check it matches the thumbprint.
        let x = URL_SAFE_NO_PAD
            .decode(header["jwk"]["x"].as_str().unwrap())
            .unwrap();
        let y = URL_SAFE_NO_PAD
            .decode(header["jwk"]["y"].as_str().unwrap())
            .unwrap();
        let mut point = vec![0x04];
        point.extend_from_slice(&x);
        point.extend_from_slice(&y);
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &point)
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .unwrap();
        assert_eq!(
            jwk_thumbprint(
                header["jwk"]["x"].as_str().unwrap(),
                header["jwk"]["y"].as_str().unwrap()
            ),
            key.thumbprint()
        );
    }

    #[test]
    fn each_proof_has_a_unique_jti() {
        let key = test_key();
        let target = Url::parse("https://nono.example.com/oauth/token").unwrap();
        let first = decode_segment(
            key.proof("POST", &target, None, None)
                .unwrap()
                .split('.')
                .nth(1)
                .unwrap(),
        );
        let second = decode_segment(
            key.proof("POST", &target, None, None)
                .unwrap()
                .split('.')
                .nth(1)
                .unwrap(),
        );
        assert_ne!(first["jti"], second["jti"]);
        assert!(first.get("nonce").is_none());
        assert!(first.get("ath").is_none());
    }

    #[test]
    fn websocket_targets_use_the_handshake_http_uri() {
        assert_eq!(
            proof_target_uri(&Url::parse("wss://c.example/api/v1/s/x/terminal?cols=80").unwrap())
                .unwrap(),
            "https://c.example/api/v1/s/x/terminal"
        );
        assert_eq!(
            proof_target_uri(&Url::parse("ws://127.0.0.1:9000/t").unwrap()).unwrap(),
            "http://127.0.0.1:9000/t"
        );
        assert!(proof_target_uri(&Url::parse("file:///etc/passwd").unwrap()).is_err());
    }

    #[test]
    fn nonces_outside_nqchar_are_rejected() {
        assert!(validate_nonce("eyJ7S_zG.eyJH0-Z.HX4w-7v").is_ok());
        assert!(validate_nonce("").is_err());
        assert!(validate_nonce("has space").is_err());
        assert!(validate_nonce("quote\"").is_err());
        assert!(validate_nonce("back\\slash").is_err());
        assert!(validate_nonce("crlf\r\n").is_err());
        assert!(validate_nonce(&"a".repeat(MAX_NONCE_LEN + 1)).is_err());
    }
}
