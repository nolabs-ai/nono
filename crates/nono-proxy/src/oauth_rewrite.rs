//! OAuth token-response body rewriting.
//!
//! When an intercepted response is the OAuth token endpoint
//! (`/v1/oauth/token` and friends), this module swaps the real
//! `access_token` / `refresh_token` JSON fields for broker-issued
//! `nono_<hex>` nonces before the body reaches the sandboxed client. The
//! sandbox persists nonces (e.g. to `Claude Code-credentials`); the proxy
//! swaps them back to the real tokens on egress.
//!
//! **Fail-closed = pass-through.** Every failure mode (body isn't JSON, has
//! no token fields, or can't be re-serialised) returns a pass-through
//! outcome so the caller forwards the *original* body unchanged. The only
//! thing that ever leaves this module is either an untouched body or one
//! whose real tokens have been replaced by nonces — never a partially
//! mangled body, and never a real token when a nonce was expected.

use crate::token::OauthCaptureResolver;
use bytes::Bytes;
use zeroize::Zeroizing;

/// Outcome of [`rewrite_oauth_json_body`].
#[derive(Debug)]
pub enum OauthRewriteOutcome {
    /// Body did not parse as JSON. Forward original unchanged.
    NotJson,
    /// Body parsed but carried no `access_token` / `refresh_token` string
    /// fields (or re-serialisation failed). Forward original unchanged.
    NoTokenFields,
    /// Tokens were substituted with nonces. Forward `bytes` with rebuilt
    /// framing. `substituted` is the count (1 or 2) for audit logging.
    Rewritten { bytes: Bytes, substituted: u32 },
}

/// Parse `body` as a JSON object, substitute `access_token` /
/// `refresh_token` string values with broker nonces (minting via
/// `capture`), and return the rewritten bytes. See the module docs for the
/// fail-closed contract.
pub fn rewrite_oauth_json_body(
    body: &[u8],
    capture: &dyn OauthCaptureResolver,
) -> OauthRewriteOutcome {
    let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return OauthRewriteOutcome::NotJson;
    };
    let Some(obj) = value.as_object_mut() else {
        return OauthRewriteOutcome::NoTokenFields;
    };

    // Extract the string token fields (non-string values are ignored).
    let access = obj
        .get("access_token")
        .and_then(serde_json::Value::as_str)
        .map(|s| Zeroizing::new(s.to_string()));
    let refresh = obj
        .get("refresh_token")
        .and_then(serde_json::Value::as_str)
        .map(|s| Zeroizing::new(s.to_string()));

    let substituted = match (access, refresh) {
        (Some(a), Some(r)) => {
            // Capture the pair together so the broker can persist it as a
            // unit (cross-session resume + refresh-rotation pruning).
            let (access_nonce, refresh_nonce) = capture.capture_oauth_pair(a, r);
            obj.insert(
                "access_token".to_string(),
                serde_json::Value::String(access_nonce),
            );
            obj.insert(
                "refresh_token".to_string(),
                serde_json::Value::String(refresh_nonce),
            );
            2
        }
        (Some(a), None) => {
            obj.insert(
                "access_token".to_string(),
                serde_json::Value::String(capture.issue(a)),
            );
            1
        }
        (None, Some(r)) => {
            obj.insert(
                "refresh_token".to_string(),
                serde_json::Value::String(capture.issue(r)),
            );
            1
        }
        (None, None) => 0,
    };

    if substituted == 0 {
        return OauthRewriteOutcome::NoTokenFields;
    }

    match serde_json::to_vec(&value) {
        Ok(bytes) => OauthRewriteOutcome::Rewritten {
            bytes: Bytes::from(bytes),
            substituted,
        },
        // Re-serialisation should never fail for a value we just parsed, but
        // if it does, pass through rather than emit a half-built body.
        Err(_) => OauthRewriteOutcome::NoTokenFields,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Capture resolver that mints predictable nonces and records what it saw.
    struct StubCapture {
        counter: Mutex<u32>,
        seen: Mutex<Vec<String>>,
    }

    impl StubCapture {
        fn new() -> Self {
            Self {
                counter: Mutex::new(0),
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    impl OauthCaptureResolver for StubCapture {
        fn issue(&self, secret: Zeroizing<String>) -> String {
            self.seen.lock().unwrap().push(secret.to_string());
            let mut c = self.counter.lock().unwrap();
            *c += 1;
            format!("nono_stub_{}", *c)
        }
    }

    fn outcome_bytes(o: OauthRewriteOutcome) -> Vec<u8> {
        match o {
            OauthRewriteOutcome::Rewritten { bytes, .. } => bytes.to_vec(),
            other => panic!("expected Rewritten, got {other:?}"),
        }
    }

    #[test]
    fn rewrites_access_and_refresh_pair() {
        let cap = StubCapture::new();
        let body = br#"{"access_token":"sk-ant-oat01-REAL","refresh_token":"sk-ant-ort01-REAL","expires_in":3600}"#;
        let out = rewrite_oauth_json_body(body, &cap);
        let OauthRewriteOutcome::Rewritten { substituted, .. } = &out else {
            panic!("expected Rewritten");
        };
        assert_eq!(*substituted, 2);
        let bytes = outcome_bytes(out);
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            v["access_token"]
                .as_str()
                .unwrap()
                .starts_with("nono_stub_")
        );
        assert!(
            v["refresh_token"]
                .as_str()
                .unwrap()
                .starts_with("nono_stub_")
        );
        // Untouched fields survive.
        assert_eq!(v["expires_in"], 3600);
        // The real tokens were handed to the broker, not leaked.
        let seen = cap.seen.lock().unwrap();
        assert!(seen.contains(&"sk-ant-oat01-REAL".to_string()));
        assert!(seen.contains(&"sk-ant-ort01-REAL".to_string()));
        // And do not appear in the output.
        let s = String::from_utf8(bytes).unwrap();
        assert!(!s.contains("sk-ant-oat01-REAL"));
        assert!(!s.contains("sk-ant-ort01-REAL"));
    }

    #[test]
    fn rewrites_access_only() {
        let cap = StubCapture::new();
        let body = br#"{"access_token":"sk-ant-oat01-REAL"}"#;
        let out = rewrite_oauth_json_body(body, &cap);
        let OauthRewriteOutcome::Rewritten { substituted, .. } = &out else {
            panic!("expected Rewritten");
        };
        assert_eq!(*substituted, 1);
    }

    #[test]
    fn non_json_passes_through() {
        let cap = StubCapture::new();
        assert!(matches!(
            rewrite_oauth_json_body(b"not json at all", &cap),
            OauthRewriteOutcome::NotJson
        ));
    }

    #[test]
    fn json_without_token_fields_passes_through() {
        let cap = StubCapture::new();
        assert!(matches!(
            rewrite_oauth_json_body(br#"{"error":"invalid_grant"}"#, &cap),
            OauthRewriteOutcome::NoTokenFields
        ));
    }

    #[test]
    fn non_object_json_passes_through() {
        let cap = StubCapture::new();
        assert!(matches!(
            rewrite_oauth_json_body(br#"["access_token","x"]"#, &cap),
            OauthRewriteOutcome::NoTokenFields
        ));
    }

    #[test]
    fn non_string_token_field_ignored() {
        // access_token present but not a string → treated as absent.
        let cap = StubCapture::new();
        assert!(matches!(
            rewrite_oauth_json_body(br#"{"access_token":12345}"#, &cap),
            OauthRewriteOutcome::NoTokenFields
        ));
    }
}
