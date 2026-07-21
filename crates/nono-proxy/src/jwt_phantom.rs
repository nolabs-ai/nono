//! JWT-shaped phantom tokens.
//!
//! Some consumers validate a token's structure (e.g. grep for three
//! dot-separated base64url segments) before using it. Handing such a consumer
//! an opaque phantom makes it reject the token before any request is made. The
//! phantom is placed in the signature segment, so a bare broker nonce embedded
//! there still resolves via the proxy's substring substitution.

use crate::error::{ProxyError, Result};
use base64::Engine;

/// Wrap `phantom` as a structurally-valid unsigned JWT: `<header>.<payload>.<phantom>`.
///
/// `alg` is `none` and `exp` is far in the future so a consumer that decodes the
/// claims still treats the token as live. The real value (if any) is injected by
/// the proxy at request time; the shaped token only needs to pass client-side
/// structure checks.
pub fn jwt_shaped_phantom(phantom: &str) -> Result<String> {
    let header =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
    let payload = serde_json::json!({
        "iss": "nono",
        "sub": phantom,
        "aud": "nono",
        "iat": 0,
        "exp": 4_102_444_800_u64
    });
    let payload = serde_json::to_vec(&payload).map_err(|err| {
        ProxyError::HttpParse(format!("failed to encode JWT phantom payload: {err}"))
    })?;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
    Ok(format!("{header}.{payload}.{phantom}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_nonce_as_three_segment_jwt() {
        let nonce = format!("nono_{}", "a".repeat(64));
        let jwt = jwt_shaped_phantom(&nonce).expect("shape");

        let segments: Vec<&str> = jwt.split('.').collect();
        assert_eq!(segments.len(), 3, "expected three JWT segments");
        // The phantom occupies the signature segment verbatim so it still resolves.
        assert_eq!(segments[2], nonce);
        // Header decodes to the expected unsigned-JWT header.
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segments[0])
            .expect("decode header");
        assert_eq!(header, br#"{"alg":"none","typ":"JWT"}"#);
    }

    #[test]
    fn matches_a_strict_jwt_shape_check() {
        // Mirrors the kind of client-side check that rejects opaque phantoms:
        // three non-empty [A-Za-z0-9_-] segments separated by dots.
        let nonce = format!("nono_{}", "0".repeat(64));
        let jwt = jwt_shaped_phantom(&nonce).expect("shape");
        let ok = jwt
            .split('.')
            .filter(|s| {
                !s.is_empty()
                    && s.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            })
            .count()
            == 3
            && jwt.matches('.').count() == 2;
        assert!(ok, "shaped token failed a strict JWT-shape check: {jwt}");
    }
}
