//! Session token generation, validation, and nonce resolution.
//!
//! Each proxy session gets a unique cryptographic token used to authenticate
//! requests to the proxy. For reverse proxy credential routes the token is
//! delivered transparently — nono sets the credential env var (e.g.
//! `GITHUB_TOKEN`) to the phantom token inside the sandbox, so standard API
//! clients include it automatically in the service-specific auth header. For
//! CONNECT tunnel requests the token is validated via `Proxy-Authorization`.
//! This prevents other local processes from hijacking the proxy session.
//!
//! The `NonceResolver` trait allows the proxy to resolve tool-sandbox broker
//! nonces (`nono_<64hex>`) found in request headers, substituting the real
//! credential value before forwarding upstream. The consumer ID passed to
//! `resolve` is `"proxy.<route_id>"`, matching the `grant_to` field of the
//! originating `capture_credential` intercept rule.

use crate::error::{ProxyError, Result};
use subtle::ConstantTimeEq;
use tracing::{debug, warn};
use zeroize::Zeroizing;

/// Resolves tool-sandbox broker nonces for L7 header injection.
///
/// Implemented by the CLI's `TokenBroker` wrapper and threaded through the
/// proxy server so that nonces appearing in request headers can be swapped for
/// real credential values immediately before the request is forwarded upstream.
pub trait NonceResolver: Send + Sync {
    /// Resolve `nonce` (a `nono_<64hex>` string) for `consumer`.
    ///
    /// Returns the real credential bytes if the nonce is known and admitted
    /// for `consumer` (`"proxy.<route_id>"`), or `None` otherwise (fail-closed).
    fn resolve(&self, nonce: &str, consumer: &str) -> Option<Zeroizing<Vec<u8>>>;

    /// If this resolver also supports OAuth capture (minting nonces for tokens
    /// sniffed from a `/v1/oauth/token` response), return itself as an
    /// [`OauthCaptureResolver`]. The default is `None` — a resolve-only
    /// resolver, so OAuth-capture routes stay inert. The CLI's broker bridge
    /// overrides this to enable capture. Keeping it an accessor (rather than
    /// widening `NonceResolver`) means resolve-only impls and the proxy server
    /// wiring need no changes.
    fn oauth_capture(&self) -> Option<&dyn OauthCaptureResolver> {
        None
    }
}

/// Mints `nono_<hex>` nonces for credentials captured at runtime from an
/// intercepted OAuth token response, holding the real secret in the broker so
/// it never crosses the sandbox boundary.
///
/// Separate from [`NonceResolver`] (which only *reads* existing mappings) so
/// that resolve-only resolvers and proxy-server wiring are unaffected; the
/// broker bridge implements both and links them via
/// [`NonceResolver::oauth_capture`].
pub trait OauthCaptureResolver: Send + Sync {
    /// Store `secret` and return a fresh opaque `nono_<hex>` nonce. Each call
    /// yields a new nonce even for repeated secrets.
    fn issue(&self, secret: Zeroizing<String>) -> String;

    /// Mint nonces for a captured OAuth `(access_token, refresh_token)` pair.
    ///
    /// Distinct from two [`Self::issue`] calls because an implementation may
    /// persist the pair to durable storage so the mapping survives across
    /// sessions. Persistence failures must NOT propagate: a backend that
    /// cannot write durably must still return valid in-memory nonces (and log
    /// a warning) so capture-and-rewrite keeps working. The default is the
    /// persistence-free two-`issue` behaviour.
    fn capture_oauth_pair(
        &self,
        access: Zeroizing<String>,
        refresh: Zeroizing<String>,
    ) -> (String, String) {
        (self.issue(access), self.issue(refresh))
    }
}

/// Length of the random token in bytes (256 bits of entropy).
const TOKEN_BYTES: usize = 32;

/// Generate a fresh session token.
///
/// Returns a hex-encoded 64-character string wrapping 32 bytes of
/// cryptographic randomness. The token is stored in a `Zeroizing<String>`
/// that clears memory on drop.
pub fn generate_session_token() -> Result<Zeroizing<String>> {
    let mut bytes = [0u8; TOKEN_BYTES];
    getrandom::fill(&mut bytes).map_err(|e| ProxyError::Config(format!("RNG failure: {}", e)))?;
    let hex = hex_encode(&bytes);
    // Zero the raw bytes immediately
    bytes.fill(0);
    Ok(Zeroizing::new(hex))
}

/// Constant-time comparison of two token strings.
///
/// Uses the `subtle` crate's `ConstantTimeEq` to prevent timing
/// side-channel attacks where an attacker could determine the correct
/// token prefix by measuring response times.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Hex-encode bytes to a lowercase string.
fn hex_encode(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        hex.push(HEX_CHARS[(byte >> 4) as usize]);
        hex.push(HEX_CHARS[(byte & 0x0f) as usize]);
    }
    hex
}

const HEX_CHARS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

/// Validate a `Proxy-Authorization` header against the session token.
///
/// Accepts two formats:
/// - `Proxy-Authorization: Bearer <token>` (nono-aware clients)
/// - `Proxy-Authorization: Basic base64(nono:<token>)` (standard HTTP clients like curl)
///
/// Case-insensitive header name and scheme matching per HTTP spec.
pub fn validate_proxy_auth(header_bytes: &[u8], session_token: &Zeroizing<String>) -> Result<()> {
    let header_str = std::str::from_utf8(header_bytes).map_err(|_| ProxyError::InvalidToken)?;

    const BEARER_PREFIX: &str = "proxy-authorization: bearer ";
    const BASIC_PREFIX: &str = "proxy-authorization: basic ";

    for line in header_str.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with(BEARER_PREFIX) {
            let value = line[BEARER_PREFIX.len()..].trim();
            if constant_time_eq(value.as_bytes(), session_token.as_bytes()) {
                return Ok(());
            }
            warn!("Invalid proxy authorization token (Bearer)");
            return Err(ProxyError::InvalidToken);
        }
        if lower.starts_with(BASIC_PREFIX) {
            let encoded = line[BASIC_PREFIX.len()..].trim();
            return validate_basic_auth(encoded, session_token);
        }
    }

    debug!("Missing Proxy-Authorization header");
    Err(ProxyError::InvalidToken)
}

/// Validate Basic auth where the password is the session token.
///
/// Expected format: base64("username:token"). The username is ignored;
/// only the password portion is compared against the session token.
fn validate_basic_auth(encoded: &str, session_token: &Zeroizing<String>) -> Result<()> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    let decoded = STANDARD
        .decode(encoded)
        .map_err(|_| ProxyError::InvalidToken)?;
    let decoded_str = std::str::from_utf8(&decoded).map_err(|_| ProxyError::InvalidToken)?;

    let password = match decoded_str.split_once(':') {
        Some((_, pw)) => pw,
        None => {
            warn!("Malformed Basic auth (no colon separator)");
            return Err(ProxyError::InvalidToken);
        }
    };

    if constant_time_eq(password.as_bytes(), session_token.as_bytes()) {
        Ok(())
    } else {
        warn!("Invalid proxy authorization token (Basic)");
        Err(ProxyError::InvalidToken)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_token_length() {
        let token = generate_session_token().unwrap();
        assert_eq!(token.len(), 64); // 32 bytes * 2 hex chars
    }

    #[test]
    fn test_generate_token_is_hex() {
        let token = generate_session_token().unwrap();
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_token_unique() {
        let t1 = generate_session_token().unwrap();
        let t2 = generate_session_token().unwrap();
        assert_ne!(*t1, *t2);
    }

    #[test]
    fn test_constant_time_eq_same() {
        let a = b"hello";
        let b = b"hello";
        assert!(constant_time_eq(a, b));
    }

    #[test]
    fn test_constant_time_eq_different() {
        let a = b"hello";
        let b = b"world";
        assert!(!constant_time_eq(a, b));
    }

    #[test]
    fn test_constant_time_eq_different_length() {
        let a = b"hello";
        let b = b"hi";
        assert!(!constant_time_eq(a, b));
    }

    #[test]
    fn test_constant_time_eq_empty() {
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn test_validate_proxy_auth_bearer() {
        let token = Zeroizing::new("abc123".to_string());
        let header = b"Proxy-Authorization: Bearer abc123\r\n\r\n";
        assert!(validate_proxy_auth(header, &token).is_ok());
    }

    #[test]
    fn test_validate_proxy_auth_bearer_case_insensitive() {
        let token = Zeroizing::new("abc123".to_string());
        let header = b"proxy-authorization: BEARER abc123\r\n\r\n";
        assert!(validate_proxy_auth(header, &token).is_ok());
    }

    #[test]
    fn test_validate_proxy_auth_bearer_invalid() {
        let token = Zeroizing::new("abc123".to_string());
        let header = b"Proxy-Authorization: Bearer wrong\r\n\r\n";
        assert!(validate_proxy_auth(header, &token).is_err());
    }

    #[test]
    fn test_validate_proxy_auth_basic() {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD;
        let token = Zeroizing::new("abc123".to_string());
        let encoded = STANDARD.encode("nono:abc123");
        let header = format!("Proxy-Authorization: Basic {}\r\n\r\n", encoded);
        assert!(validate_proxy_auth(header.as_bytes(), &token).is_ok());
    }

    #[test]
    fn test_validate_proxy_auth_basic_wrong_password() {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD;
        let token = Zeroizing::new("abc123".to_string());
        let encoded = STANDARD.encode("nono:wrong");
        let header = format!("Proxy-Authorization: Basic {}\r\n\r\n", encoded);
        assert!(validate_proxy_auth(header.as_bytes(), &token).is_err());
    }

    #[test]
    fn test_validate_proxy_auth_basic_any_username() {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD;
        let token = Zeroizing::new("abc123".to_string());
        // Any username should work — only password matters
        let encoded = STANDARD.encode("whatever:abc123");
        let header = format!("Proxy-Authorization: Basic {}\r\n\r\n", encoded);
        assert!(validate_proxy_auth(header.as_bytes(), &token).is_ok());
    }

    #[test]
    fn test_validate_proxy_auth_missing() {
        let token = Zeroizing::new("abc123".to_string());
        let header = b"Host: example.com\r\n\r\n";
        assert!(validate_proxy_auth(header, &token).is_err());
    }
}
