//! Session token generation and validation.
//!
//! Each proxy session gets a unique cryptographic token. The child process
//! receives it via `NONO_PROXY_TOKEN` env var and must include it in all
//! requests to the proxy. This prevents other local processes from using
//! the proxy.

use crate::error::{ProxyError, Result};
use subtle::ConstantTimeEq;
use tracing::{debug, warn};
use zeroize::Zeroizing;

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
