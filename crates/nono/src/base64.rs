//! Base64 encoding and decoding for trust attestation
//!
//! Provides both standard (RFC 4648 Section 4) and URL-safe (RFC 4648 Section 5)
//! base64 encoding/decoding. Used throughout the trust pipeline for DSSE payloads,
//! Sigstore bundles, and keystore serialization.

/// Encode bytes as base64url (no padding, URL-safe alphabet).
///
/// Uses `-` and `_` instead of `+` and `/`.
#[cfg(feature = "sigstore")]
#[must_use]
pub fn base64url_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    encode_with_alphabet(data, ALPHABET, false)
}

/// Decode base64url (no padding, URL-safe alphabet) to bytes.
///
/// Also accepts standard base64 characters (`+` and `/`) for interoperability
/// with implementations that use the standard alphabet in URL contexts.
///
/// # Errors
///
/// Returns an error string if the input contains invalid characters.
#[cfg(feature = "sigstore")]
pub fn base64url_decode(input: &str) -> Result<Vec<u8>, String> {
    decode_impl(input)
}

/// Encode bytes as standard base64 (with padding).
///
/// Uses `+` and `/` with `=` padding.
#[cfg(feature = "sigstore")]
#[must_use]
pub fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    encode_with_alphabet(data, ALPHABET, true)
}

/// Decode standard base64 (with or without padding) to bytes.
///
/// Also accepts URL-safe characters (`-` and `_`) for interoperability.
///
/// # Errors
///
/// Returns an error string if the input contains invalid characters.
pub fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    decode_impl(input)
}

/// Shared encoding logic for both standard and URL-safe alphabets.
#[cfg(feature = "sigstore")]
fn encode_with_alphabet(data: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(alphabet[((triple >> 18) & 0x3F) as usize] as char);
        result.push(alphabet[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(alphabet[((triple >> 6) & 0x3F) as usize] as char);
        } else if pad {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(alphabet[(triple & 0x3F) as usize] as char);
        } else if pad {
            result.push('=');
        }
    }
    result
}

/// Shared decoding logic that accepts both standard and URL-safe alphabets.
fn decode_impl(input: &str) -> Result<Vec<u8>, String> {
    // Strip trailing whitespace first, then padding, to handle PEM-style line
    // wrapped input where trailing whitespace precedes or follows padding chars.
    let input = input.trim_end();
    let input = input.trim_end_matches('=');

    let mut buf = Vec::with_capacity(input.len() * 3 / 4);
    let mut accum: u32 = 0;
    let mut bits: u32 = 0;

    for ch in input.chars() {
        if ch.is_whitespace() {
            continue;
        }
        let val = match ch {
            'A'..='Z' => ch as u32 - b'A' as u32,
            'a'..='z' => ch as u32 - b'a' as u32 + 26,
            '0'..='9' => ch as u32 - b'0' as u32 + 52,
            '+' | '-' => 62,
            '/' | '_' => 63,
            _ => return Err(format!("invalid base64 character: '{ch}'")),
        };
        accum = (accum << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            buf.push((accum >> bits) as u8);
            accum &= (1 << bits) - 1;
        }
    }

    Ok(buf)
}

#[cfg(all(test, feature = "sigstore"))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Base64url
    // -----------------------------------------------------------------------

    #[test]
    fn base64url_roundtrip() {
        let data = b"hello world";
        let encoded = base64url_encode(data);
        let decoded = base64url_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base64url_empty() {
        let encoded = base64url_encode(b"");
        assert_eq!(encoded, "");
        let decoded = base64url_decode("").unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn base64url_known_value() {
        // "hello" -> "aGVsbG8" in base64url without padding
        let encoded = base64url_encode(b"hello");
        assert_eq!(encoded, "aGVsbG8");
    }

    #[test]
    fn base64url_no_padding() {
        let encoded = base64url_encode(b"a");
        assert!(!encoded.contains('='));
    }

    #[test]
    fn base64url_url_safe_chars() {
        // Bytes that would produce + and / in standard base64
        let data = vec![0xFB, 0xFF, 0xFE];
        let encoded = base64url_encode(&data);
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
    }

    #[test]
    fn base64url_decode_with_padding() {
        let decoded = base64url_decode("aGVsbG8=").unwrap();
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn base64url_decode_standard_alphabet() {
        let decoded_url = base64url_decode("a-b_").unwrap();
        let decoded_std = base64url_decode("a+b/").unwrap();
        assert_eq!(decoded_url, decoded_std);
    }

    #[test]
    fn base64url_decode_invalid_char() {
        let result = base64url_decode("invalid!");
        assert!(result.is_err());
    }

    #[test]
    fn base64url_decode_skips_whitespace() {
        // base64url with embedded newlines and spaces (as found in PEM/JSON)
        let encoded_clean = base64url_encode(b"hello world");
        let encoded_with_ws = format!("  {}\n", encoded_clean);
        let decoded = base64url_decode(&encoded_with_ws).unwrap();
        assert_eq!(decoded, b"hello world");
    }

    // -----------------------------------------------------------------------
    // Standard base64
    // -----------------------------------------------------------------------

    #[test]
    fn base64_roundtrip() {
        let data = b"hello world PKCS#8 key material";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base64_empty() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn base64_known_value() {
        // "hello" -> "aGVsbG8="
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
    }

    #[test]
    fn base64_has_padding() {
        let encoded = base64_encode(b"a");
        assert!(encoded.ends_with("=="));
    }

    #[test]
    fn base64_decode_without_padding() {
        let decoded = base64_decode("aGVsbG8").unwrap();
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn base64_decode_skips_whitespace() {
        // standard base64 with embedded newlines (PEM line wrapping at 76 chars)
        let encoded_clean = base64_encode(b"hello world");
        let encoded_with_ws = format!("{}\n", encoded_clean);
        let decoded = base64_decode(&encoded_with_ws).unwrap();
        assert_eq!(decoded, b"hello world");
    }

    #[test]
    fn cross_alphabet_interop() {
        // Standard-encoded data should decode with URL-safe decoder and vice versa
        let data = vec![0xFB, 0xFF, 0xFE];
        let std_encoded = base64_encode(&data);
        let url_encoded = base64url_encode(&data);

        let from_std = base64url_decode(&std_encoded).unwrap();
        let from_url = base64_decode(&url_encoded).unwrap();
        assert_eq!(from_std, data);
        assert_eq!(from_url, data);
    }
}
