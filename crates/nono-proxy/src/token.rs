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
    /// Resolve `nonce` for `consumer`.
    ///
    /// `nonce` is the phantom string used as the store key — a bare
    /// `nono_<64hex>` for broker/opaque phantoms, or the full templated phantom
    /// (e.g. `sk-ant-oat01-<64hex>`) for a formatted OAuth capture field.
    /// Returns the real credential bytes if the phantom is known and admitted
    /// for `consumer` (`"proxy.<route_id>"`), or `None` otherwise (fail-closed).
    fn resolve(&self, nonce: &str, consumer: &str) -> Option<Zeroizing<Vec<u8>>>;

    /// Rewrite any phantom this resolver minted that appears in `value`,
    /// substituting the real credential for `consumer`. Returns the rewritten
    /// value, or `None` if no phantom for this resolver/consumer was found.
    ///
    /// The default recognises a bare `nono_<64hex>` nonce. Resolvers that also
    /// mint templated phantoms override this, passing their registered
    /// templates to [`rewrite_first_phantom`].
    fn rewrite_header_value(&self, value: &str, consumer: &str) -> Option<String> {
        rewrite_first_phantom(value, &[], |nonce| self.resolve(nonce, consumer))
    }
}

/// Rewrite the first phantom found in `value` to its real credential.
///
/// Tries each templated phantom shape in `templates` (whole-span replace so no
/// template literal reaches upstream), then a bare `nono_<64hex>` nonce.
/// `resolve` maps a phantom string to its real value (returning `None` when
/// unknown/unadmitted). Returns the rewritten value, or `None` if nothing
/// resolved — callers forward the original value unchanged (fail-closed). The
/// single implementation keeps the broker and OAuth-capture egress paths in
/// lockstep.
pub fn rewrite_first_phantom(
    value: &str,
    templates: &[PhantomTemplate],
    resolve: impl Fn(&str) -> Option<Zeroizing<Vec<u8>>>,
) -> Option<String> {
    let spans = templates
        .iter()
        .filter_map(|template| template.find_in(value))
        .chain(find_bare_nonce(value));
    for (start, end) in spans {
        if let Some(real) = resolve(&value[start..end])
            && let Ok(real_str) = std::str::from_utf8(&real)
        {
            return Some(format!("{}{}{}", &value[..start], real_str, &value[end..]));
        }
    }
    None
}

/// Byte length of a bare nonce: `"nono_"` (5) + 64 hex chars.
pub const BARE_NONCE_LEN: usize = 5 + 64;

/// Number of hex characters in a minted phantom body (32 bytes → 64 hex).
pub const PHANTOM_BODY_HEX_LEN: usize = 64;

/// A literal template wrapping a minted phantom body, split around the single
/// `{}` placeholder. The visible phantom is `prefix + <body> + suffix`, where
/// `<body>` is [`PHANTOM_BODY_HEX_LEN`] hex characters. Lets a client that
/// classifies a credential by sniffing a literal token prefix recognise the
/// phantom; the template is stripped on egress so it never reaches upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhantomTemplate {
    pub prefix: String,
    pub suffix: String,
}

impl PhantomTemplate {
    /// Parse a template string containing exactly one `{}` placeholder.
    pub fn parse(template: &str) -> std::result::Result<Self, String> {
        let open = template
            .find("{}")
            .ok_or_else(|| format!("format '{template}' must contain the '{{}}' placeholder"))?;
        let prefix = &template[..open];
        let suffix = &template[open + 2..];
        if suffix.contains("{}") {
            return Err(format!(
                "format '{template}' must contain exactly one '{{}}' placeholder"
            ));
        }
        Ok(Self {
            prefix: prefix.to_string(),
            suffix: suffix.to_string(),
        })
    }

    /// Render the visible phantom for a minted `body`.
    #[must_use]
    pub fn render(&self, body: &str) -> String {
        format!("{}{}{}", self.prefix, body, self.suffix)
    }

    /// Whether `real` is consistent with this template's literal prefix and
    /// suffix. A mismatch means the declared `format` no longer matches the
    /// token the provider actually returns (config drift) — the phantom is
    /// still safe (its body is random), but a prefix-sniffing client may
    /// classify it wrongly. Callers log a warning rather than fail, so a
    /// provider-side format change never blocks login.
    #[must_use]
    pub fn matches(&self, real: &str) -> bool {
        real.len() >= self.prefix.len().saturating_add(self.suffix.len())
            && real.starts_with(&self.prefix)
            && real.ends_with(&self.suffix)
    }

    /// Locate the first `prefix + <64hex> + suffix` occurrence in `value`,
    /// returning its `[start, end)` byte range (the whole templated span).
    ///
    /// Slices the underlying bytes, not the `str`, so a crafted header value
    /// whose multibyte UTF-8 straddles the body window cannot panic. The body
    /// is required to be 64 ASCII hex, so a matched span always falls on char
    /// boundaries — the returned range is safe to slice as a `str`.
    #[must_use]
    pub fn find_in(&self, value: &str) -> Option<(usize, usize)> {
        let bytes = value.as_bytes();
        let mut from = 0;
        while let Some(rel) = value.get(from..)?.find(&self.prefix) {
            let pstart = from.checked_add(rel)?;
            let bstart = pstart.checked_add(self.prefix.len())?;
            let bend = bstart.checked_add(PHANTOM_BODY_HEX_LEN)?;
            if bend <= bytes.len()
                && bytes[bstart..bend].iter().all(u8::is_ascii_hexdigit)
                && bytes[bend..].starts_with(self.suffix.as_bytes())
            {
                let send = bend.checked_add(self.suffix.len())?;
                return Some((pstart, send));
            }
            // Advance at least one byte so an empty prefix still terminates.
            from = pstart.checked_add(self.prefix.len().max(1))?;
        }
        None
    }
}

/// Locate the first bare `nono_<64hex>` nonce in `value`, returning its
/// `[start, end)` byte range, or `None` if absent.
///
/// Byte-slices the body window so a crafted value cannot panic on a UTF-8
/// boundary; the 64-hex body guarantees the returned range is char-safe.
#[must_use]
pub fn find_bare_nonce(value: &str) -> Option<(usize, usize)> {
    const NONCE_PREFIX: &str = "nono_";
    let start = value.find(NONCE_PREFIX)?;
    let end = start.checked_add(BARE_NONCE_LEN)?;
    let bytes = value.as_bytes();
    if end > bytes.len() {
        return None;
    }
    let body_start = start.checked_add(NONCE_PREFIX.len())?;
    if !bytes[body_start..end].iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    Some((start, end))
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

/// Enforce proxy authentication, honouring the `require_auth` toggle.
///
/// When `require_auth` is `false` (the standalone `nono proxy --no-auth`
/// case) this is a no-op: the proxy accepts every request without checking
/// the `Proxy-Authorization` header. When `true` it delegates to
/// [`validate_proxy_auth`]. Centralising the toggle here keeps the
/// "skip when disabled" decision in one place rather than at every call site.
pub fn enforce_proxy_auth(
    require_auth: bool,
    header_bytes: &[u8],
    session_token: &Zeroizing<String>,
) -> Result<()> {
    if !require_auth {
        return Ok(());
    }
    validate_proxy_auth(header_bytes, session_token)
}

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

    const HEX64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn phantom_template_parse_requires_placeholder() {
        let err = PhantomTemplate::parse("sk-ant-").unwrap_err();
        assert!(err.contains("must contain the '{}' placeholder"), "{err}");
    }

    #[test]
    fn phantom_template_parse_rejects_multiple_placeholders() {
        assert!(
            PhantomTemplate::parse("a{}b{}c")
                .unwrap_err()
                .contains("exactly one")
        );
        assert!(
            PhantomTemplate::parse("{}{}")
                .unwrap_err()
                .contains("exactly one")
        );
    }

    #[test]
    fn phantom_template_parse_splits_prefix_suffix() {
        let t = PhantomTemplate::parse("sk-ant-oat01-{}").unwrap();
        assert_eq!(t.prefix, "sk-ant-oat01-");
        assert_eq!(t.suffix, "");
        let mid = PhantomTemplate::parse("pre-{}-post").unwrap();
        assert_eq!(mid.prefix, "pre-");
        assert_eq!(mid.suffix, "-post");
    }

    #[test]
    fn phantom_template_render_wraps_body() {
        let t = PhantomTemplate::parse("pre-{}-post").unwrap();
        assert_eq!(t.render("BODY"), "pre-BODY-post");
        // Empty template renders the body unchanged.
        assert_eq!(PhantomTemplate::parse("{}").unwrap().render("BODY"), "BODY");
    }

    #[test]
    fn phantom_template_matches_true_and_drift_false() {
        let t = PhantomTemplate::parse("sk-ant-oat01-{}").unwrap();
        assert!(t.matches("sk-ant-oat01-realtoken"));
        assert!(!t.matches("ghp_somethingelse"));
        let mid = PhantomTemplate::parse("pre-{}-post").unwrap();
        assert!(mid.matches("pre-x-post"));
        assert!(!mid.matches("pre-x")); // missing suffix
    }

    #[test]
    fn phantom_template_matches_length_guard() {
        // prefix+suffix longer than the value must not double-count via
        // starts_with/ends_with overlapping on the same bytes.
        let t = PhantomTemplate::parse("aa{}aa").unwrap();
        assert!(!t.matches("aaa"));
        assert!(t.matches("aaXXaa"));
    }

    #[test]
    fn phantom_template_find_in_locates_span() {
        let t = PhantomTemplate::parse("sk-ant-oat01-{}").unwrap();
        let value = format!("Bearer sk-ant-oat01-{HEX64} trailing");
        let (start, end) = t.find_in(&value).unwrap();
        assert_eq!(&value[start..end], format!("sk-ant-oat01-{HEX64}"));
    }

    #[test]
    fn phantom_template_find_in_with_suffix() {
        let t = PhantomTemplate::parse("pre-{}-post").unwrap();
        let value = format!("x pre-{HEX64}-post y");
        let (start, end) = t.find_in(&value).unwrap();
        assert_eq!(&value[start..end], format!("pre-{HEX64}-post"));
    }

    #[test]
    fn phantom_template_find_in_empty_prefix_terminates() {
        let t = PhantomTemplate::parse("{}").unwrap();
        assert_eq!(t.find_in(HEX64), Some((0, 64)));
        // No 64-hex run: must terminate (not hang) and return None.
        assert_eq!(t.find_in("short"), None);
    }

    #[test]
    fn phantom_template_find_in_too_short_body() {
        let t = PhantomTemplate::parse("sk-ant-oat01-{}").unwrap();
        let value = format!("sk-ant-oat01-{}", &HEX64[..40]);
        assert_eq!(t.find_in(&value), None);
    }

    #[test]
    fn phantom_template_find_in_non_hex_body() {
        let t = PhantomTemplate::parse("sk-ant-oat01-{}").unwrap();
        let value = format!("sk-ant-oat01-{}", "g".repeat(64));
        assert_eq!(t.find_in(&value), None);
    }

    #[test]
    fn phantom_template_find_in_no_match() {
        let t = PhantomTemplate::parse("sk-ant-oat01-{}").unwrap();
        assert_eq!(t.find_in("no prefix here"), None);
        // Prefix + body but wrong suffix.
        let s = PhantomTemplate::parse("pre-{}-post").unwrap();
        assert_eq!(s.find_in(&format!("pre-{HEX64}-WRONG")), None);
    }

    #[test]
    fn phantom_template_find_in_utf8_safe() {
        // A multibyte char straddling the body window must not panic.
        let t = PhantomTemplate::parse("sk-ant-oat01-{}").unwrap();
        let value = format!("sk-ant-oat01-{}€tail", &HEX64[..63]);
        assert_eq!(t.find_in(&value), None);
        // Empty-prefix template over multibyte content also must not panic.
        let empty = PhantomTemplate::parse("{}").unwrap();
        assert_eq!(empty.find_in("héllo wörld with £ and €"), None);
    }

    #[test]
    fn find_bare_nonce_locates_first() {
        let value = format!("a nono_{HEX64} b nono_{HEX64} c");
        let (start, end) = find_bare_nonce(&value).unwrap();
        assert_eq!(&value[start..end], format!("nono_{HEX64}"));
        assert_eq!(start, 2); // first occurrence wins
    }

    #[test]
    fn find_bare_nonce_rejects_truncated() {
        let value = format!("nono_{}", &HEX64[..40]);
        assert_eq!(find_bare_nonce(&value), None);
    }

    #[test]
    fn find_bare_nonce_rejects_non_hex_and_absent() {
        assert_eq!(find_bare_nonce(&format!("nono_{}", "z".repeat(64))), None);
        assert_eq!(find_bare_nonce("no nonce here"), None);
    }

    #[test]
    fn find_bare_nonce_utf8_safe() {
        // Multibyte char right after `nono_` must not panic.
        assert_eq!(find_bare_nonce("nono_€€€€€€€€€€€€€€€€€€€€€€"), None);
    }

    #[test]
    fn rewrite_first_phantom_resolves_bare_nonce() {
        let value = format!("Bearer nono_{HEX64}");
        let out = rewrite_first_phantom(&value, &[], |n| {
            (n == format!("nono_{HEX64}")).then(|| Zeroizing::new(b"REAL".to_vec()))
        });
        assert_eq!(out.as_deref(), Some("Bearer REAL"));
    }

    #[test]
    fn rewrite_first_phantom_resolves_templated_whole_span() {
        let t = PhantomTemplate::parse("sk-ant-oat01-{}").unwrap();
        let phantom = format!("sk-ant-oat01-{HEX64}");
        let value = format!("Bearer {phantom}");
        let out = rewrite_first_phantom(&value, std::slice::from_ref(&t), |n| {
            (n == phantom).then(|| Zeroizing::new(b"sk-ant-oat01-REAL".to_vec()))
        });
        // Whole templated span replaced; no leftover template literal.
        assert_eq!(out.as_deref(), Some("Bearer sk-ant-oat01-REAL"));
    }

    #[test]
    fn rewrite_first_phantom_none_when_unresolved() {
        let value = format!("Bearer nono_{HEX64}");
        assert_eq!(rewrite_first_phantom(&value, &[], |_| None), None);
        assert_eq!(rewrite_first_phantom("no phantom", &[], |_| None), None);
    }

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

    #[test]
    fn test_enforce_proxy_auth_disabled_accepts_missing_header() {
        let token = Zeroizing::new("abc123".to_string());
        // With auth disabled, even a header with no Proxy-Authorization passes.
        let header = b"Host: example.com\r\n\r\n";
        assert!(enforce_proxy_auth(false, header, &token).is_ok());
    }

    #[test]
    fn test_enforce_proxy_auth_disabled_accepts_wrong_token() {
        let token = Zeroizing::new("abc123".to_string());
        let header = b"Proxy-Authorization: Bearer wrong\r\n\r\n";
        assert!(enforce_proxy_auth(false, header, &token).is_ok());
    }

    #[test]
    fn test_enforce_proxy_auth_enabled_delegates_valid() {
        let token = Zeroizing::new("abc123".to_string());
        let header = b"Proxy-Authorization: Bearer abc123\r\n\r\n";
        assert!(enforce_proxy_auth(true, header, &token).is_ok());
    }

    #[test]
    fn test_enforce_proxy_auth_enabled_delegates_invalid() {
        let token = Zeroizing::new("abc123".to_string());
        let header = b"Proxy-Authorization: Bearer wrong\r\n\r\n";
        assert!(enforce_proxy_auth(true, header, &token).is_err());
    }
}
