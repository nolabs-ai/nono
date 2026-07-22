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
    /// Resolve the phantom `nonce` — a bare `nono_<64hex>` or a full templated
    /// phantom — for `consumer` (`"proxy.<route_id>"`). `None` is fail-closed.
    fn resolve(&self, nonce: &str, consumer: &str) -> Option<Zeroizing<Vec<u8>>>;

    /// Substitute the real credential for any phantom this resolver minted. The
    /// default recognises only a bare `nono_<64hex>`; resolvers that mint templated
    /// phantoms override it to pass their templates to [`rewrite_first_phantom`].
    fn rewrite_header_value(&self, value: &str, consumer: &str) -> Option<String> {
        rewrite_first_phantom(value, &[], |nonce| self.resolve(nonce, consumer))
    }

    /// Whether `value` carries a phantom this resolver would try to rewrite.
    /// Callers gate a fail-closed error on it, so an override here is mandatory
    /// wherever [`Self::rewrite_header_value`] is overridden — a narrower answer
    /// forwards the phantom upstream unrewritten.
    fn contains_phantom(&self, value: &str) -> bool {
        contains_phantom(value.as_bytes(), &[])
    }
}

/// Whether `bytes` carries a phantom [`rewrite_first_phantom`] would try to
/// resolve. Kept in step with its span search: a narrower answer lets a caller
/// gating on it forward the phantom upstream unrewritten.
#[must_use]
pub fn contains_phantom(bytes: &[u8], templates: &[PhantomTemplate]) -> bool {
    (0..bytes.len()).any(|start| {
        bare_nonce_at(bytes, start).is_some()
            || templates
                .iter()
                .any(|template| template.matches_at(bytes, start).is_some())
    })
}

/// Every phantom span in `value`, earliest first and longest first at a tie —
/// a shorter overlapping span would leave template literal behind.
fn phantom_spans(value: &str, templates: &[PhantomTemplate]) -> Vec<(usize, usize)> {
    let bytes = value.as_bytes();
    let mut spans: Vec<(usize, usize)> = (0..bytes.len())
        .flat_map(|start| {
            templates
                .iter()
                .filter_map(move |template| Some((start, template.matches_at(bytes, start)?)))
                .chain(bare_nonce_at(bytes, start).map(|end| (start, end)))
        })
        .collect();
    spans.sort_unstable_by_key(|&(start, end)| (start, std::cmp::Reverse(end)));
    spans
}

/// Rewrite the first resolvable phantom in `value` to its real credential,
/// replacing the whole templated span so no template literal reaches upstream.
/// `None` means nothing resolved and the caller forwards `value` unchanged.
pub fn rewrite_first_phantom(
    value: &str,
    templates: &[PhantomTemplate],
    resolve: impl Fn(&str) -> Option<Zeroizing<Vec<u8>>>,
) -> Option<String> {
    for (start, end) in phantom_spans(value, templates) {
        if let Some(real) = resolve(&value[start..end])
            && let Ok(real_str) = std::str::from_utf8(&real)
            // Result is interpolated into raw `name: value\r\n`, so CR/LF/NUL in
            // the secret would split the upstream request. Fail closed instead.
            && !real_str.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0))
        {
            return Some(format!("{}{}{}", &value[..start], real_str, &value[end..]));
        }
    }
    None
}

/// Prefix marking a bare broker nonce.
pub const BARE_NONCE_PREFIX: &str = "nono_";

/// Byte length of a bare nonce: `"nono_"` + 64 hex chars.
pub const BARE_NONCE_LEN: usize = BARE_NONCE_PREFIX.len() + PHANTOM_BODY_HEX_LEN;

/// Number of hex characters in a minted phantom body (32 bytes → 64 hex).
pub const PHANTOM_BODY_HEX_LEN: usize = 64;

/// A `prefix + <64 hex body> + suffix` phantom shape, split around the single
/// `{}` placeholder. Exists so a client that classifies a credential by
/// sniffing a literal token prefix recognises the phantom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhantomTemplate {
    pub prefix: String,
    pub suffix: String,
}

impl PhantomTemplate {
    /// Parse a template containing exactly one `{}`. Control bytes are rejected: a
    /// rendered phantom lands in env-var entries, where CR/LF smuggles headers.
    pub fn parse(template: &str) -> std::result::Result<Self, String> {
        if template.bytes().any(|b| b.is_ascii_control()) {
            return Err(format!(
                "format '{template}' must not contain control characters"
            ));
        }
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
        if prefix.is_empty() {
            return Err(format!(
                "format '{template}' must have a non-empty prefix before '{{}}', or any 64-hex-char run (e.g. a commit hash) would false-match as a phantom"
            ));
        }
        Ok(Self {
            prefix: prefix.to_string(),
            suffix: suffix.to_string(),
        })
    }

    /// Byte length of any phantom rendered from this template.
    #[must_use]
    pub fn rendered_len(&self) -> usize {
        self.prefix
            .len()
            .saturating_add(PHANTOM_BODY_HEX_LEN)
            .saturating_add(self.suffix.len())
    }

    /// Render the visible phantom for a minted `body`.
    #[must_use]
    pub fn render(&self, body: &str) -> String {
        format!("{}{}{}", self.prefix, body, self.suffix)
    }

    /// Whether `real` fits this template. A mismatch means the declared `format`
    /// drifted from the provider's; callers warn rather than fail, so a
    /// provider-side change never blocks login.
    #[must_use]
    pub fn matches(&self, real: &str) -> bool {
        real.len() >= self.prefix.len().saturating_add(self.suffix.len())
            && real.starts_with(&self.prefix)
            && real.ends_with(&self.suffix)
    }

    /// If a phantom starts exactly at `offset` in `bytes`, return its end. Takes
    /// bytes so multibyte UTF-8 straddling the body window cannot panic; a matched
    /// span is all-ASCII and safe to slice back as a `str`.
    #[must_use]
    pub fn matches_at(&self, bytes: &[u8], offset: usize) -> Option<usize> {
        if !bytes.get(offset..)?.starts_with(self.prefix.as_bytes()) {
            return None;
        }
        let body_start = offset.checked_add(self.prefix.len())?;
        let body_end = body_start.checked_add(PHANTOM_BODY_HEX_LEN)?;
        if !bytes
            .get(body_start..body_end)?
            .iter()
            .all(u8::is_ascii_hexdigit)
            || !bytes.get(body_end..)?.starts_with(self.suffix.as_bytes())
        {
            return None;
        }
        body_end.checked_add(self.suffix.len())
    }

    /// Locate the first templated phantom in `value`, returning its
    /// `[start, end)` byte range (the whole templated span).
    #[must_use]
    pub fn find_in(&self, value: &str) -> Option<(usize, usize)> {
        let bytes = value.as_bytes();
        (0..bytes.len()).find_map(|start| Some((start, self.matches_at(bytes, start)?)))
    }
}

/// Locate the first bare `nono_<64hex>` nonce in `value` as a `[start, end)`
/// byte range. Byte-slices the body window so multibyte UTF-8 cannot panic.
#[must_use]
pub fn find_bare_nonce(value: &str) -> Option<(usize, usize)> {
    let bytes = value.as_bytes();
    (0..bytes.len()).find_map(|start| Some((start, bare_nonce_at(bytes, start)?)))
}

/// If a bare nonce starts exactly at `offset` in `bytes`, return its end. The
/// bytes counterpart of [`PhantomTemplate::matches_at`] for the untemplated shape.
fn bare_nonce_at(bytes: &[u8], offset: usize) -> Option<usize> {
    if !bytes
        .get(offset..)?
        .starts_with(BARE_NONCE_PREFIX.as_bytes())
    {
        return None;
    }
    let body_start = offset.checked_add(BARE_NONCE_PREFIX.len())?;
    let end = offset.checked_add(BARE_NONCE_LEN)?;
    bytes
        .get(body_start..end)?
        .iter()
        .all(u8::is_ascii_hexdigit)
        .then_some(end)
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
            PhantomTemplate::parse("a{}{}")
                .unwrap_err()
                .contains("exactly one")
        );
    }

    #[test]
    fn phantom_template_parse_rejects_empty_prefix() {
        // An empty prefix (and empty suffix) lets any 64-hex-char run — a commit
        // hash, a SHA-256 digest — false-match as a phantom.
        let err = PhantomTemplate::parse("{}").unwrap_err();
        assert!(err.contains("non-empty prefix"), "{err}");
    }

    #[test]
    fn rewrite_first_phantom_prefers_earliest_span() {
        // The bare nonce comes first in the value but last in the candidate
        // order; position must win.
        let template = PhantomTemplate::parse("sk-ant-oat01-{}").unwrap();
        let value = format!("nono_{HEX64} and sk-ant-oat01-{HEX64}");
        let rewritten = rewrite_first_phantom(&value, std::slice::from_ref(&template), |_| {
            Some(Zeroizing::new(b"REAL".to_vec()))
        })
        .unwrap();
        assert_eq!(rewritten, format!("REAL and sk-ant-oat01-{HEX64}"));
    }

    #[test]
    fn phantom_template_rendered_len_counts_prefix_and_suffix() {
        for template in ["x{}", "pre-{}-post", "sk-ant-oat01-{}"] {
            let template = PhantomTemplate::parse(template).unwrap();
            assert_eq!(template.rendered_len(), template.render(HEX64).len());
        }
    }

    #[test]
    fn phantom_template_parse_rejects_control_characters() {
        for bad in ["a\r\nX: y{}", "a\0{}", "a\t{}"] {
            let err = PhantomTemplate::parse(bad).unwrap_err();
            assert!(err.contains("must not contain control characters"), "{err}");
        }
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
        // No suffix: the body is wrapped by the prefix alone.
        assert_eq!(
            PhantomTemplate::parse("x{}").unwrap().render("BODY"),
            "xBODY"
        );
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
    fn phantom_template_find_in_single_char_prefix_terminates() {
        let t = PhantomTemplate::parse("x{}").unwrap();
        assert_eq!(t.find_in(&format!("x{HEX64}")), Some((0, 65)));
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
        // Single-char-prefix template over multibyte content also must not panic.
        let short = PhantomTemplate::parse("x{}").unwrap();
        assert_eq!(short.find_in("héllo wörld with £ and €"), None);
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
    fn rewrite_first_phantom_rejects_control_bytes_in_resolved_value() {
        let template = PhantomTemplate::parse("sk-ant-oat01-{}").unwrap();
        let bare = format!("Bearer nono_{HEX64}");
        let templated = format!("Bearer sk-ant-oat01-{HEX64}");
        for evil in ["a\r\nX-Injected: y", "a\nb", "a\0b"] {
            let resolve = |_: &str| Some(Zeroizing::new(evil.as_bytes().to_vec()));
            assert_eq!(
                rewrite_first_phantom(&bare, &[], resolve),
                None,
                "bare nonce must fail closed on {evil:?}"
            );
            assert_eq!(
                rewrite_first_phantom(&templated, std::slice::from_ref(&template), resolve),
                None,
                "templated phantom must fail closed on {evil:?}"
            );
        }
    }

    /// An earlier value of the same shape that resolves for nobody must not
    /// shadow a later real phantom — every match is a candidate, not just the
    /// first per template.
    #[test]
    fn rewrite_first_phantom_skips_unresolvable_earlier_match() {
        let template = PhantomTemplate::parse("sk-ant-oat01-{}").unwrap();
        let decoy = format!("sk-ant-oat01-{}", "b".repeat(64));
        let real_phantom = format!("sk-ant-oat01-{HEX64}");
        let value = format!("{decoy} {real_phantom}");
        let out = rewrite_first_phantom(&value, std::slice::from_ref(&template), |n| {
            (n == real_phantom).then(|| Zeroizing::new(b"REAL".to_vec()))
        });
        assert_eq!(out, Some(format!("{decoy} REAL")));
    }

    #[test]
    fn contains_phantom_matches_what_rewrite_would_try() {
        let template = PhantomTemplate::parse("sk-ant-oat01-{}").unwrap();
        let templates = std::slice::from_ref(&template);
        assert!(contains_phantom(
            format!("Bearer nono_{HEX64}").as_bytes(),
            &[]
        ));
        // A templated phantom carries no `nono_` marker.
        let templated = format!("Bearer sk-ant-oat01-{HEX64}");
        assert!(!contains_phantom(templated.as_bytes(), &[]));
        assert!(contains_phantom(templated.as_bytes(), templates));
        assert!(!contains_phantom(b"Bearer plain-token", templates));
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
