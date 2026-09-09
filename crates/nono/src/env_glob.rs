//! Shared glob matching for environment variable names.
//!
//! Environment variable name patterns appear in more than one place: the
//! allow/deny lists that decide which variables a sandboxed child inherits,
//! and the redaction patterns that decide which names and values are scrubbed
//! from diagnostics and audit output. Those two must agree — a pattern that
//! denies a variable in one place and fails to redact it in the other is a
//! silent hole — so the grammar lives here once rather than being
//! reimplemented per call site.
//!
//! The grammar is deliberately minimal: `*` is the only wildcard, it matches
//! any run of zero or more characters, and the match is anchored to the full
//! name. There are no character classes, no `?`, and no escaping, so a
//! pattern can never match a proper substring of a name by accident.

/// Whether `text` matches `pattern`.
///
/// `*` may appear anywhere in `pattern` — leading, trailing, or infix — and
/// matches any run of zero or more characters: `"AWS_*"`, `"*_TOKEN"`,
/// `"*SECRET*"`, and `"AWS_*_TOKEN"` are all valid. A bare `"*"` matches
/// everything. Every other character matches literally, and the match is
/// anchored to the full string, so `"ACME_*"` does not match
/// `"XACME_API_KEY"`.
///
/// An empty pattern never matches. It is invalid input, and treating it as
/// "no constraint" would silently turn into match-all at every call site.
///
/// Matching is byte-exact; callers that want case-insensitive behavior
/// lowercase both sides before calling (see
/// [`str::to_ascii_lowercase`](str::to_ascii_lowercase)).
pub fn env_var_glob_matches(pattern: &str, text: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }
    // `split('*')` always yields at least one item, so the `unwrap_or_default`
    // below is unreachable; a pattern with no `*` is just an exact match.
    let mut parts = pattern.split('*').peekable();
    let first = parts.next().unwrap_or_default();
    let Some(mut rest) = text.strip_prefix(first) else {
        return false;
    };
    if parts.peek().is_none() {
        // No `*`: exact full-string match.
        return rest.is_empty();
    }
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            // Last segment: must match the remaining text as a suffix.
            return rest.ends_with(part);
        }
        if part.is_empty() {
            continue;
        }
        match rest.find(part) {
            Some(idx) => rest = &rest[idx.saturating_add(part.len())..],
            None => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::env_var_glob_matches as matches;

    #[test]
    fn exact_pattern_matches_only_the_whole_name() {
        assert!(matches("ACME_TOKEN", "ACME_TOKEN"));
        assert!(!matches("ACME_TOKEN", "ACME_TOKEN_2"));
        assert!(!matches("ACME_TOKEN", "MY_ACME_TOKEN"));
    }

    #[test]
    fn trailing_star_is_anchored_at_the_start() {
        assert!(matches("ACME_*", "ACME_API_KEY"));
        assert!(matches("ACME_*", "ACME_"));
        // The anchoring case a substring matcher would get wrong.
        assert!(!matches("ACME_*", "XACME_API_KEY"));
        assert!(!matches("ACME_*", "MY_ACME_API_KEY"));
    }

    #[test]
    fn leading_star_is_anchored_at_the_end() {
        assert!(matches("*_TOKEN", "ACME_TOKEN"));
        assert!(matches("*_TOKEN", "_TOKEN"));
        assert!(!matches("*_TOKEN", "ACME_TOKEN_ID"));
    }

    #[test]
    fn infix_star_requires_both_ends() {
        assert!(matches("AWS_*_TOKEN", "AWS_SESSION_TOKEN"));
        assert!(matches("AWS_*_TOKEN", "AWS__TOKEN"));
        assert!(!matches("AWS_*_TOKEN", "GCP_SESSION_TOKEN"));
        assert!(!matches("AWS_*_TOKEN", "AWS_SESSION_TOKEN_ID"));
    }

    #[test]
    fn surrounding_stars_match_a_substring() {
        assert!(matches("*SECRET*", "MY_SECRET_VALUE"));
        assert!(matches("*SECRET*", "SECRET"));
        assert!(!matches("*SECRET*", "MY_TOKEN"));
    }

    #[test]
    fn bare_star_matches_everything_including_empty() {
        assert!(matches("*", "ANYTHING"));
        assert!(matches("*", ""));
    }

    #[test]
    fn empty_pattern_never_matches() {
        assert!(!matches("", "ANYTHING"));
        assert!(!matches("", ""));
    }

    #[test]
    fn matching_is_byte_exact_so_callers_normalize_case() {
        assert!(!matches("acme_*", "ACME_API_KEY"));
        assert!(matches("acme_*", "acme_api_key"));
    }

    #[test]
    fn consecutive_stars_collapse() {
        assert!(matches("ACME_**KEY", "ACME_API_KEY"));
        assert!(matches("**", "ANYTHING"));
    }
}
