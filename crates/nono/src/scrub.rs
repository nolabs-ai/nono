//! Best-effort redaction for values that may be written to diagnostics or audit records.
//!
//! This module is output hygiene, not sandbox policy. It intentionally favors
//! false positives for well-known secret-bearing flag, header, and query names.

use crate::env_glob::env_var_glob_matches;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::BTreeSet;

const REDACTED: &str = "[REDACTED]";

const SENSITIVE_FLAGS: &[&str] = &[
    "--token",
    "--password",
    "--api-key",
    "--apikey",
    "--secret",
    "--auth",
    "--bearer",
    "--access-token",
    "--client-secret",
];

const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
    "cookie",
    "set-cookie",
];

const SENSITIVE_QUERY_KEYS: &[&str] = &[
    "token",
    "access_token",
    "api_key",
    "apikey",
    "key",
    "secret",
    "password",
    "code",
    "state",
    "nonce",
    "client_secret",
];

const SENSITIVE_ENV_VARS: &[&str] = &[
    "ANTHROPIC_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AZURE_OPENAI_API_KEY",
    "COHERE_API_KEY",
    "GEMINI_API_KEY",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GOOGLE_API_KEY",
    "HUGGINGFACE_API_TOKEN",
    "MISTRAL_API_KEY",
    "NONO_PROXY_TOKEN",
    "OPENAI_API_KEY",
    "TOGETHER_API_KEY",
];

/// Redaction policy for diagnostics and persisted command context.
///
/// The secure default policy redacts well-known secret-bearing flags,
/// headers, URL query keys, and common secret-bearing environment variable
/// names. Callers may add entries for local tools, or explicitly remove
/// defaults when they need unsafe debugging output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScrubPolicy {
    sensitive_flags: BTreeSet<String>,
    sensitive_headers: BTreeSet<String>,
    sensitive_query_keys: BTreeSet<String>,
    sensitive_env_vars: BTreeSet<String>,
    /// Glob patterns matched against environment variable names, in addition
    /// to the exact names in `sensitive_env_vars`. Empty in the secure
    /// default: patterns exist so callers can describe families of
    /// credential variables their own tooling injects.
    sensitive_env_var_patterns: BTreeSet<String>,
}

/// Difference between a scrub policy and the secure default policy.
///
/// This is intended for audit records so a session can explain why its
/// persisted command context was scrubbed differently from the default.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScrubPolicyDiff {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added_flags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed_flags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added_headers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed_headers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added_query_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed_query_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added_env_vars: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed_env_vars: Vec<String>,
}

impl ScrubPolicyDiff {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added_flags.is_empty()
            && self.removed_flags.is_empty()
            && self.added_headers.is_empty()
            && self.removed_headers.is_empty()
            && self.added_query_keys.is_empty()
            && self.removed_query_keys.is_empty()
            && self.added_env_vars.is_empty()
            && self.removed_env_vars.is_empty()
    }

    #[must_use]
    pub fn into_option(self) -> Option<Self> {
        if self.is_empty() { None } else { Some(self) }
    }
}

impl Default for ScrubPolicy {
    fn default() -> Self {
        Self::secure_default()
    }
}

impl ScrubPolicy {
    #[must_use]
    pub fn secure_default() -> Self {
        Self {
            sensitive_flags: normalized_set(SENSITIVE_FLAGS),
            sensitive_headers: normalized_set(SENSITIVE_HEADERS),
            sensitive_query_keys: normalized_set(SENSITIVE_QUERY_KEYS),
            sensitive_env_vars: normalized_set(SENSITIVE_ENV_VARS),
            sensitive_env_var_patterns: BTreeSet::new(),
        }
    }

    pub fn add_flag(&mut self, flag: impl AsRef<str>) {
        insert_normalized(&mut self.sensitive_flags, flag.as_ref());
    }

    pub fn add_header(&mut self, header: impl AsRef<str>) {
        insert_normalized(&mut self.sensitive_headers, header.as_ref());
    }

    pub fn add_query_key(&mut self, key: impl AsRef<str>) {
        insert_normalized(&mut self.sensitive_query_keys, key.as_ref());
    }

    pub fn add_env_var(&mut self, name: impl AsRef<str>) {
        insert_normalized(&mut self.sensitive_env_vars, name.as_ref());
    }

    /// Redact any environment variable whose name matches `pattern`.
    ///
    /// `*` matches any run of zero or more characters and is the only
    /// wildcard; matching is anchored to the whole name and is ASCII
    /// case-insensitive. An empty pattern is ignored rather than treated as
    /// match-all. There is deliberately no removal counterpart: patterns can
    /// only widen redaction.
    pub fn add_env_var_pattern(&mut self, pattern: impl AsRef<str>) {
        insert_normalized(&mut self.sensitive_env_var_patterns, pattern.as_ref());
    }

    pub fn remove_flag(&mut self, flag: &str) {
        remove_normalized(&mut self.sensitive_flags, flag);
    }

    pub fn remove_header(&mut self, header: &str) {
        remove_normalized(&mut self.sensitive_headers, header);
    }

    pub fn remove_query_key(&mut self, key: &str) {
        remove_normalized(&mut self.sensitive_query_keys, key);
    }

    pub fn remove_env_var(&mut self, name: &str) {
        remove_normalized(&mut self.sensitive_env_vars, name);
    }

    #[must_use]
    pub fn diff_from_secure_default(&self) -> ScrubPolicyDiff {
        let default = Self::secure_default();
        ScrubPolicyDiff {
            added_flags: set_difference(&self.sensitive_flags, &default.sensitive_flags),
            removed_flags: set_difference(&default.sensitive_flags, &self.sensitive_flags),
            added_headers: set_difference(&self.sensitive_headers, &default.sensitive_headers),
            removed_headers: set_difference(&default.sensitive_headers, &self.sensitive_headers),
            added_query_keys: set_difference(
                &self.sensitive_query_keys,
                &default.sensitive_query_keys,
            ),
            removed_query_keys: set_difference(
                &default.sensitive_query_keys,
                &self.sensitive_query_keys,
            ),
            // Exact names and glob patterns are reported in one list rather
            // than a new public field, which would be a breaking change to
            // this struct. A pattern is self-describing: `*` cannot occur in a
            // POSIX environment variable name, so an entry containing one is
            // a pattern and an entry without one is an exact name.
            added_env_vars: {
                let mut added =
                    set_difference(&self.sensitive_env_vars, &default.sensitive_env_vars);
                added.extend(set_difference(
                    &self.sensitive_env_var_patterns,
                    &default.sensitive_env_var_patterns,
                ));
                added.sort();
                added.dedup();
                added
            },
            removed_env_vars: set_difference(&default.sensitive_env_vars, &self.sensitive_env_vars),
        }
    }

    fn is_sensitive_flag(&self, flag: &str) -> bool {
        contains_normalized_ascii(&self.sensitive_flags, flag)
    }

    fn is_sensitive_header(&self, name: &str) -> bool {
        contains_normalized_ascii(&self.sensitive_headers, name)
    }

    fn is_sensitive_query_key(&self, name: &str) -> bool {
        contains_normalized_ascii(&self.sensitive_query_keys, name)
    }

    fn is_sensitive_env_var(&self, name: &str) -> bool {
        contains_normalized_ascii(&self.sensitive_env_vars, name)
            || matches_normalized_glob(&self.sensitive_env_var_patterns, name)
    }
}

/// Redact sensitive values in a single string.
///
/// Handles URL userinfo, sensitive URL query parameters, and complete HTTP
/// header lines such as `Authorization: Bearer ...`.
#[must_use]
pub fn scrub_value(s: &str) -> Cow<'_, str> {
    scrub_value_with_policy(s, &ScrubPolicy::secure_default())
}

/// Redact sensitive values in a single string using a configured policy.
#[must_use]
pub fn scrub_value_with_policy<'a>(s: &'a str, policy: &ScrubPolicy) -> Cow<'a, str> {
    let header_scrubbed = scrub_header_line(s, policy);
    let url_scrubbed = scrub_url_userinfo(header_scrubbed.as_ref());
    let query_scrubbed = scrub_query_params(url_scrubbed.as_ref(), policy);

    if &*query_scrubbed == s {
        Cow::Borrowed(s)
    } else {
        Cow::Owned(query_scrubbed.into_owned())
    }
}

/// Redact an environment variable name when it is sensitive.
#[must_use]
pub fn scrub_env_name<'a>(name: &'a str) -> Cow<'a, str> {
    scrub_env_name_with_policy(name, &ScrubPolicy::secure_default())
}

/// Redact an environment variable name with a configured policy.
#[must_use]
pub fn scrub_env_name_with_policy<'a>(name: &'a str, policy: &ScrubPolicy) -> Cow<'a, str> {
    if policy.is_sensitive_env_var(name) {
        Cow::Borrowed(REDACTED)
    } else {
        Cow::Borrowed(name)
    }
}

/// Redact an environment variable value when its name is sensitive.
#[must_use]
pub fn scrub_env_value<'a>(name: &str, value: &'a str) -> Cow<'a, str> {
    scrub_env_value_with_policy(name, value, &ScrubPolicy::secure_default())
}

/// Redact an environment variable value with a configured policy.
#[must_use]
pub fn scrub_env_value_with_policy<'a>(
    name: &str,
    value: &'a str,
    policy: &ScrubPolicy,
) -> Cow<'a, str> {
    if policy.is_sensitive_env_var(name) {
        Cow::Borrowed(REDACTED)
    } else {
        scrub_value_with_policy(value, policy)
    }
}

/// Redact sensitive values across an argv vector.
///
/// Sensitive flags with a following value redact that value. Sensitive
/// `--flag=value` forms redact only the value side. Header flags redact their
/// following value only when the header name itself is sensitive.
#[must_use]
pub fn scrub_argv(args: &[String]) -> Vec<String> {
    scrub_argv_with_policy(args, &ScrubPolicy::secure_default())
}

/// Redact sensitive values across an argv vector using a configured policy.
#[must_use]
pub fn scrub_argv_with_policy(args: &[String], policy: &ScrubPolicy) -> Vec<String> {
    let mut scrubbed = Vec::with_capacity(args.len());
    let mut redact_next = false;
    let mut scrub_next_header = false;

    for arg in args {
        if redact_next {
            scrubbed.push(REDACTED.to_string());
            redact_next = false;
            continue;
        }

        if scrub_next_header {
            scrubbed.push(scrub_header_arg(arg, policy).into_owned());
            scrub_next_header = false;
            continue;
        }

        if policy.is_sensitive_flag(arg) {
            scrubbed.push(arg.clone());
            redact_next = true;
            continue;
        }

        if is_header_flag(arg) {
            scrubbed.push(arg.clone());
            scrub_next_header = true;
            continue;
        }

        if let Some((name, value)) = arg.split_once('=') {
            if policy.is_sensitive_flag(name) {
                scrubbed.push(format!("{name}={REDACTED}"));
                continue;
            }

            if is_header_flag(name) {
                scrubbed.push(format!("{name}={}", scrub_header_arg(value, policy)));
                continue;
            }
        }

        scrubbed.push(scrub_value_with_policy(arg, policy).into_owned());
    }

    scrubbed
}

/// Redact an HTTP header value when its name is sensitive.
#[must_use]
pub fn scrub_header<'a>(name: &str, value: &'a str) -> Cow<'a, str> {
    scrub_header_with_policy(name, value, &ScrubPolicy::secure_default())
}

/// Redact an HTTP header value with a configured policy when its name is sensitive.
#[must_use]
pub fn scrub_header_with_policy<'a>(
    name: &str,
    value: &'a str,
    policy: &ScrubPolicy,
) -> Cow<'a, str> {
    if policy.is_sensitive_header(name) {
        Cow::Borrowed(REDACTED)
    } else {
        Cow::Borrowed(value)
    }
}

fn scrub_header_arg<'a>(value: &'a str, policy: &ScrubPolicy) -> Cow<'a, str> {
    if let Some((name, header_value)) = value.split_once(':') {
        let scrubbed = scrub_header_with_policy(name.trim(), header_value.trim_start(), policy);
        if &*scrubbed != header_value.trim_start() {
            return Cow::Owned(format!("{}: {}", name, scrubbed));
        }
    }
    scrub_value_with_policy(value, policy)
}

fn scrub_header_line<'a>(value: &'a str, policy: &ScrubPolicy) -> Cow<'a, str> {
    let Some((name, header_value)) = value.split_once(':') else {
        return Cow::Borrowed(value);
    };

    let trimmed_name = name.trim();
    if !policy.is_sensitive_header(trimmed_name) {
        return Cow::Borrowed(value);
    }

    let leading = &header_value[..header_value.len() - header_value.trim_start().len()];
    Cow::Owned(format!("{name}:{leading}{REDACTED}"))
}

fn scrub_url_userinfo(value: &str) -> Cow<'_, str> {
    if !value.contains("://") {
        return Cow::Borrowed(value);
    }

    let mut result = String::with_capacity(value.len());
    let mut changed = false;
    let mut cursor = 0;

    while let Some(relative_scheme_end) = value[cursor..].find("://") {
        let scheme_end = cursor + relative_scheme_end;
        let authority_start = scheme_end + 3;
        let authority_end = value[authority_start..]
            .find(['/', '?', '#', ' ', '\t', '\r', '\n'])
            .map_or(value.len(), |offset| authority_start + offset);

        let authority = &value[authority_start..authority_end];
        if let Some(at_offset) = authority.rfind('@') {
            let userinfo = &authority[..at_offset];
            if let Some((user, _password)) = userinfo.split_once(':') {
                result.push_str(&value[cursor..authority_start]);
                result.push_str(user);
                result.push(':');
                result.push_str(REDACTED);
                result.push('@');
                result.push_str(&authority[at_offset + 1..]);
                cursor = authority_end;
                changed = true;
                continue;
            }
        }

        result.push_str(&value[cursor..authority_end]);
        cursor = authority_end;
    }

    if changed {
        result.push_str(&value[cursor..]);
        Cow::Owned(result)
    } else {
        Cow::Borrowed(value)
    }
}

fn scrub_query_params<'a>(value: &'a str, policy: &ScrubPolicy) -> Cow<'a, str> {
    if !value.contains('?') {
        return Cow::Borrowed(value);
    }

    let mut result = String::with_capacity(value.len());
    let mut cursor = 0;
    let mut changed = false;

    while let Some(relative_query_start) = value[cursor..].find('?') {
        let query_start = cursor + relative_query_start;
        result.push_str(&value[cursor..=query_start]);

        let query_end = value[query_start + 1..]
            .find(['#', ' ', '\t', '\r', '\n'])
            .map_or(value.len(), |offset| query_start + 1 + offset);
        let query = &value[query_start + 1..query_end];

        let mut segment_start = 0;
        for (idx, ch) in query.char_indices() {
            if matches!(ch, '&' | ';') {
                let segment = &query[segment_start..idx];
                changed |= push_scrubbed_query_segment(&mut result, segment, policy);
                result.push(ch);
                segment_start = idx + ch.len_utf8();
            }
        }
        let segment = &query[segment_start..];
        changed |= push_scrubbed_query_segment(&mut result, segment, policy);

        cursor = query_end;
    }

    result.push_str(&value[cursor..]);

    if changed {
        Cow::Owned(result)
    } else {
        Cow::Borrowed(value)
    }
}

fn push_scrubbed_query_segment(result: &mut String, segment: &str, policy: &ScrubPolicy) -> bool {
    let Some((name, _value)) = segment.split_once('=') else {
        result.push_str(segment);
        return false;
    };

    if policy.is_sensitive_query_key(name) {
        result.push_str(name);
        result.push('=');
        result.push_str(REDACTED);
        true
    } else {
        result.push_str(segment);
        false
    }
}

fn is_header_flag(flag: &str) -> bool {
    flag == "-H" || flag.eq_ignore_ascii_case("--header")
}

fn normalized_set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| normalize_name(value)).collect()
}

fn normalize_name(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn insert_normalized(set: &mut BTreeSet<String>, value: &str) {
    let normalized = normalize_name(value);
    if !normalized.is_empty() {
        set.insert(normalized);
    }
}

fn remove_normalized(set: &mut BTreeSet<String>, value: &str) {
    set.remove(normalize_name(value).as_str());
}

fn contains_normalized_ascii(set: &BTreeSet<String>, value: &str) -> bool {
    let trimmed = value.trim();
    set.iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(trimmed))
}

/// Whether `value` matches any glob in `patterns`.
///
/// Patterns are stored already normalized (trimmed, lowercased), so only the
/// candidate needs normalizing here. The glob grammar itself is
/// [`env_var_glob_matches`], shared with the environment allow/deny lists so
/// the two cannot drift.
fn matches_normalized_glob(patterns: &BTreeSet<String>, value: &str) -> bool {
    if patterns.is_empty() {
        return false;
    }
    let normalized = normalize_name(value);
    patterns
        .iter()
        .any(|pattern| env_var_glob_matches(pattern, &normalized))
}

fn set_difference(left: &BTreeSet<String>, right: &BTreeSet<String>) -> Vec<String> {
    left.difference(right).cloned().collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn scrub_value_leaves_safe_strings_unchanged() {
        let value = "https://example.com/path?format=json";
        assert!(matches!(scrub_value(value), Cow::Borrowed(_)));
        assert_eq!(scrub_value(value), value);
    }

    #[test]
    fn scrub_value_redacts_url_userinfo() {
        assert_eq!(
            scrub_value("https://alice:secret@example.com/api"),
            "https://alice:[REDACTED]@example.com/api"
        );
    }

    #[test]
    fn scrub_value_redacts_sensitive_query_parameters() {
        assert_eq!(
            scrub_value("https://example.com/api?token=abc&format=json&nonce=xyz"),
            "https://example.com/api?token=[REDACTED]&format=json&nonce=[REDACTED]"
        );
    }

    #[test]
    fn scrub_header_redacts_sensitive_header_values() {
        assert_eq!(scrub_header("Authorization", "Bearer secret"), REDACTED);
        assert_eq!(scrub_header("X-Api-Key", "secret"), REDACTED);
        assert_eq!(
            scrub_header("Accept", "application/json"),
            "application/json"
        );
    }

    #[test]
    fn scrub_argv_redacts_sensitive_flag_pairs_and_equals_forms() {
        let args = vec![
            "curl".to_string(),
            "--token".to_string(),
            "secret-token".to_string(),
            "--api-key=secret-key".to_string(),
            "--format=json".to_string(),
        ];

        assert_eq!(
            scrub_argv(&args),
            vec![
                "curl".to_string(),
                "--token".to_string(),
                REDACTED.to_string(),
                format!("--api-key={REDACTED}"),
                "--format=json".to_string(),
            ]
        );
    }

    #[test]
    fn scrub_argv_redacts_sensitive_header_arguments() {
        let args = vec![
            "curl".to_string(),
            "-H".to_string(),
            "Authorization: Bearer secret".to_string(),
            "--header=X-Api-Key: secret".to_string(),
            "-H".to_string(),
            "Accept: application/json".to_string(),
        ];

        assert_eq!(
            scrub_argv(&args),
            vec![
                "curl".to_string(),
                "-H".to_string(),
                "Authorization: [REDACTED]".to_string(),
                "--header=X-Api-Key: [REDACTED]".to_string(),
                "-H".to_string(),
                "Accept: application/json".to_string(),
            ]
        );
    }

    #[test]
    fn scrub_policy_adds_local_sensitive_names() {
        let mut redactions = ScrubPolicy::secure_default();
        redactions.add_flag("--private-token");
        redactions.add_header("Private-Token");
        redactions.add_query_key("signature");
        redactions.add_env_var("CONFIGURED_ENV");

        let args = vec![
            "curl".to_string(),
            "--private-token=secret".to_string(),
            "-H".to_string(),
            "Private-Token: secret".to_string(),
            "https://example.com/api?signature=secret&format=json".to_string(),
        ];

        assert_eq!(
            scrub_argv_with_policy(&args, &redactions),
            vec![
                "curl".to_string(),
                format!("--private-token={REDACTED}"),
                "-H".to_string(),
                "Private-Token: [REDACTED]".to_string(),
                "https://example.com/api?signature=[REDACTED]&format=json".to_string(),
            ]
        );

        assert_eq!(
            scrub_env_value_with_policy("CONFIGURED_ENV", "redacted-value", &redactions),
            REDACTED
        );
        assert_eq!(
            scrub_env_value_with_policy("OBSERVED_ENV", "visible-value", &redactions),
            "visible-value"
        );
    }

    #[test]
    fn scrub_policy_env_var_patterns_redact_matching_names() {
        let mut redactions = ScrubPolicy::secure_default();
        redactions.add_env_var_pattern("ACME_*");
        redactions.add_env_var_pattern("*_DEPLOY_SECRET");

        for name in ["ACME_API_KEY", "acme_app_key", "STAGING_DEPLOY_SECRET"] {
            assert_eq!(
                scrub_env_value_with_policy(name, "tool-secret", &redactions),
                REDACTED,
                "{name} should have been redacted by pattern"
            );
            assert_eq!(scrub_env_name_with_policy(name, &redactions), REDACTED);
        }

        assert_eq!(
            scrub_env_value_with_policy("ACMEISH", "visible-value", &redactions),
            "visible-value"
        );
        assert_eq!(
            scrub_env_value_with_policy("PATH", "/usr/bin", &redactions),
            "/usr/bin"
        );
    }

    #[test]
    fn secure_default_has_no_env_var_patterns() {
        let redactions = ScrubPolicy::secure_default();
        assert_eq!(
            scrub_env_value_with_policy("ACME_API_KEY", "tool-secret", &redactions),
            "tool-secret",
            "patterns must be opt-in; the secure default ships none"
        );
        assert!(redactions.diff_from_secure_default().is_empty());
    }

    #[test]
    fn empty_env_var_pattern_is_ignored_not_match_all() {
        let mut redactions = ScrubPolicy::secure_default();
        redactions.add_env_var_pattern("");
        redactions.add_env_var_pattern("   ");

        assert_eq!(
            scrub_env_value_with_policy("PATH", "/usr/bin", &redactions),
            "/usr/bin"
        );
        assert!(
            redactions
                .diff_from_secure_default()
                .added_env_vars
                .is_empty()
        );
    }

    #[test]
    fn bare_star_env_var_pattern_redacts_everything() {
        let mut redactions = ScrubPolicy::secure_default();
        redactions.add_env_var_pattern("*");
        assert_eq!(
            scrub_env_value_with_policy("PATH", "/usr/bin", &redactions),
            REDACTED
        );
    }

    #[test]
    fn env_var_patterns_are_reported_in_the_policy_diff() {
        let mut redactions = ScrubPolicy::secure_default();
        redactions.add_env_var_pattern("ACME_*");

        let diff = redactions.diff_from_secure_default();
        assert_eq!(diff.added_env_vars, vec!["acme_*".to_string()]);
        assert!(!diff.is_empty());
    }

    #[test]
    fn env_var_patterns_cannot_unredact_a_secure_default() {
        // Patterns are add-only: there is no removal counterpart, and adding
        // one must never widen what is visible.
        let mut redactions = ScrubPolicy::secure_default();
        redactions.add_env_var_pattern("ACME_*");
        assert_eq!(
            scrub_env_value_with_policy("OPENAI_API_KEY", "provider-secret", &redactions),
            REDACTED
        );
    }

    #[test]
    fn secure_default_redacts_common_provider_env_vars() {
        let redactions = ScrubPolicy::secure_default();
        for name in ["OPENAI_API_KEY", "GEMINI_API_KEY"] {
            assert_eq!(scrub_env_name_with_policy(name, &redactions), REDACTED);
            assert_eq!(
                scrub_env_value_with_policy(name, "provider-secret", &redactions),
                REDACTED
            );
        }
    }

    #[test]
    fn scrub_policy_can_remove_defaults_for_unsafe_debugging() {
        let mut redactions = ScrubPolicy::secure_default();
        redactions.remove_query_key("state");

        assert_eq!(
            scrub_value_with_policy(
                "https://example.com/callback?state=debug&token=secret",
                &redactions
            ),
            "https://example.com/callback?state=debug&token=[REDACTED]"
        );

        let diff = redactions.diff_from_secure_default();
        assert!(diff.added_query_keys.is_empty());
        assert_eq!(diff.removed_query_keys, vec!["state".to_string()]);
    }
}
