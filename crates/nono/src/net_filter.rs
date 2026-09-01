//! Network host filtering for proxy-level domain matching.
//!
//! This module provides application-layer host filtering that complements
//! the OS-level port restrictions from [`CapabilitySet`](crate::CapabilitySet).
//! The proxy uses [`HostFilter`] to decide whether to allow or deny CONNECT
//! requests based on hostname allowlists and a cloud metadata deny list.
//!
//! # Security Properties
//!
//! - **Cloud metadata endpoints are hardcoded and non-overridable**: Instance
//!   metadata services (169.254.169.254, metadata.google.internal, etc.) are
//!   always denied regardless of allowlist configuration.
//! - **Link-local IP protection**: Resolved IPs in the link-local range
//!   (169.254.0.0/16, fe80::/10) are always denied to prevent DNS rebinding
//!   attacks targeting cloud metadata services.
//! - **Wildcard subdomain matching**: `*.googleapis.com` matches
//!   `storage.googleapis.com` but not `googleapis.com` itself. A `*` may
//!   also occupy a whole label in a non-leading position, matching exactly
//!   one label there — see [`host_pattern_matches`].
//! - **Normalized comparison**: hostnames are IDNA-normalized before
//!   matching, so a trailing dot, mixed case, or Unicode/punycode spelling
//!   can't slip past a deny entry. Unparseable hosts are denied.

use std::net::IpAddr;

/// Normalize a hostname for deny/allow-list comparison: strips a trailing
/// FQDN dot, rejects control characters, and applies IDNA/punycode
/// normalization (which also lowercases). Fails on malformed input rather
/// than falling back to a raw string compare.
fn normalize_host(host: &str) -> Result<String, idna::Errors> {
    let trimmed = host.trim().trim_end_matches('.');
    if trimmed.chars().any(char::is_control) {
        return Err(idna::Errors::default());
    }
    let ascii = idna::domain_to_ascii(trimmed)?;
    // domain_to_ascii folds Unicode label separators (e.g. U+3002) to ASCII
    // '.', so a trailing one only shows up as a dot after this call.
    Ok(ascii.trim_end_matches('.').to_string())
}

/// Normalize a stored filter entry, falling back to a plain trim/lowercase
/// on malformed input. Unlike `normalize_host`, this never fails: an inert
/// (non-matching) entry is safe on both the allow and deny side, since
/// `check_host` denies any incoming host that fails normalization anyway.
fn normalize_entry(entry: &str) -> String {
    normalize_host(entry).unwrap_or_else(|_| entry.trim().trim_end_matches('.').to_lowercase())
}

/// Whether `host` matches `pattern` under nono's hostname wildcard grammar.
/// Both must already be normalized (lowercased) the same way, e.g. via
/// [`normalize_entry`].
///
/// Three wildcard forms are supported:
/// - A bare `*` matches any non-empty host, regardless of label count.
/// - A leading `*.` matches one or more labels (subdomain wildcard):
///   `*.example.com` matches `a.example.com` and `a.b.example.com`, but not
///   `example.com` itself.
/// - `*` occupying an entire label in any other position matches exactly
///   one non-empty label: `jenkins.*.ci.example.com` matches
///   `jenkins.prod.ci.example.com`, but not `jenkins.ci.example.com` or
///   `jenkins.a.b.ci.example.com`.
///
/// A `*` that only occupies part of a label (`foo*bar`) is not a wildcard;
/// since a real hostname label can never contain `*`, such a pattern never
/// matches anything.
#[must_use]
pub fn host_pattern_matches(pattern: &str, host: &str) -> bool {
    // A bare "*" matches any non-empty host, regardless of label count.
    if pattern == "*" {
        return !host.is_empty();
    }

    if let Some(suffix) = pattern.strip_prefix('*') {
        if !suffix.starts_with('.') {
            return false;
        }
        let Some(prefix) = host.strip_suffix(suffix) else {
            return false;
        };
        // Require a real (non-empty) label before the suffix: `idna` lets
        // through empty DNS labels, so `prefix` ending in `.` (e.g. from
        // `..example.com`) must not count as "one or more labels".
        return !prefix.is_empty() && !prefix.ends_with('.');
    }

    let mut pattern_labels = pattern.split('.');
    let mut host_labels = host.split('.');
    loop {
        match (pattern_labels.next(), host_labels.next()) {
            (Some(p), Some(h)) => {
                // `idna` lets through empty labels (e.g. `jenkins..ci...`),
                // so an empty `h` here must not satisfy the wildcard.
                if p == "*" {
                    if h.is_empty() {
                        return false;
                    }
                } else if p != h {
                    return false;
                }
            }
            (None, None) => return true,
            _ => return false,
        }
    }
}

/// Validates that `pattern` is a well-formed entry under the wildcard grammar
/// documented on [`host_pattern_matches`], returning `Err` with a description
/// of the problem if not. A pattern outside that grammar can never match any
/// real hostname.
pub fn validate_host_pattern(pattern: &str) -> Result<(), String> {
    if pattern.is_empty() {
        return Err("pattern is empty".to_string());
    }
    if pattern == "*" {
        return Ok(());
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        if !suffix.starts_with('.') {
            return Err(format!(
                "pattern '{pattern}': a leading '*' must be followed by '.' (e.g. '*.example.com')"
            ));
        }
        let rest = &suffix[1..];
        if rest.is_empty() {
            return Err(format!(
                "pattern '{pattern}': '*.' must be followed by a domain"
            ));
        }
        if rest.contains('*') {
            return Err(format!(
                "pattern '{pattern}': a leading '*.' wildcard cannot be combined with another '*' \
                 elsewhere in the pattern — the remainder is matched literally, so this can never match"
            ));
        }
        return Ok(());
    }
    for label in pattern.split('.') {
        if label.contains('*') && label != "*" {
            return Err(format!(
                "pattern '{pattern}': '*' must occupy a whole label (e.g. 'a.*.b.com'), not part of \
                 one like '{label}' — a real hostname label can never contain '*', so this can never match"
            ));
        }
    }
    Ok(())
}

/// Result of a host filter check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterResult {
    /// Host is allowed by the allowlist
    Allow,
    /// Host is denied because a specific hostname is in the deny list
    DenyHost {
        /// The hostname that was denied
        host: String,
    },
    /// Host is denied because a resolved IP is in the link-local range
    DenyLinkLocal {
        /// The resolved IP that matched the link-local range
        ip: IpAddr,
    },
    /// Host is not in the allowlist (default deny)
    DenyNotAllowed {
        /// The hostname that was not found in any allowlist
        host: String,
    },
}

impl FilterResult {
    /// Whether the result is an allow decision
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, FilterResult::Allow)
    }

    /// A human-readable reason for the decision
    ///
    /// The host is untrusted, attacker-controlled input (it may not even have
    /// passed [`normalize_host`]), and this string is printed directly to
    /// terminals/logs by callers. Control characters (including the ESC that
    /// begins an ANSI escape sequence) are stripped so a malicious hostname
    /// can't spoof or hijack terminal output.
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            FilterResult::Allow => "allowed by host filter".to_string(),
            FilterResult::DenyHost { host } => {
                format!("host {} is in the deny list", sanitize_for_display(host))
            }
            FilterResult::DenyLinkLocal { ip } => {
                format!(
                    "resolved IP {} is in the link-local range (cloud metadata protection)",
                    ip
                )
            }
            FilterResult::DenyNotAllowed { host } => {
                format!(
                    "host {} is not in the allowlist",
                    sanitize_for_display(host)
                )
            }
        }
    }
}

/// Strip control characters (including ESC, which begins ANSI/CSI escape
/// sequences) from untrusted text before it is embedded in a
/// terminal-displayed or logged string.
fn sanitize_for_display(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

/// Check if an IP address is in the link-local range.
///
/// Link-local addresses are used by cloud metadata services (169.254.169.254)
/// and must be blocked to prevent DNS rebinding SSRF attacks.
///
/// - IPv4: 169.254.0.0/16
/// - IPv6: fe80::/10
/// - IPv4-mapped IPv6: ::ffff:169.254.x.x (prevents bypass via AAAA records)
fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.octets()[0] == 169 && v4.octets()[1] == 254,
        IpAddr::V6(v6) => {
            if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            // Check IPv4-mapped IPv6 (::ffff:x.x.x.x) to prevent bypass
            // via attacker-controlled AAAA records pointing to link-local IPs
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.octets()[0] == 169 && v4.octets()[1] == 254;
            }
            false
        }
    }
}

/// Hosts that are always denied regardless of allowlist configuration.
/// These are cloud metadata endpoints commonly targeted for SSRF attacks.
const DENY_HOSTS: &[&str] = &[
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.azure.internal",
];

/// Split raw host entries into normalized exact hosts and normalized
/// wildcard patterns (anything containing `*`), the categorization shared
/// by every constructor of [`HostFilter`].
fn partition_hosts(entries: &[String]) -> (Vec<String>, Vec<String>) {
    let mut exact = Vec::new();
    let mut patterns = Vec::new();
    for entry in entries {
        if entry.contains('*') {
            patterns.push(normalize_entry(entry));
        } else {
            exact.push(normalize_entry(entry));
        }
    }
    (exact, patterns)
}

/// A filter for host-based network access control.
///
/// Supports exact domain match and wildcard subdomains (`*.googleapis.com`).
///
/// Cloud metadata endpoints are always denied and cannot be overridden.
/// The allowlist determines which hosts are permitted; everything else
/// is denied by default.
#[derive(Debug, Clone)]
pub struct HostFilter {
    /// Allowed exact hosts (lowercased)
    allowed_hosts: Vec<String>,
    /// Allowed wildcard patterns (e.g., `*.googleapis.com`, `jenkins.*.ci.example.com`), lowercased
    allowed_patterns: Vec<String>,
    /// Exact hostnames that are always denied
    deny_hosts: Vec<String>,
    /// Wildcard patterns that are always denied (e.g., `*.ads.example.com`)
    deny_patterns: Vec<String>,
    /// When true, an empty allowlist denies instead of allowing.
    strict: bool,
}

impl HostFilter {
    /// Create a new host filter with the given allowed hosts.
    ///
    /// Cloud metadata endpoints are automatically denied and cannot be removed.
    ///
    /// Entries containing `*` are treated as wildcard patterns (see
    /// [`host_pattern_matches`]). All other entries are exact matches.
    /// Matching is case-insensitive.
    #[must_use]
    pub fn new(allowed_hosts: &[String]) -> Self {
        let (exact, patterns) = partition_hosts(allowed_hosts);

        Self {
            allowed_hosts: exact,
            allowed_patterns: patterns,
            deny_hosts: DENY_HOSTS.iter().map(|s| normalize_entry(s)).collect(),
            deny_patterns: Vec::new(),
            strict: false,
        }
    }

    /// Create a strict host filter: empty allowlist denies everything.
    #[must_use]
    pub fn new_strict(allowed_hosts: &[String]) -> Self {
        let mut filter = Self::new(allowed_hosts);
        filter.strict = true;
        filter
    }

    /// Create a host filter that allows everything (no filtering).
    ///
    /// Cloud metadata endpoints are still blocked.
    #[must_use]
    pub fn allow_all() -> Self {
        Self {
            allowed_hosts: Vec::new(),
            allowed_patterns: Vec::new(),
            deny_hosts: DENY_HOSTS.iter().map(|s| normalize_entry(s)).collect(),
            deny_patterns: Vec::new(),
            strict: false,
        }
    }

    /// Append user-configured deny entries on top of the hardcoded deny list.
    ///
    /// Supports the same wildcard syntax as the allowlist (see
    /// [`host_pattern_matches`]).
    #[must_use]
    pub fn with_denied_hosts(mut self, denied: &[String]) -> Self {
        let (exact, patterns) = partition_hosts(denied);
        self.deny_hosts.extend(exact);
        self.deny_patterns.extend(patterns);
        self
    }

    /// Check a host against the filter.
    ///
    /// `resolved_ips` should contain the DNS-resolved IP addresses for the host.
    /// The caller is responsible for performing DNS resolution before calling this
    /// method. This prevents DNS rebinding attacks: the proxy resolves once, checks
    /// the resolved IPs here, then connects to the same resolved IP.
    ///
    /// # Check Order
    ///
    /// 1. Deny hosts (exact match against cloud metadata hostnames)
    /// 2. Link-local IP check (resolved IPs in 169.254.0.0/16 or fe80::/10)
    /// 3. Allowlist (exact host match, then wildcard subdomain match)
    /// 4. Default deny (if not in allowlist and allowlist is non-empty)
    #[must_use]
    pub fn check_host(&self, host: &str, resolved_ips: &[IpAddr]) -> FilterResult {
        // 0. Normalize the incoming host (trailing-dot FQDN, case, Unicode/punycode).
        // Malformed input is denied rather than compared raw.
        let Ok(lower_host) = normalize_host(host) else {
            return FilterResult::DenyNotAllowed {
                host: host.to_string(),
            };
        };

        // 1. Check deny hosts (exact match)
        if self.deny_hosts.contains(&lower_host) {
            return FilterResult::DenyHost {
                host: host.to_string(),
            };
        }

        // 1b. Check deny patterns (wildcard match, e.g. *.ads.example.com)
        if self
            .deny_patterns
            .iter()
            .any(|pattern| host_pattern_matches(pattern, &lower_host))
        {
            return FilterResult::DenyHost {
                host: host.to_string(),
            };
        }

        // 2. Check resolved IPs for link-local addresses (cloud metadata protection)
        for ip in resolved_ips {
            if is_link_local(ip) {
                return FilterResult::DenyLinkLocal { ip: *ip };
            }
        }

        // 3. Empty allowlist: deny when strict, allow otherwise.
        if self.allowed_hosts.is_empty() && self.allowed_patterns.is_empty() {
            if self.strict {
                return FilterResult::DenyNotAllowed {
                    host: host.to_string(),
                };
            }
            return FilterResult::Allow;
        }

        // 4. Check exact host match
        if self.allowed_hosts.contains(&lower_host) {
            return FilterResult::Allow;
        }

        // 5. Check wildcard pattern match
        if self
            .allowed_patterns
            .iter()
            .any(|pattern| host_pattern_matches(pattern, &lower_host))
        {
            return FilterResult::Allow;
        }

        // 6. Not in allowlist
        FilterResult::DenyNotAllowed {
            host: host.to_string(),
        }
    }

    /// Check only the deny list, skipping the allowlist (which a wildcard
    /// `*` would otherwise satisfy before a port-scoped deny is checked).
    pub fn check_deny(&self, host: &str) -> Option<FilterResult> {
        // Infallible: deny_hosts/deny_patterns are populated via the same
        // fallback (normalize_entry), so a fallible lookup here could miss
        // an entry that IDNA rejects (e.g. a host:port or IPv6 literal).
        let lower_host = normalize_entry(host);

        if self.deny_hosts.contains(&lower_host) {
            return Some(FilterResult::DenyHost {
                host: host.to_string(),
            });
        }

        if self
            .deny_patterns
            .iter()
            .any(|pattern| host_pattern_matches(pattern, &lower_host))
        {
            return Some(FilterResult::DenyHost {
                host: host.to_string(),
            });
        }

        None
    }

    /// Normalize a host before embedding it in a `host:port` string, so a
    /// trailing dot can't land past where normalization looks for it.
    #[must_use]
    pub fn normalize_authority_host(host: &str) -> String {
        normalize_entry(host)
    }

    /// Number of allowed hosts (exact + wildcard)
    #[must_use]
    pub fn allowed_count(&self) -> usize {
        self.allowed_hosts
            .len()
            .saturating_add(self.allowed_patterns.len())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn public_ip() -> Vec<IpAddr> {
        vec![IpAddr::V4(Ipv4Addr::new(104, 18, 7, 96))]
    }

    #[test]
    fn test_validate_host_pattern_accepts_all_three_wildcard_forms() {
        assert!(validate_host_pattern("*").is_ok());
        assert!(validate_host_pattern("*.example.com").is_ok());
        assert!(validate_host_pattern("jenkins.*.ci.example.com").is_ok());
        assert!(validate_host_pattern("api.openai.com").is_ok());
    }

    #[test]
    fn test_validate_host_pattern_rejects_empty() {
        assert!(validate_host_pattern("").is_err());
    }

    #[test]
    fn test_validate_host_pattern_rejects_partial_label_wildcard() {
        assert!(validate_host_pattern("foo*bar.com").is_err());
        assert!(validate_host_pattern("foo.ba*r.com").is_err());
    }

    #[test]
    fn test_validate_host_pattern_rejects_bare_leading_star_without_dot() {
        assert!(validate_host_pattern("*example.com").is_err());
    }

    #[test]
    fn test_validate_host_pattern_rejects_dangling_leading_wildcard() {
        assert!(validate_host_pattern("*.").is_err());
    }

    #[test]
    fn test_validate_host_pattern_rejects_leading_wildcard_combined_with_another() {
        assert!(validate_host_pattern("*.foo.*.com").is_err());
    }

    #[test]
    fn test_exact_host_allowed() {
        let filter = HostFilter::new(&["api.openai.com".to_string()]);
        let result = filter.check_host("api.openai.com", &public_ip());
        assert!(result.is_allowed());
    }

    #[test]
    fn test_exact_host_case_insensitive() {
        let filter = HostFilter::new(&["API.OpenAI.COM".to_string()]);
        let result = filter.check_host("api.openai.com", &public_ip());
        assert!(result.is_allowed());
    }

    #[test]
    fn test_host_not_in_allowlist() {
        let filter = HostFilter::new(&["api.openai.com".to_string()]);
        let result = filter.check_host("evil.com", &public_ip());
        assert!(!result.is_allowed());
        assert!(matches!(result, FilterResult::DenyNotAllowed { .. }));
    }

    #[test]
    fn test_wildcard_subdomain_match() {
        let filter = HostFilter::new(&["*.googleapis.com".to_string()]);

        // Subdomain should match
        let result = filter.check_host("storage.googleapis.com", &public_ip());
        assert!(result.is_allowed());

        // Deep subdomain should match
        let result = filter.check_host("us-central1-aiplatform.googleapis.com", &public_ip());
        assert!(result.is_allowed());
    }

    #[test]
    fn test_wildcard_does_not_match_bare_domain() {
        let filter = HostFilter::new(&["*.googleapis.com".to_string()]);

        // Bare domain should NOT match wildcard
        let result = filter.check_host("googleapis.com", &public_ip());
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_partial_label_wildcard_never_matches() {
        // profile-authoring-guide.md: a `*` occupying only part of a label
        // (`jenkins-*.example.com`) is not a wildcard and can never match,
        // since a real hostname label never contains `*`.
        assert!(!host_pattern_matches(
            "jenkins-*.example.com",
            "jenkins-prod.example.com"
        ));
    }

    #[test]
    fn test_leading_wildcard_rejects_empty_label_before_suffix() {
        // "*.example.com" requires one or more non-empty labels; a
        // double-dot host must not satisfy that via an empty label.
        assert!(!host_pattern_matches("*.example.com", "..example.com"));
        assert!(!host_pattern_matches("*.example.com", "a..example.com"));
        assert!(host_pattern_matches("*.example.com", "a.example.com"));
        assert!(host_pattern_matches("*.example.com", "a.b.example.com"));
    }

    #[test]
    fn test_non_leading_wildcard_label_matches_exactly_one_label() {
        let filter = HostFilter::new(&["jenkins.*.ci.example.com".to_string()]);

        assert!(
            filter
                .check_host("jenkins.prod.ci.example.com", &public_ip())
                .is_allowed()
        );
        assert!(
            filter
                .check_host("jenkins.stage.ci.example.com", &public_ip())
                .is_allowed()
        );

        // Zero labels in the wildcard slot: no match.
        assert!(
            !filter
                .check_host("jenkins.ci.example.com", &public_ip())
                .is_allowed()
        );
        // Two labels in the wildcard slot: no match.
        assert!(
            !filter
                .check_host("jenkins.foo.bar.ci.example.com", &public_ip())
                .is_allowed()
        );
        // Different fixed labels: no match.
        assert!(
            !filter
                .check_host("other.prod.ci.example.com", &public_ip())
                .is_allowed()
        );
    }

    #[test]
    fn test_non_leading_wildcard_label_rejects_empty_label() {
        // The wildcard slot must require a real (non-empty) label, not a
        // double-dot's empty one.
        assert!(!host_pattern_matches(
            "jenkins.*.ci.example.com",
            "jenkins..ci.example.com"
        ));
    }

    #[test]
    fn test_non_leading_wildcard_label_deny() {
        let filter =
            HostFilter::allow_all().with_denied_hosts(&["jenkins.*.ci.example.com".to_string()]);

        assert!(
            !filter
                .check_host("jenkins.prod.ci.example.com", &public_ip())
                .is_allowed()
        );
        assert!(
            filter
                .check_host("jenkins.ci.example.com", &public_ip())
                .is_allowed()
        );
    }

    #[test]
    fn test_deny_cloud_metadata_hostname() {
        let filter = HostFilter::new(&["169.254.169.254".to_string()]);

        // Should be denied even if in allowlist
        let result = filter.check_host("169.254.169.254", &public_ip());
        assert!(!result.is_allowed());
        assert!(matches!(result, FilterResult::DenyHost { .. }));
    }

    #[test]
    fn test_deny_google_metadata() {
        let filter = HostFilter::new(&["metadata.google.internal".to_string()]);
        let result = filter.check_host("metadata.google.internal", &public_ip());
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_allow_all_mode() {
        // No allowlist = allow all (except deny list)
        let filter = HostFilter::allow_all();
        let result = filter.check_host("any-host.example.com", &public_ip());
        assert!(result.is_allowed());
    }

    #[test]
    fn test_allow_all_allows_private_networks() {
        let filter = HostFilter::allow_all();
        // RFC1918 addresses are allowed for enterprise use
        let private_ip = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];
        let result = filter.check_host("internal.corp.com", &private_ip);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_allow_all_allows_192_168() {
        let filter = HostFilter::allow_all();
        let private_ip = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))];
        let result = filter.check_host("nas.local", &private_ip);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_deny_link_local_ipv4() {
        let filter = HostFilter::new(&["*.example.com".to_string()]);
        let link_local = vec![IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))];
        let result = filter.check_host("api.example.com", &link_local);
        assert!(!result.is_allowed());
        assert!(matches!(result, FilterResult::DenyLinkLocal { .. }));
    }

    #[test]
    fn test_deny_link_local_ipv6() {
        let filter = HostFilter::new(&["*.example.com".to_string()]);
        let link_local = vec![IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))];
        let result = filter.check_host("api.example.com", &link_local);
        assert!(!result.is_allowed());
        assert!(matches!(result, FilterResult::DenyLinkLocal { .. }));
    }

    #[test]
    fn test_deny_ipv4_mapped_ipv6_link_local() {
        // Attacker returns AAAA record ::ffff:169.254.169.254 to bypass IPv4 check
        let filter = HostFilter::new(&["attacker.com".to_string()]);
        let mapped = vec![IpAddr::V6(Ipv6Addr::new(
            0, 0, 0, 0, 0, 0xffff, 0xa9fe, 0xa9fe,
        ))];
        let result = filter.check_host("attacker.com", &mapped);
        assert!(!result.is_allowed());
        assert!(matches!(result, FilterResult::DenyLinkLocal { .. }));
    }

    #[test]
    fn test_deny_ipv4_mapped_ipv6_other_link_local() {
        // Any link-local in mapped form must be caught
        let filter = HostFilter::allow_all();
        let mapped = vec![IpAddr::V6(Ipv6Addr::new(
            0, 0, 0, 0, 0, 0xffff, 0xa9fe, 0x0001,
        ))];
        let result = filter.check_host("evil.com", &mapped);
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_ipv4_mapped_ipv6_non_link_local_allowed() {
        // ::ffff:104.18.7.96 is a public IP in mapped form — should be allowed
        let filter = HostFilter::allow_all();
        let mapped = vec![IpAddr::V6(Ipv6Addr::new(
            0, 0, 0, 0, 0, 0xffff, 0x6812, 0x0760,
        ))];
        let result = filter.check_host("example.com", &mapped);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_dns_rebinding_to_metadata_ip() {
        // Attacker's domain resolves to cloud metadata IP — must be blocked
        let filter = HostFilter::new(&["attacker.com".to_string()]);
        let metadata_ip = vec![IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))];
        let result = filter.check_host("attacker.com", &metadata_ip);
        assert!(!result.is_allowed());
        assert!(matches!(result, FilterResult::DenyLinkLocal { .. }));
    }

    #[test]
    fn test_dns_rebinding_allow_all_blocked() {
        // Even in allow_all mode, link-local IPs are blocked
        let filter = HostFilter::allow_all();
        let metadata_ip = vec![IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))];
        let result = filter.check_host("evil.com", &metadata_ip);
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_empty_resolved_ips_skips_link_local_check() {
        let filter = HostFilter::new(&["api.openai.com".to_string()]);
        // No resolved IPs = skip link-local check, just check hostname
        let result = filter.check_host("api.openai.com", &[]);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_multiple_ips_any_link_local_denied() {
        let filter = HostFilter::new(&["multi.example.com".to_string()]);
        // First IP is public, second is link-local
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(104, 18, 7, 96)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 0, 1)),
        ];
        let result = filter.check_host("multi.example.com", &ips);
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_user_deny_host_exact() {
        let filter = HostFilter::allow_all().with_denied_hosts(&["evil.com".to_string()]);
        let result = filter.check_host("evil.com", &public_ip());
        assert!(!result.is_allowed());
        assert!(matches!(result, FilterResult::DenyHost { .. }));
    }

    #[test]
    fn test_user_deny_host_does_not_affect_others() {
        let filter = HostFilter::allow_all().with_denied_hosts(&["evil.com".to_string()]);
        let result = filter.check_host("good.com", &public_ip());
        assert!(result.is_allowed());
    }

    #[test]
    fn test_user_deny_host_wildcard() {
        let filter = HostFilter::allow_all().with_denied_hosts(&["*.ads.example.com".to_string()]);
        assert!(
            !filter
                .check_host("tracker.ads.example.com", &public_ip())
                .is_allowed()
        );
        assert!(
            !filter
                .check_host("pixel.ads.example.com", &public_ip())
                .is_allowed()
        );
        // bare domain must NOT match wildcard
        assert!(
            filter
                .check_host("ads.example.com", &public_ip())
                .is_allowed()
        );
    }

    #[test]
    fn test_user_deny_beats_allowlist() {
        let filter =
            HostFilter::new(&["evil.com".to_string()]).with_denied_hosts(&["evil.com".to_string()]);
        let result = filter.check_host("evil.com", &public_ip());
        assert!(!result.is_allowed());
        assert!(matches!(result, FilterResult::DenyHost { .. }));
    }

    #[test]
    fn test_user_deny_case_insensitive() {
        let filter = HostFilter::allow_all().with_denied_hosts(&["Evil.COM".to_string()]);
        let result = filter.check_host("evil.com", &public_ip());
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_check_deny_matches_host_port_entry() {
        let filter = HostFilter::allow_all().with_denied_hosts(&["127.0.0.1:8975".to_string()]);

        // The deny-only check must match the exact host:port string...
        assert!(matches!(
            filter.check_deny("127.0.0.1:8975"),
            Some(FilterResult::DenyHost { .. })
        ));
        // ...but not the bare host, since the deny entry is port-scoped.
        assert!(filter.check_deny("127.0.0.1").is_none());
        // ...and not an unrelated port on the same host.
        assert!(filter.check_deny("127.0.0.1:8787").is_none());
    }

    #[test]
    fn test_check_deny_ignores_allowlist() {
        // check_deny only ever returns a deny verdict or None; it never
        // consults the allowlist, unlike check_host.
        let filter = HostFilter::new(&["good.com".to_string()]);
        assert!(filter.check_deny("good.com").is_none());
        assert!(filter.check_deny("anything-else.com").is_none());
    }

    #[test]
    fn test_allowed_count() {
        let filter = HostFilter::new(&[
            "api.openai.com".to_string(),
            "*.googleapis.com".to_string(),
            "github.com".to_string(),
        ]);
        assert_eq!(filter.allowed_count(), 3);
    }

    #[test]
    fn test_filter_result_reason() {
        let allow = FilterResult::Allow;
        assert!(allow.reason().contains("allowed"));

        let deny = FilterResult::DenyNotAllowed {
            host: "evil.com".to_string(),
        };
        assert!(deny.reason().contains("evil.com"));
    }

    #[test]
    fn test_filter_result_reason_strips_terminal_escape_sequences() {
        // A malicious hostname could smuggle ANSI escapes to spoof/hijack
        // terminal output when the reason is printed by callers.
        let deny = FilterResult::DenyNotAllowed {
            host: "evil\x1b[31mFAKE ADMIN PROMPT\x1b[0m.com".to_string(),
        };
        let reason = deny.reason();
        assert!(!reason.contains('\x1b'));
        assert!(reason.contains("evil"));
        assert!(reason.contains("FAKE ADMIN PROMPT"));

        let deny_host = FilterResult::DenyHost {
            host: "\x07evil.com".to_string(),
        };
        assert!(!deny_host.reason().contains('\x07'));

        let link_local = FilterResult::DenyLinkLocal {
            ip: IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
        };
        assert!(link_local.reason().contains("link-local"));
    }

    #[test]
    fn test_strict_filter_empty_allowlist_denies() {
        let filter = HostFilter::new_strict(&[]);
        let result = filter.check_host("example.com", &public_ip());
        assert!(matches!(result, FilterResult::DenyNotAllowed { .. }));
    }

    #[test]
    fn test_strict_filter_respects_explicit_allowlist() {
        let filter = HostFilter::new_strict(&["api.openai.com".to_string()]);
        let allowed = filter.check_host("api.openai.com", &public_ip());
        assert!(matches!(allowed, FilterResult::Allow));

        let denied = filter.check_host("evil.com", &public_ip());
        assert!(matches!(denied, FilterResult::DenyNotAllowed { .. }));
    }

    #[test]
    fn test_non_strict_empty_allowlist_allows() {
        let filter = HostFilter::new(&[]);
        let result = filter.check_host("example.com", &public_ip());
        assert!(matches!(result, FilterResult::Allow));
    }

    #[test]
    fn test_trailing_dot_bypass_on_hardcoded_metadata_deny() {
        let filter = HostFilter::allow_all();
        let result = filter.check_host("metadata.google.internal.", &public_ip());
        assert!(!result.is_allowed());
        assert!(matches!(result, FilterResult::DenyHost { .. }));

        let result = filter.check_host("metadata.azure.internal.", &public_ip());
        assert!(!result.is_allowed());
        assert!(matches!(result, FilterResult::DenyHost { .. }));
    }

    #[test]
    fn test_trailing_dot_bypass_on_user_deny_entry() {
        let filter = HostFilter::allow_all().with_denied_hosts(&["evil.com".to_string()]);
        let result = filter.check_host("evil.com.", &public_ip());
        assert!(!result.is_allowed());
        assert!(matches!(result, FilterResult::DenyHost { .. }));
    }

    #[test]
    fn test_trailing_dot_on_deny_entry_itself_still_matches() {
        // A trailing dot on the *configured* deny entry should normalize the
        // same way as a trailing dot on the incoming host.
        let filter = HostFilter::allow_all().with_denied_hosts(&["evil.com.".to_string()]);
        let result = filter.check_host("evil.com", &public_ip());
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_unicode_and_punycode_deny_entries_are_equivalent() {
        // Denying the Unicode form must also deny requests spelled in punycode.
        let filter = HostFilter::allow_all().with_denied_hosts(&["münchen.de".to_string()]);
        let result = filter.check_host("xn--mnchen-3ya.de", &public_ip());
        assert!(!result.is_allowed());

        // And denying the punycode form must also deny the Unicode spelling.
        let filter = HostFilter::allow_all().with_denied_hosts(&["xn--mnchen-3ya.de".to_string()]);
        let result = filter.check_host("münchen.de", &public_ip());
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_unicode_dns_label_separators_normalize_like_dot() {
        // U+3002 IDEOGRAPHIC FULL STOP is DNS-equivalent to '.'.
        let filter = HostFilter::allow_all().with_denied_hosts(&["evil.com".to_string()]);
        let result = filter.check_host("evil\u{3002}com", &public_ip());
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_trailing_unicode_label_separator_bypass_on_metadata_deny() {
        // Trailing U+3002 only becomes a dot after domain_to_ascii runs.
        let filter = HostFilter::allow_all();
        let result = filter.check_host("metadata.google.internal\u{3002}", &public_ip());
        assert!(!result.is_allowed());
        assert!(matches!(result, FilterResult::DenyHost { .. }));
    }

    #[test]
    fn test_embedded_nul_byte_fails_closed() {
        // A NUL byte could desync a resolver that truncates C strings at it.
        let filter = HostFilter::allow_all();
        let result = filter.check_host("metadata.google.internal\0", &public_ip());
        assert!(!result.is_allowed());
        assert!(matches!(result, FilterResult::DenyNotAllowed { .. }));
    }

    #[test]
    fn test_control_characters_fail_closed() {
        let filter = HostFilter::allow_all();
        for host in ["a\tb.com", "a\nb.com", "a\u{7f}b.com", "a\u{1}b.com"] {
            let result = filter.check_host(host, &public_ip());
            assert!(!result.is_allowed(), "host {host:?} should fail closed");
        }
    }

    #[test]
    fn test_malformed_punycode_host_fails_closed() {
        let filter = HostFilter::allow_all();
        let result = filter.check_host("xn--zz", &public_ip());
        assert!(!result.is_allowed());
        assert!(matches!(result, FilterResult::DenyNotAllowed { .. }));
    }

    #[test]
    fn test_trailing_dot_does_not_break_wildcard_allow() {
        let filter = HostFilter::new(&["*.googleapis.com".to_string()]);
        let result = filter.check_host("storage.googleapis.com.", &public_ip());
        assert!(result.is_allowed());
    }

    #[test]
    fn test_check_deny_matches_idna_invalid_entry() {
        // deny_hosts stores entries via the infallible normalize_entry
        // fallback, so check_deny must use the same fallback rather than
        // silently treating an IDNA-invalid lookup key as "not denied".
        let filter = HostFilter::allow_all().with_denied_hosts(&["xn--zz:443".to_string()]);
        assert!(matches!(
            filter.check_deny("xn--zz:443"),
            Some(FilterResult::DenyHost { .. })
        ));
    }
}
