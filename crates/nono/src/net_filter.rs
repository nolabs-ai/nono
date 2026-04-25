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
//!   `storage.googleapis.com` but not `googleapis.com` itself.

use std::net::IpAddr;

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
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            FilterResult::Allow => "allowed by host filter".to_string(),
            FilterResult::DenyHost { host } => {
                format!("host {} is in the deny list", host)
            }
            FilterResult::DenyLinkLocal { ip } => {
                format!(
                    "resolved IP {} is in the link-local range (cloud metadata protection)",
                    ip
                )
            }
            FilterResult::DenyNotAllowed { host } => {
                format!("host {} is not in the allowlist", host)
            }
        }
    }
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

/// A filter for host-based network access control.
///
/// Supports exact domain match and wildcard subdomains (`*.googleapis.com`)
/// for both allow and deny lists.
///
/// Cloud metadata endpoints are always denied and cannot be overridden.
/// The allowlist determines which hosts are permitted; everything else
/// is denied by default. The deny list (including user-specified
/// `reject_domain` entries) takes priority over the allowlist.
#[derive(Debug, Clone)]
pub struct HostFilter {
    /// Allowed exact hosts (lowercased)
    allowed_hosts: Vec<String>,
    /// Allowed wildcard suffixes (e.g., ".googleapis.com", lowercased)
    allowed_suffixes: Vec<String>,
    /// Hostnames that are always denied (cloud metadata + user-specified)
    deny_hosts: Vec<String>,
    /// Wildcard suffixes that are always denied (e.g., ".evil.com")
    deny_suffixes: Vec<String>,
}

impl HostFilter {
    /// Separate a list of domain patterns into exact hosts and wildcard suffixes.
    ///
    /// Entries starting with `*.` are treated as wildcard subdomain patterns
    /// (the `*` is stripped, producing `.example.com`). All other entries are
    /// exact matches. All values are lowercased.
    fn split_patterns(patterns: &[String]) -> (Vec<String>, Vec<String>) {
        let mut exact = Vec::new();
        let mut suffixes = Vec::new();

        for pattern in patterns {
            let lower = pattern.to_lowercase();
            if let Some(suffix) = lower.strip_prefix('*') {
                suffixes.push(suffix.to_string());
            } else {
                exact.push(lower);
            }
        }

        (exact, suffixes)
    }

    /// Create a new host filter with the given allowed hosts.
    ///
    /// Cloud metadata endpoints are automatically denied and cannot be removed.
    ///
    /// Hosts starting with `*.` are treated as wildcard subdomain patterns.
    /// All other entries are exact matches. Matching is case-insensitive.
    #[must_use]
    pub fn new(allowed_hosts: &[String]) -> Self {
        Self::new_with_reject(allowed_hosts, &[])
    }

    /// Create a new host filter with both allowed and rejected hosts.
    ///
    /// Like [`new()`](Self::new), but also accepts a list of rejected domain
    /// patterns. Rejected hosts are always denied, even if they appear in the
    /// allow list. Supports wildcards (`*.evil.com`) just like the allow list.
    ///
    /// Cloud metadata endpoints are automatically included in the deny list.
    #[must_use]
    pub fn new_with_reject(allowed_hosts: &[String], rejected_hosts: &[String]) -> Self {
        let (exact_allowed, allowed_suffixes) = Self::split_patterns(allowed_hosts);
        let (exact_denied, deny_suffixes) = Self::split_patterns(rejected_hosts);

        let mut deny_hosts: Vec<String> = DENY_HOSTS.iter().map(|s| s.to_lowercase()).collect();
        deny_hosts.extend(exact_denied);

        Self {
            allowed_hosts: exact_allowed,
            allowed_suffixes,
            deny_hosts,
            deny_suffixes,
        }
    }

    /// Create a host filter that allows everything (no filtering).
    ///
    /// Cloud metadata endpoints are still blocked.
    #[must_use]
    pub fn allow_all() -> Self {
        Self {
            allowed_hosts: Vec::new(),
            allowed_suffixes: Vec::new(),
            deny_hosts: DENY_HOSTS.iter().map(|s| s.to_lowercase()).collect(),
            deny_suffixes: Vec::new(),
        }
    }

    /// Create a host filter that denies everything by default.
    ///
    /// Unlike [`allow_all()`](Self::allow_all), no host is permitted unless
    /// explicitly added via [`add_host()`](Self::add_host) or
    /// [`add_suffix()`](Self::add_suffix). Cloud metadata endpoints remain
    /// unconditionally denied.
    ///
    /// This is used for runtime approval filters where the filter starts
    /// empty and only approved hosts are added dynamically.
    #[must_use]
    pub fn deny_all() -> Self {
        Self {
            allowed_hosts: vec!["__deny_all_sentinel__.invalid".to_string()],
            allowed_suffixes: Vec::new(),
            deny_hosts: DENY_HOSTS.iter().map(|s| s.to_lowercase()).collect(),
            deny_suffixes: Vec::new(),
        }
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
    /// 1. Deny hosts (exact match against deny list)
    /// 2. Deny suffixes (wildcard match, e.g. `*.evil.com`)
    /// 3. Link-local IP check (resolved IPs in 169.254.0.0/16 or fe80::/10)
    /// 4. Allowlist (exact host match, then wildcard subdomain match)
    /// 5. Default deny (if not in allowlist and allowlist is non-empty)
    #[must_use]
    pub fn check_host(&self, host: &str, resolved_ips: &[IpAddr]) -> FilterResult {
        let lower_host = host.to_lowercase();

        // 1. Check deny hosts (exact match)
        if self.deny_hosts.contains(&lower_host) {
            return FilterResult::DenyHost {
                host: host.to_string(),
            };
        }

        // 2. Check deny suffixes (wildcard match)
        for suffix in &self.deny_suffixes {
            if lower_host.ends_with(suffix.as_str()) && lower_host.len() > suffix.len() {
                return FilterResult::DenyHost {
                    host: host.to_string(),
                };
            }
        }

        // 3. Check resolved IPs for link-local addresses (cloud metadata protection)
        for ip in resolved_ips {
            if is_link_local(ip) {
                return FilterResult::DenyLinkLocal { ip: *ip };
            }
        }

        // 4. If no allowlist is configured (allow_all mode), allow
        if self.allowed_hosts.is_empty() && self.allowed_suffixes.is_empty() {
            return FilterResult::Allow;
        }

        // 5. Check exact host match
        if self.allowed_hosts.contains(&lower_host) {
            return FilterResult::Allow;
        }

        // 6. Check wildcard subdomain match
        for suffix in &self.allowed_suffixes {
            if lower_host.ends_with(suffix.as_str()) && lower_host.len() > suffix.len() {
                return FilterResult::Allow;
            }
        }

        // 7. Not in allowlist
        FilterResult::DenyNotAllowed {
            host: host.to_string(),
        }
    }

    /// Number of allowed hosts (exact + wildcard)
    #[must_use]
    pub fn allowed_count(&self) -> usize {
        self.allowed_hosts
            .len()
            .saturating_add(self.allowed_suffixes.len())
    }

    /// Add an exact host to the allowlist at runtime.
    ///
    /// The host is lowercased before insertion. If it already exists,
    /// this is a no-op. Cloud metadata hosts in the deny list are
    /// rejected — they can never be allowed.
    ///
    /// # Errors
    ///
    /// Returns [`NonoError`](crate::NonoError) if the host is empty
    /// or is a cloud metadata endpoint.
    pub fn add_host(&mut self, host: &str) -> crate::Result<()> {
        let lower = host.to_lowercase();
        if lower.is_empty() {
            return Err(crate::NonoError::InvalidConfig {
                reason: "host must not be empty".to_string(),
            });
        }
        if self.deny_hosts.contains(&lower) {
            return Err(crate::NonoError::InvalidConfig {
                reason: format!("host {host} is a cloud metadata endpoint and cannot be allowed"),
            });
        }
        if !self.allowed_hosts.contains(&lower) {
            self.allowed_hosts.push(lower);
        }
        Ok(())
    }

    /// Add a wildcard subdomain suffix to the allowlist at runtime.
    ///
    /// The suffix should be in the form `.example.com` (leading dot).
    /// If it starts with `*`, the `*` is stripped. If it already exists,
    /// this is a no-op.
    ///
    /// # Errors
    ///
    /// Returns [`NonoError`](crate::NonoError) if the suffix is empty.
    pub fn add_suffix(&mut self, suffix: &str) -> crate::Result<()> {
        let lower = suffix.to_lowercase();
        let normalized = lower.strip_prefix('*').unwrap_or(&lower);
        if normalized.is_empty() {
            return Err(crate::NonoError::InvalidConfig {
                reason: "suffix must not be empty".to_string(),
            });
        }
        let suffix_str = if normalized.starts_with('.') {
            normalized.to_string()
        } else {
            format!(".{normalized}")
        };
        if !self.allowed_suffixes.contains(&suffix_str) {
            self.allowed_suffixes.push(suffix_str);
        }
        Ok(())
    }

    /// Add a host to the deny list at runtime.
    ///
    /// The host is lowercased before insertion. If it already exists
    /// in the deny list, this is a no-op. Cloud metadata hosts are
    /// always present and cannot be removed — adding them again is
    /// a no-op.
    ///
    /// Once denied, a host cannot pass the filter regardless of the
    /// allowlist. This is useful for "always deny" decisions from the
    /// network approval flow.
    ///
    /// # Errors
    ///
    /// Returns [`NonoError`](crate::NonoError) if the host is empty.
    pub fn add_deny_host(&mut self, host: &str) -> crate::Result<()> {
        let lower = host.to_lowercase();
        if lower.is_empty() {
            return Err(crate::NonoError::InvalidConfig {
                reason: "host must not be empty".to_string(),
            });
        }
        if !self.deny_hosts.contains(&lower) {
            self.deny_hosts.push(lower);
        }
        Ok(())
    }

    /// Add a wildcard subdomain suffix to the deny list at runtime.
    ///
    /// The suffix should be in the form `.example.com` (leading dot).
    /// If it starts with `*`, the `*` is stripped. If it already exists,
    /// this is a no-op.
    ///
    /// Once denied, any subdomain matching the suffix cannot pass the
    /// filter regardless of the allowlist.
    ///
    /// # Errors
    ///
    /// Returns [`NonoError`](crate::NonoError) if the suffix is empty.
    pub fn add_deny_suffix(&mut self, suffix: &str) -> crate::Result<()> {
        let lower = suffix.to_lowercase();
        let normalized = lower.strip_prefix('*').unwrap_or(&lower);
        if normalized.is_empty() {
            return Err(crate::NonoError::InvalidConfig {
                reason: "suffix must not be empty".to_string(),
            });
        }
        let suffix_str = if normalized.starts_with('.') {
            normalized.to_string()
        } else {
            format!(".{normalized}")
        };
        if !self.deny_suffixes.contains(&suffix_str) {
            self.deny_suffixes.push(suffix_str);
        }
        Ok(())
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
    fn test_deny_all_mode() {
        let filter = HostFilter::deny_all();
        let result = filter.check_host("any-host.example.com", &public_ip());
        assert!(!result.is_allowed());
        assert!(matches!(result, FilterResult::DenyNotAllowed { .. }));
    }

    #[test]
    fn test_deny_all_then_add_host() {
        let mut filter = HostFilter::deny_all();
        assert!(!filter
            .check_host("approved.example.com", &public_ip())
            .is_allowed());

        filter.add_host("approved.example.com").expect("add_host");
        assert!(filter
            .check_host("approved.example.com", &public_ip())
            .is_allowed());
        assert!(!filter
            .check_host("other.example.com", &public_ip())
            .is_allowed());
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

        let link_local = FilterResult::DenyLinkLocal {
            ip: IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
        };
        assert!(link_local.reason().contains("link-local"));
    }

    #[test]
    fn test_new_with_reject_exact() {
        let filter =
            HostFilter::new_with_reject(&["api.openai.com".to_string()], &["evil.com".to_string()]);
        assert!(filter
            .check_host("api.openai.com", &public_ip())
            .is_allowed());
        assert!(!filter.check_host("evil.com", &public_ip()).is_allowed());
        assert!(matches!(
            filter.check_host("evil.com", &public_ip()),
            FilterResult::DenyHost { .. }
        ));
    }

    #[test]
    fn test_reject_overrides_allow() {
        let filter =
            HostFilter::new_with_reject(&["evil.com".to_string()], &["evil.com".to_string()]);
        assert!(
            !filter.check_host("evil.com", &public_ip()).is_allowed(),
            "deny should override allow for same host"
        );
    }

    #[test]
    fn test_reject_wildcard_overrides_allow() {
        let filter =
            HostFilter::new_with_reject(&["api.evil.com".to_string()], &["*.evil.com".to_string()]);
        assert!(
            !filter.check_host("api.evil.com", &public_ip()).is_allowed(),
            "deny wildcard should override allow for subdomain"
        );
    }

    #[test]
    fn test_add_deny_host() {
        let mut filter = HostFilter::new(&["api.openai.com".to_string(), "evil.com".to_string()]);
        filter.add_deny_host("evil.com").expect("add_deny_host");
        assert!(
            !filter.check_host("evil.com", &public_ip()).is_allowed(),
            "deny should override allow"
        );
    }

    #[test]
    fn test_add_deny_suffix() {
        let mut filter =
            HostFilter::new(&["api.example.com".to_string(), "track.evil.com".to_string()]);
        filter
            .add_deny_suffix("*.evil.com")
            .expect("add_deny_suffix");
        assert!(
            !filter
                .check_host("track.evil.com", &public_ip())
                .is_allowed(),
            "deny suffix should override allow"
        );
        assert!(
            !filter
                .check_host("other.evil.com", &public_ip())
                .is_allowed(),
            "deny suffix should match other subdomains"
        );
    }

    #[test]
    fn test_deny_suffix_does_not_match_bare_domain() {
        let mut filter = HostFilter::new(&["evil.com".to_string()]);
        filter
            .add_deny_suffix("*.evil.com")
            .expect("add_deny_suffix");
        assert!(
            filter.check_host("evil.com", &public_ip()).is_allowed(),
            "deny suffix should not match bare domain"
        );
    }
}
