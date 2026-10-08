//! Async host filtering wrapping the library's [`HostFilter`](nono::HostFilter).
//!
//! Checks the hostname against the allowlist/deny list before resolving DNS,
//! then resolves and checks the resulting IPs against the link-local range
//! (cloud metadata SSRF protection).

use crate::config::{is_proxy_denied_metadata_ip, parse_host_ip_literal};
use crate::error::Result;
use nono::RuntimeHostFilter;
use nono::net_filter::{FilterResult, HostFilter};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use tracing::debug;

pub const NO_IPS: &[IpAddr] = &[];

/// Result of a filter check including resolved socket addresses.
///
/// When the filter allows a host, `resolved_addrs` contains the DNS-resolved
/// addresses. Callers MUST connect to these addresses (not re-resolve the
/// hostname) to prevent DNS rebinding TOCTOU attacks.
pub struct CheckResult {
    /// The filter decision
    pub result: FilterResult,
    /// DNS-resolved addresses (empty if denied or DNS failed)
    pub resolved_addrs: Vec<SocketAddr>,
}

/// Async wrapper around `HostFilter` that performs DNS resolution.
#[derive(Debug, Clone)]
pub struct ProxyFilter {
    inner: HostFilter,
}

impl ProxyFilter {
    /// Create a new proxy filter with the given allowed hosts.
    #[must_use]
    pub fn new(allowed_hosts: &[String]) -> Self {
        Self {
            inner: HostFilter::new(allowed_hosts),
        }
    }

    /// Create a strict proxy filter: an empty allowlist denies every host.
    #[must_use]
    pub fn new_strict(allowed_hosts: &[String]) -> Self {
        Self {
            inner: HostFilter::new_strict(allowed_hosts),
        }
    }

    /// Create a new proxy filter with both allowed and rejected hosts.
    #[must_use]
    pub fn new_with_reject(allowed_hosts: &[String], rejected_hosts: &[String]) -> Self {
        Self {
            inner: HostFilter::new_with_reject(allowed_hosts, rejected_hosts),
        }
    }

    /// Create a filter that allows all hosts (except cloud metadata).
    #[must_use]
    pub fn allow_all() -> Self {
        Self {
            inner: HostFilter::allow_all(),
        }
    }

    /// Append user-configured deny entries. Evaluated before the allowlist.
    ///
    /// Supports the same wildcard syntax as the allowlist (`*.example.com`).
    #[must_use]
    pub fn with_denied_hosts(self, denied: &[String]) -> Self {
        if denied.is_empty() {
            return self;
        }
        Self {
            inner: self.inner.with_denied_hosts(denied),
        }
    }

    /// Check a host against the filter with async DNS resolution.
    ///
    /// The allowlist/deny check runs on the hostname alone before any DNS
    /// lookup, since resolution itself sends a query to the domain's
    /// nameserver and would leak the hostname even for a denied host.
    ///
    /// Once resolved, all resolved IPs are checked against the link-local
    /// deny range (cloud metadata SSRF / DNS rebinding protection).
    ///
    /// On success, returns both the filter result and the resolved socket
    /// addresses. Callers MUST use `resolved_addrs` to connect to the upstream
    /// instead of re-resolving the hostname, eliminating the DNS rebinding
    /// TOCTOU window.
    pub async fn check_host(&self, host: &str, port: u16) -> Result<CheckResult> {
        let pre_check = proxy_metadata_filter_result(host, &[])
            .unwrap_or_else(|| self.check_host_result(host, port, &[]));

        if !pre_check.is_allowed() {
            return Ok(CheckResult {
                result: pre_check,
                resolved_addrs: Vec::new(),
            });
        }

        let addr_str = format!("{}:{}", host, port);
        let resolved: Vec<SocketAddr> = match tokio::net::lookup_host(&addr_str).await {
            Ok(addrs) => addrs.collect(),
            Err(e) => {
                debug!("DNS resolution failed for {}: {}", host, e);
                Vec::new()
            }
        };

        let resolved_ips: Vec<IpAddr> = resolved.iter().map(|a| a.ip()).collect();
        let result = proxy_metadata_filter_result(host, &resolved_ips)
            .unwrap_or_else(|| self.check_host_result(host, port, &resolved_ips));

        // Only return resolved addrs on allow to prevent misuse
        let addrs = if result.is_allowed() {
            resolved
        } else {
            Vec::new()
        };

        Ok(CheckResult {
            result,
            resolved_addrs: addrs,
        })
    }

    /// Check a host with pre-resolved IPs (no DNS lookup).
    #[must_use]
    pub fn check_host_with_ips(&self, host: &str, resolved_ips: &[IpAddr]) -> FilterResult {
        proxy_metadata_filter_result(host, resolved_ips)
            .unwrap_or_else(|| self.inner.check_host(host, resolved_ips))
    }

    /// Checks deny (incl. `host:port`) before the allowlist, so a wildcard
    /// `allow_domain: ["*"]` can't shadow a port-scoped deny entry.
    fn check_host_result(&self, host: &str, port: u16, resolved_ips: &[IpAddr]) -> FilterResult {
        // Normalize before appending the port: a raw trailing dot would land
        // mid-string (e.g. "evil.com.:443"), past where normalization looks.
        let normalized_host = HostFilter::normalize_authority_host(host);
        // Bracket IPv6 literals so their embedded colons can't be mistaken
        // for the port separator (e.g. "[::1]:8975", not "::1:8975").
        let host_port = if normalized_host.parse::<Ipv6Addr>().is_ok() {
            format!("[{normalized_host}]:{port}")
        } else {
            format!("{normalized_host}:{port}")
        };

        if let Some(deny) = self.inner.check_deny(&host_port) {
            return deny;
        }
        if let Some(deny) = self.inner.check_deny(host) {
            return deny;
        }

        let result = self.inner.check_host(host, resolved_ips);
        if !matches!(result, FilterResult::DenyNotAllowed { .. }) {
            return result;
        }

        self.inner.check_host(&host_port, resolved_ips)
    }

    /// Number of allowed hosts configured.
    #[must_use]
    pub fn allowed_count(&self) -> usize {
        self.inner.allowed_count()
    }
}

fn proxy_metadata_filter_result(host: &str, resolved_ips: &[IpAddr]) -> Option<FilterResult> {
    if parse_host_ip_literal(host).is_some_and(|ip| is_proxy_denied_metadata_ip(&ip))
        || resolved_ips.iter().any(is_proxy_denied_metadata_ip)
    {
        return Some(FilterResult::DenyHost {
            host: host.to_string(),
        });
    }
    None
}

/// Async wrapper around [`RuntimeHostFilter`] for runtime-mutable filtering.
///
/// Like [`ProxyFilter`] but backed by a [`RuntimeHostFilter`] that can be
/// extended at runtime (e.g., when the user approves a new host via
/// an OS notification). DNS resolution is still performed on each check.
#[derive(Debug, Clone)]
pub struct RuntimeProxyFilter {
    inner: RuntimeHostFilter,
}

impl RuntimeProxyFilter {
    /// Create a new runtime proxy filter from a [`RuntimeHostFilter`].
    #[must_use]
    pub fn new(inner: RuntimeHostFilter) -> Self {
        Self { inner }
    }

    /// Check a host against the filter with async DNS resolution.
    pub async fn check_host(&self, host: &str, port: u16) -> Result<CheckResult> {
        let addr_str = format!("{}:{}", host, port);
        let resolved: Vec<SocketAddr> = match tokio::net::lookup_host(&addr_str).await {
            Ok(addrs) => addrs.collect(),
            Err(e) => {
                debug!("DNS resolution failed for {}: {}", host, e);
                Vec::new()
            }
        };

        let resolved_ips: Vec<IpAddr> = resolved.iter().map(|a| a.ip()).collect();
        let result = self.inner.check_host(host, &resolved_ips);

        let addrs = if result.is_allowed() {
            resolved
        } else {
            Vec::new()
        };

        Ok(CheckResult {
            result,
            resolved_addrs: addrs,
        })
    }

    /// Resolve a hostname to socket addresses via DNS without filter check.
    ///
    /// Used for "once" approvals where the host is not in the runtime filter
    /// but we still need resolved addresses to connect.
    pub async fn resolve_host(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        let addr_str = format!("{}:{}", host, port);
        let result = tokio::net::lookup_host(&addr_str).await;
        match result {
            Ok(addrs) => Ok(addrs.collect()),
            Err(e) => {
                debug!("DNS resolution failed for {}: {}", host, e);
                Ok(Vec::new())
            }
        }
    }

    /// Check a host with pre-resolved IPs (no DNS lookup).
    #[must_use]
    pub fn check_host_with_ips(&self, host: &str, resolved_ips: &[IpAddr]) -> FilterResult {
        self.inner.check_host(host, resolved_ips)
    }

    /// Add a host to the runtime allowlist.
    pub fn add_host(&self, host: &str) -> nono::Result<()> {
        self.inner.add_host(host)
    }

    /// Add a wildcard suffix to the runtime allowlist.
    pub fn add_suffix(&self, suffix: &str) -> nono::Result<()> {
        self.inner.add_suffix(suffix)
    }

    /// Add a host to the runtime deny list.
    ///
    /// Once denied, the host cannot pass the filter regardless of the
    /// allowlist. Used for "always deny" decisions.
    pub fn add_deny_host(&self, host: &str) -> nono::Result<()> {
        self.inner.add_deny_host(host)
    }

    /// Add a wildcard suffix to the runtime deny list.
    ///
    /// Once denied, any subdomain matching the suffix cannot pass the
    /// filter regardless of the allowlist.
    pub fn add_deny_suffix(&self, suffix: &str) -> nono::Result<()> {
        self.inner.add_deny_suffix(suffix)
    }

    /// Get a reference to the underlying [`RuntimeHostFilter`].
    #[must_use]
    pub fn inner(&self) -> &RuntimeHostFilter {
        &self.inner
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_proxy_filter_delegates_to_host_filter() {
        let filter = ProxyFilter::new(&["api.openai.com".to_string()]);
        let public_ip = vec![IpAddr::V4(Ipv4Addr::new(104, 18, 7, 96))];

        let result = filter.check_host_with_ips("api.openai.com", &public_ip);
        assert!(result.is_allowed());

        let result = filter.check_host_with_ips("evil.com", &public_ip);
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_proxy_filter_allows_host_port_entries() {
        let filter = ProxyFilter::new(&["platform.claude.com:443".to_string()]);
        let public_ip = vec![IpAddr::V4(Ipv4Addr::new(160, 79, 104, 10))];

        let result = filter.check_host_result("platform.claude.com", 443, &public_ip);
        assert!(result.is_allowed());

        let result = filter.check_host_result("platform.claude.com", 8443, &public_ip);
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_proxy_filter_host_port_entries_do_not_override_metadata_deny() {
        let filter = ProxyFilter::new(&["metadata.google.internal:443".to_string()]);
        let public_ip = vec![IpAddr::V4(Ipv4Addr::new(104, 18, 7, 96))];

        let result = filter.check_host_result("metadata.google.internal", 443, &public_ip);
        assert!(!result.is_allowed());
        assert!(matches!(result, FilterResult::DenyHost { .. }));
    }

    #[test]
    fn test_proxy_filter_with_denied_hosts() {
        let filter = ProxyFilter::allow_all().with_denied_hosts(&["evil.com".to_string()]);
        let public_ip = vec![IpAddr::V4(Ipv4Addr::new(104, 18, 7, 96))];

        let result = filter.check_host_with_ips("evil.com", &public_ip);
        assert!(!result.is_allowed());

        let result = filter.check_host_with_ips("good.com", &public_ip);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_proxy_filter_with_denied_hosts_wildcard() {
        let filter = ProxyFilter::allow_all().with_denied_hosts(&["*.ads.example.com".to_string()]);
        let public_ip = vec![IpAddr::V4(Ipv4Addr::new(104, 18, 7, 96))];

        let result = filter.check_host_with_ips("tracker.ads.example.com", &public_ip);
        assert!(!result.is_allowed());

        // bare domain must NOT match wildcard
        let result = filter.check_host_with_ips("ads.example.com", &public_ip);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_proxy_filter_denied_host_port_honored_under_wildcard_allow() {
        // A port-scoped deny must hold under a wildcard allow, without
        // affecting other ports on the same host.
        let filter =
            ProxyFilter::new(&["*".to_string()]).with_denied_hosts(&["127.0.0.1:8975".to_string()]);
        let loopback = vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))];

        let result = filter.check_host_result("127.0.0.1", 8975, &loopback);
        assert!(!result.is_allowed(), "denied port must not be allowed");
        assert!(matches!(result, FilterResult::DenyHost { .. }));

        let result = filter.check_host_result("127.0.0.1", 8787, &loopback);
        assert!(
            result.is_allowed(),
            "unrelated port on the same host must remain allowed"
        );
    }

    #[test]
    fn test_proxy_filter_denied_host_port_honored_for_trailing_dot_fqdn() {
        // A trailing-dot FQDN must not bypass a port-scoped deny via
        // unnormalized host:port construction (see check_host_result).
        let filter =
            ProxyFilter::new(&["*".to_string()]).with_denied_hosts(&["evil.com:443".to_string()]);

        let result = filter.check_host_result("evil.com.", 443, &[]);
        assert!(
            !result.is_allowed(),
            "trailing-dot form must still be denied"
        );
        assert!(matches!(result, FilterResult::DenyHost { .. }));
    }

    #[test]
    fn test_proxy_filter_denied_host_port_honored_for_ipv6_literal() {
        // An IPv6 host:port deny must match the bracketed authority form,
        // not "::1:8975" (ambiguous with the port separator).
        let filter =
            ProxyFilter::new(&["*".to_string()]).with_denied_hosts(&["[::1]:8975".to_string()]);

        let result = filter.check_host_result("::1", 8975, &[]);
        assert!(!result.is_allowed(), "IPv6 host:port form must be denied");
        assert!(matches!(result, FilterResult::DenyHost { .. }));

        let result = filter.check_host_result("::1", 8787, &[]);
        assert!(
            result.is_allowed(),
            "unrelated port on the same IPv6 host must remain allowed"
        );
    }

    #[test]
    fn test_proxy_filter_allow_all() {
        let filter = ProxyFilter::allow_all();
        let public_ip = vec![IpAddr::V4(Ipv4Addr::new(104, 18, 7, 96))];
        let result = filter.check_host_with_ips("anything.com", &public_ip);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_proxy_filter_allows_private_networks() {
        let filter = ProxyFilter::allow_all();
        let private_ip = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];
        let result = filter.check_host_with_ips("corp.internal", &private_ip);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_proxy_filter_denies_link_local() {
        let filter = ProxyFilter::allow_all();
        let link_local = vec![IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))];
        let result = filter.check_host_with_ips("evil.com", &link_local);
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_proxy_filter_denies_aws_ipv6_metadata_literals() {
        let filter = ProxyFilter::allow_all();
        for host in [
            "fd00:ec2::254",
            "fd00:0ec2::254",
            "fd00:ec2:0:0:0:0:0:254",
            "[fd00:ec2::254]",
        ] {
            let result = filter.check_host_with_ips(host, &[]);
            assert!(
                !result.is_allowed(),
                "AWS IPv6 metadata literal {host:?} must be denied"
            );
        }
    }

    #[test]
    fn test_pre_resolution_check_denies_disallowed_host_without_ips() {
        let filter = ProxyFilter::new(&["api.openai.com".to_string()]);
        let result = filter.check_host_result("evil.com", 443, &[]);
        assert!(!result.is_allowed());
        assert!(matches!(result, FilterResult::DenyNotAllowed { .. }));
    }

    #[test]
    fn test_pre_resolution_check_allows_allowed_host_without_ips() {
        let filter = ProxyFilter::new(&["api.openai.com".to_string()]);
        let result = filter.check_host_result("api.openai.com", 443, &[]);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_pre_resolution_check_host_port_fallback_without_ips() {
        let filter = ProxyFilter::new(&["platform.claude.com:443".to_string()]);
        let result = filter.check_host_result("platform.claude.com", 443, &[]);
        assert!(result.is_allowed());

        let result = filter.check_host_result("platform.claude.com", 8443, &[]);
        assert!(!result.is_allowed());
    }

    #[tokio::test]
    async fn test_check_host_denies_disallowed_host_without_dns_resolution() {
        // .invalid (RFC 2606) never resolves, so a hang/error here would mean
        // DNS was attempted before the allowlist check.
        let filter = ProxyFilter::new(&["api.openai.com".to_string()]);
        let result = filter
            .check_host("data-exfiltration-secret.example.invalid", 443)
            .await
            .unwrap();
        assert!(!result.result.is_allowed());
        assert!(matches!(result.result, FilterResult::DenyNotAllowed { .. }));
        assert!(result.resolved_addrs.is_empty());
    }

    #[test]
    fn test_proxy_filter_denies_trailing_dot_metadata_hostname() {
        // CONNECT-path callers pass the raw wire hostname straight through
        // with no normalization; the filter itself must catch this.
        let filter = ProxyFilter::allow_all();
        let result = filter.check_host_with_ips("metadata.google.internal.", &[]);
        assert!(!result.is_allowed());
        assert!(matches!(result, FilterResult::DenyHost { .. }));
    }

    #[test]
    fn test_proxy_filter_denies_unicode_form_of_punycode_deny_entry() {
        let filter = ProxyFilter::allow_all().with_denied_hosts(&["xn--mnchen-3ya.de".to_string()]);
        let result = filter.check_host_with_ips("münchen.de", &[]);
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_proxy_filter_denies_resolved_aws_ipv6_metadata_ip() {
        let filter = ProxyFilter::allow_all();
        let resolved = vec![IpAddr::V6(Ipv6Addr::new(
            0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254,
        ))];
        let result = filter.check_host_with_ips("allowed.example", &resolved);
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_proxy_filter_rejected_hosts_deny_even_if_allow_all() {
        let filter = ProxyFilter::new_with_reject(&[], &["evil.com".to_string()]);
        let public_ip = vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))];
        let result = filter.check_host_with_ips("evil.com", &public_ip);
        assert!(matches!(result, FilterResult::DenyHost { .. }));
    }

    #[test]
    fn test_proxy_filter_rejected_hosts_take_priority_over_allowed() {
        let filter = ProxyFilter::new_with_reject(
            &["api.openai.com".to_string(), "evil.com".to_string()],
            &["evil.com".to_string()],
        );
        let public_ip = vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))];
        let result = filter.check_host_with_ips("evil.com", &public_ip);
        assert!(matches!(result, FilterResult::DenyHost { .. }));

        let result = filter.check_host_with_ips("api.openai.com", &public_ip);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_proxy_filter_rejected_hosts_allow_non_blacklisted() {
        let filter = ProxyFilter::new_with_reject(&[], &["evil.com".to_string()]);
        let public_ip = vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))];
        let result = filter.check_host_with_ips("safe.com", &public_ip);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_runtime_proxy_filter_add_deny_host_overrides_allow() {
        let inner = RuntimeHostFilter::new(HostFilter::new(&[
            "api.openai.com".to_string(),
            "evil.com".to_string(),
        ]));
        let filter = RuntimeProxyFilter::new(inner);
        let public_ip = vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))];

        let result = filter.check_host_with_ips("evil.com", &public_ip);
        assert!(result.is_allowed());

        filter.add_deny_host("evil.com").unwrap();

        let result = filter.check_host_with_ips("evil.com", &public_ip);
        assert!(matches!(result, FilterResult::DenyHost { .. }));

        let result = filter.check_host_with_ips("api.openai.com", &public_ip);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_runtime_proxy_filter_deny_suffix_blocks_subdomains() {
        let inner = RuntimeHostFilter::new(HostFilter::allow_all());
        let filter = RuntimeProxyFilter::new(inner);
        let public_ip = vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))];

        filter.add_deny_suffix(".cloud2.influxdata.com").unwrap();

        let result =
            filter.check_host_with_ips("eu-central-1-1.aws.cloud2.influxdata.com", &public_ip);
        assert!(matches!(result, FilterResult::DenyHost { .. }));

        let result = filter.check_host_with_ips("influxdata.com", &public_ip);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_runtime_proxy_filter_once_scope_host_not_in_filter() {
        let inner = RuntimeHostFilter::new(HostFilter::new(&["allowed.com".to_string()]));
        let filter = RuntimeProxyFilter::new(inner);
        let public_ip = vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))];

        let result = filter.check_host_with_ips("once-approved.com", &public_ip);
        assert!(!result.is_allowed());

        let result = filter.check_host_with_ips("allowed.com", &public_ip);
        assert!(result.is_allowed());
    }
}
