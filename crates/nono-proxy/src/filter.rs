//! Async host filtering wrapping the library's [`HostFilter`](nono::HostFilter).
//!
//! Performs DNS resolution via `tokio::net::lookup_host()`, checks resolved
//! IPs against the link-local range (cloud metadata SSRF protection), and
//! validates the hostname against the cloud metadata deny list and allowlist.

use crate::error::Result;
use nono::net_filter::{FilterResult, HostFilter};
use nono::RuntimeHostFilter;
use std::net::{IpAddr, SocketAddr};
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

    /// Check a host against the filter with async DNS resolution.
    ///
    /// Resolves the hostname to IP addresses, then checks all resolved IPs
    /// against the link-local deny range (cloud metadata SSRF protection).
    /// If any resolved IP is link-local, the request is blocked.
    ///
    /// On success, returns both the filter result and the resolved socket
    /// addresses. Callers MUST use `resolved_addrs` to connect to the upstream
    /// instead of re-resolving the hostname, eliminating the DNS rebinding
    /// TOCTOU window.
    pub async fn check_host(&self, host: &str, port: u16) -> Result<CheckResult> {
        // Resolve DNS
        let addr_str = format!("{}:{}", host, port);
        let resolved: Vec<SocketAddr> = match tokio::net::lookup_host(&addr_str).await {
            Ok(addrs) => addrs.collect(),
            Err(e) => {
                debug!("DNS resolution failed for {}: {}", host, e);
                // If DNS fails, we still check the hostname against deny list
                // (cloud metadata hostnames don't need DNS resolution to be blocked)
                Vec::new()
            }
        };

        let resolved_ips: Vec<IpAddr> = resolved.iter().map(|a| a.ip()).collect();
        let result = self.inner.check_host(host, &resolved_ips);

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
        self.inner.check_host(host, resolved_ips)
    }

    /// Number of allowed hosts configured.
    #[must_use]
    pub fn allowed_count(&self) -> usize {
        self.inner.allowed_count()
    }
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
    use std::net::Ipv4Addr;

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
