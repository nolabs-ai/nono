//! Async host filtering wrapping the library's [`HostFilter`](nono::HostFilter).
//!
//! Performs DNS resolution via `tokio::net::lookup_host()`, checks resolved
//! IPs against the link-local range (cloud metadata SSRF protection), and
//! validates the hostname against the cloud metadata deny list and allowlist.

use crate::config::{is_proxy_denied_metadata_ip, parse_host_ip_literal};
use crate::error::Result;
use nono::net_filter::{FilterResult, HostFilter};
use std::net::{IpAddr, SocketAddr};
use tracing::debug;

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
    /// Resolves the hostname to IP addresses, then checks all resolved IPs
    /// against the link-local deny range (cloud metadata SSRF protection).
    /// If any resolved IP is link-local, the request is blocked.
    ///
    /// On success, returns both the filter result and the resolved socket
    /// addresses. Callers MUST use `resolved_addrs` to connect to the upstream
    /// instead of re-resolving the hostname, eliminating the DNS rebinding
    /// TOCTOU window.
    pub async fn check_host(&self, host: &str, port: u16) -> Result<CheckResult> {
        if let Some(result) = proxy_metadata_filter_result(host, &[]) {
            return Ok(CheckResult {
                result,
                resolved_addrs: Vec::new(),
            });
        }

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

    fn check_host_result(&self, host: &str, port: u16, resolved_ips: &[IpAddr]) -> FilterResult {
        let result = self.inner.check_host(host, resolved_ips);
        if !matches!(result, FilterResult::DenyNotAllowed { .. }) {
            return result;
        }

        let host_port = format!("{host}:{port}");
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
    fn test_proxy_filter_denies_resolved_aws_ipv6_metadata_ip() {
        let filter = ProxyFilter::allow_all();
        let resolved = vec![IpAddr::V6(Ipv6Addr::new(
            0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254,
        ))];
        let result = filter.check_host_with_ips("allowed.example", &resolved);
        assert!(!result.is_allowed());
    }
}
