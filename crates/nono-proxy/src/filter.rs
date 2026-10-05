//! Async host filtering wrapping the library's [`HostFilter`](nono::HostFilter).
//!
//! Checks the hostname against the allowlist/deny list before resolving DNS,
//! then resolves and checks the resulting IPs against the link-local range
//! (cloud metadata SSRF protection) and, when configured, against the
//! loopback interface (proxy-bypass protection).

use crate::config::{is_proxy_denied_metadata_ip, parse_host_ip_literal};
use crate::error::Result;
use nono::net_filter::{FilterResult, HostFilter};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use tracing::debug;

/// Opt-in restriction on proxying to the loopback interface.
///
/// The OS sandbox pins the child to `loopback:<proxy port>` in
/// `NetworkMode::ProxyOnly`, so the proxy is the only route off the child's
/// loopback interface. Without this gate the child can still ask the proxy to
/// `CONNECT` to any other loopback service — reaching, for example, a local
/// Kubernetes API server directly and stepping around the credential-injecting
/// route that was meant to mediate it.
///
/// The only exemption is `ports`: loopback ports the operator declared
/// reachable. A configured credential route to a loopback upstream is handled
/// separately, by [`ProxyFilter::check_route_upstream`] — *not* by exempting
/// the upstream's `host:port` here.
///
/// That distinction is the whole point. Exempting the destination would let a
/// client ask the proxy for that same `host:port` directly and get it, which
/// skips the route's `endpoint_policy` and credential injection — exactly the
/// bypass this type exists to close. The exemption has to follow the *caller*
/// (the proxy dialling on a route's behalf), never the address.
#[derive(Debug, Clone, Default)]
pub struct LoopbackPolicy {
    ports: HashSet<u16>,
}

impl LoopbackPolicy {
    /// Build a policy from the operator-declared allowed loopback ports.
    #[must_use]
    pub fn new(ports: &[u16]) -> Self {
        Self {
            ports: ports.iter().copied().collect(),
        }
    }

    fn permits(&self, port: u16) -> bool {
        self.ports.contains(&port)
    }
}

/// Whether a hostname is a loopback name under RFC 6761: `localhost` itself
/// and anything under `.localhost`.
///
/// Checked on the literal hostname so a request is refused before DNS is
/// consulted; resolved IPs are checked separately, which is what catches a
/// public name that resolves to `127.0.0.1` (DNS rebinding).
fn is_loopback_hostname(host: &str) -> bool {
    let host = HostFilter::normalize_authority_host(host).to_ascii_lowercase();
    let host = host.strip_suffix('.').unwrap_or(&host);
    host == "localhost" || host.ends_with(".localhost")
}

/// Whether connecting to this address lands on the local host.
///
/// Three things count, and all three are reachable ways to say "here":
/// - `127.0.0.0/8` and `::1` — loopback proper.
/// - IPv4-mapped IPv6 forms of both of the above (`::ffff:127.0.0.0/104`
///   and `::ffff:0.0.0.0`), so an AAAA record cannot sidestep the check.
/// - The unspecified addresses `0.0.0.0` and `::` — `connect(2)` to these
///   reaches localhost on both Linux and macOS, so treating them as
///   non-loopback would leave the restriction trivially bypassable. The same
///   equivalence is already applied to upstream URL validation in the CLI.
fn reaches_loopback_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_unspecified(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4.is_loopback() || v4.is_unspecified())
        }
    }
}

/// Decision from a proxy filter check.
///
/// Wraps the library's [`FilterResult`] and adds the proxy-only loopback
/// denial. The loopback policy lives entirely in this crate, so its decision
/// does too: the library's public result type stays unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyFilterResult {
    /// Decision from the library host filter (allowlist, deny list,
    /// link-local).
    Host(FilterResult),
    /// Destination is on the loopback interface and the loopback policy does
    /// not exempt its port.
    DenyLoopback {
        /// The destination that was denied, as `host:port`
        destination: String,
    },
}

impl ProxyFilterResult {
    /// Whether the result is an allow decision
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, ProxyFilterResult::Host(result) if result.is_allowed())
    }

    /// A human-readable reason for the decision.
    ///
    /// The destination is untrusted input that callers print to terminals and
    /// logs, so control characters are stripped, matching
    /// [`FilterResult::reason`].
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            ProxyFilterResult::Host(result) => result.reason(),
            ProxyFilterResult::DenyLoopback { destination } => {
                let destination: String = destination.chars().filter(|c| !c.is_control()).collect();
                format!(
                    "destination {destination} is on the loopback interface and is not in \
                     the loopback allowlist"
                )
            }
        }
    }
}

impl From<FilterResult> for ProxyFilterResult {
    fn from(result: FilterResult) -> Self {
        ProxyFilterResult::Host(result)
    }
}

/// Whether a given check applies the loopback policy.
///
/// `Bypassed` is reachable only from [`ProxyFilter::check_route_upstream`],
/// so the exemption is tied to the proxy dialling for a configured route and
/// can never be reached by a client-supplied destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoopbackGate {
    Enforced,
    Bypassed,
}

/// Result of a filter check including resolved socket addresses.
///
/// When the filter allows a host, `resolved_addrs` contains the DNS-resolved
/// addresses. Callers MUST connect to these addresses (not re-resolve the
/// hostname) to prevent DNS rebinding TOCTOU attacks.
pub struct CheckResult {
    /// The filter decision
    pub result: ProxyFilterResult,
    /// DNS-resolved addresses (empty if denied or DNS failed)
    pub resolved_addrs: Vec<SocketAddr>,
}

/// Async wrapper around `HostFilter` that performs DNS resolution.
#[derive(Debug, Clone)]
pub struct ProxyFilter {
    inner: HostFilter,
    /// `None` (the default) leaves loopback egress unrestricted, matching the
    /// documented behaviour that only link-local is denied outright.
    loopback: Option<LoopbackPolicy>,
}

impl ProxyFilter {
    /// Create a new proxy filter with the given allowed hosts.
    #[must_use]
    pub fn new(allowed_hosts: &[String]) -> Self {
        Self {
            inner: HostFilter::new(allowed_hosts),
            loopback: None,
        }
    }

    /// Create a strict proxy filter: an empty allowlist denies every host.
    #[must_use]
    pub fn new_strict(allowed_hosts: &[String]) -> Self {
        Self {
            inner: HostFilter::new_strict(allowed_hosts),
            loopback: None,
        }
    }

    /// Create a filter that allows all hosts (except cloud metadata).
    #[must_use]
    pub fn allow_all() -> Self {
        Self {
            inner: HostFilter::allow_all(),
            loopback: None,
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
            loopback: self.loopback,
        }
    }

    /// Restrict proxying to the loopback interface.
    ///
    /// Evaluated before the allowlist, so a wildcard `allow_domain: ["*"]`
    /// cannot shadow it — the same ordering the metadata deny list uses.
    #[must_use]
    pub fn with_loopback_policy(mut self, policy: LoopbackPolicy) -> Self {
        self.loopback = Some(policy);
        self
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
        self.resolve_and_check(host, port, LoopbackGate::Enforced)
            .await
    }

    /// Check an upstream the proxy is dialling on behalf of a configured
    /// credential route.
    ///
    /// Identical to [`Self::check_host`] except the loopback policy does not
    /// apply: a route to a local service is the sanctioned path, and the
    /// request has already passed that route's `endpoint_policy` and had its
    /// credential injected. Client-initiated requests never reach this — they
    /// go through [`Self::check_host`] and stay subject to the policy, so
    /// asking the proxy for the route's upstream directly is still refused.
    pub async fn check_route_upstream(&self, host: &str, port: u16) -> Result<CheckResult> {
        self.resolve_and_check(host, port, LoopbackGate::Bypassed)
            .await
    }

    async fn resolve_and_check(
        &self,
        host: &str,
        port: u16,
        gate: LoopbackGate,
    ) -> Result<CheckResult> {
        let pre_check = proxy_metadata_filter_result(host, &[])
            .map(ProxyFilterResult::from)
            .unwrap_or_else(|| self.check_host_result_gated(host, port, &[], gate));

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
            .map(ProxyFilterResult::from)
            .unwrap_or_else(|| self.check_host_result_gated(host, port, &resolved_ips, gate));

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
    ///
    /// Hostname-level only: with no port there is nothing to match a loopback
    /// policy against, so this does **not** apply one. It is for config-time
    /// introspection (is this upstream allowlisted at all?), never for
    /// admitting a request — those go through [`Self::check_host`].
    #[must_use]
    pub fn check_host_with_ips(&self, host: &str, resolved_ips: &[IpAddr]) -> FilterResult {
        proxy_metadata_filter_result(host, resolved_ips)
            .unwrap_or_else(|| self.inner.check_host(host, resolved_ips))
    }

    /// Checks deny (incl. `host:port`) before the allowlist, so a wildcard
    /// `allow_domain: ["*"]` can't shadow a port-scoped deny entry.
    #[cfg(test)]
    fn check_host_result(
        &self,
        host: &str,
        port: u16,
        resolved_ips: &[IpAddr],
    ) -> ProxyFilterResult {
        self.check_host_result_gated(host, port, resolved_ips, LoopbackGate::Enforced)
    }

    fn check_host_result_gated(
        &self,
        host: &str,
        port: u16,
        resolved_ips: &[IpAddr],
        gate: LoopbackGate,
    ) -> ProxyFilterResult {
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

        if gate == LoopbackGate::Enforced
            && let Some(deny) = self.loopback_result(host, port, &host_port, resolved_ips)
        {
            return deny;
        }

        if let Some(deny) = self.inner.check_deny(&host_port) {
            return deny.into();
        }
        if let Some(deny) = self.inner.check_deny(host) {
            return deny.into();
        }

        let result = self.inner.check_host(host, resolved_ips);
        if !matches!(result, FilterResult::DenyNotAllowed { .. }) {
            return result.into();
        }

        self.inner.check_host(&host_port, resolved_ips).into()
    }

    /// Deny a loopback destination unless the configured policy exempts it.
    ///
    /// Both the literal hostname and every resolved IP are checked: the
    /// literal catches `127.0.0.1` / `localhost` before DNS is consulted, and
    /// the resolved set catches a public name pointed at loopback (rebinding).
    fn loopback_result(
        &self,
        host: &str,
        port: u16,
        host_port: &str,
        resolved_ips: &[IpAddr],
    ) -> Option<ProxyFilterResult> {
        let policy = self.loopback.as_ref()?;

        let literal_is_loopback = parse_host_ip_literal(host)
            .is_some_and(|ip| reaches_loopback_ip(&ip))
            || is_loopback_hostname(host);
        if !literal_is_loopback && !resolved_ips.iter().any(reaches_loopback_ip) {
            return None;
        }
        if policy.permits(port) {
            return None;
        }

        debug!(
            "loopback destination {} denied by loopback policy",
            host_port
        );
        Some(ProxyFilterResult::DenyLoopback {
            destination: host_port.to_string(),
        })
    }

    /// Whether a loopback policy is configured.
    #[must_use]
    pub fn restricts_loopback(&self) -> bool {
        self.loopback.is_some()
    }

    /// The target to name when asking an upstream (enterprise) proxy to
    /// CONNECT on a client's behalf.
    ///
    /// Without a loopback policy this is `host` unchanged, the existing
    /// behaviour. With one, a hostname would be resolved a second time by the
    /// upstream proxy, and that answer can differ from the one checked here
    /// (DNS rebinding). If the upstream proxy runs on this machine, a
    /// rebound answer lands on local loopback. So the target is pinned to
    /// the first address this filter checked, bracketed for IPv6.
    ///
    /// Returns `None` when there is no checked address to pin to (local DNS
    /// failed). Callers must refuse the request: forwarding the hostname would
    /// skip the loopback check entirely.
    #[must_use]
    pub fn upstream_proxy_target(&self, host: &str, check: &CheckResult) -> Option<String> {
        if !self.restricts_loopback() {
            return Some(host.to_string());
        }
        let ip = check.resolved_addrs.first()?.ip();
        Some(match ip {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => format!("[{v6}]"),
        })
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
        assert!(matches!(
            result,
            ProxyFilterResult::Host(FilterResult::DenyHost { .. })
        ));
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
        assert!(matches!(
            result,
            ProxyFilterResult::Host(FilterResult::DenyHost { .. })
        ));

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
        assert!(matches!(
            result,
            ProxyFilterResult::Host(FilterResult::DenyHost { .. })
        ));
    }

    #[test]
    fn test_proxy_filter_denied_host_port_honored_for_ipv6_literal() {
        // An IPv6 host:port deny must match the bracketed authority form,
        // not "::1:8975" (ambiguous with the port separator).
        let filter =
            ProxyFilter::new(&["*".to_string()]).with_denied_hosts(&["[::1]:8975".to_string()]);

        let result = filter.check_host_result("::1", 8975, &[]);
        assert!(!result.is_allowed(), "IPv6 host:port form must be denied");
        assert!(matches!(
            result,
            ProxyFilterResult::Host(FilterResult::DenyHost { .. })
        ));

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
        assert!(matches!(
            result,
            ProxyFilterResult::Host(FilterResult::DenyNotAllowed { .. })
        ));
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
        assert!(matches!(
            result.result,
            ProxyFilterResult::Host(FilterResult::DenyNotAllowed { .. })
        ));
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

    // ---- Loopback policy (issue #605) -------------------------------------
    //
    // The bypass these cover: with the proxy active the OS sandbox pins the
    // child to `loopback:<proxy port>`, so the proxy is the only route off
    // loopback. Without a loopback policy the child can still ask the proxy to
    // CONNECT to another local service (e.g. a Kind API server on 6443) and
    // reach it directly, skipping the credential route meant to mediate it.

    /// The default filter is unchanged: loopback stays reachable unless a
    /// policy is attached. Guards against silently tightening existing setups.
    #[test]
    fn test_loopback_reachable_without_policy() {
        let filter = ProxyFilter::allow_all();
        let loopback = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];
        assert!(
            filter
                .check_host_result("127.0.0.1", 6443, &loopback)
                .is_allowed()
        );
        assert!(
            filter
                .check_host_result("localhost", 6443, &loopback)
                .is_allowed()
        );
    }

    #[test]
    fn test_loopback_policy_denies_ipv4_literal() {
        let filter = ProxyFilter::allow_all().with_loopback_policy(LoopbackPolicy::new(&[]));
        let result = filter.check_host_result("127.0.0.1", 6443, &[]);
        assert!(matches!(result, ProxyFilterResult::DenyLoopback { .. }));
    }

    /// Any address in 127.0.0.0/8 is loopback, not just 127.0.0.1.
    #[test]
    fn test_loopback_policy_denies_whole_127_range() {
        let filter = ProxyFilter::allow_all().with_loopback_policy(LoopbackPolicy::new(&[]));
        let result = filter.check_host_result("127.9.9.9", 6443, &[]);
        assert!(matches!(result, ProxyFilterResult::DenyLoopback { .. }));
    }

    #[test]
    fn test_loopback_policy_denies_ipv6_literal() {
        let filter = ProxyFilter::allow_all().with_loopback_policy(LoopbackPolicy::new(&[]));
        let result = filter.check_host_result("::1", 6443, &[]);
        assert!(matches!(result, ProxyFilterResult::DenyLoopback { .. }));
    }

    /// `localhost` is refused on the hostname alone, before DNS is consulted.
    #[test]
    fn test_loopback_policy_denies_localhost_name_without_dns() {
        let filter = ProxyFilter::allow_all().with_loopback_policy(LoopbackPolicy::new(&[]));
        let result = filter.check_host_result("localhost", 6443, &[]);
        assert!(matches!(result, ProxyFilterResult::DenyLoopback { .. }));
    }

    /// RFC 6761: names under `.localhost` are loopback too, and a trailing dot
    /// must not sidestep the check.
    #[test]
    fn test_loopback_policy_denies_localhost_subdomain_and_trailing_dot() {
        let filter = ProxyFilter::allow_all().with_loopback_policy(LoopbackPolicy::new(&[]));
        assert!(
            !filter
                .check_host_result("api.localhost", 6443, &[])
                .is_allowed()
        );
        assert!(
            !filter
                .check_host_result("LOCALHOST.", 6443, &[])
                .is_allowed()
        );
    }

    /// DNS rebinding: a public name that resolves onto loopback is denied on
    /// the resolved IP even though the literal looks innocuous.
    #[test]
    fn test_loopback_policy_denies_rebinding_to_loopback() {
        let filter = ProxyFilter::allow_all().with_loopback_policy(LoopbackPolicy::new(&[]));
        let rebound = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];
        let result = filter.check_host_result("evil.example", 6443, &rebound);
        assert!(matches!(result, ProxyFilterResult::DenyLoopback { .. }));
    }

    /// An IPv4-mapped IPv6 answer (`::ffff:127.0.0.1`) must not slip past.
    #[test]
    fn test_loopback_policy_denies_ipv4_mapped_ipv6_loopback() {
        let filter = ProxyFilter::allow_all().with_loopback_policy(LoopbackPolicy::new(&[]));
        let mapped = vec![IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped())];
        let result = filter.check_host_result("evil.example", 6443, &mapped);
        assert!(matches!(result, ProxyFilterResult::DenyLoopback { .. }));
    }

    /// The mapped check covers all of `::ffff:127.0.0.0/104`, not just
    /// `::ffff:127.0.0.1`, plus the mapped unspecified address.
    #[test]
    fn test_loopback_policy_denies_whole_mapped_range_and_mapped_unspecified() {
        let filter = ProxyFilter::allow_all().with_loopback_policy(LoopbackPolicy::new(&[]));
        for v4 in [
            Ipv4Addr::new(127, 0, 0, 2),
            Ipv4Addr::new(127, 255, 255, 254),
            Ipv4Addr::UNSPECIFIED,
        ] {
            let mapped = vec![IpAddr::V6(v4.to_ipv6_mapped())];
            let result = filter.check_host_result("evil.example", 6443, &mapped);
            assert!(
                matches!(result, ProxyFilterResult::DenyLoopback { .. }),
                "{v4} mapped into IPv6 must be denied"
            );
        }
    }

    fn check_with_addrs(addrs: &[SocketAddr]) -> CheckResult {
        CheckResult {
            result: ProxyFilterResult::Host(FilterResult::Allow),
            resolved_addrs: addrs.to_vec(),
        }
    }

    /// Without a loopback policy the upstream proxy is still sent the
    /// hostname, so existing upstream-proxy setups are unaffected.
    #[test]
    fn test_upstream_proxy_target_unchanged_without_policy() {
        let filter = ProxyFilter::allow_all();
        let check = check_with_addrs(&[SocketAddr::from(([93, 184, 215, 14], 443))]);
        assert_eq!(
            filter.upstream_proxy_target("example.com", &check),
            Some("example.com".to_string())
        );
    }

    /// With a policy, the target is pinned to the checked address so the
    /// upstream proxy cannot resolve the name to something else.
    #[test]
    fn test_upstream_proxy_target_pins_checked_ip() {
        let filter = ProxyFilter::allow_all().with_loopback_policy(LoopbackPolicy::new(&[]));
        let check = check_with_addrs(&[
            SocketAddr::from(([93, 184, 215, 14], 443)),
            SocketAddr::from(([93, 184, 215, 15], 443)),
        ]);
        assert_eq!(
            filter.upstream_proxy_target("example.com", &check),
            Some("93.184.215.14".to_string())
        );
    }

    #[test]
    fn test_upstream_proxy_target_brackets_ipv6() {
        let filter = ProxyFilter::allow_all().with_loopback_policy(LoopbackPolicy::new(&[]));
        let v6: Ipv6Addr = "2606:2800:21f:cb07:6820:80da:af6b:8b2c"
            .parse()
            .expect("valid IPv6 literal");
        let check = check_with_addrs(&[SocketAddr::from((v6, 443))]);
        assert_eq!(
            filter.upstream_proxy_target("example.com", &check),
            Some(format!("[{v6}]"))
        );
    }

    /// No checked address means nothing safe to pin to. The caller must refuse
    /// rather than fall back to forwarding the hostname.
    #[test]
    fn test_upstream_proxy_target_fails_closed_without_resolution() {
        let filter = ProxyFilter::allow_all().with_loopback_policy(LoopbackPolicy::new(&[]));
        let check = check_with_addrs(&[]);
        assert_eq!(filter.upstream_proxy_target("example.com", &check), None);
    }

    /// The deny runs before the allowlist, so a wildcard allow cannot shadow
    /// it — same ordering guarantee the metadata deny list has.
    #[test]
    fn test_loopback_policy_beats_wildcard_allowlist() {
        let filter =
            ProxyFilter::new(&["*".to_string()]).with_loopback_policy(LoopbackPolicy::new(&[]));
        let result = filter.check_host_result("127.0.0.1", 6443, &[]);
        assert!(matches!(result, ProxyFilterResult::DenyLoopback { .. }));
    }

    /// `connect(2)` to `0.0.0.0` reaches localhost on Linux and macOS, so the
    /// unspecified address must be treated as loopback — otherwise the whole
    /// restriction is one spelling away from useless.
    #[test]
    fn test_loopback_policy_denies_unspecified_ipv4() {
        let filter = ProxyFilter::allow_all().with_loopback_policy(LoopbackPolicy::new(&[]));
        let result = filter.check_host_result("0.0.0.0", 6443, &[]);
        assert!(matches!(result, ProxyFilterResult::DenyLoopback { .. }));
    }

    #[test]
    fn test_loopback_policy_denies_unspecified_ipv6() {
        let filter = ProxyFilter::allow_all().with_loopback_policy(LoopbackPolicy::new(&[]));
        let result = filter.check_host_result("::", 6443, &[]);
        assert!(matches!(result, ProxyFilterResult::DenyLoopback { .. }));
    }

    /// And the same when it arrives as a resolved answer rather than a literal.
    #[test]
    fn test_loopback_policy_denies_resolved_unspecified_address() {
        let filter = ProxyFilter::allow_all().with_loopback_policy(LoopbackPolicy::new(&[]));
        let resolved = vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)];
        let result = filter.check_host_result("evil.example", 6443, &resolved);
        assert!(matches!(result, ProxyFilterResult::DenyLoopback { .. }));
    }

    /// The metadata deny list has a matching test for this spelling; a
    /// non-ASCII label separator must not slip `localhost` past either.
    #[test]
    fn test_loopback_policy_denies_unicode_label_separator() {
        let filter = ProxyFilter::allow_all().with_loopback_policy(LoopbackPolicy::new(&[]));
        let result = filter.check_host_result("localhost\u{3002}", 6443, &[]);
        assert!(
            !result.is_allowed(),
            "a unicode label separator must not bypass the loopback policy"
        );
    }

    #[test]
    fn test_loopback_policy_allows_listed_port() {
        let filter = ProxyFilter::allow_all().with_loopback_policy(LoopbackPolicy::new(&[8080]));
        assert!(
            filter
                .check_host_result("127.0.0.1", 8080, &[])
                .is_allowed()
        );
        // Neighbouring ports stay denied.
        assert!(
            !filter
                .check_host_result("127.0.0.1", 8081, &[])
                .is_allowed()
        );
    }

    /// The route-upstream exemption follows the caller, not the address: the
    /// proxy dialling for a configured route gets through, while a client
    /// asking for that same address does not. Exempting the address instead
    /// would hand the client a way around the route's endpoint_policy and
    /// credential injection.
    #[tokio::test]
    async fn test_route_upstream_bypasses_policy_but_client_path_does_not() {
        let filter = ProxyFilter::allow_all().with_loopback_policy(LoopbackPolicy::new(&[]));

        let as_route = filter
            .check_route_upstream("127.0.0.1", 6443)
            .await
            .expect("route upstream check");
        assert!(
            as_route.result.is_allowed(),
            "a configured route's own upstream dial must not be blocked"
        );

        let as_client = filter
            .check_host("127.0.0.1", 6443)
            .await
            .expect("client check");
        assert!(
            matches!(as_client.result, ProxyFilterResult::DenyLoopback { .. }),
            "a client asking for the route's upstream directly must be refused"
        );
    }

    /// The route path is exempt from the loopback policy only — it must still
    /// obey the metadata deny list.
    #[tokio::test]
    async fn test_route_upstream_still_honours_metadata_deny() {
        let filter = ProxyFilter::allow_all().with_loopback_policy(LoopbackPolicy::new(&[]));
        let check = filter
            .check_route_upstream("169.254.169.254", 80)
            .await
            .expect("route upstream check");
        assert!(!check.result.is_allowed());
    }

    /// A loopback exemption must not become a hole in the metadata deny list.
    #[test]
    fn test_loopback_policy_does_not_weaken_metadata_deny() {
        let filter = ProxyFilter::allow_all().with_loopback_policy(LoopbackPolicy::new(&[80]));
        let result = filter.check_host_result("169.254.169.254", 80, &[]);
        assert!(!result.is_allowed());
    }

    /// Non-loopback traffic is untouched by the policy.
    #[test]
    fn test_loopback_policy_leaves_public_hosts_alone() {
        let filter = ProxyFilter::new(&["api.openai.com".to_string()])
            .with_loopback_policy(LoopbackPolicy::new(&[]));
        let public = vec![IpAddr::V4(Ipv4Addr::new(104, 18, 7, 96))];
        assert!(
            filter
                .check_host_result("api.openai.com", 443, &public)
                .is_allowed()
        );
    }

    /// RFC1918 stays allowed: the security model documents private address
    /// space as reachable, and this change must not narrow that.
    #[test]
    fn test_loopback_policy_leaves_rfc1918_alone() {
        let filter = ProxyFilter::allow_all().with_loopback_policy(LoopbackPolicy::new(&[]));
        let private = vec![IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))];
        assert!(
            filter
                .check_host_result("internal.example", 6443, &private)
                .is_allowed()
        );
    }

    #[test]
    fn test_loopback_deny_reason_is_descriptive() {
        let filter = ProxyFilter::allow_all().with_loopback_policy(LoopbackPolicy::new(&[]));
        let reason = filter.check_host_result("127.0.0.1", 6443, &[]).reason();
        assert!(reason.contains("loopback"), "unexpected reason: {reason}");
        assert!(
            reason.contains("127.0.0.1:6443"),
            "unexpected reason: {reason}"
        );
    }

    /// `with_denied_hosts` is a consuming builder; make sure it does not drop
    /// a policy attached before it.
    #[test]
    fn test_loopback_policy_survives_with_denied_hosts() {
        let filter = ProxyFilter::allow_all()
            .with_loopback_policy(LoopbackPolicy::new(&[]))
            .with_denied_hosts(&["blocked.example".to_string()]);
        assert!(
            !filter
                .check_host_result("127.0.0.1", 6443, &[])
                .is_allowed()
        );
    }
}
