//! External proxy passthrough handler (Mode 3 — Enterprise).
//!
//! Chains CONNECT requests to an upstream enterprise proxy (Squid, Cisco WSA,
//! Zscaler, etc.). Cloud metadata endpoints are still denied before forwarding.
//! The enterprise proxy makes the final allow/deny decision.
//!
//! The CONNECT-handshake-against-the-enterprise-proxy logic is extracted into
//! [`connect_via_proxy`] so the TLS-intercept upstream leg can reuse it.

use crate::audit;
use crate::config::ExternalProxyConfig;
use crate::error::{ProxyError, Result};
use crate::filter::ProxyFilter;
use crate::token;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::debug;
use zeroize::Zeroizing;

/// TCP-connect to an enterprise proxy and CONNECT through it to `target_host:target_port`.
///
/// Returns the resulting TCP stream after a successful `200 Connection Established`.
/// Used by:
///
/// * [`handle_external_proxy`] for the transparent passthrough mode (the
///   stream is then byte-relayed to the agent).
/// * The TLS-intercept upstream leg ([`crate::tls_intercept`]) which wraps
///   the returned stream in a TLS handshake to the real upstream.
///
/// `proxy_auth_header` is the literal value to send in `Proxy-Authorization`
/// when authenticating to the enterprise proxy (e.g. `"Basic dXNlcjpwYXNz"`).
/// Pass `None` for unauthenticated proxies.
pub async fn connect_via_proxy(
    proxy_addr: &str,
    target_host: &str,
    target_port: u16,
    proxy_auth_header: Option<&str>,
) -> Result<TcpStream> {
    let mut proxy_stream = TcpStream::connect(proxy_addr).await.map_err(|e| {
        ProxyError::ExternalProxy(format!(
            "cannot connect to external proxy {}: {}",
            proxy_addr, e
        ))
    })?;

    let mut connect_req = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n",
        target_host, target_port, target_host, target_port
    );
    if let Some(auth) = proxy_auth_header {
        connect_req.push_str(&format!("Proxy-Authorization: {}\r\n", auth));
    }
    connect_req.push_str("\r\n");

    proxy_stream
        .write_all(connect_req.as_bytes())
        .await
        .map_err(|e| {
            ProxyError::ExternalProxy(format!("failed to send CONNECT to external proxy: {}", e))
        })?;

    let mut buf_reader = BufReader::new(&mut proxy_stream);
    let mut response_line = String::new();
    buf_reader
        .read_line(&mut response_line)
        .await
        .map_err(|e| {
            ProxyError::ExternalProxy(format!(
                "failed to read response from external proxy: {}",
                e
            ))
        })?;

    let status = parse_status_code(&response_line)?;
    if status != 200 {
        return Err(ProxyError::ExternalProxy(format!(
            "enterprise proxy rejected CONNECT to {}:{} with status {}",
            target_host, target_port, status
        )));
    }

    // Drain headers up to the empty line.
    loop {
        let mut line = String::new();
        buf_reader.read_line(&mut line).await.map_err(|e| {
            ProxyError::ExternalProxy(format!("failed to drain proxy response headers: {}", e))
        })?;
        if line.trim().is_empty() {
            break;
        }
    }
    drop(buf_reader);
    Ok(proxy_stream)
}

/// Matcher for hosts that should bypass the external proxy.
///
/// Supports exact hostname match and `*.` wildcard suffix match,
/// both case-insensitive. Uses the same `*`-prefix parsing pattern
/// as `HostFilter::new()`.
#[derive(Debug, Clone)]
pub struct BypassMatcher {
    /// Exact hostnames (lowercased)
    exact: Vec<String>,
    /// Wildcard suffixes (e.g., ".internal.corp", lowercased)
    suffixes: Vec<String>,
}

impl BypassMatcher {
    /// Create a new bypass matcher from a list of host patterns.
    ///
    /// Entries starting with `*.` are wildcard patterns matching any subdomain.
    /// All other entries are exact matches. Matching is case-insensitive.
    ///
    /// Only the `*.domain` form is accepted for wildcards. Bare `*` and
    /// patterns like `*corp` (without the dot) are treated as exact hostnames
    /// to prevent accidental over-broad matching.
    #[must_use]
    pub fn new(hosts: &[String]) -> Self {
        let mut exact = Vec::new();
        let mut suffixes = Vec::new();

        for host in hosts {
            let lower = host.to_lowercase();
            if let Some(suffix) = lower.strip_prefix("*.") {
                // *.example.com -> .example.com
                if !suffix.is_empty() {
                    suffixes.push(format!(".{suffix}"));
                }
                // Bare "*." with nothing after is silently ignored (no valid domain)
            } else {
                exact.push(lower);
            }
        }

        Self { exact, suffixes }
    }

    /// Check whether a host should bypass the external proxy.
    #[must_use]
    pub fn matches(&self, host: &str) -> bool {
        let lower = host.to_lowercase();

        // Exact match
        if self.exact.contains(&lower) {
            return true;
        }

        // Wildcard suffix match
        for suffix in &self.suffixes {
            if lower.ends_with(suffix.as_str()) && lower.len() > suffix.len() {
                return true;
            }
        }

        false
    }

    /// Whether any bypass hosts are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.suffixes.is_empty()
    }
}

/// Handle a CONNECT request by chaining it to an external proxy.
///
/// 1. Validate session token
/// 2. Check host against cloud metadata deny list
/// 3. Connect to enterprise proxy
/// 4. Send CONNECT to enterprise proxy (with optional Proxy-Authorization)
/// 5. Wait for enterprise proxy 200
/// 6. Bidirectional tunnel: agent <-> enterprise proxy <-> upstream
pub async fn handle_external_proxy(
    first_line: &str,
    stream: &mut TcpStream,
    remaining_header: &[u8],
    filter: &ProxyFilter,
    session_token: &Zeroizing<String>,
    external_config: &ExternalProxyConfig,
    audit_log: Option<&audit::SharedAuditLog>,
) -> Result<()> {
    // Parse CONNECT target
    let (host, port) = parse_connect_target(first_line)?;
    debug!("External proxy CONNECT to {}:{}", host, port);

    // Validate session token
    validate_proxy_auth(remaining_header, session_token)?;

    // Check cloud metadata deny list.
    // Cloud metadata endpoints are always blocked even through enterprise proxies.
    let check = filter.check_host(&host, port).await?;
    if !check.result.is_allowed() {
        let reason = check.result.reason();
        audit::log_denied(
            audit_log,
            audit::ProxyMode::External,
            &audit::EventContext {
                auth_mechanism: Some(nono::undo::NetworkAuditAuthMechanism::ProxyAuthorization),
                auth_outcome: Some(nono::undo::NetworkAuditAuthOutcome::Succeeded),
                denial_category: Some(nono::undo::NetworkAuditDenialCategory::HostDenied),
                ..audit::EventContext::default()
            },
            &host,
            port,
            &reason,
        );
        send_response(stream, 403, &format!("Forbidden: {}", reason)).await?;
        return Err(ProxyError::HostDenied { host, reason });
    }

    // External proxy authentication is not yet implemented. If auth is
    // configured, fail loudly rather than silently sending unauthenticated
    // requests that the enterprise proxy will reject.
    if external_config.auth.is_some() {
        return Err(ProxyError::ExternalProxy(
            "external proxy authentication is configured but not yet implemented; \
             remove the auth section from the external proxy config or wait for \
             a future release"
                .to_string(),
        ));
    }

    // Connect to enterprise proxy and CONNECT through it to the upstream.
    // Auth is gated above; pass None until configurable proxy auth lands.
    let mut proxy_stream = match connect_via_proxy(&external_config.address, &host, port, None)
        .await
    {
        Ok(s) => s,
        Err(ProxyError::ExternalProxy(msg)) if msg.contains("rejected CONNECT") => {
            // Enterprise proxy returned non-200. Surface the same status
            // back to the agent so it can react sensibly (e.g. blocked
            // by corporate policy).
            audit::log_denied(
                audit_log,
                audit::ProxyMode::External,
                &audit::EventContext {
                    auth_mechanism: Some(nono::undo::NetworkAuditAuthMechanism::ProxyAuthorization),
                    auth_outcome: Some(nono::undo::NetworkAuditAuthOutcome::Succeeded),
                    denial_category: Some(
                        nono::undo::NetworkAuditDenialCategory::ExternalProxyRejected,
                    ),
                    ..audit::EventContext::default()
                },
                &host,
                port,
                &msg,
            );
            send_response(stream, 502, "Bad Gateway").await?;
            return Err(ProxyError::ExternalProxy(msg));
        }
        Err(e) => {
            audit::log_denied(
                audit_log,
                audit::ProxyMode::External,
                &audit::EventContext {
                    auth_mechanism: Some(nono::undo::NetworkAuditAuthMechanism::ProxyAuthorization),
                    auth_outcome: Some(nono::undo::NetworkAuditAuthOutcome::Succeeded),
                    denial_category: Some(
                        nono::undo::NetworkAuditDenialCategory::UpstreamConnectFailed,
                    ),
                    ..audit::EventContext::default()
                },
                &host,
                port,
                &e.to_string(),
            );
            send_response(stream, 502, "Bad Gateway").await?;
            return Err(e);
        }
    };

    // Send 200 to agent
    send_response(stream, 200, "Connection Established").await?;
    audit::log_allowed(
        audit_log,
        audit::ProxyMode::External,
        &audit::EventContext {
            auth_mechanism: Some(nono::undo::NetworkAuditAuthMechanism::ProxyAuthorization),
            auth_outcome: Some(nono::undo::NetworkAuditAuthOutcome::Succeeded),
            ..audit::EventContext::default()
        },
        &host,
        port,
        "CONNECT",
    );

    // Bidirectional tunnel: agent <-> enterprise proxy <-> upstream
    let result = tokio::io::copy_bidirectional(stream, &mut proxy_stream).await;
    debug!(
        "External proxy tunnel closed for {}:{}: {:?}",
        host, port, result
    );

    Ok(())
}

/// Parse CONNECT target (reused from connect.rs pattern).
fn parse_connect_target(line: &str) -> Result<(String, u16)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(ProxyError::HttpParse(format!(
            "malformed CONNECT line: {}",
            line
        )));
    }

    let authority = parts[1];
    if let Some((host, port_str)) = authority.rsplit_once(':') {
        let port = port_str.parse::<u16>().map_err(|_| {
            ProxyError::HttpParse(format!("invalid port in CONNECT: {}", authority))
        })?;
        Ok((host.to_string(), port))
    } else {
        Ok((authority.to_string(), 443))
    }
}

/// Validate Proxy-Authorization header.
///
/// Delegates to `token::validate_proxy_auth` which accepts both Bearer
/// and Basic auth formats.
fn validate_proxy_auth(header_bytes: &[u8], session_token: &Zeroizing<String>) -> Result<()> {
    token::validate_proxy_auth(header_bytes, session_token)
}

/// Parse HTTP status code from a response line.
fn parse_status_code(line: &str) -> Result<u16> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(ProxyError::HttpParse(format!(
            "malformed HTTP response: {}",
            line
        )));
    }
    parts[1]
        .parse::<u16>()
        .map_err(|_| ProxyError::HttpParse(format!("invalid status code in response: {}", line)))
}

/// Send an HTTP response line.
async fn send_response(stream: &mut TcpStream, status: u16, reason: &str) -> Result<()> {
    let response = format!("HTTP/1.1 {} {}\r\n\r\n", status, reason);
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_connect_target() {
        let (host, port) = parse_connect_target("CONNECT api.openai.com:443 HTTP/1.1").unwrap();
        assert_eq!(host, "api.openai.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_status_code_200() {
        assert_eq!(
            parse_status_code("HTTP/1.1 200 Connection Established\r\n").unwrap(),
            200
        );
    }

    #[test]
    fn test_parse_status_code_403() {
        assert_eq!(
            parse_status_code("HTTP/1.1 403 Forbidden\r\n").unwrap(),
            403
        );
    }

    #[test]
    fn test_parse_status_code_malformed() {
        assert!(parse_status_code("garbage").is_err());
    }

    #[test]
    fn test_bypass_matcher_exact() {
        let matcher = BypassMatcher::new(&["internal.corp".to_string()]);
        assert!(matcher.matches("internal.corp"));
        assert!(!matcher.matches("other.corp"));
    }

    #[test]
    fn test_bypass_matcher_case_insensitive() {
        let matcher = BypassMatcher::new(&["Internal.Corp".to_string()]);
        assert!(matcher.matches("internal.corp"));
        assert!(matcher.matches("INTERNAL.CORP"));
    }

    #[test]
    fn test_bypass_matcher_wildcard() {
        let matcher = BypassMatcher::new(&["*.internal.corp".to_string()]);
        assert!(matcher.matches("app.internal.corp"));
        assert!(matcher.matches("deep.sub.internal.corp"));
        // Bare domain should NOT match wildcard
        assert!(!matcher.matches("internal.corp"));
    }

    #[test]
    fn test_bypass_matcher_wildcard_case_insensitive() {
        let matcher = BypassMatcher::new(&["*.Internal.Corp".to_string()]);
        assert!(matcher.matches("APP.INTERNAL.CORP"));
    }

    #[test]
    fn test_bypass_matcher_no_match() {
        let matcher =
            BypassMatcher::new(&["internal.corp".to_string(), "*.private.net".to_string()]);
        assert!(!matcher.matches("api.openai.com"));
        assert!(!matcher.matches("evil.com"));
    }

    #[test]
    fn test_bypass_matcher_empty() {
        let matcher = BypassMatcher::new(&[]);
        assert!(matcher.is_empty());
        assert!(!matcher.matches("anything.com"));
    }

    #[test]
    fn test_bypass_matcher_mixed() {
        let matcher =
            BypassMatcher::new(&["exact.host.com".to_string(), "*.wildcard.com".to_string()]);
        assert!(matcher.matches("exact.host.com"));
        assert!(matcher.matches("sub.wildcard.com"));
        assert!(!matcher.matches("wildcard.com"));
        assert!(!matcher.matches("other.com"));
    }

    #[test]
    fn test_bypass_matcher_bare_star_is_not_wildcard() {
        // Bare "*" must NOT bypass everything — it should be treated as
        // a literal (non-matching) hostname, not a universal wildcard.
        let matcher = BypassMatcher::new(&["*".to_string()]);
        assert!(!matcher.matches("anything.com"));
        assert!(!matcher.matches("internal.corp"));
    }

    #[test]
    fn test_bypass_matcher_star_without_dot_is_literal() {
        // "*corp" (no dot) must NOT be treated as a wildcard suffix.
        // Only "*.corp" is a valid wildcard pattern.
        let matcher = BypassMatcher::new(&["*corp".to_string()]);
        assert!(!matcher.matches("internal.corp"));
        assert!(!matcher.matches("subcorp"));
        // It's treated as the literal hostname "*corp"
        assert!(matcher.matches("*corp"));
    }

    #[test]
    fn test_bypass_matcher_star_dot_only_is_ignored() {
        // "*." with nothing after is not a valid domain pattern.
        let matcher = BypassMatcher::new(&["*.".to_string()]);
        assert!(matcher.is_empty());
        assert!(!matcher.matches("anything.com"));
    }
}
