//! Proxy configuration types.
//!
//! Defines the configuration for the proxy server, including allowed hosts,
//! credential routes, and external proxy settings.

use globset::Glob;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;
use zeroize::Zeroizing;

/// Credential injection mode determining how credentials are inserted into requests.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InjectMode {
    /// Inject credential into an HTTP header (default)
    #[default]
    Header,
    /// Replace a pattern in the URL path with the credential
    UrlPath,
    /// Add or replace a query parameter with the credential
    QueryParam,
    /// Use HTTP Basic Authentication (credential format: "username:password")
    BasicAuth,
}

/// Configuration for the proxy server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Bind address (default: 127.0.0.1)
    #[serde(default = "default_bind_addr")]
    pub bind_addr: IpAddr,

    /// Bind port (0 = OS-assigned ephemeral port)
    #[serde(default)]
    pub bind_port: u16,

    /// Allowed hosts for CONNECT mode (exact match + wildcards).
    /// Empty = allow all hosts (except deny list).
    #[serde(default)]
    pub allowed_hosts: Vec<String>,

    /// Rejected hosts for CONNECT mode (exact match + wildcards).
    /// Takes priority over `allowed_hosts`. Supports wildcards
    /// (`*.evil.com`).
    #[serde(default)]
    pub rejected_hosts: Vec<String>,

    /// Reverse proxy credential routes.
    #[serde(default)]
    pub routes: Vec<RouteConfig>,

    /// External (enterprise) proxy URL for passthrough mode.
    /// When set, CONNECT requests are chained to this proxy.
    #[serde(default)]
    pub external_proxy: Option<ExternalProxyConfig>,

    /// Outbound TCP ports that the sandbox allows direct connections on
    /// (via Landlock ConnectTcp). Hosts whose resolved port is NOT in this
    /// set must go through the proxy and should NOT appear in NO_PROXY.
    #[serde(default)]
    pub direct_connect_ports: Vec<u16>,

    /// Maximum concurrent connections (0 = unlimited).
    #[serde(default)]
    pub max_connections: usize,

    /// Directory the proxy will write the TLS-intercept trust bundle into.
    ///
    /// When set together with at least one route requiring L7 visibility
    /// (`endpoint_rules`, `credential_key`, or `oauth2`), the proxy generates
    /// an ephemeral session CA and writes a PEM bundle (system roots +
    /// optional parent `SSL_CERT_FILE` + ephemeral CA) into this directory at
    /// startup. The path is exposed via `ProxyHandle::intercept_ca_path()`
    /// so the CLI can grant the sandboxed child a Landlock/Seatbelt read
    /// capability for it.
    ///
    /// The directory must exist and be owner-only readable (mode `0o700`)
    /// before `start()` is called. The CLI conventionally points this at
    /// `~/.nono/sessions/<session_id>/`.
    ///
    /// `None` disables TLS interception entirely; CONNECT requests behave
    /// as before (transparent tunnel for non-route hosts; 403 for routes
    /// without L7 requirements).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intercept_ca_dir: Option<PathBuf>,

    /// Optional contents of the parent process's `SSL_CERT_FILE`, merged
    /// into the trust bundle so any corporate CA configured on the host
    /// remains trusted by the sandboxed child.
    ///
    /// The CLI reads this from `std::env::var("SSL_CERT_FILE")` and
    /// `std::fs::read(...)` before calling `start()`. Skipped during
    /// (de)serialisation: it's not part of any user-authored config file.
    #[serde(default, skip)]
    pub intercept_parent_ca_pems: Option<Vec<u8>>,

    /// Pre-generated CA material for cross-session reuse (`--trust-proxy-ca`).
    ///
    /// When `Some`, the proxy uses this CA instead of generating a fresh
    /// ephemeral one. The private key was loaded from macOS Keychain by the
    /// CLI supervisor; the cert is already trusted in the user's trust store.
    #[serde(default, skip)]
    pub preloaded_ca: Option<PreloadedCa>,

    /// Optional CA validity override for TLS interception.
    /// Default (`None`) uses `CA_VALIDITY_DEFAULT` (24h).
    /// Set by CLI `--proxy-ca-validity` flag.
    #[serde(default, skip)]
    pub ca_validity: Option<std::time::Duration>,
}

/// Pre-generated CA key material for cross-session CA reuse.
///
/// Used by `--trust-proxy-ca` on macOS: the CLI persists the CA in Keychain
/// and passes it to the proxy so all sessions within the CA's validity window
/// share the same signing key (and the same trusted cert in the system store).
///
/// ## Security note
///
/// The Keychain item's access control depends on the binary's code-signing
/// identity. Release-signed builds get per-app isolation; unsigned dev builds
/// allow any local process to read the key.
///
/// Because the CA is trusted user-wide during its validity window, any
/// same-user process that can read the Keychain item could mint certificates
/// trusted by macOS trust consumers. Release-signed builds are expected to
/// receive stronger Keychain access isolation than unsigned development builds.
/// The configurable CA validity (`--proxy-ca-validity`) limits exposure.
#[derive(Clone)]
pub struct PreloadedCa {
    /// PKCS#8 DER-encoded private key for the CA. Zeroized on drop.
    pub key_der: Zeroizing<Vec<u8>>,
    /// PEM-encoded CA certificate (public).
    pub cert_pem: String,
}

impl std::fmt::Debug for PreloadedCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreloadedCa")
            .field("key_der", &"[REDACTED]")
            .field("cert_pem_len", &self.cert_pem.len())
            .finish()
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_bind_addr(),
            bind_port: 0,
            allowed_hosts: Vec::new(),
            rejected_hosts: Vec::new(),
            routes: Vec::new(),
            external_proxy: None,
            direct_connect_ports: Vec::new(),
            max_connections: 256,
            intercept_ca_dir: None,
            intercept_parent_ca_pems: None,
            preloaded_ca: None,
            ca_validity: None,
        }
    }
}

fn default_bind_addr() -> IpAddr {
    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
}

/// Configuration for a reverse proxy credential route.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    /// Path prefix for routing (e.g., "openai").
    /// Must NOT include leading or trailing slashes — it is a bare service name, not a URL path.
    pub prefix: String,

    /// Upstream URL to forward to (e.g., "https://api.openai.com")
    pub upstream: String,

    /// Keystore account name to load the credential from.
    /// If `None`, no credential is injected.
    pub credential_key: Option<String>,

    /// Injection mode (default: "header")
    #[serde(default)]
    pub inject_mode: InjectMode,

    // --- Header mode fields ---
    /// HTTP header name for the credential (default: "Authorization")
    /// Only used when inject_mode is "header".
    #[serde(default = "default_inject_header")]
    pub inject_header: String,

    /// How the injected header value is built (`{}` is replaced by the secret). Only when `inject_mode` is header.
    ///
    /// If you set this field, that whole string is used as-is — `Authorization` or any other header.
    ///
    /// If you omit it: an `Authorization` header (any capitalization) defaults to `Bearer {}`; any other header defaults to `{}` (secret only, no prefix).
    #[serde(default)]
    pub credential_format: Option<String>,

    // --- URL path mode fields ---
    /// Pattern to match in incoming URL path. Use {} as placeholder for phantom token.
    /// Example: "/bot{}/" matches "/bot<token>/getMe"
    /// Only used when inject_mode is "url_path".
    #[serde(default)]
    pub path_pattern: Option<String>,

    /// Pattern for outgoing URL path. Use {} as placeholder for real credential.
    /// Defaults to same as path_pattern if not specified.
    /// Only used when inject_mode is "url_path".
    #[serde(default)]
    pub path_replacement: Option<String>,

    // --- Query param mode fields ---
    /// Name of the query parameter to add/replace with the credential.
    /// Only used when inject_mode is "query_param".
    #[serde(default)]
    pub query_param_name: Option<String>,

    /// Optional overrides for proxy-side phantom token handling.
    ///
    /// When set, these values are used to validate the incoming phantom token
    /// from the sandboxed client request. Outbound credential injection to the
    /// upstream continues to use the top-level route fields.
    #[serde(default)]
    pub proxy: Option<ProxyInjectConfig>,

    /// Explicit environment variable name for the phantom token (e.g., "OPENAI_API_KEY").
    ///
    /// When set, this is used as the SDK API key env var name instead of deriving
    /// it from `credential_key.to_uppercase()`. Required when `credential_key` is
    /// a URI manager reference (e.g., `op://`, `apple-password://`) which would
    /// otherwise produce a nonsensical env var name.
    #[serde(default)]
    pub env_var: Option<String>,

    /// Optional L7 endpoint rules for method+path filtering.
    ///
    /// When non-empty, only requests matching at least one rule are allowed
    /// (default-deny). When empty, all method+path combinations are permitted
    /// (backward compatible).
    #[serde(default)]
    pub endpoint_rules: Vec<EndpointRule>,

    /// Optional path to a PEM-encoded CA certificate file for upstream TLS.
    ///
    /// When set, the proxy trusts this CA in addition to the system roots
    /// when connecting to the upstream for this route. This is required for
    /// upstreams that use self-signed or private CA certificates (e.g.,
    /// Kubernetes API servers).
    #[serde(default)]
    pub tls_ca: Option<String>,

    /// Optional path to a PEM-encoded client certificate for upstream mTLS.
    ///
    /// When set together with `tls_client_key`, the proxy presents this
    /// certificate to the upstream during TLS handshake. Required for
    /// upstreams that enforce mutual TLS (e.g., Kubernetes API servers
    /// configured with client-certificate authentication).
    #[serde(default)]
    pub tls_client_cert: Option<String>,

    /// Optional path to a PEM-encoded private key for upstream mTLS.
    ///
    /// Must be set together with `tls_client_cert`. The key must correspond
    /// to the certificate in `tls_client_cert`.
    #[serde(default)]
    pub tls_client_key: Option<String>,

    /// Optional OAuth2 client_credentials configuration.
    /// When present, the proxy handles token exchange automatically instead
    /// of using a static credential from the keystore.
    /// Mutually exclusive with `credential_key` — use one or the other.
    #[serde(default)]
    pub oauth2: Option<OAuth2Config>,
}

/// Optional proxy-side overrides for credential injection shape.
///
/// These settings apply only to how the proxy validates the phantom token from
/// the client request. Any field omitted here falls back to the corresponding
/// top-level route field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyInjectConfig {
    /// Optional injection mode override for proxy-side token parsing.
    #[serde(default)]
    pub inject_mode: Option<InjectMode>,

    /// Optional header name override for header/basic_auth modes.
    #[serde(default)]
    pub inject_header: Option<String>,

    /// Optional format override for header mode.
    #[serde(default)]
    pub credential_format: Option<String>,

    /// Optional path pattern override for url_path mode.
    #[serde(default)]
    pub path_pattern: Option<String>,

    /// Optional path replacement override for url_path mode.
    #[serde(default)]
    pub path_replacement: Option<String>,

    /// Optional query parameter override for query_param mode.
    #[serde(default)]
    pub query_param_name: Option<String>,
}

/// An HTTP method+path access rule for reverse proxy endpoint filtering.
///
/// Used to restrict which API endpoints an agent can access through a
/// credential route. Patterns use `/` separated segments with wildcards:
/// - `*` matches exactly one path segment
/// - `**` matches zero or more path segments
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointRule {
    /// HTTP method to match ("GET", "POST", etc.) or "*" for any method.
    pub method: String,
    /// URL path pattern with glob segments.
    /// Example: "/api/v4/projects/*/merge_requests/**"
    pub path: String,
}

/// Pre-compiled endpoint rules for the request hot path.
///
/// Built once at proxy startup from `EndpointRule` definitions. Holds
/// compiled `globset::GlobMatcher`s so the hot path does a regex match,
/// not a glob compile.
pub struct CompiledEndpointRules {
    rules: Vec<CompiledRule>,
}

struct CompiledRule {
    method: String,
    matcher: globset::GlobMatcher,
}

impl CompiledEndpointRules {
    /// Compile endpoint rules into matchers. Invalid glob patterns are
    /// rejected at startup with an error, not silently ignored at runtime.
    pub fn compile(rules: &[EndpointRule]) -> Result<Self, String> {
        let mut compiled = Vec::with_capacity(rules.len());
        for rule in rules {
            let glob = Glob::new(&rule.path)
                .map_err(|e| format!("invalid endpoint path pattern '{}': {}", rule.path, e))?;
            compiled.push(CompiledRule {
                method: rule.method.clone(),
                matcher: glob.compile_matcher(),
            });
        }
        Ok(Self { rules: compiled })
    }

    /// `true` if no endpoint rules are defined (allow-all).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// `true` if method+path matches a rule, or if no rules are defined.
    #[must_use]
    pub fn is_allowed(&self, method: &str, path: &str) -> bool {
        if self.rules.is_empty() {
            return true;
        }
        let normalized = normalize_path(path);
        self.rules.iter().any(|r| {
            (r.method == "*" || r.method.eq_ignore_ascii_case(method))
                && r.matcher.is_match(&normalized)
        })
    }
}

impl std::fmt::Debug for CompiledEndpointRules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledEndpointRules")
            .field("count", &self.rules.len())
            .finish()
    }
}

/// Check if any endpoint rule permits the given method+path.
/// Returns `true` if rules is empty (allow-all, backward compatible).
///
/// Test convenience only — compiles globs on each call. Production code
/// should use `CompiledEndpointRules::is_allowed()` instead.
#[cfg(test)]
fn endpoint_allowed(rules: &[EndpointRule], method: &str, path: &str) -> bool {
    if rules.is_empty() {
        return true;
    }
    let normalized = normalize_path(path);
    rules.iter().any(|r| {
        (r.method == "*" || r.method.eq_ignore_ascii_case(method))
            && Glob::new(&r.path)
                .ok()
                .map(|g| g.compile_matcher())
                .is_some_and(|m| m.is_match(&normalized))
    })
}

/// Normalize a URL path for matching: percent-decode, strip query string,
/// collapse double slashes, strip trailing slash (but preserve root "/").
///
/// Percent-decoding prevents bypass via encoded characters (e.g.,
/// `/api/%70rojects` evading a rule for `/api/projects/*`).
fn normalize_path(path: &str) -> String {
    // Strip query string
    let path = path.split('?').next().unwrap_or(path);

    // Percent-decode to prevent bypass via encoded segments.
    // Use decode_binary + from_utf8_lossy so invalid UTF-8 sequences
    // (e.g., %FF) become U+FFFD instead of falling back to the raw path.
    let binary = urlencoding::decode_binary(path.as_bytes());
    let decoded = String::from_utf8_lossy(&binary);

    // Collapse double slashes by splitting on '/' and filtering empties,
    // then rejoin. This also strips trailing slash.
    let segments: Vec<&str> = decoded.split('/').filter(|s| !s.is_empty()).collect();
    if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    }
}

fn default_inject_header() -> String {
    "Authorization".to_string()
}

/// Template for the header value before `{}` is replaced by the secret.
///
/// Set in config → use that string as-is. Omitted → `Bearer {}` for an `Authorization` header (case-insensitive), `{}` for any other header.
#[must_use]
pub fn resolved_credential_format(inject_header: &str, credential_format: Option<&str>) -> String {
    match credential_format {
        Some(fmt) => fmt.to_string(),
        None => {
            if inject_header.eq_ignore_ascii_case("Authorization") {
                "Bearer {}".to_string()
            } else {
                "{}".to_string()
            }
        }
    }
}

/// Configuration for an external (enterprise) proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalProxyConfig {
    /// Proxy address (e.g., "squid.corp.internal:3128")
    pub address: String,

    /// Optional authentication for the external proxy.
    pub auth: Option<ExternalProxyAuth>,

    /// Hosts to bypass the external proxy and route directly.
    /// Supports exact hostnames and `*.` wildcard suffixes (case-insensitive).
    /// Empty = all traffic goes through the external proxy.
    #[serde(default)]
    pub bypass_hosts: Vec<String>,
}

/// Authentication for an external proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalProxyAuth {
    /// Keystore account name for proxy credentials.
    pub keyring_account: String,

    /// Authentication scheme (only "basic" supported).
    #[serde(default = "default_auth_scheme")]
    pub scheme: String,
}

fn default_auth_scheme() -> String {
    "basic".to_string()
}

/// OAuth2 client_credentials configuration for automatic token exchange.
///
/// When configured on a route, the proxy handles the token lifecycle:
/// 1. Exchanges client_id + client_secret for an access_token at startup
/// 2. Caches the token with TTL from the `expires_in` response
/// 3. Refreshes automatically before expiry (30s buffer)
/// 4. Injects the access_token as `Authorization: Bearer <token>`
///
/// The agent never sees client_id or client_secret — only a phantom token.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OAuth2Config {
    /// Token endpoint URL (e.g., "https://auth.example.com/oauth/token")
    pub token_url: String,
    /// Client ID — plain value or credential reference (env://, file://, op://)
    pub client_id: String,
    /// Client secret — credential reference (env://, file://, op://)
    pub client_secret: String,
    /// OAuth2 scopes (space-separated). Empty = no scope parameter sent.
    #[serde(default)]
    pub scope: String,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ProxyConfig::default();
        assert_eq!(config.bind_addr, IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        assert_eq!(config.bind_port, 0);
        assert!(config.allowed_hosts.is_empty());
        assert!(config.routes.is_empty());
        assert!(config.external_proxy.is_none());
    }

    #[test]
    fn test_config_serialization() {
        let config = ProxyConfig {
            allowed_hosts: vec!["api.openai.com".to_string()],
            ..Default::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ProxyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.allowed_hosts, vec!["api.openai.com"]);
    }

    #[test]
    fn test_external_proxy_config_with_bypass_hosts() {
        let config = ProxyConfig {
            external_proxy: Some(ExternalProxyConfig {
                address: "squid.corp:3128".to_string(),
                auth: None,
                bypass_hosts: vec!["internal.corp".to_string(), "*.private.net".to_string()],
            }),
            ..Default::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ProxyConfig = serde_json::from_str(&json).unwrap();
        let ext = deserialized.external_proxy.unwrap();
        assert_eq!(ext.address, "squid.corp:3128");
        assert_eq!(ext.bypass_hosts.len(), 2);
        assert_eq!(ext.bypass_hosts[0], "internal.corp");
        assert_eq!(ext.bypass_hosts[1], "*.private.net");
    }

    #[test]
    fn test_external_proxy_config_bypass_hosts_default_empty() {
        let json = r#"{"address": "proxy:3128", "auth": null}"#;
        let ext: ExternalProxyConfig = serde_json::from_str(json).unwrap();
        assert!(ext.bypass_hosts.is_empty());
    }

    // ========================================================================
    // EndpointRule + path matching tests
    // ========================================================================

    #[test]
    fn test_endpoint_allowed_empty_rules_allows_all() {
        assert!(endpoint_allowed(&[], "GET", "/anything"));
        assert!(endpoint_allowed(&[], "DELETE", "/admin/nuke"));
    }

    /// Helper: check a single rule against method+path via endpoint_allowed.
    fn check(rule: &EndpointRule, method: &str, path: &str) -> bool {
        endpoint_allowed(std::slice::from_ref(rule), method, path)
    }

    #[test]
    fn test_endpoint_rule_exact_path() {
        let rule = EndpointRule {
            method: "GET".to_string(),
            path: "/v1/chat/completions".to_string(),
        };
        assert!(check(&rule, "GET", "/v1/chat/completions"));
        assert!(!check(&rule, "GET", "/v1/chat"));
        assert!(!check(&rule, "GET", "/v1/chat/completions/extra"));
    }

    #[test]
    fn test_endpoint_rule_method_case_insensitive() {
        let rule = EndpointRule {
            method: "get".to_string(),
            path: "/api".to_string(),
        };
        assert!(check(&rule, "GET", "/api"));
        assert!(check(&rule, "Get", "/api"));
    }

    #[test]
    fn test_endpoint_rule_method_wildcard() {
        let rule = EndpointRule {
            method: "*".to_string(),
            path: "/api/resource".to_string(),
        };
        assert!(check(&rule, "GET", "/api/resource"));
        assert!(check(&rule, "DELETE", "/api/resource"));
        assert!(check(&rule, "POST", "/api/resource"));
    }

    #[test]
    fn test_endpoint_rule_method_mismatch() {
        let rule = EndpointRule {
            method: "GET".to_string(),
            path: "/api/resource".to_string(),
        };
        assert!(!check(&rule, "POST", "/api/resource"));
        assert!(!check(&rule, "DELETE", "/api/resource"));
    }

    #[test]
    fn test_endpoint_rule_single_wildcard() {
        let rule = EndpointRule {
            method: "GET".to_string(),
            path: "/api/v4/projects/*/merge_requests".to_string(),
        };
        assert!(check(&rule, "GET", "/api/v4/projects/123/merge_requests"));
        assert!(check(
            &rule,
            "GET",
            "/api/v4/projects/my-proj/merge_requests"
        ));
        assert!(!check(&rule, "GET", "/api/v4/projects/merge_requests"));
    }

    #[test]
    fn test_endpoint_rule_double_wildcard() {
        let rule = EndpointRule {
            method: "GET".to_string(),
            path: "/api/v4/projects/**".to_string(),
        };
        assert!(check(&rule, "GET", "/api/v4/projects/123"));
        assert!(check(&rule, "GET", "/api/v4/projects/123/merge_requests"));
        assert!(check(&rule, "GET", "/api/v4/projects/a/b/c/d"));
        assert!(!check(&rule, "GET", "/api/v4/other"));
    }

    #[test]
    fn test_endpoint_rule_double_wildcard_middle() {
        let rule = EndpointRule {
            method: "*".to_string(),
            path: "/api/**/notes".to_string(),
        };
        assert!(check(&rule, "GET", "/api/notes"));
        assert!(check(&rule, "POST", "/api/projects/123/notes"));
        assert!(check(&rule, "GET", "/api/a/b/c/notes"));
        assert!(!check(&rule, "GET", "/api/a/b/c/comments"));
    }

    #[test]
    fn test_endpoint_rule_strips_query_string() {
        let rule = EndpointRule {
            method: "GET".to_string(),
            path: "/api/data".to_string(),
        };
        assert!(check(&rule, "GET", "/api/data?page=1&limit=10"));
    }

    #[test]
    fn test_endpoint_rule_trailing_slash_normalized() {
        let rule = EndpointRule {
            method: "GET".to_string(),
            path: "/api/data".to_string(),
        };
        assert!(check(&rule, "GET", "/api/data/"));
        assert!(check(&rule, "GET", "/api/data"));
    }

    #[test]
    fn test_endpoint_rule_double_slash_normalized() {
        let rule = EndpointRule {
            method: "GET".to_string(),
            path: "/api/data".to_string(),
        };
        assert!(check(&rule, "GET", "/api//data"));
    }

    #[test]
    fn test_endpoint_rule_root_path() {
        let rule = EndpointRule {
            method: "GET".to_string(),
            path: "/".to_string(),
        };
        assert!(check(&rule, "GET", "/"));
        assert!(!check(&rule, "GET", "/anything"));
    }

    #[test]
    fn test_compiled_endpoint_rules_hot_path() {
        let rules = vec![
            EndpointRule {
                method: "GET".to_string(),
                path: "/repos/*/issues".to_string(),
            },
            EndpointRule {
                method: "POST".to_string(),
                path: "/repos/*/issues/*/comments".to_string(),
            },
        ];
        let compiled = CompiledEndpointRules::compile(&rules).unwrap();
        assert!(compiled.is_allowed("GET", "/repos/myrepo/issues"));
        assert!(compiled.is_allowed("POST", "/repos/myrepo/issues/42/comments"));
        assert!(!compiled.is_allowed("DELETE", "/repos/myrepo"));
        assert!(!compiled.is_allowed("GET", "/repos/myrepo/pulls"));
    }

    #[test]
    fn test_compiled_endpoint_rules_empty_allows_all() {
        let compiled = CompiledEndpointRules::compile(&[]).unwrap();
        assert!(compiled.is_allowed("DELETE", "/admin/nuke"));
    }

    #[test]
    fn test_compiled_endpoint_rules_invalid_pattern_rejected() {
        let rules = vec![EndpointRule {
            method: "GET".to_string(),
            path: "/api/[invalid".to_string(),
        }];
        assert!(CompiledEndpointRules::compile(&rules).is_err());
    }

    #[test]
    fn test_endpoint_allowed_multiple_rules() {
        let rules = vec![
            EndpointRule {
                method: "GET".to_string(),
                path: "/repos/*/issues".to_string(),
            },
            EndpointRule {
                method: "POST".to_string(),
                path: "/repos/*/issues/*/comments".to_string(),
            },
        ];
        assert!(endpoint_allowed(&rules, "GET", "/repos/myrepo/issues"));
        assert!(endpoint_allowed(
            &rules,
            "POST",
            "/repos/myrepo/issues/42/comments"
        ));
        assert!(!endpoint_allowed(&rules, "DELETE", "/repos/myrepo"));
        assert!(!endpoint_allowed(&rules, "GET", "/repos/myrepo/pulls"));
    }

    #[test]
    fn test_endpoint_rule_serde_default() {
        let json = r#"{
            "prefix": "test",
            "upstream": "https://example.com"
        }"#;
        let route: RouteConfig = serde_json::from_str(json).unwrap();
        assert!(route.endpoint_rules.is_empty());
        assert!(route.tls_ca.is_none());
    }

    #[test]
    fn test_tls_ca_serde_roundtrip() {
        let json = r#"{
            "prefix": "k8s",
            "upstream": "https://kubernetes.local:6443",
            "tls_ca": "/run/secrets/k8s-ca.crt"
        }"#;
        let route: RouteConfig = serde_json::from_str(json).unwrap();
        assert_eq!(route.tls_ca.as_deref(), Some("/run/secrets/k8s-ca.crt"));

        let serialized = serde_json::to_string(&route).unwrap();
        let deserialized: RouteConfig = serde_json::from_str(&serialized).unwrap();
        assert_eq!(
            deserialized.tls_ca.as_deref(),
            Some("/run/secrets/k8s-ca.crt")
        );
    }

    #[test]
    fn test_endpoint_rule_percent_encoded_path_decoded() {
        // Security: percent-encoded segments must not bypass rules.
        // e.g., /api/v4/%70rojects should match a rule for /api/v4/projects/*
        let rule = EndpointRule {
            method: "GET".to_string(),
            path: "/api/v4/projects/*/issues".to_string(),
        };
        assert!(check(&rule, "GET", "/api/v4/%70rojects/123/issues"));
        assert!(check(&rule, "GET", "/api/v4/pro%6Aects/123/issues"));
    }

    #[test]
    fn test_endpoint_rule_percent_encoded_full_segment() {
        let rule = EndpointRule {
            method: "POST".to_string(),
            path: "/api/data".to_string(),
        };
        // %64%61%74%61 = "data"
        assert!(check(&rule, "POST", "/api/%64%61%74%61"));
    }

    #[test]
    fn test_compiled_endpoint_rules_percent_encoded() {
        let rules = vec![EndpointRule {
            method: "GET".to_string(),
            path: "/repos/*/issues".to_string(),
        }];
        let compiled = CompiledEndpointRules::compile(&rules).unwrap();
        // %69ssues = "issues"
        assert!(compiled.is_allowed("GET", "/repos/myrepo/%69ssues"));
        assert!(!compiled.is_allowed("GET", "/repos/myrepo/%70ulls"));
    }

    #[test]
    fn test_endpoint_rule_percent_encoded_invalid_utf8() {
        // Security: invalid UTF-8 percent sequences must not fall back to
        // the raw path (which could bypass rules). Lossy decoding replaces
        // invalid bytes with U+FFFD, so the path won't match real segments.
        let rule = EndpointRule {
            method: "GET".to_string(),
            path: "/api/projects".to_string(),
        };
        // %FF is not valid UTF-8 — must not match "/api/projects"
        assert!(!check(&rule, "GET", "/api/%FFprojects"));
    }

    #[test]
    fn test_endpoint_rule_serde_roundtrip() {
        let rule = EndpointRule {
            method: "GET".to_string(),
            path: "/api/*/data".to_string(),
        };
        let json = serde_json::to_string(&rule).unwrap();
        let deserialized: EndpointRule = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.method, "GET");
        assert_eq!(deserialized.path, "/api/*/data");
    }

    // ========================================================================
    // OAuth2Config tests
    // ========================================================================

    #[test]
    fn test_oauth2_config_deserialization() {
        let json = r#"{
            "token_url": "https://auth.example.com/oauth/token",
            "client_id": "my-client",
            "client_secret": "env://CLIENT_SECRET",
            "scope": "read write"
        }"#;
        let config: OAuth2Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.token_url, "https://auth.example.com/oauth/token");
        assert_eq!(config.client_id, "my-client");
        assert_eq!(config.client_secret, "env://CLIENT_SECRET");
        assert_eq!(config.scope, "read write");
    }

    #[test]
    fn test_oauth2_config_default_scope() {
        let json = r#"{
            "token_url": "https://auth.example.com/oauth/token",
            "client_id": "my-client",
            "client_secret": "env://SECRET"
        }"#;
        let config: OAuth2Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.scope, "");
    }

    #[test]
    fn test_route_config_with_oauth2() {
        let json = r#"{
            "prefix": "/my-api",
            "upstream": "https://api.example.com",
            "oauth2": {
                "token_url": "https://auth.example.com/oauth/token",
                "client_id": "agent-1",
                "client_secret": "env://CLIENT_SECRET",
                "scope": "api.read"
            }
        }"#;
        let route: RouteConfig = serde_json::from_str(json).unwrap();
        assert!(route.oauth2.is_some());
        assert!(route.credential_key.is_none());
        let oauth2 = route.oauth2.unwrap();
        assert_eq!(oauth2.token_url, "https://auth.example.com/oauth/token");
    }

    #[test]
    fn test_route_config_without_oauth2() {
        let json = r#"{
            "prefix": "/openai",
            "upstream": "https://api.openai.com",
            "credential_key": "openai"
        }"#;
        let route: RouteConfig = serde_json::from_str(json).unwrap();
        assert!(route.oauth2.is_none());
        assert!(route.credential_key.is_some());
    }

    #[test]
    fn test_route_config_credential_format_omitted_is_none() {
        let json = r#"{
            "prefix": "anthropic",
            "upstream": "https://api.anthropic.com",
            "credential_key": "env://ANTHROPIC_API_KEY",
            "inject_header": "x-api-key"
        }"#;
        let route: RouteConfig = serde_json::from_str(json).unwrap();
        assert!(route.credential_format.is_none());
        assert_eq!(
            resolved_credential_format(&route.inject_header, route.credential_format.as_deref()),
            "{}"
        );
    }

    #[test]
    fn test_route_config_explicit_bearer_on_custom_header_preserved() {
        let json = r#"{
            "prefix": "litellm",
            "upstream": "https://litellm",
            "credential_key": "env://LITELLM_TOKEN",
            "inject_header": "x-litellm-api-key",
            "credential_format": "Bearer {}"
        }"#;
        let route: RouteConfig = serde_json::from_str(json).unwrap();
        assert_eq!(route.credential_format.as_deref(), Some("Bearer {}"));
        assert_eq!(
            resolved_credential_format(&route.inject_header, route.credential_format.as_deref()),
            "Bearer {}"
        );
    }

    #[test]
    fn test_resolved_credential_format_authorization_case_insensitive() {
        for header in ["authorization", "AUTHORIZATION", "Authorization"] {
            assert_eq!(
                resolved_credential_format(header, None),
                "Bearer {}",
                "omitted format: Authorization header name is matched case-insensitively for Bearer default"
            );
        }
    }
}
