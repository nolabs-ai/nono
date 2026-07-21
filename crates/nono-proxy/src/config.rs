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
    /// Empty = allow all hosts (except deny list), unless `strict_filter`
    /// is `true`.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,

    /// Hosts to deny regardless of the allowlist (exact match + wildcards).
    /// Evaluated before the allowlist.
    #[serde(default)]
    pub denied_hosts: Vec<String>,

    /// When `true`, an empty `allowed_hosts` denies every host instead of
    /// falling back to allow-all.
    #[serde(default)]
    pub strict_filter: bool,

    /// When `true` (the default), the proxy enforces the per-session token
    /// on incoming requests via the `Proxy-Authorization` header. When
    /// `false`, token enforcement is skipped entirely — an open proxy on the
    /// bind address.
    ///
    /// This MUST remain `true` for the sandboxed `nono run`/`shell`/`wrap`
    /// path: the token is the localhost auth boundary that stops other local
    /// processes from using the proxy. It is set `false` only by the
    /// standalone `nono proxy --no-auth` command, which keeps the bind
    /// address on loopback.
    #[serde(default = "default_require_auth")]
    pub require_auth: bool,

    /// Make `Proxy-Authorization` validation fatal on the transparent CONNECT
    /// path (returns `407 Proxy Authentication Required` instead of tunnelling).
    ///
    /// Defaults to `false`, which preserves the lenient CONNECT behaviour the
    /// sandboxed `nono run`/`shell`/`wrap` path relies on: Node.js undici does
    /// not echo URL-userinfo credentials as `Proxy-Authorization` on CONNECT,
    /// and the sandbox itself is the trust boundary there.
    ///
    /// Set `true` only by the standalone `nono proxy` command (unless
    /// `--no-auth`), where the session token — not an OS sandbox — is the auth
    /// boundary for the external tools pointed at the proxy. Has no effect when
    /// `require_auth` is `false`.
    #[serde(default)]
    pub strict_connect_auth: bool,

    /// Optional caller-supplied auth password used in place of a freshly
    /// generated random session token.
    ///
    /// When `Some` (and non-empty), [`crate::server::start`] uses this exact
    /// value as the credential clients must present via the
    /// `Proxy-Authorization` header (Basic password or Bearer token), instead
    /// of minting 256 bits of randomness. Set only by the standalone
    /// `nono proxy --pass` flag so the operator controls the exact secret;
    /// the sandboxed `run`/`shell`/`wrap` path always leaves this `None` and
    /// uses a random per-session token.
    ///
    /// Skipped during (de)serialisation — a secret must never be persisted to
    /// or read from a config file on disk. Has no effect when
    /// `require_auth` is `false`.
    #[serde(default, skip)]
    pub session_token: Option<Zeroizing<String>>,

    /// Reverse proxy credential routes.
    #[serde(default)]
    pub routes: Vec<RouteConfig>,

    /// Declarative OAuth token capture routes.
    ///
    /// These are not reverse-proxy routes. They mark OAuth token endpoints
    /// whose JSON responses must be rewritten from real tokens to phantom
    /// nonces before reaching the sandboxed process.
    #[serde(default)]
    pub oauth_capture: Vec<OAuthCaptureConfig>,

    /// Optional host-only persistence file for OAuth capture phantom mappings.
    ///
    /// The sandboxed process never receives this path. It only sees phantom
    /// tokens in provider-owned credential files; the proxy uses this file to
    /// resolve those phantoms in later nono sessions.
    #[serde(default, skip)]
    pub oauth_capture_store_path: Option<PathBuf>,

    /// External (enterprise) proxy URL for passthrough mode.
    /// When set, CONNECT requests are chained to this proxy.
    #[serde(default)]
    pub external_proxy: Option<ExternalProxyConfig>,

    /// Outbound TCP ports that the sandbox allows direct connections on
    /// (via Landlock ConnectTcp). Hosts whose resolved port is NOT in this
    /// set must go through the proxy and should NOT appear in NO_PROXY.
    #[serde(default)]
    pub direct_connect_ports: Vec<u16>,

    /// Additional client-side proxy bypass entries to append to generated
    /// NO_PROXY/no_proxy values.
    ///
    /// These entries are host patterns only. They do not grant network access;
    /// they only tell standard HTTP clients not to use the local nono proxy for
    /// matching destinations. Route upstreams that require L7 filtering or
    /// credential injection are filtered out at proxy startup.
    #[serde(default)]
    pub no_proxy: Vec<String>,

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

    /// Environment variables that should point at the TLS-intercept trust
    /// bundle when interception is active.
    #[serde(default = "default_intercept_ca_env_vars")]
    pub intercept_ca_env_vars: Vec<String>,

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

    /// Optional leaf certificate validity override for TLS interception.
    /// Leaf expiry is capped by the issuer CA expiry.
    #[serde(default, skip)]
    pub leaf_validity: Option<std::time::Duration>,

    /// Enable HTTP/2 negotiation for upstream connections.
    /// When false (default), the reverse proxy pool uses HTTP/1.1 with
    /// keep-alive and the CONNECT intercept only advertises HTTP/1.1 ALPN.
    #[serde(default)]
    pub enable_h2: bool,
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
            denied_hosts: Vec::new(),
            strict_filter: false,
            require_auth: default_require_auth(),
            strict_connect_auth: false,
            session_token: None,
            routes: Vec::new(),
            oauth_capture: Vec::new(),
            oauth_capture_store_path: None,
            external_proxy: None,
            direct_connect_ports: Vec::new(),
            no_proxy: Vec::new(),
            max_connections: 256,
            intercept_ca_dir: None,
            intercept_parent_ca_pems: None,
            intercept_ca_env_vars: default_intercept_ca_env_vars(),
            preloaded_ca: None,
            ca_validity: None,
            leaf_validity: None,
            enable_h2: false,
        }
    }
}

pub fn default_intercept_ca_env_vars() -> Vec<String> {
    [
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
        "NODE_EXTRA_CA_CERTS",
        "CURL_CA_BUNDLE",
        "GIT_SSL_CAINFO",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

/// Declarative OAuth capture provider configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthCaptureConfig {
    /// Provider name from the profile.
    pub provider: String,
    /// OAuth token endpoints whose responses are rewritten.
    #[serde(default)]
    pub token_endpoints: Vec<OAuthTokenEndpointConfig>,
    /// Nonce consumers admitted for tokens minted by this provider.
    ///
    /// Values use the same namespace as [`crate::token::NonceResolver`], for
    /// example `proxy.anthropic_oauth`.
    #[serde(default)]
    pub admitted_consumers: Vec<String>,
}

/// OAuth token endpoint capture configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthTokenEndpointConfig {
    /// URL origin serving the token endpoint, for example
    /// `https://platform.claude.com`.
    pub host: String,
    /// Absolute token endpoint path.
    pub path: String,
    /// JSON response fields containing real token material.
    pub response_fields: Vec<OAuthTokenResponseFieldConfig>,
    /// Request body encoding for token refresh/exchange requests.
    #[serde(default)]
    pub request_body: OAuthTokenRequestBodyFormat,
    /// JSON request fields where phantom tokens must be resolved before
    /// forwarding token refresh/exchange requests upstream.
    #[serde(default)]
    pub request_nonce_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthTokenResponseFieldConfig {
    pub path: String,
    #[serde(default)]
    pub kind: OAuthTokenResponseFieldKind,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthTokenResponseFieldKind {
    #[default]
    Opaque,
    Jwt,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthTokenRequestBodyFormat {
    #[default]
    Auto,
    Json,
    Form,
}

fn default_bind_addr() -> IpAddr {
    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
}

fn default_require_auth() -> bool {
    true
}

/// Validate a client-side NO_PROXY entry.
///
/// Accepts single-label local aliases, IP literals, `*.example.com` wildcard
/// suffixes, and `.example.com` suffix patterns. Bare multi-label domains are
/// rejected because common clients treat them as suffix matches. Full URLs,
/// credentials, ports, path/query/fragment-bearing values, comma-separated
/// lists, and catch-all `*` are rejected so profile values cannot silently
/// broaden proxy bypass behavior.
///
/// # Errors
///
/// Returns a human-readable validation error if `entry` is not a host pattern.
#[must_use = "the no_proxy validation result must be handled"]
pub fn validate_no_proxy_entry(entry: &str) -> crate::error::Result<()> {
    if entry.is_empty() {
        return Err(no_proxy_config_error("entry must not be empty"));
    }
    if entry.trim() != entry {
        return Err(no_proxy_config_error(
            "entry must not contain leading or trailing whitespace",
        ));
    }
    if entry
        .chars()
        .any(|c| c.is_control() || c.is_ascii_whitespace())
    {
        return Err(no_proxy_config_error(
            "entry must not contain whitespace or control characters",
        ));
    }
    if entry.contains(',') {
        return Err(no_proxy_config_error(
            "entry must be a single host pattern, not a comma-separated list",
        ));
    }
    if entry.contains("://") {
        return Err(no_proxy_config_error("entry must not include a URL scheme"));
    }
    if entry.contains('@') {
        return Err(no_proxy_config_error("entry must not include credentials"));
    }
    if entry.contains('/') || entry.contains('?') || entry.contains('#') {
        return Err(no_proxy_config_error(
            "entry must not include a path, query, or fragment",
        ));
    }

    if entry.contains('[') || entry.contains(']') {
        if !entry.starts_with('[') || !entry.ends_with(']') {
            return Err(no_proxy_config_error(
                "brackets are only allowed around IPv6 literals",
            ));
        }
        let Some(host) = entry
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
        else {
            return Err(no_proxy_config_error(
                "brackets are only allowed around IPv6 literals",
            ));
        };
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(no_proxy_config_error(
                "bracketed entry must be an IPv6 literal",
            ));
        }
    } else if has_host_port_separator(entry) {
        return Err(no_proxy_config_error("entry must not include a port"));
    }

    validate_no_proxy_host_pattern(entry)
}

fn no_proxy_config_error(message: impl Into<String>) -> crate::error::ProxyError {
    crate::error::ProxyError::Config(message.into())
}

fn has_host_port_separator(entry: &str) -> bool {
    entry
        .rsplit_once(':')
        .is_some_and(|(host, port)| !host.contains(':') && !port.is_empty())
}

pub(crate) fn no_proxy_host_pattern_matches(pattern: &str, host: &str) -> bool {
    let pattern = normalise_no_proxy_host(pattern);
    let host = normalise_no_proxy_host(host);
    if pattern == host {
        return true;
    }

    if let Some(suffix) = pattern.strip_prefix("*.") {
        return host
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1);
    }

    if let Some(suffix) = pattern.strip_prefix('.') {
        return host == suffix || host.ends_with(&format!(".{suffix}"));
    }

    false
}

/// Return true when a client-side NO_PROXY-style entry could overlap a proxy
/// allow/route host pattern.
///
/// The grammar and overlap semantics live in `nono-proxy` because this crate
/// owns proxy env generation, route protection, and startup fail-safe checks.
/// CLI profile validation calls this helper for parse-time UX but the proxy
/// still enforces the same semantics at startup.
#[must_use]
pub fn no_proxy_entry_overlaps_host_pattern(no_proxy_entry: &str, host_pattern: &str) -> bool {
    let entry_host = strip_no_proxy_port(no_proxy_entry);
    let host_pattern = strip_no_proxy_port(host_pattern);
    if entry_host.is_empty() || host_pattern.is_empty() {
        return true;
    }

    if no_proxy_host_pattern_matches(&entry_host, &host_pattern) {
        return true;
    }
    if bare_single_label_suffix_overlaps_host(&entry_host, &host_pattern) {
        return true;
    }

    let Some(entry_suffix) = no_proxy_suffix_for_overlap(&entry_host) else {
        return false;
    };

    if let Some(host_suffix) = host_pattern
        .strip_prefix("*.")
        .map(normalise_no_proxy_host_pattern)
    {
        if host_suffix.is_empty() {
            return true;
        }
        return domain_suffixes_overlap(&entry_suffix, &host_suffix);
    }

    let host = normalise_no_proxy_host_pattern(&host_pattern);
    host == entry_suffix || host.ends_with(&format!(".{entry_suffix}"))
}

fn bare_single_label_suffix_overlaps_host(entry: &str, host_pattern: &str) -> bool {
    let entry = normalise_no_proxy_host(entry);
    if entry.is_empty() || entry.contains('.') || entry.contains(':') || entry.contains('*') {
        return false;
    }

    let host = normalise_host_pattern_for_suffix_overlap(host_pattern);
    host == entry || host.ends_with(&format!(".{entry}"))
}

fn normalise_host_pattern_for_suffix_overlap(host_pattern: &str) -> String {
    let normalised = normalise_no_proxy_host(host_pattern);
    normalised
        .strip_prefix("*.")
        .or_else(|| normalised.strip_prefix('.'))
        .unwrap_or(&normalised)
        .to_string()
}

pub(crate) fn strip_no_proxy_port(entry: &str) -> String {
    if let Some(rest) = entry.strip_prefix('[') {
        if let Some((host, remainder)) = rest.split_once(']')
            && let Some(port) = remainder.strip_prefix(':')
            && port.parse::<u16>().is_ok()
        {
            return format!("[{host}]");
        }
        return entry.to_string();
    }

    if entry.parse::<std::net::Ipv6Addr>().is_ok() {
        return entry.to_string();
    }

    entry
        .rsplit_once(':')
        .and_then(|(host, port)| {
            if host.contains(':') {
                return None;
            }
            port.parse::<u16>().ok().map(|_| host.to_string())
        })
        .unwrap_or_else(|| entry.to_string())
}

fn no_proxy_suffix_for_overlap(entry: &str) -> Option<String> {
    let normalised = normalise_no_proxy_host_pattern(entry);
    let explicit_suffix = entry.starts_with('.') || normalised.starts_with("*.");
    let suffix = normalised.strip_prefix("*.").unwrap_or(&normalised);
    if suffix.is_empty() || suffix.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    if explicit_suffix || suffix.contains('.') {
        Some(suffix.to_string())
    } else {
        None
    }
}

fn domain_suffixes_overlap(left: &str, right: &str) -> bool {
    left == right || left.ends_with(&format!(".{right}")) || right.ends_with(&format!(".{left}"))
}

pub(crate) fn normalise_no_proxy_host_pattern(pattern: &str) -> String {
    let normalised = normalise_no_proxy_host(pattern);
    normalised
        .strip_prefix('.')
        .unwrap_or(&normalised)
        .to_string()
}

pub(crate) fn normalise_no_proxy_env_entry(entry: &str) -> String {
    let host = strip_no_proxy_port(entry);
    let normalised = normalise_no_proxy_host(&host);
    if let Some(suffix) = normalised.strip_prefix("*.") {
        format!(".{suffix}")
    } else {
        normalised
    }
}

#[must_use = "no_proxy host pattern validation result must be handled"]
fn validate_no_proxy_host_pattern(pattern: &str) -> crate::error::Result<()> {
    if pattern.is_empty() {
        return Err(no_proxy_config_error("entry host must not be empty"));
    }
    if pattern == "*" {
        return Err(no_proxy_config_error("catch-all '*' is not allowed"));
    }

    let host = if let Some(suffix) = pattern.strip_prefix("*.") {
        if suffix.is_empty() {
            return Err(no_proxy_config_error(
                "wildcard entry must include a suffix",
            ));
        }
        if suffix.contains('*') {
            return Err(no_proxy_config_error(
                "wildcards are only allowed as a leading '*.'",
            ));
        }
        suffix
    } else if let Some(suffix) = pattern.strip_prefix('.') {
        if suffix.is_empty() {
            return Err(no_proxy_config_error("suffix entry must include a domain"));
        }
        if suffix.contains('*') {
            return Err(no_proxy_config_error(
                "wildcards are only allowed as a leading '*.'",
            ));
        }
        suffix
    } else {
        if pattern.contains('*') {
            return Err(no_proxy_config_error(
                "wildcards are only allowed as a leading '*.'",
            ));
        }
        pattern
    };

    let host = normalise_no_proxy_host(host);
    if host.is_empty() || host.starts_with('.') || host.ends_with('.') || host.contains("..") {
        return Err(no_proxy_config_error(
            "entry host must be a non-empty hostname or IP literal",
        ));
    }
    if no_proxy_pattern_overlaps_always_denied_host(pattern) {
        return Err(no_proxy_config_error(
            "entry overlaps a proxy-denied metadata host",
        ));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_proxy_denied_metadata_ip(&ip) {
            return Err(no_proxy_config_error(
                "entry overlaps a proxy-denied metadata IP",
            ));
        }
        if is_link_local_ip(&ip) {
            return Err(no_proxy_config_error(
                "entry must not bypass link-local or cloud metadata IP ranges",
            ));
        }
        return Ok(());
    }
    if normalise_no_proxy_host(pattern) == host && host.contains('.') {
        return Err(no_proxy_config_error(
            "bare multi-label domains are not allowed; use an explicit leading-dot or '*.' suffix pattern",
        ));
    }
    if host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Ok(());
    }

    Err(no_proxy_config_error(
        "entry host contains invalid characters",
    ))
}

const ALWAYS_DENIED_HOSTS: &[&str] = &[
    "169.254.169.254",
    "fd00:ec2::254",
    "metadata.google.internal",
    "metadata.azure.internal",
];

pub(crate) fn parse_host_ip_literal(host: &str) -> Option<IpAddr> {
    normalise_no_proxy_host(host).parse::<IpAddr>().ok()
}

pub(crate) fn is_proxy_denied_metadata_ip(ip: &IpAddr) -> bool {
    ALWAYS_DENIED_HOSTS
        .iter()
        .filter_map(|host| host.parse::<IpAddr>().ok())
        .any(|denied| denied == *ip)
}

// Mirrors the proxy HostFilter's non-overridable metadata deny list at the
// client-bypass boundary: NO_PROXY must not let clients skip that filter.
fn no_proxy_pattern_overlaps_always_denied_host(pattern: &str) -> bool {
    ALWAYS_DENIED_HOSTS
        .iter()
        .any(|denied| no_proxy_entry_overlaps_host_pattern(pattern, denied))
}

fn is_link_local_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.octets()[0] == 169 && v4.octets()[1] == 254,
        IpAddr::V6(v6) => {
            if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            v6.to_ipv4_mapped()
                .is_some_and(|v4| v4.octets()[0] == 169 && v4.octets()[1] == 254)
        }
    }
}

fn normalise_no_proxy_host(host: &str) -> String {
    let lower = host.trim_matches(['[', ']']).to_ascii_lowercase();
    lower.parse::<IpAddr>().map_or(lower, |ip| ip.to_string())
}

/// Configuration for a reverse proxy credential route.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouteConfig {
    /// Path prefix for routing (e.g., "openai").
    /// Must NOT include leading or trailing slashes — it is a bare service name, not a URL path.
    pub prefix: String,

    /// Upstream URL to forward to (e.g., "https://api.openai.com")
    pub upstream: String,

    /// Keystore account name to load the credential from.
    /// If `None`, no credential is injected.
    pub credential_key: Option<String>,

    /// Broker credential names redeemable at this route from a caller-presented
    /// phantom (by-value / proof-of-possession). Non-empty forces
    /// `requires_intercept`. Composes with a managed `credential_key`/`oauth2`;
    /// not honored with `aws_auth`/`spiffe` (dedicated handlers).
    #[serde(default)]
    pub redeem_phantoms: Vec<String>,

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

    /// Optional L7 endpoint policy with explicit allow/deny/approve routes.
    ///
    /// When omitted, `endpoint_rules` preserves the legacy behavior:
    /// empty means allow-all, non-empty means default-deny with matching
    /// rules allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_policy: Option<EndpointPolicyConfig>,

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

    /// Optional AWS SigV4 signing configuration.
    ///
    /// When present, the proxy will sign outbound requests with AWS SigV4
    /// credentials. Mutually exclusive with `credential_key` and `oauth2`.
    #[serde(default)]
    pub aws_auth: Option<AwsAuthConfig>,

    /// SPIFFE/SPIRE workload identity auth. Mutually exclusive with `credential_key`, `oauth2`, and `aws_auth`.
    /// See `SpiffeAuthConfig` for JWT-SVID options.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spiffe: Option<SpiffeAuthConfig>,

    /// Optional allow-list of WebSocket upgrade targets for this route.
    ///
    /// When a client requests an HTTP `Upgrade` on this route, it is only
    /// tunneled if its normalized path matches one of these rules. Classic
    /// WebSockets imply HTTP/1.1 GET. Empty (the default) permits no upgrades — the request is
    /// rejected before any upstream contact is made.
    #[serde(default)]
    pub upgrades: Vec<WebSocketRuleConfig>,
}

/// A WebSocket path allow-listed on one concrete upstream route.
///
/// Origin selection belongs to the profile layer that expands a credential
/// provider into concrete routes. Keeping only the path here makes it
/// impossible for the runtime to silently ignore a security-relevant origin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSocketRuleConfig {
    pub path: String,
}

/// SPIFFE/SPIRE auth for an upstream route.
///
/// Currently only `type: "jwt"` is supported — JWT-SVID injected as a bearer
/// token into the configured header.
///
/// The sandboxed process makes a plain request with no credentials; nono fetches
/// the SVID from the SPIRE Workload API and handles everything. The SPIRE
/// operator registers the workload entry and configures the agent — nono's
/// config is just the socket path and what to request.
///
/// Future variant: `type: "x509"` — mTLS with an X.509-SVID (client cert
/// presented during TLS handshake, with atomic rotation). Planned once the
/// TLS-intercept CONNECT path is wired to support it for HTTPS upstreams.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SpiffeAuthConfig {
    /// JWT-SVID injected as a bearer token. Tokens refresh before expiry via the agent cache.
    Jwt {
        /// Path to the SPIRE agent Unix domain socket.
        workload_api_socket: String,
        /// Audience(s) for the minted JWT-SVID.
        audience: Vec<String>,
        /// Header to inject the JWT into (default: `Authorization`).
        #[serde(default = "default_inject_header")]
        inject_header: String,
        /// Format string; `{}` is replaced by the token. Default: `Bearer {}`.
        #[serde(default)]
        credential_format: Option<String>,
        /// Select a specific SVID by SPIFFE ID when the Workload API returns multiple SVIDs for
        /// the same workload. When absent, nono uses the first SVID returned by the agent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        svid_hint: Option<String>,
    },
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

/// L7 endpoint action used by route endpoint policies.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointPolicyDecision {
    #[default]
    Deny,
    Approve,
    Allow,
}

/// Default endpoint-policy action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointPolicyDefault {
    pub decision: EndpointPolicyDecision,
    #[serde(default)]
    pub backend: Option<String>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

impl Default for EndpointPolicyDefault {
    fn default() -> Self {
        Self {
            decision: EndpointPolicyDecision::Deny,
            backend: None,
            timeout_secs: None,
        }
    }
}

/// An endpoint policy rule with optional approval routing metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointPolicyRule {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub backend: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

/// Explicit L7 endpoint policy for a route.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointPolicyConfig {
    #[serde(default)]
    pub default: EndpointPolicyDefault,
    #[serde(default)]
    pub deny: Vec<EndpointPolicyRule>,
    #[serde(default)]
    pub approve: Vec<EndpointPolicyRule>,
    #[serde(default)]
    pub allow: Vec<EndpointPolicyRule>,
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

/// Compiled explicit endpoint policy for the request hot path.
pub struct CompiledEndpointPolicy {
    default: EndpointPolicyDefault,
    deny: Vec<CompiledPolicyRule>,
    approve: Vec<CompiledPolicyRule>,
    allow: Vec<CompiledPolicyRule>,
    explicit: bool,
}

struct CompiledPolicyRule {
    method: String,
    path: String,
    matcher: globset::GlobMatcher,
    backend: Option<String>,
    reason: Option<String>,
    timeout_secs: Option<u64>,
}

/// Result of evaluating a compiled endpoint policy.
pub enum EndpointPolicyOutcome<'a> {
    Allow {
        rule_label: String,
    },
    Deny {
        reason: Option<&'a str>,
        rule_label: String,
    },
    Approve {
        backend: Option<&'a str>,
        reason: Option<&'a str>,
        timeout_secs: Option<u64>,
        rule_label: String,
    },
}

/// Pre-compiled WebSocket upgrade allow-list for the request hot path.
///
/// Built once at proxy startup from route-local [`WebSocketRuleConfig`]
/// entries. Classic WebSocket handshakes are always HTTP/1.1 GET requests,
/// so the runtime policy only needs to retain normalized paths.
#[derive(Debug, Default)]
pub struct CompiledUpgradeRules {
    rules: Vec<CompiledUpgradeRule>,
}

#[derive(Debug)]
struct CompiledUpgradeRule {
    path: String,
}

impl CompiledUpgradeRules {
    /// Compile upgrade rules for one route. There is no glob support here —
    /// `path` is matched exactly (after normalization) on purpose, since
    /// upgrade targets are a small fixed set of endpoints, not a broad API
    /// surface.
    pub fn compile(rules: &[WebSocketRuleConfig]) -> Result<Self, String> {
        let mut compiled = Vec::with_capacity(rules.len());
        for rule in rules {
            if !rule.path.starts_with('/') {
                return Err(format!(
                    "WebSocket path must start with '/': '{}'",
                    rule.path
                ));
            }
            if rule.path.contains(['?', '#']) || rule.path.chars().any(char::is_control) {
                return Err(format!(
                    "WebSocket path must be an absolute path without query, fragment, or control characters: '{}'",
                    rule.path
                ));
            }
            let path = normalize_path(&rule.path);
            if !compiled
                .iter()
                .any(|entry: &CompiledUpgradeRule| entry.path == path)
            {
                compiled.push(CompiledUpgradeRule { path });
            }
        }
        Ok(Self { rules: compiled })
    }

    /// `true` if `protocol`+`method`+`path` matches one of the compiled
    /// rules. `path` is normalized (query string stripped, percent-decoded,
    /// trailing slash removed) before comparison so callers can pass the raw
    /// request path.
    #[must_use]
    pub fn matches(&self, path: &str) -> bool {
        let normalized = normalize_path(path);
        self.rules.iter().any(|r| r.path == normalized)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
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

impl CompiledEndpointPolicy {
    /// Compile the route endpoint policy, preserving legacy endpoint_rules
    /// behavior when no explicit policy is configured.
    pub fn compile(
        policy: Option<&EndpointPolicyConfig>,
        legacy_rules: &[EndpointRule],
    ) -> Result<Self, String> {
        if let Some(policy) = policy {
            return Self::compile_explicit(policy);
        }

        let allow = legacy_rules
            .iter()
            .map(|rule| EndpointPolicyRule {
                method: rule.method.clone(),
                path: rule.path.clone(),
                backend: None,
                reason: None,
                timeout_secs: None,
            })
            .collect::<Vec<_>>();
        let default = if allow.is_empty() {
            EndpointPolicyDefault {
                decision: EndpointPolicyDecision::Allow,
                backend: None,
                timeout_secs: None,
            }
        } else {
            EndpointPolicyDefault::default()
        };
        Self::compile_explicit(&EndpointPolicyConfig {
            default,
            deny: Vec::new(),
            approve: Vec::new(),
            allow,
        })
        .map(|mut compiled| {
            compiled.explicit = false;
            compiled
        })
    }

    fn compile_explicit(policy: &EndpointPolicyConfig) -> Result<Self, String> {
        Ok(Self {
            default: policy.default.clone(),
            deny: compile_policy_rules(&policy.deny)?,
            approve: compile_policy_rules(&policy.approve)?,
            allow: compile_policy_rules(&policy.allow)?,
            explicit: true,
        })
    }

    /// `true` when the policy does not require L7 visibility.
    #[must_use]
    pub fn allows_all_without_l7(&self) -> bool {
        self.deny.is_empty()
            && self.approve.is_empty()
            && self.allow.is_empty()
            && self.default.decision == EndpointPolicyDecision::Allow
    }

    /// `true` when this was authored as an explicit endpoint policy.
    #[must_use]
    pub fn is_explicit(&self) -> bool {
        self.explicit
    }

    /// Evaluate method+path using deny, approve, allow, default precedence.
    #[must_use]
    pub fn evaluate<'a>(&'a self, method: &str, path: &str) -> EndpointPolicyOutcome<'a> {
        let normalized = normalize_path(path);
        if let Some(rule) = first_policy_match(&self.deny, method, &normalized) {
            return EndpointPolicyOutcome::Deny {
                reason: rule.reason.as_deref(),
                rule_label: format!("endpoint_policy.deny[{} {}]", rule.method, rule.path),
            };
        }
        if let Some(rule) = first_policy_match(&self.approve, method, &normalized) {
            return EndpointPolicyOutcome::Approve {
                backend: rule.backend.as_deref(),
                reason: rule.reason.as_deref(),
                timeout_secs: rule.timeout_secs,
                rule_label: format!("endpoint_policy.approve[{} {}]", rule.method, rule.path),
            };
        }
        if let Some(rule) = first_policy_match(&self.allow, method, &normalized) {
            return EndpointPolicyOutcome::Allow {
                rule_label: format!("endpoint_policy.allow[{} {}]", rule.method, rule.path),
            };
        }

        match self.default.decision {
            EndpointPolicyDecision::Allow => EndpointPolicyOutcome::Allow {
                rule_label: "endpoint_policy.default".to_string(),
            },
            EndpointPolicyDecision::Deny => EndpointPolicyOutcome::Deny {
                reason: None,
                rule_label: "endpoint_policy.default".to_string(),
            },
            EndpointPolicyDecision::Approve => EndpointPolicyOutcome::Approve {
                backend: self.default.backend.as_deref(),
                reason: None,
                timeout_secs: self.default.timeout_secs,
                rule_label: "endpoint_policy.default".to_string(),
            },
        }
    }
}

fn compile_policy_rules(rules: &[EndpointPolicyRule]) -> Result<Vec<CompiledPolicyRule>, String> {
    let mut compiled = Vec::with_capacity(rules.len());
    for rule in rules {
        let glob = Glob::new(&rule.path)
            .map_err(|e| format!("invalid endpoint path pattern '{}': {}", rule.path, e))?;
        compiled.push(CompiledPolicyRule {
            method: rule.method.clone(),
            path: rule.path.clone(),
            matcher: glob.compile_matcher(),
            backend: rule.backend.clone(),
            reason: rule.reason.clone(),
            timeout_secs: rule.timeout_secs,
        });
    }
    Ok(compiled)
}

fn first_policy_match<'a>(
    rules: &'a [CompiledPolicyRule],
    method: &str,
    normalized_path: &str,
) -> Option<&'a CompiledPolicyRule> {
    rules.iter().find(|r| {
        (r.method == "*" || r.method.eq_ignore_ascii_case(method))
            && r.matcher.is_match(normalized_path)
    })
}

impl std::fmt::Debug for CompiledEndpointPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledEndpointPolicy")
            .field("default", &self.default)
            .field("deny_count", &self.deny.len())
            .field("approve_count", &self.approve.len())
            .field("allow_count", &self.allow.len())
            .field("explicit", &self.explicit)
            .finish()
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
    // Strip query string before percent-decoding: a literal %3F must not be
    // treated as a query delimiter, so the split must precede the decode.
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
    pub token_url: String,
    /// Mutually exclusive with `client_assertion`.
    #[serde(default)]
    pub client_id: String,
    /// Mutually exclusive with `client_assertion`.
    #[serde(default)]
    pub client_secret: String,
    #[serde(default)]
    pub scope: String,
    /// Use a SPIFFE JWT-SVID as the OAuth2 client assertion instead of client_id/secret.
    /// Mutually exclusive with `client_id`/`client_secret`.
    #[serde(default)]
    pub client_assertion: Option<ClientAssertionConfig>,
    /// Extra parameters merged into the token exchange POST body verbatim.
    #[serde(default)]
    pub extra_params: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientAssertionConfig {
    SpiffeJwt {
        workload_api_socket: String,
        audience: Vec<String>,
        /// Select a specific SVID by SPIFFE ID when the Workload API returns multiple.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        svid_hint: Option<String>,
    },
}

/// AWS SigV4 signing configuration for a credential route.
///
/// When present on a route, the proxy will sign outbound requests using AWS
/// SigV4. All fields are optional: an empty `aws_auth: {}` block is valid and
/// uses the default credential chain with region and service auto-detected from
/// the upstream URL.
///
/// Mutually exclusive with `credential_key` and `oauth2`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AwsAuthConfig {
    /// AWS profile name to use for credentials.
    /// If omitted, the default credential chain is used.
    /// Must be non-empty with no whitespace if provided (whitespace breaks the
    /// AWS INI config parser; profile names are case-sensitive).
    #[serde(default)]
    pub profile: Option<String>,

    /// Explicit SigV4 signing region (e.g., `"us-east-1"`).
    /// If omitted, auto-detected from the upstream URL.
    /// Must be non-empty and lowercase if provided (SigV4 credential scope
    /// requires lowercase region codes).
    #[serde(default)]
    pub region: Option<String>,

    /// Explicit SigV4 service name (e.g., `"bedrock"`, `"s3"`, `"execute-api"`).
    /// If omitted, auto-detected from the upstream URL.
    /// Must be non-empty and lowercase if provided (SigV4 credential scope
    /// requires lowercase service codes).
    #[serde(default)]
    pub service: Option<String>,
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
        assert!(config.no_proxy.is_empty());
    }

    #[test]
    fn test_validate_no_proxy_entry_accepts_host_patterns() {
        for entry in [
            "redis",
            "*.internal.example",
            ".dev.local",
            ".svc.cluster.local",
            "127.0.0.1",
            "::1",
            "[::1]",
        ] {
            assert!(
                validate_no_proxy_entry(entry).is_ok(),
                "no_proxy entry {entry:?} should be valid"
            );
        }
    }

    #[test]
    fn test_validate_no_proxy_entry_rejects_non_host_values() {
        for entry in [
            "",
            " https://dev.local",
            "https://dev.local",
            "user@dev.local",
            "dev.local/path",
            "dev.local?debug=true",
            "dev.local,other.local",
            "dev.local",
            "api.openai.com",
            "API.OPENAI.COM",
            "*",
            "*corp",
            "api.example.com:443",
            "169.254.169.254",
            "169.254.1.2",
            "internal",
            "fd00:ec2::254",
            "fd00:0ec2::254",
            "fd00:ec2:0:0:0:0:0:254",
            "[fd00:ec2::254]",
            "[fd00:0ec2::254]",
            "[fe80::1]",
            "metadata.google.internal",
            ".google.internal",
            "[::1]:8443",
            "[dev.local]",
            "dev.local]",
        ] {
            assert!(
                validate_no_proxy_entry(entry).is_err(),
                "no_proxy entry {entry:?} should be invalid"
            );
        }
    }

    #[test]
    fn test_no_proxy_host_pattern_matches_only_explicit_suffix_semantics() {
        assert!(!no_proxy_host_pattern_matches(
            "openai.com",
            "api.openai.com"
        ));
        assert!(!no_proxy_host_pattern_matches("com", "api.openai.com"));
        assert!(no_proxy_host_pattern_matches(
            ".openai.com",
            "api.openai.com"
        ));
        assert!(no_proxy_host_pattern_matches(
            "*.openai.com",
            "api.openai.com"
        ));
        assert!(!no_proxy_host_pattern_matches("*.openai.com", "openai.com"));
        assert!(no_proxy_host_pattern_matches("[0:0:0:0:0:0:0:1]", "::1"));
        assert!(no_proxy_host_pattern_matches("0:0:0:0:0:0:0:1", "[::1]"));
        assert!(!no_proxy_host_pattern_matches(
            "evilopenai.com",
            "api.openai.com"
        ));
    }

    #[test]
    fn test_no_proxy_overlap_models_common_client_bare_suffixes_for_protected_hosts() {
        assert!(no_proxy_entry_overlaps_host_pattern(
            "internal",
            "metadata.google.internal"
        ));
        assert!(no_proxy_entry_overlaps_host_pattern(
            "254",
            "169.254.169.254"
        ));
        assert!(no_proxy_entry_overlaps_host_pattern(
            "internal",
            "api.internal"
        ));
        assert!(!no_proxy_entry_overlaps_host_pattern(
            "redis",
            "metadata.google.internal"
        ));
    }

    #[test]
    fn test_config_serialization() {
        let config = ProxyConfig {
            allowed_hosts: vec!["api.openai.com".to_string()],
            no_proxy: vec!["redis".to_string()],
            ..Default::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ProxyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.allowed_hosts, vec!["api.openai.com"]);
        assert_eq!(deserialized.no_proxy, vec!["redis"]);
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
    fn test_compiled_endpoint_policy_preserves_legacy_allow_list() {
        let rules = vec![EndpointRule {
            method: "GET".to_string(),
            path: "/v1/tasks/**".to_string(),
        }];
        let policy = CompiledEndpointPolicy::compile(None, &rules).unwrap();

        assert!(matches!(
            policy.evaluate("GET", "/v1/tasks/123"),
            EndpointPolicyOutcome::Allow { .. }
        ));
        assert!(matches!(
            policy.evaluate("POST", "/v1/tasks/123"),
            EndpointPolicyOutcome::Deny { .. }
        ));
    }

    #[test]
    fn test_compiled_endpoint_policy_deny_beats_approve_and_allow() {
        let policy = EndpointPolicyConfig {
            default: EndpointPolicyDefault {
                decision: EndpointPolicyDecision::Allow,
                backend: None,
                timeout_secs: None,
            },
            deny: vec![EndpointPolicyRule {
                method: "POST".to_string(),
                path: "/v1/tasks/*/comments".to_string(),
                backend: None,
                reason: Some("blocked".to_string()),
                timeout_secs: None,
            }],
            approve: vec![EndpointPolicyRule {
                method: "POST".to_string(),
                path: "/v1/tasks/*/comments".to_string(),
                backend: Some("terminal".to_string()),
                reason: None,
                timeout_secs: Some(5),
            }],
            allow: vec![EndpointPolicyRule {
                method: "POST".to_string(),
                path: "/v1/tasks/*/comments".to_string(),
                backend: None,
                reason: None,
                timeout_secs: None,
            }],
        };
        let compiled = CompiledEndpointPolicy::compile(Some(&policy), &[]).unwrap();

        assert!(matches!(
            compiled.evaluate("POST", "/v1/tasks/123/comments"),
            EndpointPolicyOutcome::Deny {
                reason: Some("blocked"),
                ..
            }
        ));
    }

    #[test]
    fn test_compiled_endpoint_policy_approve_route_carries_backend() {
        let policy = EndpointPolicyConfig {
            approve: vec![EndpointPolicyRule {
                method: "GET".to_string(),
                path: "/v1/secrets/**".to_string(),
                backend: Some("terminal".to_string()),
                reason: Some("sensitive endpoint".to_string()),
                timeout_secs: Some(10),
            }],
            ..EndpointPolicyConfig::default()
        };
        let compiled = CompiledEndpointPolicy::compile(Some(&policy), &[]).unwrap();

        assert!(matches!(
            compiled.evaluate("GET", "/v1/secrets/token"),
            EndpointPolicyOutcome::Approve {
                backend: Some("terminal"),
                reason: Some("sensitive endpoint"),
                timeout_secs: Some(10),
                ..
            }
        ));
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

    // ========================================================================
    // AwsAuthConfig tests
    // ========================================================================

    #[test]
    fn test_aws_auth_config_minimal_deserializes() {
        let json = r#"{}"#;
        let aws: AwsAuthConfig = serde_json::from_str(json).unwrap();
        assert!(aws.profile.is_none());
        assert!(aws.region.is_none());
        assert!(aws.service.is_none());
    }

    #[test]
    fn test_aws_auth_config_all_fields_roundtrip() {
        let original = AwsAuthConfig {
            profile: Some("my-aws-profile".to_string()),
            region: Some("us-east-1".to_string()),
            service: Some("bedrock".to_string()),
        };
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: AwsAuthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.profile.as_deref(), Some("my-aws-profile"));
        assert_eq!(deserialized.region.as_deref(), Some("us-east-1"));
        assert_eq!(deserialized.service.as_deref(), Some("bedrock"));
    }

    #[test]
    fn test_aws_auth_field_absent_is_none() {
        let json = r#"{"prefix": "bedrock", "upstream": "https://bedrock-runtime.us-east-1.amazonaws.com"}"#;
        let route: RouteConfig = serde_json::from_str(json).unwrap();
        assert!(route.aws_auth.is_none());
    }

    #[test]
    fn test_aws_auth_config_unknown_field_rejected() {
        let json = r#"{"profile": "foo", "unknown_field": "bar"}"#;
        let result: std::result::Result<AwsAuthConfig, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "unknown fields must be rejected by deny_unknown_fields"
        );
    }

    #[test]
    fn test_route_config_with_aws_auth_deserializes() {
        let json = r#"{
            "prefix": "bedrock",
            "upstream": "https://bedrock-runtime.us-east-1.amazonaws.com",
            "aws_auth": {
                "profile": "my-aws-profile"
            }
        }"#;
        let route: RouteConfig = serde_json::from_str(json).unwrap();
        let aws = route.aws_auth.unwrap();
        assert_eq!(aws.profile.as_deref(), Some("my-aws-profile"));
        assert!(aws.region.is_none());
        assert!(aws.service.is_none());
    }

    #[test]
    fn test_route_config_with_full_aws_auth_deserializes() {
        let json = r#"{
            "prefix": "bedrock",
            "upstream": "https://bedrock-runtime.us-east-1.amazonaws.com",
            "aws_auth": {
                "profile": "my-aws-profile",
                "region": "us-west-2",
                "service": "bedrock"
            }
        }"#;
        let route: RouteConfig = serde_json::from_str(json).unwrap();
        let aws = route.aws_auth.unwrap();
        assert_eq!(aws.profile.as_deref(), Some("my-aws-profile"));
        assert_eq!(aws.region.as_deref(), Some("us-west-2"));
        assert_eq!(aws.service.as_deref(), Some("bedrock"));
    }

    #[test]
    fn test_aws_auth_empty_object_sets_all_none() {
        let json = r#"{
            "prefix": "bedrock",
            "upstream": "https://bedrock-runtime.us-east-1.amazonaws.com",
            "aws_auth": {}
        }"#;
        let route: RouteConfig = serde_json::from_str(json).unwrap();
        let aws = route.aws_auth.unwrap();
        assert!(aws.profile.is_none());
        assert!(aws.region.is_none());
        assert!(aws.service.is_none());
    }

    #[test]
    fn test_spiffe_jwt_config_roundtrip() {
        let json = r#"{
            "prefix": "inventory",
            "upstream": "https://inventory.internal.example",
            "spiffe": {
                "type": "jwt",
                "workload_api_socket": "/run/spire/sockets/agent.sock",
                "audience": ["inventory.internal.example"],
                "inject_header": "Authorization",
                "credential_format": "Bearer {}"
            }
        }"#;
        let route: RouteConfig = serde_json::from_str(json).unwrap();
        let SpiffeAuthConfig::Jwt {
            workload_api_socket,
            audience,
            inject_header,
            credential_format,
            ..
        } = route.spiffe.unwrap();
        assert_eq!(workload_api_socket, "/run/spire/sockets/agent.sock");
        assert_eq!(audience, vec!["inventory.internal.example"]);
        assert_eq!(inject_header, "Authorization");
        assert_eq!(credential_format.as_deref(), Some("Bearer {}"));
    }

    #[test]
    fn test_spiffe_absent_by_default() {
        let json = r#"{"prefix": "openai", "upstream": "https://api.openai.com"}"#;
        let route: RouteConfig = serde_json::from_str(json).unwrap();
        assert!(route.spiffe.is_none());
    }

    #[test]
    fn websocket_rules_validate_and_deduplicate_paths() {
        let rules = vec![
            WebSocketRuleConfig {
                path: "/backend-api/codex/responses".to_string(),
            },
            WebSocketRuleConfig {
                path: "/backend-api//codex/responses/".to_string(),
            },
        ];
        let compiled = CompiledUpgradeRules::compile(&rules).unwrap();
        assert!(compiled.matches("/backend-api/codex/responses?session=1"));
        assert!(!compiled.matches("/backend-api/codex/other"));
    }

    #[test]
    fn websocket_rules_reject_ambiguous_or_non_absolute_paths() {
        for path in ["relative", "/socket?scope=all", "/socket#fragment"] {
            assert!(
                CompiledUpgradeRules::compile(&[WebSocketRuleConfig {
                    path: path.to_string(),
                }])
                .is_err()
            );
        }
    }
}
