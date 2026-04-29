//! Profile system for pre-configured capability sets
//!
//! Profiles provide named configurations for common applications like
//! opencode and swival. They can be built-in (compiled into the binary),
//! installed via registry packs, or user-defined (in ~/.config/nono/profiles/).

pub(crate) mod builtin;

use nono::{NonoError, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

// Re-export InjectMode and OAuth2Config from nono-proxy for use in profiles
pub use nono_proxy::config::{InjectMode, OAuth2Config};

/// Profile metadata
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct ProfileMeta {
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub author: Option<String>,
}

/// Filesystem configuration in a profile
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemConfig {
    /// Directories with read+write access
    #[serde(default)]
    pub allow: Vec<String>,
    /// Directories with read-only access
    #[serde(default)]
    pub read: Vec<String>,
    /// Directories with write-only access
    #[serde(default)]
    pub write: Vec<String>,
    /// Single files with read+write access
    #[serde(default)]
    pub allow_file: Vec<String>,
    /// Single files with read-only access
    #[serde(default)]
    pub read_file: Vec<String>,
    /// Single files with write-only access
    #[serde(default)]
    pub write_file: Vec<String>,
    /// Single AF_UNIX socket paths — connect only.
    /// Implies read access on the socket path. See issue #685.
    #[serde(default)]
    pub unix_socket: Vec<String>,
    /// Single AF_UNIX socket paths — connect and bind.
    /// Implies read+write access on the socket path when it exists, or
    /// on its parent directory when it does not yet exist (the normal
    /// `bind(2)` workflow — the syscall creates the socket file).
    /// Dangling symlinks are rejected at grant time. For runtime-generated
    /// filenames (e.g. PID-suffixed paths) prefer `unix_socket_dir_bind`
    /// so the implied fs grant stays scoped to a dedicated directory.
    #[serde(default)]
    pub unix_socket_bind: Vec<String>,
    /// Directories where any direct-child AF_UNIX socket may be connected to.
    /// Non-recursive. Implies read access on the directory.
    #[serde(default)]
    pub unix_socket_dir: Vec<String>,
    /// Directories where any direct-child AF_UNIX socket may be connected to
    /// or bound. Non-recursive. Implies read+write access on the directory.
    #[serde(default)]
    pub unix_socket_dir_bind: Vec<String>,
}

/// Policy patch configuration in a profile.
///
/// These fields provide explicit subtractive/additive composition on top of
/// inherited groups and existing filesystem configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPatchConfig {
    /// Group names to remove from the resolved group set.
    #[serde(default)]
    pub exclude_groups: Vec<String>,
    /// Additional read-only directories to allow.
    #[serde(default)]
    pub add_allow_read: Vec<String>,
    /// Additional write-only directories to allow.
    #[serde(default)]
    pub add_allow_write: Vec<String>,
    /// Additional read-write directories to allow.
    #[serde(default)]
    pub add_allow_readwrite: Vec<String>,
    /// Additional deny.access paths to apply.
    #[serde(default)]
    pub add_deny_access: Vec<String>,
    /// Deprecated startup-only command denylist extension.
    /// Parsed for compatibility in v0.33.0, but not enforced for child processes.
    #[serde(default)]
    pub add_deny_commands: Vec<String>,
    /// Paths to exempt from deny groups.
    /// Each path must also be explicitly granted via `filesystem` or `policy.add_allow_*`.
    /// Does not implicitly grant access; only removes the deny rule.
    #[serde(default)]
    pub override_deny: Vec<String>,
}

/// Custom credential route definition for reverse proxy.
///
/// Allows users to define their own credential services in profiles,
/// enabling `--proxy-credential` to work with any API without requiring
/// changes to the built-in `network-policy.json`.
///
/// Supports multiple injection modes:
/// - `header`: Inject into HTTP header with format string (default)
/// - `url_path`: Replace pattern in URL path (e.g., Telegram Bot API `/bot{}/`)
/// - `query_param`: Add/replace query parameter (e.g., `?api_key=...`)
/// - `basic_auth`: HTTP Basic Authentication (credential as `username:password`)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomCredentialDef {
    /// Upstream URL to proxy requests to (e.g., "https://api.telegram.org")
    pub upstream: String,
    /// Keystore account name for the credential (e.g., "telegram_bot_token").
    /// Mutually exclusive with `auth` — use one or the other.
    #[serde(default)]
    pub credential_key: Option<String>,
    /// Optional OAuth2 client_credentials configuration.
    /// When present, the proxy handles token exchange automatically.
    /// Mutually exclusive with `credential_key` — use one or the other.
    #[serde(default)]
    pub auth: Option<OAuth2Config>,
    /// Injection mode (default: "header")
    #[serde(default)]
    pub inject_mode: InjectMode,

    // --- Header mode fields ---
    /// HTTP header to inject the credential into (default: "Authorization")
    /// Only used when inject_mode is "header".
    #[serde(default = "default_inject_header")]
    pub inject_header: String,
    /// Format string for the credential value (default: "Bearer {}")
    /// Use {} as placeholder for the credential value.
    /// Only used when inject_mode is "header".
    #[serde(default = "default_credential_format")]
    pub credential_format: String,

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
    /// When set, these values control how the local proxy validates incoming
    /// phantom tokens from the sandboxed process. Outbound upstream injection
    /// still uses the top-level fields.
    #[serde(default)]
    pub proxy: Option<nono_proxy::config::ProxyInjectConfig>,

    /// Explicit environment variable name for the phantom token (e.g., "OPENAI_API_KEY").
    ///
    /// When set, the proxy uses this as the SDK API key env var instead of
    /// deriving it from `credential_key.to_uppercase()`. Required when
    /// `credential_key` is a URI manager reference (`op://`,
    /// `apple-password://`, or `file://`).
    #[serde(default)]
    pub env_var: Option<String>,

    /// Optional L7 endpoint rules for method+path filtering.
    /// When non-empty, only matching method+path combinations are allowed.
    #[serde(default)]
    pub endpoint_rules: Vec<nono_proxy::config::EndpointRule>,

    /// Optional path to a PEM-encoded CA certificate file for upstream TLS.
    ///
    /// When set, the proxy trusts this CA in addition to the system roots
    /// when connecting to the upstream for this route. Required for upstreams
    /// with self-signed or private CA certificates (e.g., Kubernetes API servers).
    ///
    /// Supports absolute paths and tilde (`~/…`) expansion. Relative paths
    /// resolve against the working directory; prefer absolute paths to avoid
    /// ambiguity.
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
}

fn default_inject_header() -> String {
    "Authorization".to_string()
}

fn default_credential_format() -> String {
    "Bearer {}".to_string()
}

/// Check if a character is a valid HTTP token character per RFC 7230.
fn is_http_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '!' | '#'
                | '$'
                | '%'
                | '&'
                | '\''
                | '*'
                | '+'
                | '-'
                | '.'
                | '^'
                | '_'
                | '`'
                | '|'
                | '~'
        )
}

/// Validate a credential key.
///
/// Accepts either:
/// - A bare keyring account name (alphanumeric + underscores only)
/// - A 1Password `op://` URI (validated by `nono::keystore::validate_op_uri`)
/// - An Apple Passwords `apple-password://` URI
/// - A `file://` URI pointing to an absolute path (validated by `nono::keystore::validate_file_uri`)
fn validate_credential_key(context_name: &str, key: &str) -> Result<()> {
    if key.is_empty() {
        return Err(NonoError::ProfileParse(format!(
            "credential_key for custom credential '{}' cannot be empty",
            context_name
        )));
    }

    if nono::keystore::is_op_uri(key) {
        // Validate as 1Password URI
        nono::keystore::validate_op_uri(key).map_err(|e| {
            NonoError::ProfileParse(format!(
                "invalid 1Password URI for custom credential '{}': {}",
                context_name, e
            ))
        })
    } else if nono::keystore::is_apple_password_uri(key) {
        nono::keystore::validate_apple_password_uri(key).map_err(|e| {
            NonoError::ProfileParse(format!(
                "invalid Apple Passwords URI for custom credential '{}': {}",
                context_name, e
            ))
        })
    } else if nono::keystore::is_file_uri(key) {
        nono::keystore::validate_file_uri(key).map_err(|e| {
            NonoError::ProfileParse(format!(
                "invalid file:// URI for custom credential '{}': {}",
                context_name, e
            ))
        })
    } else {
        // Validate as keyring account name (alphanumeric + underscore)
        if !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(NonoError::ProfileParse(format!(
                "credential_key '{}' for custom credential '{}' must contain only \
                 alphanumeric characters and underscores (or use op:// / apple-password:// / file:// URI)",
                key, context_name
            )));
        }
        Ok(())
    }
}

/// Validate a custom credential definition for security issues.
///
/// Checks:
/// - `credential_key` must be alphanumeric + underscores only, or a valid
///   `op://` / `apple-password://` / `file://` URI
/// - `upstream` must be HTTPS (or HTTP for loopback only)
/// - Mode-specific validation:
///   - `header`: inject_header must be valid HTTP token, credential_format no CRLF
///   - `url_path`: path_pattern required, no CRLF in patterns
///   - `query_param`: query_param_name required, valid query param name
///   - `basic_auth`: no additional required fields
fn validate_custom_credential(name: &str, cred: &CustomCredentialDef) -> Result<()> {
    // Mutual exclusion: credential_key and auth cannot both be set
    if cred.credential_key.is_some() && cred.auth.is_some() {
        return Err(NonoError::ProfileParse(format!(
            "custom credential '{}' has both 'credential_key' and 'auth' set; \
             these are mutually exclusive — use one or the other",
            name
        )));
    }

    // At least one of credential_key or auth must be set
    if cred.credential_key.is_none() && cred.auth.is_none() {
        return Err(NonoError::ProfileParse(format!(
            "custom credential '{}' must have either 'credential_key' or 'auth' set",
            name
        )));
    }

    // Validate OAuth2 auth if present
    if let Some(ref auth) = cred.auth {
        validate_oauth2_auth(name, auth)?;
    }

    // Validate credential_key if present
    if let Some(ref key) = cred.credential_key {
        validate_credential_key(name, key)?;

        // When credential_key is a URI manager reference, env_var is required because the URI
        // cannot be meaningfully uppercased into an env var name (e.g.,
        // "op://vault/item/field" -> "OP://VAULT/ITEM/FIELD" is nonsensical).
        if (nono::keystore::is_op_uri(key)
            || nono::keystore::is_apple_password_uri(key)
            || nono::keystore::is_file_uri(key))
            && cred.env_var.is_none()
        {
            return Err(NonoError::ProfileParse(format!(
                "env_var is required for custom credential '{}' when credential_key is a URI \
                 manager reference (op://, apple-password://, or file://); \
                 set it to the SDK API key env var name (e.g., \"OPENAI_API_KEY\")",
                name
            )));
        }
    }

    // Validate env_var format if specified
    if let Some(ref ev) = cred.env_var {
        if ev.is_empty() {
            return Err(NonoError::ProfileParse(format!(
                "env_var for custom credential '{}' cannot be empty",
                name
            )));
        }
        if !ev.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(NonoError::ProfileParse(format!(
                "env_var '{}' for custom credential '{}' must contain only \
                 alphanumeric characters and underscores",
                ev, name
            )));
        }
    }

    // Validate upstream URL (HTTPS required, HTTP only for loopback)
    validate_upstream_url(&cred.upstream, name)?;

    // Mode-specific validation (only applies to credential_key-based routes,
    // not OAuth2 routes which always inject as Bearer header)
    if cred.credential_key.is_some() {
        match cred.inject_mode {
            InjectMode::Header => {
                validate_header_mode(name, cred)?;
            }
            InjectMode::UrlPath => {
                validate_url_path_mode(name, cred)?;
            }
            InjectMode::QueryParam => {
                validate_query_param_mode(name, cred)?;
            }
            InjectMode::BasicAuth => {
                // No additional required fields for basic_auth mode
                // Credential value is expected to be "username:password" format
            }
        }
    }

    validate_proxy_override(name, cred)?;

    Ok(())
}

fn validate_proxy_override(name: &str, cred: &CustomCredentialDef) -> Result<()> {
    let Some(proxy) = cred.proxy.as_ref() else {
        return Ok(());
    };

    let mode = proxy.inject_mode.as_ref().unwrap_or(&cred.inject_mode);

    match mode {
        InjectMode::Header | InjectMode::BasicAuth => {
            let header = proxy
                .inject_header
                .as_deref()
                .unwrap_or(cred.inject_header.as_str());
            if header.is_empty() {
                return Err(NonoError::ProfileParse(format!(
                    "proxy.inject_header for custom credential '{}' cannot be empty",
                    name
                )));
            }
            if !header.chars().all(is_http_token_char) {
                return Err(NonoError::ProfileParse(format!(
                    "proxy.inject_header '{}' for custom credential '{}' contains invalid characters; \
                     header names must be valid HTTP tokens (alphanumeric and !#$%&'*+-.^_`|~)",
                    header, name
                )));
            }

            if *mode == InjectMode::Header {
                let format = proxy
                    .credential_format
                    .as_deref()
                    .unwrap_or(cred.credential_format.as_str());
                if format.contains('\r') || format.contains('\n') {
                    return Err(NonoError::ProfileParse(format!(
                        "proxy.credential_format for custom credential '{}' contains invalid CRLF characters; \
                         this could enable header injection attacks",
                        name
                    )));
                }
            }
        }
        InjectMode::UrlPath => {
            let pattern = proxy
                .path_pattern
                .as_deref()
                .or(cred.path_pattern.as_deref())
                .ok_or_else(|| {
                    NonoError::ProfileParse(format!(
                        "proxy.path_pattern is required for custom credential '{}' when effective inject_mode is 'url_path'",
                        name
                    ))
                })?;
            if !pattern.contains("{}") {
                return Err(NonoError::ProfileParse(format!(
                    "proxy.path_pattern '{}' for custom credential '{}' must contain {{}} placeholder",
                    pattern, name
                )));
            }
            if pattern.contains('\r') || pattern.contains('\n') {
                return Err(NonoError::ProfileParse(format!(
                    "proxy.path_pattern for custom credential '{}' contains invalid CRLF characters",
                    name
                )));
            }

            if let Some(replacement) = proxy
                .path_replacement
                .as_deref()
                .or(cred.path_replacement.as_deref())
            {
                if !replacement.contains("{}") {
                    return Err(NonoError::ProfileParse(format!(
                        "proxy.path_replacement '{}' for custom credential '{}' must contain {{}} placeholder",
                        replacement, name
                    )));
                }
                if replacement.contains('\r') || replacement.contains('\n') {
                    return Err(NonoError::ProfileParse(format!(
                        "proxy.path_replacement for custom credential '{}' contains invalid CRLF characters",
                        name
                    )));
                }
            }
        }
        InjectMode::QueryParam => {
            let param_name = proxy
                .query_param_name
                .as_deref()
                .or(cred.query_param_name.as_deref())
                .ok_or_else(|| {
                    NonoError::ProfileParse(format!(
                        "proxy.query_param_name is required for custom credential '{}' when effective inject_mode is 'query_param'",
                        name
                    ))
                })?;

            if param_name.is_empty() {
                return Err(NonoError::ProfileParse(format!(
                    "proxy.query_param_name for custom credential '{}' cannot be empty",
                    name
                )));
            }
            if !param_name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                return Err(NonoError::ProfileParse(format!(
                    "proxy.query_param_name '{}' for custom credential '{}' must contain only \
                     alphanumeric characters, underscores, and hyphens",
                    param_name, name
                )));
            }
        }
    }

    Ok(())
}

/// Validate OAuth2 client_credentials auth configuration.
///
/// Checks:
/// - `token_url` must be HTTPS (or HTTP for loopback addresses)
/// - `client_id` must not be empty
/// - `client_secret` must not be empty and must be a credential reference
///   (env://, file://, op://, apple-password://) or plain value
fn validate_oauth2_auth(name: &str, auth: &OAuth2Config) -> Result<()> {
    // Validate token_url — same rules as upstream URL (HTTPS or loopback HTTP)
    validate_upstream_url(&auth.token_url, &format!("{}/auth.token_url", name))?;

    // client_id must not be empty
    if auth.client_id.is_empty() {
        return Err(NonoError::ProfileParse(format!(
            "auth.client_id for custom credential '{}' cannot be empty",
            name
        )));
    }

    // client_secret must not be empty
    if auth.client_secret.is_empty() {
        return Err(NonoError::ProfileParse(format!(
            "auth.client_secret for custom credential '{}' cannot be empty",
            name
        )));
    }

    Ok(())
}

/// Validate header injection mode fields.
fn validate_header_mode(name: &str, cred: &CustomCredentialDef) -> Result<()> {
    // Validate inject_header (RFC 7230 token)
    if cred.inject_header.is_empty() {
        return Err(NonoError::ProfileParse(format!(
            "inject_header for custom credential '{}' cannot be empty",
            name
        )));
    }
    if !cred.inject_header.chars().all(is_http_token_char) {
        return Err(NonoError::ProfileParse(format!(
            "inject_header '{}' for custom credential '{}' contains invalid characters; \
             header names must be valid HTTP tokens (alphanumeric and !#$%&'*+-.^_`|~)",
            cred.inject_header, name
        )));
    }

    // Validate credential_format (no CRLF injection)
    if cred.credential_format.contains('\r') || cred.credential_format.contains('\n') {
        return Err(NonoError::ProfileParse(format!(
            "credential_format for custom credential '{}' contains invalid CRLF characters; \
             this could enable header injection attacks",
            name
        )));
    }

    Ok(())
}

/// Validate URL path injection mode fields.
fn validate_url_path_mode(name: &str, cred: &CustomCredentialDef) -> Result<()> {
    // path_pattern is required for url_path mode
    let pattern = cred.path_pattern.as_ref().ok_or_else(|| {
        NonoError::ProfileParse(format!(
            "path_pattern is required for custom credential '{}' with inject_mode 'url_path'",
            name
        ))
    })?;

    // Pattern must contain {} placeholder
    if !pattern.contains("{}") {
        return Err(NonoError::ProfileParse(format!(
            "path_pattern '{}' for custom credential '{}' must contain {{}} placeholder for the token",
            pattern, name
        )));
    }

    // No CRLF in pattern
    if pattern.contains('\r') || pattern.contains('\n') {
        return Err(NonoError::ProfileParse(format!(
            "path_pattern for custom credential '{}' contains invalid CRLF characters",
            name
        )));
    }

    // Validate path_replacement if specified
    if let Some(replacement) = &cred.path_replacement {
        if !replacement.contains("{}") {
            return Err(NonoError::ProfileParse(format!(
                "path_replacement '{}' for custom credential '{}' must contain {{}} placeholder",
                replacement, name
            )));
        }
        if replacement.contains('\r') || replacement.contains('\n') {
            return Err(NonoError::ProfileParse(format!(
                "path_replacement for custom credential '{}' contains invalid CRLF characters",
                name
            )));
        }
    }

    Ok(())
}

/// Validate query parameter injection mode fields.
fn validate_query_param_mode(name: &str, cred: &CustomCredentialDef) -> Result<()> {
    // query_param_name is required for query_param mode
    let param_name = cred.query_param_name.as_ref().ok_or_else(|| {
        NonoError::ProfileParse(format!(
            "query_param_name is required for custom credential '{}' with inject_mode 'query_param'",
            name
        ))
    })?;

    // Validate query param name (alphanumeric + underscore + hyphen)
    if param_name.is_empty() {
        return Err(NonoError::ProfileParse(format!(
            "query_param_name for custom credential '{}' cannot be empty",
            name
        )));
    }
    if !param_name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(NonoError::ProfileParse(format!(
            "query_param_name '{}' for custom credential '{}' must contain only \
             alphanumeric characters, underscores, and hyphens",
            param_name, name
        )));
    }

    Ok(())
}

/// Validate an upstream URL for security.
///
/// HTTP is only allowed for loopback addresses:
/// - `localhost` (hostname)
/// - `127.0.0.0/8` (IPv4 loopback range)
/// - `::1` (IPv6 loopback)
/// - `0.0.0.0` (unspecified IPv4, binds to all interfaces)
/// - `::` (unspecified IPv6)
fn validate_upstream_url(url: &str, service_name: &str) -> Result<()> {
    let parsed = url::Url::parse(url).map_err(|e| {
        NonoError::ProfileParse(format!(
            "Invalid upstream URL for custom credential '{}': {}",
            service_name, e
        ))
    })?;

    match parsed.scheme() {
        "https" => Ok(()),
        "http" => {
            // For IPv6 addresses, url::Url returns the address in host()
            // but host_str() may include brackets. We need to handle both cases.
            let is_loopback = match parsed.host() {
                Some(url::Host::Ipv4(ip)) => ip.is_loopback() || ip.is_unspecified(),
                Some(url::Host::Ipv6(ip)) => ip.is_loopback() || ip.is_unspecified(),
                Some(url::Host::Domain(domain)) => domain == "localhost",
                None => false,
            };

            if is_loopback {
                Ok(())
            } else {
                Err(NonoError::ProfileParse(format!(
                    "Upstream URL for custom credential '{}' must use HTTPS \
                     (HTTP only allowed for loopback addresses): {}",
                    service_name, url
                )))
            }
        }
        scheme => Err(NonoError::ProfileParse(format!(
            "Upstream URL for custom credential '{}' must use HTTPS, got scheme '{}': {}",
            service_name, scheme, url
        ))),
    }
}

/// Validate all custom credentials in a profile.
fn validate_profile_custom_credentials(profile: &Profile) -> Result<()> {
    for (name, cred) in &profile.network.custom_credentials {
        validate_custom_credential(name, cred)?;
    }
    Ok(())
}

/// Validate env_credentials keys in a profile.
///
/// Keys can be keyring account names, `op://` URIs, `apple-password://` URIs,
/// `keyring://` URIs, `env://` URIs, or `file://` URIs.
/// Keyring account names are validated at load time by the keyring crate itself,
/// but URI entries need structural validation upfront.
fn validate_env_credential_keys(profile: &Profile) -> Result<()> {
    for (key, value) in &profile.env_credentials.mappings {
        if nono::keystore::is_op_uri(key) {
            nono::keystore::validate_op_uri(key).map_err(|e| {
                NonoError::ProfileParse(format!("invalid 1Password URI in env_credentials: {}", e))
            })?;
        } else if nono::keystore::is_apple_password_uri(key) {
            nono::keystore::validate_apple_password_uri(key).map_err(|e| {
                NonoError::ProfileParse(format!(
                    "invalid Apple Passwords URI in env_credentials: {}",
                    e
                ))
            })?;
        } else if nono::keystore::is_keyring_uri(key) {
            nono::keystore::validate_keyring_uri(key).map_err(|e| {
                NonoError::ProfileParse(format!("invalid keyring URI in env_credentials: {}", e))
            })?;
        } else if nono::keystore::is_env_uri(key) {
            nono::keystore::validate_env_uri(key).map_err(|e| {
                NonoError::ProfileParse(format!("invalid env:// URI in env_credentials: {}", e))
            })?;
        } else if nono::keystore::is_file_uri(key) {
            nono::keystore::validate_file_uri(key).map_err(|e| {
                NonoError::ProfileParse(format!("invalid file:// URI in env_credentials: {}", e))
            })?;
        }
        // Validate destination env var name against dangerous blocklist
        nono::validate_destination_env_var(value).map_err(|e| {
            NonoError::ProfileParse(format!(
                "invalid destination env var '{}' in env_credentials: {}",
                value, e
            ))
        })?;
    }
    Ok(())
}

/// Three-state value used for inheritable profile fields.
///
/// - `Inherit`: field was absent in the child profile, so keep the base value
/// - `Clear`: field was explicitly set to `null`, so remove the base value
/// - `Set(T)`: field was provided with a concrete override value
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum InheritableValue<T> {
    #[default]
    Inherit,
    Clear,
    Set(T),
}

impl<T> InheritableValue<T> {
    fn merge(self, base: Self) -> Self {
        match self {
            Self::Inherit => base,
            Self::Clear => Self::Clear,
            Self::Set(value) => Self::Set(value),
        }
    }

    pub fn as_ref(&self) -> Option<&T> {
        match self {
            Self::Set(value) => Some(value),
            Self::Inherit | Self::Clear => None,
        }
    }

    /// Returns `true` if this value is `Inherit` (absent in the source JSON).
    ///
    /// Used with `#[serde(skip_serializing_if)]` to omit inherited fields
    /// from serialized output, preserving the distinction between absent
    /// (inherit) and explicit null (clear).
    pub fn is_inherit(&self) -> bool {
        matches!(self, Self::Inherit)
    }
}

impl<T> Serialize for InheritableValue<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Set(value) => value.serialize(serializer),
            Self::Clear => serializer.serialize_none(),
            // Inherit should be skipped via skip_serializing_if.
            // If serialize is called anyway, emit null as a safe fallback.
            Self::Inherit => serializer.serialize_none(),
        }
    }
}

impl<'de, T> Deserialize<'de> for InheritableValue<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Option::<T>::deserialize(deserializer)? {
            Some(value) => Ok(Self::Set(value)),
            None => Ok(Self::Clear),
        }
    }
}

/// Network configuration in a profile
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// Block network access (network allowed by default; true = blocked).
    /// Canonical profile key: `block`.
    #[serde(default)]
    pub block: bool,
    /// Network proxy profile name (from network-policy.json).
    /// When set, outbound traffic is filtered through the proxy.
    ///
    /// `null` explicitly clears an inherited profile value, while an absent
    /// field inherits the base profile's value.
    #[serde(default, skip_serializing_if = "InheritableValue::is_inherit")]
    pub network_profile: InheritableValue<String>,
    /// Additional domains to allow through the proxy (on top of profile hosts).
    /// Canonical profile key: `allow_domain` (legacy `proxy_allow` and
    /// `allow_proxy` are also accepted).
    #[serde(
        default,
        rename = "allow_domain",
        alias = "proxy_allow",
        alias = "allow_proxy"
    )]
    pub allow_domain: Vec<String>,
    /// Credential services to enable via reverse proxy.
    /// Canonical profile key: `credentials` (legacy `proxy_credentials` accepted).
    ///
    /// When `None` (absent from profile), inherits parent credentials during merge.
    /// When `Some([])` (explicitly set to empty array), overrides parent to disable
    /// all inherited credential routes.
    #[serde(
        default,
        rename = "credentials",
        alias = "proxy_credentials",
        skip_serializing_if = "Option::is_none"
    )]
    pub credentials: Option<Vec<String>>,
    /// Localhost TCP ports to allow bidirectional IPC (connect + bind).
    /// Equivalent to `--open-port` CLI flag.
    /// Canonical profile key: `open_port` (legacy `port_allow` and `allow_port`
    /// are also accepted).
    #[serde(
        default,
        rename = "open_port",
        alias = "port_allow",
        alias = "allow_port"
    )]
    pub open_port: Vec<u16>,
    /// TCP ports the sandboxed child may listen on.
    /// Equivalent to `--listen-port` CLI flag.
    #[serde(default)]
    pub listen_port: Vec<u16>,
    /// Outbound TCP connect ports (allowlist). Linux Landlock V4+ only.
    /// Equivalent to `--allow-connect-port` CLI flag.
    #[serde(default)]
    pub connect_port: Vec<u16>,
    /// Custom credential definitions for services not in network-policy.json.
    /// Keys are service names (used with `--credential`), values define
    /// how to route and inject credentials for that service.
    #[serde(default)]
    pub custom_credentials: HashMap<String, CustomCredentialDef>,
    /// Upstream proxy address (host:port) for enterprise proxy passthrough.
    /// Canonical profile key: `upstream_proxy` (legacy `external_proxy`
    /// accepted).
    #[serde(default, rename = "upstream_proxy", alias = "external_proxy")]
    pub upstream_proxy: Option<String>,
    /// Hosts to bypass the upstream proxy and route directly.
    /// Canonical profile key: `upstream_bypass` (legacy
    /// `external_proxy_bypass` accepted).
    #[serde(default, rename = "upstream_bypass", alias = "external_proxy_bypass")]
    pub upstream_bypass: Vec<String>,
}

impl NetworkConfig {
    pub fn resolved_network_profile(&self) -> Option<&str> {
        self.network_profile.as_ref().map(String::as_str)
    }

    /// Returns the resolved credentials list, defaulting to empty if unset.
    pub fn resolved_credentials(&self) -> &[String] {
        self.credentials.as_deref().unwrap_or(&[])
    }

    /// Whether any profile setting requires proxy mode activation.
    pub fn has_proxy_flags(&self) -> bool {
        self.resolved_network_profile().is_some()
            || !self.allow_domain.is_empty()
            || !self.resolved_credentials().is_empty()
            || self.upstream_proxy.is_some()
    }
}

/// Secrets configuration in a profile
///
/// Maps keystore account names to environment variable names.
/// Secrets are loaded from the system keystore (macOS Keychain / Linux Secret Service)
/// under the service name "nono".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretsConfig {
    /// Map of keystore account name -> environment variable name
    /// Example: { "openai_api_key" = "OPENAI_API_KEY" }
    #[serde(flatten)]
    pub mappings: HashMap<String, String>,
}

/// Hook configuration for an agent
///
/// Defines hooks that nono will install for the target application.
/// For example, Claude Code hooks are installed to ~/.claude/hooks/
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookConfig {
    /// Event that triggers the hook (e.g., "PostToolUseFailure")
    pub event: String,
    /// Regex pattern to match tool names (e.g., "Read|Write|Edit|Bash")
    pub matcher: String,
    /// Script filename from data/hooks/ to install
    pub script: String,
}

/// Hooks configuration in a profile
///
/// Maps target application names to their hook configurations.
/// Example: [hooks.claude-code] for Claude Code hooks
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HooksConfig {
    /// Map of target application -> hook configuration
    #[serde(flatten)]
    pub hooks: HashMap<String, HookConfig>,
}

/// Working directory access level for profiles
///
/// Controls whether and how the current working directory is automatically
/// shared with the sandboxed process. This is profile-driven so each
/// application can declare its own CWD requirements.
/// Signal isolation mode as specified in a profile.
///
/// Maps to `nono::SignalMode` when building the `CapabilitySet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileSignalMode {
    /// Signals restricted to the current process only
    Isolated,
    /// Signals allowed to child processes in the same sandbox only
    AllowSameSandbox,
    /// Signals allowed to any process
    AllowAll,
}

impl From<ProfileSignalMode> for nono::SignalMode {
    fn from(val: ProfileSignalMode) -> Self {
        match val {
            ProfileSignalMode::Isolated => nono::SignalMode::Isolated,
            ProfileSignalMode::AllowSameSandbox => nono::SignalMode::AllowSameSandbox,
            ProfileSignalMode::AllowAll => nono::SignalMode::AllowAll,
        }
    }
}

/// Process inspection mode as specified in a profile.
///
/// Maps to `nono::ProcessInfoMode` when building the `CapabilitySet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileProcessInfoMode {
    /// Inspection restricted to self only (default)
    Isolated,
    /// Inspection allowed for same-sandbox children
    AllowSameSandbox,
    /// Inspection allowed for any process
    AllowAll,
}

impl From<ProfileProcessInfoMode> for nono::ProcessInfoMode {
    fn from(val: ProfileProcessInfoMode) -> Self {
        match val {
            ProfileProcessInfoMode::Isolated => nono::ProcessInfoMode::Isolated,
            ProfileProcessInfoMode::AllowSameSandbox => nono::ProcessInfoMode::AllowSameSandbox,
            ProfileProcessInfoMode::AllowAll => nono::ProcessInfoMode::AllowAll,
        }
    }
}

/// IPC mode as specified in a profile.
///
/// Maps to `nono::IpcMode` when building the `CapabilitySet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileIpcMode {
    /// POSIX shared memory only (default). Semaphores denied.
    SharedMemoryOnly,
    /// Full POSIX IPC: shared memory + semaphores.
    Full,
}

impl From<ProfileIpcMode> for nono::IpcMode {
    fn from(val: ProfileIpcMode) -> Self {
        match val {
            ProfileIpcMode::SharedMemoryOnly => nono::IpcMode::SharedMemoryOnly,
            ProfileIpcMode::Full => nono::IpcMode::Full,
        }
    }
}

/// WSL2 proxy fallback policy.
///
/// Controls what happens when `NetworkMode::ProxyOnly` is requested on WSL2
/// where the seccomp-notify fallback cannot be used (EBUSY). On native Linux
/// (including pre-V4 kernels), the seccomp fallback enforces proxy-only
/// networking. On WSL2, that enforcement is unavailable.
///
/// Default: `Error` — refuse to run rather than silently losing enforcement.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Wsl2ProxyPolicy {
    /// Refuse to run if ProxyOnly cannot be kernel-enforced on WSL2.
    /// This is the secure default.
    #[default]
    Error,
    /// Allow degraded execution: credential proxy runs and env vars are
    /// injected, but the child is NOT prevented from bypassing the proxy
    /// and opening arbitrary outbound connections directly.
    /// Use only when credential injection is more important than network
    /// lockdown (e.g., development workflows where the agent is trusted).
    InsecureProxy,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkdirAccess {
    /// No automatic CWD access
    #[default]
    None,
    /// Read-only access to CWD
    Read,
    /// Write-only access to CWD
    Write,
    /// Full read+write access to CWD
    ReadWrite,
}

/// Working directory configuration in a profile
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkdirConfig {
    /// Access level for the current working directory
    #[serde(default)]
    pub access: WorkdirAccess,
}

/// Security configuration referencing policy.json groups
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    /// Policy group names to resolve (from policy.json)
    #[serde(default)]
    pub groups: Vec<String>,
    /// Deprecated startup-only command allowlist override.
    /// Parsed for compatibility in v0.33.0, but not enforced for child processes.
    #[serde(default)]
    pub allowed_commands: Vec<String>,
    /// Signal isolation mode. Controls whether the sandboxed process can signal
    /// other processes. When `None`, inherits from the base profile during merge
    /// (defaults to `Isolated` if no base sets it).
    #[serde(default)]
    pub signal_mode: Option<ProfileSignalMode>,
    /// Process inspection mode. Controls whether the sandboxed process can read
    /// process info (ps, proc_pidinfo) for other processes. When `None`, defaults
    /// to `Isolated`.
    #[serde(default)]
    pub process_info_mode: Option<ProfileProcessInfoMode>,
    /// IPC mode. Controls whether the sandboxed process can use POSIX semaphores
    /// (needed for multiprocessing). When `None`, defaults to `SharedMemoryOnly`.
    #[serde(default)]
    pub ipc_mode: Option<ProfileIpcMode>,
    /// Enable runtime capability elevation via seccomp-notify (Linux).
    /// When true, the supervisor intercepts file opens and can grant access
    /// to paths not in the initial capability set. When false (default),
    /// the sandbox is static — no seccomp interception, no PTY mux, no prompts.
    #[serde(default)]
    pub capability_elevation: Option<bool>,
    /// WSL2 proxy fallback policy. Controls behavior when ProxyOnly network
    /// mode cannot be kernel-enforced on WSL2 (seccomp notify returns EBUSY).
    /// Default: `error` — refuse to run. Set to `insecure_proxy` to allow
    /// degraded execution where the credential proxy runs but the child is
    /// not prevented from bypassing it.
    #[serde(default)]
    pub wsl2_proxy_policy: Option<Wsl2ProxyPolicy>,
}

/// Rollback snapshot configuration in a profile
///
/// Controls which files are excluded from rollback snapshots. Patterns are
/// matched against path components (exact match) or, if they contain `/`,
/// as substrings of the full path. Glob patterns are matched against
/// the filename (last path component).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackConfig {
    /// Patterns to exclude from rollback snapshots.
    /// Added on top of the CLI's base exclusion list.
    #[serde(default)]
    pub exclude_patterns: Vec<String>,
    /// Glob patterns to exclude from rollback snapshots.
    /// Matched against the filename using standard glob syntax.
    #[serde(default)]
    pub exclude_globs: Vec<String>,
}

/// Controls which environment variables are passed to the sandboxed process.
///
/// By default, all environment variables are inherited from the parent process.
/// When `allow_vars` is set, only the listed variables (and nono-injected
/// credentials) are passed through. Supports exact names (`"PATH"`) and
/// prefix patterns (`"AWS_*"`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentConfig {
    /// Allow-list of environment variable names passed to the sandboxed process.
    ///
    /// Supports exact names (`"PATH"`) and prefix patterns ending with `*`
    /// (`"AWS_*"` matches `AWS_REGION`, `AWS_SECRET_ACCESS_KEY`, etc.).
    /// When empty, all variables are allowed (default).
    /// Nono-injected credentials always bypass this list.
    #[serde(default)]
    pub allow_vars: Vec<String>,
}

/// Configuration for supervisor-delegated URL opening.
///
/// Controls which URLs the sandboxed child can request the supervisor to
/// open in the user's browser. Used for OAuth2 login flows and similar
/// operations where the sandboxed process cannot launch a browser directly.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenUrlConfig {
    /// Allowed URL origins (scheme + host, e.g., "https://console.anthropic.com").
    /// The supervisor validates each URL open request against this list.
    /// An empty list means no URLs are allowed.
    #[serde(default)]
    pub allow_origins: Vec<String>,
    /// Allow opening http://localhost and http://127.0.0.1 URLs (for OAuth2 callbacks).
    #[serde(default)]
    pub allow_localhost: bool,
}

/// Deserialize the `extends` field from either a single string or an array of strings.
///
/// Accepts:
/// - `"extends": "base"` → `Some(vec!["base"])`
/// - `"extends": ["a", "b"]` → `Some(vec!["a", "b"])`
/// - absent / null → `None`
fn deserialize_extends<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum ExtendsValue {
        Single(String),
        Multiple(Vec<String>),
    }

    let value: Option<ExtendsValue> = Option::deserialize(deserializer)?;
    Ok(match value {
        Some(ExtendsValue::Single(s)) => Some(vec![s]),
        Some(ExtendsValue::Multiple(v)) => {
            if v.is_empty() {
                None
            } else {
                Some(v)
            }
        }
        None => None,
    })
}

/// A complete profile definition
#[derive(Debug, Clone, Default, Serialize)]
pub struct Profile {
    /// Optional base profile(s) to inherit from (by name).
    /// Accepts either a single string `"extends": "base"` or an array
    /// `"extends": ["base-a", "base-b"]`. Multiple bases are merged
    /// left-to-right before the child overrides.
    #[serde(default, deserialize_with = "deserialize_extends")]
    pub extends: Option<Vec<String>>,
    #[serde(default)]
    pub meta: ProfileMeta,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub filesystem: FilesystemConfig,
    #[serde(default)]
    pub policy: PolicyPatchConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default, alias = "secrets")]
    pub env_credentials: SecretsConfig,
    #[serde(default)]
    pub environment: Option<EnvironmentConfig>,
    #[serde(default)]
    pub workdir: WorkdirConfig,
    #[serde(default)]
    pub hooks: HooksConfig,
    #[serde(default, alias = "undo")]
    pub rollback: RollbackConfig,
    /// Supervisor-delegated URL opening (e.g., for OAuth2 login flows).
    /// When `None` (absent from JSON), inherits from the base profile.
    /// When `Some`, replaces the base profile's config entirely, allowing
    /// derived profiles to narrow permissions.
    #[serde(default)]
    pub open_urls: Option<OpenUrlConfig>,
    /// Opt-in gate for temporary direct LaunchServices opens on macOS.
    /// Must be paired with the CLI flag `--allow-launch-services`.
    /// When `None`, inherits from the base profile.
    #[serde(default)]
    pub allow_launch_services: Option<bool>,
    /// Opt-in gate for GPU access (Metal/IOKit on macOS, render nodes on Linux).
    /// Must be paired with the CLI flag `--allow-gpu`.
    /// When `None`, inherits from the base profile.
    #[serde(default)]
    pub allow_gpu: Option<bool>,
    /// Opt-in to allow parent-of-protected-root grants on macOS.
    /// When `true` (and on macOS), `--allow ~` is permitted because Seatbelt deny
    /// rules protect `~/.nono`. Ignored on Linux. Default is `false`.
    #[serde(default)]
    pub allow_parent_of_protected: Option<bool>,
    /// Deprecated: Parsed for backward compatibility but ignored.
    /// Supervised mode preserves TTY by default, making this unnecessary.
    #[serde(default)]
    pub interactive: bool,
    /// Directory names to skip during trust scanning and rollback preflight.
    /// Treated like built-in heavy directories (for example `target`).
    #[serde(default)]
    pub skipdirs: Vec<String>,
    /// Pack dependencies verified at launch before sandbox is applied.
    /// Each entry is a `<namespace>/<name>` reference to an installed pack.
    #[serde(default)]
    pub packs: Vec<String>,
    /// Extra arguments appended to the child command at launch.
    /// Supports variable expansion (e.g. `$NONO_PACKAGES`).
    #[serde(default)]
    pub command_args: Vec<String>,
    /// Raw macOS-only Seatbelt S-expression rules applied verbatim to the sandbox policy.
    ///
    /// Expert escape hatch for capability gaps. Each entry must be a valid Seatbelt
    /// S-expression such as `(allow iokit-open)`. Rules are validated at load time
    /// and rejected if malformed. Ignored on Linux. Prominently surfaced in
    /// `nono profile show` output when present so it is obvious a profile uses
    /// raw platform rules.
    ///
    /// This field is intentionally named `unsafe_*` — it bypasses nono's capability
    /// model. If a rule pattern becomes common, prefer promoting it to a typed
    /// first-class capability.
    #[serde(default)]
    pub unsafe_macos_seatbelt_rules: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileDeserialize {
    /// Optional JSON Schema URI for editor tooling. Parsed and ignored.
    #[serde(rename = "$schema", default)]
    _schema: Option<String>,
    #[serde(default, deserialize_with = "deserialize_extends")]
    extends: Option<Vec<String>>,
    #[serde(default)]
    meta: ProfileMeta,
    #[serde(default)]
    security: SecurityConfig,
    #[serde(default)]
    filesystem: FilesystemConfig,
    #[serde(default)]
    policy: PolicyPatchConfig,
    #[serde(default)]
    network: NetworkConfig,
    #[serde(default, alias = "secrets")]
    env_credentials: SecretsConfig,
    #[serde(default)]
    environment: Option<EnvironmentConfig>,
    #[serde(default)]
    workdir: WorkdirConfig,
    #[serde(default)]
    hooks: HooksConfig,
    #[serde(default, alias = "undo")]
    rollback: RollbackConfig,
    #[serde(default)]
    open_urls: Option<OpenUrlConfig>,
    #[serde(default)]
    allow_launch_services: Option<bool>,
    #[serde(default)]
    allow_gpu: Option<bool>,
    allow_parent_of_protected: Option<bool>,
    #[serde(default)]
    interactive: bool,
    #[serde(default)]
    skipdirs: Vec<String>,
    #[serde(default)]
    packs: Vec<String>,
    #[serde(default)]
    #[serde(alias = "brokered_commands")]
    command_args: Vec<String>,
    #[serde(default)]
    unsafe_macos_seatbelt_rules: Vec<String>,
}

impl From<ProfileDeserialize> for Profile {
    fn from(raw: ProfileDeserialize) -> Self {
        Self {
            extends: raw.extends,
            meta: raw.meta,
            security: raw.security,
            filesystem: raw.filesystem,
            policy: raw.policy,
            network: raw.network,
            env_credentials: raw.env_credentials,
            environment: raw.environment,
            workdir: raw.workdir,
            hooks: raw.hooks,
            rollback: raw.rollback,
            open_urls: raw.open_urls,
            allow_launch_services: raw.allow_launch_services,
            allow_gpu: raw.allow_gpu,
            allow_parent_of_protected: raw.allow_parent_of_protected,
            interactive: raw.interactive,
            skipdirs: raw.skipdirs,
            packs: raw.packs,
            command_args: raw.command_args,
            unsafe_macos_seatbelt_rules: raw.unsafe_macos_seatbelt_rules,
        }
    }
}

impl<'de> Deserialize<'de> for Profile {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = ProfileDeserialize::deserialize(deserializer)?;
        Ok(raw.into())
    }
}

/// Check whether a profile name is loaded from a user file rather than the built-in set.
///
/// Returns `true` when a user profile file exists at `~/.config/nono/profiles/<name>.json`,
/// which means the user has overridden or shadowed any built-in profile of the same name.
pub fn is_user_override(name: &str) -> bool {
    if !is_valid_profile_name(name) {
        return false;
    }
    get_user_profile_path(name)
        .map(|p| p.exists())
        .unwrap_or(false)
}

/// Load a profile's raw (unresolved) extends target names.
///
/// Returns `Some(base_names)` if the profile declares `extends`, `None` otherwise.
/// This reads the raw profile definition before inheritance resolution clears the field.
pub fn load_profile_extends(name_or_path: &str) -> Option<Vec<String>> {
    // Direct file path
    if name_or_path.contains('/') || name_or_path.ends_with(".json") {
        return parse_profile_file(Path::new(name_or_path))
            .ok()
            .and_then(|p| p.extends);
    }

    if !is_valid_profile_name(name_or_path) {
        return None;
    }

    // User profile
    if let Ok(profile_path) = get_user_profile_path(name_or_path) {
        if profile_path.exists() {
            return parse_profile_file(&profile_path)
                .ok()
                .and_then(|p| p.extends);
        }
    }

    // Pack-store: any installed pack that declares a profile artifact with
    // matching `install_as`.
    if let Some(profile_path) = find_pack_store_profile(name_or_path) {
        return parse_profile_file(&profile_path)
            .ok()
            .and_then(|p| p.extends);
    }

    // Built-in profile
    if let Ok(policy) = crate::policy::load_embedded_policy() {
        if let Some(def) = policy.profiles.get(name_or_path) {
            return def.extends.as_ref().map(|s| vec![s.clone()]);
        }
    }

    None
}

/// Load a profile by name or file path
///
/// If `name_or_path` contains a path separator or ends with `.json`, it is
/// treated as a direct file path. Otherwise it is resolved as a profile name.
///
/// Name loading precedence:
/// 1. User profiles from `~/.config/nono/profiles/<name>.json` — never written
///    by nono. Users (and Claude's "Option B" guidance) own this directory.
/// 2. Pack-store scan — any installed pack with a profile artifact whose
///    `install_as` matches the requested name. Self-heals Claude Code plugin
///    wiring (symlink + `enabledPlugins`) on every successful resolution.
/// 3. Built-in profiles (compiled into binary).
/// 4. Auto-pull prompt for the registry pack `always-further/claude` when
///    the requested profile is `claude-code` (or inherits from it).
pub fn load_profile(name_or_path: &str) -> Result<Profile> {
    // Enable the chain-aware migration prompt for the duration of this
    // call: if `extends` resolution hits a pack-provided base that isn't
    // installed (e.g. user profile that `extends: ["claude-code"]`),
    // `load_base_profile_raw` will run `migration::check_and_run` rather
    // than failing with "base profile not found". The flag is restored
    // on exit so nested `load_profile_no_migrate` calls stay quiet.
    with_missing_base_prompt(true, || {
        if let Some(profile) = load_profile_inner(name_or_path)? {
            return Ok(profile);
        }

        // Top-level miss: ask whether to install the pack that provides
        // the requested name (or the chain it would inherit through).
        let outcome = crate::migration::check_and_run(name_or_path)?;
        match outcome {
            crate::migration::MigrationOutcome::Migrated => {
                // Pull completed AND the wiring interpreter ran during
                // install — no extra "wire" pass needed here. Just
                // re-resolve through the pack-store branch and load.
                if let Some(profile_path) = find_pack_store_profile(name_or_path) {
                    tracing::info!(
                        "Loading pack-store profile from: {}",
                        profile_path.display()
                    );
                    return finalize_profile(load_from_file(&profile_path)?);
                }
                Err(NonoError::ProfileNotFound(format!(
                    "{name_or_path}\n  the registry pack pulled but did not install \
                     the expected profile artifact"
                )))
            }
            crate::migration::MigrationOutcome::Skipped => {
                // The migration prompt has already printed a friendly
                // stderr hint (decline / non-TTY / NO_MIGRATE). Surface
                // the cancellation so main.rs exits cleanly without an
                // ERROR log line or duplicated "Profile not found"
                // framing — declining a prompt isn't a fault.
                Err(NonoError::Cancelled(format!(
                    "install of `{name_or_path}` declined"
                )))
            }
            crate::migration::MigrationOutcome::NotApplicable => {
                Err(NonoError::ProfileNotFound(name_or_path.to_string()))
            }
        }
    })
}

/// Same precedence as `load_profile` but never triggers the auto-pull
/// migration prompt — neither for the top-level miss nor for missing
/// `extends:` bases. Inspection commands (`profile show`, `profile diff`,
/// `profile validate`) use this so reading what's there never surprises
/// the user with a network operation.
pub fn load_profile_no_migrate(name_or_path: &str) -> Result<Profile> {
    with_missing_base_prompt(false, || {
        if let Some(profile) = load_profile_inner(name_or_path)? {
            return Ok(profile);
        }
        Err(NonoError::ProfileNotFound(name_or_path.to_string()))
    })
}

// Per-call flag that controls whether `load_base_profile_raw` may prompt
// the user (via `migration::check_and_run`) when an `extends:` base is
// missing AND the missing name maps to a registry pack. Thread-local so
// nested calls don't bleed flags into each other; `with_missing_base_prompt`
// always restores the previous value on exit.
thread_local! {
    static PROMPT_ON_MISSING_BASE: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

fn with_missing_base_prompt<R>(enable: bool, f: impl FnOnce() -> R) -> R {
    let prev = PROMPT_ON_MISSING_BASE.with(|c| c.replace(enable));
    let result = f();
    PROMPT_ON_MISSING_BASE.with(|c| c.set(prev));
    result
}

#[inline]
fn missing_base_prompt_enabled() -> bool {
    PROMPT_ON_MISSING_BASE.with(std::cell::Cell::get)
}

/// Steps 1–3 of profile resolution (user dir → pack store → built-in).
/// Returns `Ok(Some(profile))` on a hit, `Ok(None)` if all sources miss,
/// and `Err(_)` on validation/IO failures. Shared between `load_profile`
/// (which then runs the migration prompt) and `load_profile_no_migrate`
/// (which surfaces a not-found error directly).
fn load_profile_inner(name_or_path: &str) -> Result<Option<Profile>> {
    if is_registry_ref(name_or_path) {
        return load_registry_profile(name_or_path).map(Some);
    }
    if name_or_path.contains('/') || name_or_path.ends_with(".json") {
        return load_profile_from_path(Path::new(name_or_path)).map(Some);
    }
    if !is_valid_profile_name(name_or_path) {
        return Err(NonoError::ProfileParse(format!(
            "Invalid profile name '{}': must be alphanumeric with hyphens only",
            name_or_path
        )));
    }
    let profile_path = get_user_profile_path(name_or_path)?;
    if profile_path.exists() {
        tracing::info!("Loading user profile from: {}", profile_path.display());
        return finalize_profile(load_from_file(&profile_path)?).map(Some);
    }
    if let Some(profile_path) = find_pack_store_profile(name_or_path) {
        tracing::info!(
            "Loading pack-store profile from: {}",
            profile_path.display()
        );
        let profile = finalize_profile(load_from_file(&profile_path)?)?;
        // If we just resolved through `always-further/claude`, also offer
        // to strip pre-0.43 inbuilt-hook leftovers. Catches the path
        // where users `nono pull always-further/claude` directly,
        // bypassing the post-pull cleanup hook in `migration::check_and_run`.
        // Idempotent: silent no-op when no legacy artifacts exist, so safe
        // to fire on every claude resolution.
        if is_always_further_claude_pack(&profile_path) {
            crate::legacy_cleanup::check_and_offer_cleanup()?;
        }
        return Ok(Some(profile));
    }
    if let Some(profile) = builtin::get_builtin(name_or_path) {
        tracing::info!("Using built-in profile: {}", name_or_path);
        return Ok(Some(profile));
    }
    Ok(None)
}

/// True when `profile_path` lives inside `<package_store>/always-further/claude/`.
/// Used to gate legacy-cleanup invocation on the canonical claude pack
/// rather than any pack that happens to publish a profile named `claude`
/// or `claude-code`.
fn is_always_further_claude_pack(profile_path: &Path) -> bool {
    let Ok(store) = crate::package::package_store_dir() else {
        return false;
    };
    profile_path_is_in_pack(profile_path, &store, "always-further", "claude")
}

/// Pure path-component matcher: does `profile_path` live under
/// `<store>/<ns>/<name>/...`? Split out of `is_always_further_claude_pack`
/// so it can be tested without touching `XDG_CONFIG_HOME` / `HOME`.
fn profile_path_is_in_pack(profile_path: &Path, store: &Path, ns: &str, name: &str) -> bool {
    let Ok(rel) = profile_path.strip_prefix(store) else {
        return false;
    };
    let mut components = rel.components();
    matches!(
        (components.next(), components.next()),
        (
            Some(std::path::Component::Normal(got_ns)),
            Some(std::path::Component::Normal(got_name)),
        ) if got_ns == ns && got_name == name
    )
}

/// Scan installed packs for a profile artifact whose `install_as` matches
/// the requested name. Returns the path to the profile JSON inside the
/// package store, or `None` if no pack provides it. Multiple matches are
/// resolved by returning the first (alphabetical by `<namespace>/<name>`)
/// — collisions are rare and the resolver is best-effort; the operator
/// can pin via the user profile dir if needed.
pub(crate) fn find_pack_store_profile(name: &str) -> Option<PathBuf> {
    let store = crate::package::package_store_dir().ok()?;
    if !store.exists() {
        return None;
    }
    let mut matches: Vec<(String, PathBuf)> = Vec::new();
    let ns_entries = std::fs::read_dir(&store).ok()?;
    for ns_entry in ns_entries.flatten() {
        let ns_path = ns_entry.path();
        if !ns_path.is_dir() {
            continue;
        }
        let pack_entries = match std::fs::read_dir(&ns_path) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for pack_entry in pack_entries.flatten() {
            let pack_path = pack_entry.path();
            if !pack_path.is_dir() {
                continue;
            }
            let manifest_path = pack_path.join("package.json");
            if !manifest_path.exists() {
                continue;
            }
            let manifest_str = match std::fs::read_to_string(&manifest_path) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let manifest: crate::package::PackageManifest =
                match serde_json::from_str(&manifest_str) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
            for artifact in &manifest.artifacts {
                if artifact.artifact_type != crate::package::ArtifactType::Profile {
                    continue;
                }
                let install_as = match artifact.install_as.as_deref() {
                    Some(n) => n,
                    None => continue,
                };
                let matches_canonical = install_as == name;
                let matches_alias = artifact.aliases.iter().any(|a| a == name);
                if !matches_canonical && !matches_alias {
                    continue;
                }
                let profile_file = pack_path
                    .join("profiles")
                    .join(format!("{install_as}.json"));
                if profile_file.exists() {
                    let key = format!(
                        "{}/{}",
                        ns_entry.file_name().to_string_lossy(),
                        pack_entry.file_name().to_string_lossy()
                    );
                    matches.push((key, profile_file));
                }
            }
        }
    }
    matches.sort_by(|a, b| a.0.cmp(&b.0));
    matches.into_iter().next().map(|(_, p)| p)
}

/// Returns true if the string looks like a registry package reference
/// (`namespace/name` or `namespace/name@version`) rather than a filesystem path.
fn is_registry_ref(s: &str) -> bool {
    // Strip optional @version suffix for the path check
    let path_part = s.split_once('@').map_or(s, |(p, _)| p);
    let parts: Vec<&str> = path_part.split('/').collect();
    parts.len() == 2
        && !s.starts_with('.')
        && !s.starts_with('~')
        && !s.starts_with('/')
        && !s.ends_with(".json")
        && parts.iter().all(|p| !p.is_empty())
}

/// Load a profile from a registry pack. If the pack isn't installed locally,
/// pull it first (Docker-style auto-pull with Sigstore verification).
fn load_registry_profile(name_or_path: &str) -> Result<Profile> {
    let package_ref = crate::package::parse_package_ref(name_or_path)?;
    let install_dir =
        crate::package::package_install_dir(&package_ref.namespace, &package_ref.name)?;

    // Check if pack is already installed
    if !install_dir.join("package.json").exists() {
        eprintln!("Profile '{}' not found locally.", package_ref.key());

        // Auto-pull from registry
        crate::package_cmd::run_pull(crate::cli::PullArgs {
            package_ref: name_or_path.to_string(),
            registry: None,
            force: false,
            init: false,
            help: None,
        })?;
    }

    // Read manifest to check pack type and find profile artifacts
    let manifest_path = install_dir.join("package.json");
    if !manifest_path.exists() {
        return Err(NonoError::ProfileNotFound(format!(
            "pack '{}' failed to install",
            package_ref.key()
        )));
    }

    let manifest_json = std::fs::read_to_string(&manifest_path).map_err(NonoError::Io)?;
    let manifest: crate::package::PackageManifest =
        serde_json::from_str(&manifest_json).map_err(|e| {
            NonoError::ProfileParse(format!(
                "invalid package.json in '{}': {e}",
                package_ref.key()
            ))
        })?;

    if !manifest.has_profile_artifact() {
        return Err(NonoError::ProfileParse(format!(
            "pack '{}' has no profile artifact and cannot be used with --profile.\n\
             Use 'nono pull {}' to install it instead.",
            package_ref.key(),
            package_ref.key()
        )));
    }

    // Find the profile JSON in the installed pack
    for artifact in &manifest.artifacts {
        if artifact.artifact_type == crate::package::ArtifactType::Profile {
            let install_name = artifact.install_as.as_deref().unwrap_or(&artifact.path);
            let profile_path = install_dir
                .join("profiles")
                .join(format!("{install_name}.json"));
            if profile_path.exists() {
                tracing::info!("Loading registry profile from: {}", profile_path.display());
                return finalize_profile(load_from_file(&profile_path)?);
            }
        }
    }

    Err(NonoError::ProfileParse(format!(
        "no profile found in pack '{}'",
        package_ref.key()
    )))
}

/// Load a profile from a direct file path.
///
/// The path must exist and point to a valid JSON profile file.
/// Base groups are merged automatically.
pub fn load_profile_from_path(path: &Path) -> Result<Profile> {
    if !path.exists() {
        return Err(NonoError::ProfileRead {
            path: path.to_path_buf(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "profile file not found"),
        });
    }

    tracing::info!("Loading profile from path: {}", path.display());
    finalize_profile(load_from_file(path)?)
}

/// Load a raw profile from a direct file path without resolving inheritance.
pub(crate) fn load_raw_profile_from_path(path: &Path) -> Result<Profile> {
    if !path.exists() {
        return Err(NonoError::ProfileRead {
            path: path.to_path_buf(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "profile file not found"),
        });
    }

    tracing::info!("Loading raw profile from path: {}", path.display());
    parse_profile_file(path)
}

/// Resolve inheritance and apply implicit default-group merging for a raw profile.
pub(crate) fn finalize_profile(mut profile: Profile) -> Result<Profile> {
    merge_implicit_default_groups(&mut profile)?;
    Ok(profile)
}

/// Resolve inheritance and apply implicit default-group merging for a raw profile.
pub(crate) fn resolve_and_finalize_profile(profile: Profile) -> Result<Profile> {
    finalize_profile(resolve_extends(profile, &mut Vec::new(), 0)?)
}

/// Get the implicit default groups for a finalized profile.
///
/// The built-in `default` profile is now the canonical source of implicit
/// groups. The `default` profile itself does not inherit any additional groups.
fn implicit_default_groups(profile: &Profile) -> Result<Vec<String>> {
    if profile.meta.name == "default" {
        return Ok(Vec::new());
    }

    let default = crate::policy::get_policy_profile("default")?
        .ok_or_else(|| NonoError::ProfileNotFound("default".to_string()))?;
    Ok(default.security.groups)
}

/// Merge the implicit default profile groups into a finalized profile.
///
/// User profiles loaded from file only declare their own groups in
/// `security.groups`. Built-in profiles also resolve through the same raw
/// profile pipeline before implicit default groups are merged.
/// This function applies:
/// `((implicit_default_groups + profile.groups) - profile.policy.exclude_groups)`.
///
/// This means exclusions win even if the same group is also added explicitly in
/// `security.groups`.
fn merge_implicit_default_groups(profile: &mut Profile) -> Result<()> {
    let policy = crate::policy::load_embedded_policy()?;
    let exclusions = &profile.policy.exclude_groups;
    crate::policy::validate_group_exclusions(&policy, exclusions)?;

    let mut merged = implicit_default_groups(profile)?;
    // Append profile-specific groups (avoiding duplicates)
    let mut seen: std::collections::HashSet<String> = merged.iter().cloned().collect();
    for g in &profile.security.groups {
        if seen.insert(g.clone()) {
            merged.push(g.clone());
        }
    }
    if !exclusions.is_empty() {
        let exclude_set: std::collections::HashSet<&String> = exclusions.iter().collect();
        merged.retain(|g| !exclude_set.contains(g));
    }
    profile.security.groups = merged;
    Ok(())
}

/// Parse a profile JSON file without resolving inheritance.
///
/// Returns the raw deserialized `Profile` with `extends` still set.
/// Used during inheritance resolution to load base profiles without
/// triggering infinite recursion.
fn parse_profile_file(path: &Path) -> Result<Profile> {
    let content = fs::read_to_string(path).map_err(|e| NonoError::ProfileRead {
        path: path.to_path_buf(),
        source: e,
    })?;

    let profile: Profile =
        serde_json::from_str(&content).map_err(|e| NonoError::ProfileParse(e.to_string()))?;

    // Validate custom credentials for security issues
    validate_profile_custom_credentials(&profile)?;

    // Validate env_credentials keys (URI entries need structural validation)
    validate_env_credential_keys(&profile)?;

    Ok(profile)
}

/// Load a profile from a JSON file, resolving inheritance.
fn load_from_file(path: &Path) -> Result<Profile> {
    let profile = parse_profile_file(path)?;
    resolve_extends(profile, &mut Vec::new(), 0)
}

// ============================================================================
// Profile inheritance (extends)
// ============================================================================

/// Maximum depth for profile inheritance chains.
const MAX_INHERITANCE_DEPTH: usize = 10;

/// Resolve the `extends` chain for a profile.
///
/// If the profile declares `extends` (one or more base names), each base is
/// loaded and resolved recursively, then they are fold-merged left-to-right.
/// The accumulated base is finally merged with the child. The `visited` vec
/// tracks profile names already in the chain to detect circular dependencies.
///
/// Shared transitive bases are handled naturally: `visited` tracks only the
/// current ancestor chain (push before recurse, pop after). When two siblings
/// share a transitive base, it is resolved once per sibling; because
/// `merge_profiles` is idempotent, the result is correct. Only true cycles
/// (a profile extending one of its own ancestors) are rejected.
fn resolve_extends(child: Profile, visited: &mut Vec<String>, depth: usize) -> Result<Profile> {
    let base_names = match child.extends {
        Some(ref names) => names.clone(),
        None => return Ok(child),
    };

    if depth >= MAX_INHERITANCE_DEPTH {
        return Err(NonoError::ProfileInheritance(format!(
            "inheritance chain too deep (max {}): {}",
            MAX_INHERITANCE_DEPTH,
            visited.join(" -> ")
        )));
    }

    // Resolve each base and fold-merge them left-to-right
    let mut accumulated_base: Option<Profile> = None;
    for base_name in &base_names {
        if visited.contains(base_name) {
            return Err(NonoError::ProfileInheritance(format!(
                "circular dependency detected: {} -> {}",
                visited.join(" -> "),
                base_name
            )));
        }

        visited.push(base_name.clone());

        let base = load_base_profile_raw(base_name)?;
        let resolved_base = resolve_extends(base, visited, depth + 1)?;
        // Pop to restore the stack to the pre-base state. On the error path
        // above (? propagation), visited is abandoned so the missing pop is harmless.
        visited.pop();

        accumulated_base = Some(match accumulated_base {
            Some(acc) => merge_profiles(acc, resolved_base),
            None => resolved_base,
        });
    }

    match accumulated_base {
        Some(base) => Ok(merge_profiles(base, child)),
        None => Ok(child),
    }
}

/// Load a base profile by name WITHOUT applying implicit default-group merging.
///
/// Checks user profiles, then installed packs, then built-in profiles.
/// Built-in profiles are loaded as raw profile definitions so inheritance
/// can resolve before implicit default groups are merged. The pack-store
/// branch lets a user profile do `"extends": "claude-code"` and pick up
/// the pack-shipped profile transparently — same precedence as
/// `load_profile`.
///
/// If all three resolvers miss AND the requested name is in
/// `migration::PACK_PROVIDED_PROFILES` AND we were entered via
/// `load_profile` (not `load_profile_no_migrate`), prompt the user to
/// install the providing pack, then retry the pack-store lookup once.
/// This handles the v0.42 → v0.43 upgrade case where a user profile
/// `extends: ["claude-code"]` and the inbuilt `claude-code` is gone:
/// instead of an inscrutable "base profile not found" error, the user
/// sees the same install prompt that `--profile claude-code` would
/// produce, with the chain still resolving cleanly on accept.
fn load_base_profile_raw(name: &str) -> Result<Profile> {
    if !is_valid_profile_name(name) {
        return Err(NonoError::ProfileInheritance(format!(
            "invalid base profile name '{}'",
            name
        )));
    }

    // 1. User profiles take precedence.
    let profile_path = get_user_profile_path(name)?;
    if profile_path.exists() {
        return parse_profile_file(&profile_path);
    }

    // 2. Pack-store: any installed pack with a matching `install_as`.
    if let Some(profile_path) = find_pack_store_profile(name) {
        return parse_profile_file(&profile_path);
    }

    // 3. Built-in profile from embedded policy.
    let policy = crate::policy::load_embedded_policy()?;
    if let Some(def) = policy.profiles.get(name) {
        return Ok(def.to_raw_profile());
    }

    // 4. Pack-provided rescue: when we were entered through
    //    `load_profile` (the explicit usage path) AND the missing
    //    base name has at least one pack provider in the registry,
    //    prompt to install. Inspection commands flow through
    //    `load_profile_no_migrate`, which leaves the prompt flag off
    //    so this branch stays dormant for them.
    //
    //    The lookup is registry-side — no in-tree table of "name →
    //    pack". `migration::check_and_run` returns NotApplicable
    //    when the registry returns no providers (or is unreachable).
    if missing_base_prompt_enabled() {
        let outcome = crate::migration::check_and_run(name)?;
        match outcome {
            crate::migration::MigrationOutcome::Migrated => {
                if let Some(profile_path) = find_pack_store_profile(name) {
                    return parse_profile_file(&profile_path);
                }
            }
            crate::migration::MigrationOutcome::Skipped => {
                // Hint already printed by `check_and_run`. Surface a
                // cancellation so main.rs exits cleanly without re-
                // logging this as a fatal "inheritance error".
                return Err(NonoError::Cancelled(format!(
                    "install of `{name}` declined"
                )));
            }
            crate::migration::MigrationOutcome::NotApplicable => {}
        }
    }

    Err(NonoError::ProfileInheritance(format!(
        "base profile '{}' not found",
        name
    )))
}

/// Merge a resolved base profile with a child profile.
///
/// The child's values take precedence for scalar fields. Collection fields
/// are appended and deduplicated. The `extends` field is consumed (set to `None`).
fn merge_profiles(base: Profile, child: Profile) -> Profile {
    Profile {
        extends: None,
        meta: child.meta,
        security: SecurityConfig {
            groups: dedup_append(&base.security.groups, &child.security.groups),
            allowed_commands: dedup_append(
                &base.security.allowed_commands,
                &child.security.allowed_commands,
            ),
            signal_mode: child.security.signal_mode.or(base.security.signal_mode),
            process_info_mode: child
                .security
                .process_info_mode
                .or(base.security.process_info_mode),
            ipc_mode: child.security.ipc_mode.or(base.security.ipc_mode),
            capability_elevation: child
                .security
                .capability_elevation
                .or(base.security.capability_elevation),
            wsl2_proxy_policy: child
                .security
                .wsl2_proxy_policy
                .or(base.security.wsl2_proxy_policy),
        },
        filesystem: FilesystemConfig {
            allow: dedup_append(&base.filesystem.allow, &child.filesystem.allow),
            read: dedup_append(&base.filesystem.read, &child.filesystem.read),
            write: dedup_append(&base.filesystem.write, &child.filesystem.write),
            allow_file: dedup_append(&base.filesystem.allow_file, &child.filesystem.allow_file),
            read_file: dedup_append(&base.filesystem.read_file, &child.filesystem.read_file),
            write_file: dedup_append(&base.filesystem.write_file, &child.filesystem.write_file),
            unix_socket: dedup_append(&base.filesystem.unix_socket, &child.filesystem.unix_socket),
            unix_socket_bind: dedup_append(
                &base.filesystem.unix_socket_bind,
                &child.filesystem.unix_socket_bind,
            ),
            unix_socket_dir: dedup_append(
                &base.filesystem.unix_socket_dir,
                &child.filesystem.unix_socket_dir,
            ),
            unix_socket_dir_bind: dedup_append(
                &base.filesystem.unix_socket_dir_bind,
                &child.filesystem.unix_socket_dir_bind,
            ),
        },
        policy: PolicyPatchConfig {
            exclude_groups: dedup_append(&base.policy.exclude_groups, &child.policy.exclude_groups),
            add_allow_read: dedup_append(&base.policy.add_allow_read, &child.policy.add_allow_read),
            add_allow_write: dedup_append(
                &base.policy.add_allow_write,
                &child.policy.add_allow_write,
            ),
            add_allow_readwrite: dedup_append(
                &base.policy.add_allow_readwrite,
                &child.policy.add_allow_readwrite,
            ),
            add_deny_access: dedup_append(
                &base.policy.add_deny_access,
                &child.policy.add_deny_access,
            ),
            add_deny_commands: dedup_append(
                &base.policy.add_deny_commands,
                &child.policy.add_deny_commands,
            ),
            override_deny: dedup_append(&base.policy.override_deny, &child.policy.override_deny),
        },
        network: NetworkConfig {
            block: base.network.block || child.network.block,
            network_profile: child
                .network
                .network_profile
                .merge(base.network.network_profile),
            allow_domain: dedup_append(&base.network.allow_domain, &child.network.allow_domain),
            open_port: dedup_append(&base.network.open_port, &child.network.open_port),
            listen_port: dedup_append(&base.network.listen_port, &child.network.listen_port),
            connect_port: dedup_append(&base.network.connect_port, &child.network.connect_port),
            // Child `Some([])` overrides parent credentials to empty (disables proxy).
            // Child `None` inherits parent credentials. Child `Some([...])` merges with parent.
            credentials: match child.network.credentials {
                Some(ref child_creds) => {
                    if child_creds.is_empty() {
                        // Explicitly empty — override parent, disable inherited credentials
                        Some(Vec::new())
                    } else {
                        // Child has credentials — merge with parent
                        Some(dedup_append(
                            base.network.credentials.as_deref().unwrap_or(&[]),
                            child_creds,
                        ))
                    }
                }
                None => base.network.credentials,
            },
            custom_credentials: {
                let mut merged = base.network.custom_credentials;
                merged.extend(child.network.custom_credentials);
                merged
            },
            // Child overrides base upstream proxy; if child has None, inherit base
            upstream_proxy: child.network.upstream_proxy.or(base.network.upstream_proxy),
            upstream_bypass: dedup_append(
                &base.network.upstream_bypass,
                &child.network.upstream_bypass,
            ),
        },
        env_credentials: SecretsConfig {
            mappings: {
                let mut merged = base.env_credentials.mappings;
                merged.extend(child.env_credentials.mappings);
                merged
            },
        },
        environment: match (&base.environment, &child.environment) {
            (None, None) => None,
            (Some(base_env), None) => Some(base_env.clone()),
            (None, Some(child_env)) => Some(child_env.clone()),
            (Some(base_env), Some(child_env)) => Some(EnvironmentConfig {
                allow_vars: dedup_append(&base_env.allow_vars, &child_env.allow_vars),
            }),
        },
        // NOTE: WorkdirAccess::None serves as both "not specified" and "explicitly no access".
        // A child cannot override a base's workdir grant to None. This is a v1 limitation;
        // fixing it requires wrapping in Option<WorkdirAccess> and updating all consumers.
        workdir: if child.workdir.access != WorkdirAccess::None {
            child.workdir
        } else {
            base.workdir
        },
        hooks: HooksConfig {
            hooks: {
                let mut merged = base.hooks.hooks;
                merged.extend(child.hooks.hooks);
                merged
            },
        },
        rollback: RollbackConfig {
            exclude_patterns: dedup_append(
                &base.rollback.exclude_patterns,
                &child.rollback.exclude_patterns,
            ),
            exclude_globs: dedup_append(
                &base.rollback.exclude_globs,
                &child.rollback.exclude_globs,
            ),
        },
        open_urls: match child.open_urls {
            Some(child_urls) => Some(child_urls),
            None => base.open_urls,
        },
        allow_launch_services: child.allow_launch_services.or(base.allow_launch_services),
        allow_gpu: child.allow_gpu.or(base.allow_gpu),
        allow_parent_of_protected: child
            .allow_parent_of_protected
            .or(base.allow_parent_of_protected),
        interactive: base.interactive || child.interactive,
        skipdirs: dedup_append(&base.skipdirs, &child.skipdirs),
        packs: dedup_append(&base.packs, &child.packs),
        command_args: dedup_append(&base.command_args, &child.command_args),
        unsafe_macos_seatbelt_rules: dedup_append(
            &base.unsafe_macos_seatbelt_rules,
            &child.unsafe_macos_seatbelt_rules,
        ),
    }
}

/// Append child items after base items, deduplicating while preserving order.
pub(crate) fn dedup_append<T: Eq + std::hash::Hash + Clone>(base: &[T], child: &[T]) -> Vec<T> {
    let mut seen = std::collections::HashSet::with_capacity(base.len() + child.len());
    let mut result = Vec::with_capacity(base.len() + child.len());
    for item in base.iter().chain(child.iter()) {
        if seen.insert(item) {
            result.push(item.clone());
        }
    }
    result
}

/// Get the path to a user profile
pub(crate) fn get_user_profile_path(name: &str) -> Result<PathBuf> {
    let config_dir = resolve_user_config_dir()?;

    Ok(config_dir
        .join("nono")
        .join("profiles")
        .join(format!("{}.json", name)))
}

/// Resolve the user config directory with secure validation.
///
/// Security behavior:
/// - If `XDG_CONFIG_HOME` is set, it must be absolute.
/// - If absolute, we canonicalize it to avoid path confusion through symlinks.
/// - If invalid (relative or cannot be canonicalized), we fall back to `$HOME/.config`.
pub(crate) fn resolve_user_config_dir() -> Result<PathBuf> {
    if let Ok(raw) = std::env::var("XDG_CONFIG_HOME") {
        let path = PathBuf::from(&raw);
        if path.is_absolute() {
            match path.canonicalize() {
                Ok(canonical) => return Ok(canonical),
                Err(e) => {
                    tracing::warn!(
                        "Ignoring invalid XDG_CONFIG_HOME='{}' (canonicalize failed: {}), falling back to $HOME/.config",
                        raw,
                        e
                    );
                }
            }
        } else {
            tracing::warn!(
                "Ignoring invalid XDG_CONFIG_HOME='{}' (must be absolute), falling back to $HOME/.config",
                raw
            );
        }
    }

    // Fallback: use HOME/.config. Canonicalize HOME when possible, but do not
    // fail hard if HOME currently points to a non-existent path.
    let home = home_dir()?;
    let home_base = match home.canonicalize() {
        Ok(canonical) => canonical,
        Err(e) => {
            tracing::warn!(
                "Failed to canonicalize HOME='{}' ({}), using raw HOME path for fallback",
                home.display(),
                e
            );
            home
        }
    };
    Ok(home_base.join(".config"))
}

/// Get home directory path using xdg-home
fn home_dir() -> Result<PathBuf> {
    xdg_home::home_dir().ok_or(NonoError::HomeNotFound)
}

/// Validate profile name (alphanumeric + hyphen only, no path traversal)
pub(crate) fn is_valid_profile_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && !name.starts_with('-')
        && !name.ends_with('-')
}

/// Expand environment variables in a path string
///
/// Supported variables:
/// - $WORKDIR: Working directory (--workdir or cwd)
/// - $HOME: User's home directory
/// - $XDG_CONFIG_HOME: XDG config directory
/// - $XDG_DATA_HOME: XDG data directory
/// - $XDG_STATE_HOME: XDG state directory
/// - $XDG_CACHE_HOME: XDG cache directory
/// - $XDG_RUNTIME_DIR: XDG runtime directory (no default; left unexpanded when unset)
/// - $TMPDIR: System temporary directory
/// - $UID: Current user ID
///
/// If $HOME cannot be determined and the path uses $HOME or XDG variables,
/// the unexpanded variable is left in place (which will cause the path to not exist).
pub fn expand_vars(path: &str, workdir: &Path) -> Result<PathBuf> {
    use crate::config;

    let home = config::validated_home()?;

    // Expand ~/... to $HOME/... before other substitutions
    let path = if let Some(rest) = path.strip_prefix("~/") {
        format!("{}/{}", home, rest)
    } else if path == "~" {
        home.clone()
    } else {
        path.to_string()
    };

    let expanded = path.replace("$WORKDIR", &workdir.to_string_lossy());

    // Expand $TMPDIR and $UID
    let tmpdir = config::validated_tmpdir()?;
    let uid = nix::unistd::getuid().to_string();
    let expanded = expanded
        .replace("$TMPDIR", tmpdir.trim_end_matches('/'))
        .replace("$UID", &uid);

    let xdg_config = std::env::var("XDG_CONFIG_HOME")
        .unwrap_or_else(|_| format!("{}", PathBuf::from(&home).join(".config").display()));
    let xdg_data = std::env::var("XDG_DATA_HOME").unwrap_or_else(|_| {
        format!(
            "{}",
            PathBuf::from(&home).join(".local").join("share").display()
        )
    });
    let xdg_state = std::env::var("XDG_STATE_HOME").unwrap_or_else(|_| {
        format!(
            "{}",
            PathBuf::from(&home).join(".local").join("state").display()
        )
    });
    let xdg_cache = std::env::var("XDG_CACHE_HOME")
        .unwrap_or_else(|_| format!("{}", PathBuf::from(&home).join(".cache").display()));

    // $XDG_RUNTIME_DIR has no default per the XDG Base Directory spec.
    // When unset, leave the variable unexpanded so the path won't resolve.
    let xdg_runtime = std::env::var("XDG_RUNTIME_DIR").ok();

    // Validate XDG paths are absolute
    let mut xdg_vars: Vec<(&str, &str)> = vec![
        ("XDG_CONFIG_HOME", &xdg_config),
        ("XDG_DATA_HOME", &xdg_data),
        ("XDG_STATE_HOME", &xdg_state),
        ("XDG_CACHE_HOME", &xdg_cache),
    ];
    if let Some(ref rt) = xdg_runtime {
        xdg_vars.push(("XDG_RUNTIME_DIR", rt));
    }
    for (var, val) in &xdg_vars {
        if !Path::new(val).is_absolute() {
            return Err(NonoError::EnvVarValidation {
                var: var.to_string(),
                reason: format!("must be an absolute path, got: {}", val),
            });
        }
    }

    let mut expanded = expanded
        .replace("$HOME", &home)
        .replace("$XDG_CONFIG_HOME", &xdg_config)
        .replace("$XDG_STATE_HOME", &xdg_state)
        .replace("$XDG_CACHE_HOME", &xdg_cache)
        .replace("$XDG_DATA_HOME", &xdg_data);

    // Only expand $XDG_RUNTIME_DIR when set; leave literal otherwise
    if let Some(ref rt) = xdg_runtime {
        expanded = expanded.replace("$XDG_RUNTIME_DIR", rt);
    }

    // Expand $NONO_PACKAGES to the package store directory
    if expanded.contains("$NONO_PACKAGES") {
        let packages_dir = crate::package::package_store_dir()?;
        expanded = expanded.replace("$NONO_PACKAGES", &packages_dir.to_string_lossy());
    }

    Ok(PathBuf::from(expanded))
}

/// List available profiles (built-in + user)
pub fn list_profiles() -> Vec<String> {
    let mut profiles = builtin::list_builtin();

    // Add user profiles (if home directory is available)
    if let Ok(profile_path) = get_user_profile_path("") {
        if let Some(dir) = profile_path.parent() {
            if dir.exists() {
                if let Ok(entries) = fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        if let Some(name) = entry.path().file_stem() {
                            let name_str = name.to_string_lossy().to_string();
                            if !profiles.contains(&name_str) {
                                profiles.push(name_str);
                            }
                        }
                    }
                }
            }
        }
    }

    // Add pack-store profiles — names exposed by installed packs via
    // `install_as`. Without this, `--profile claude-code` works (the
    // resolver finds it) but `nono profile list` doesn't surface it,
    // confusing users who expect a one-stop catalogue.
    for (name, _pack_ref) in list_pack_store_profiles() {
        if !profiles.contains(&name) {
            profiles.push(name);
        }
    }

    profiles.sort();
    profiles
}

/// Scan the package store for every profile artifact, returning
/// `(install_as_name, "<namespace>/<pack>")` pairs. Stable ordering by
/// pack ref so callers get a deterministic catalogue.
#[must_use]
pub fn list_pack_store_profiles() -> Vec<(String, String)> {
    let store = match crate::package::package_store_dir() {
        Ok(s) if s.exists() => s,
        _ => return Vec::new(),
    };
    let mut out: Vec<(String, String)> = Vec::new();
    let Ok(ns_entries) = fs::read_dir(&store) else {
        return out;
    };
    for ns_entry in ns_entries.flatten() {
        let ns_path = ns_entry.path();
        if !ns_path.is_dir() {
            continue;
        }
        let Ok(pack_entries) = fs::read_dir(&ns_path) else {
            continue;
        };
        for pack_entry in pack_entries.flatten() {
            let pack_path = pack_entry.path();
            if !pack_path.is_dir() {
                continue;
            }
            let manifest_path = pack_path.join("package.json");
            if !manifest_path.exists() {
                continue;
            }
            let Ok(manifest_str) = fs::read_to_string(&manifest_path) else {
                continue;
            };
            let Ok(manifest): std::result::Result<crate::package::PackageManifest, _> =
                serde_json::from_str(&manifest_str)
            else {
                continue;
            };
            let pack_ref = format!(
                "{}/{}",
                ns_entry.file_name().to_string_lossy(),
                pack_entry.file_name().to_string_lossy()
            );
            for artifact in &manifest.artifacts {
                if artifact.artifact_type != crate::package::ArtifactType::Profile {
                    continue;
                }
                if let Some(name) = artifact.install_as.as_deref() {
                    let install_path = pack_path.join("profiles").join(format!("{name}.json"));
                    if install_path.exists() {
                        out.push((name.to_string(), pack_ref.clone()));
                        for alias in &artifact.aliases {
                            out.push((alias.clone(), pack_ref.clone()));
                        }
                    }
                }
            }
        }
    }
    out.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn profile_path_is_in_pack_matches_canonical_layout() {
        let store = Path::new("/store");
        let claude_profile = Path::new("/store/always-further/claude/profile/claude.json");
        assert!(profile_path_is_in_pack(
            claude_profile,
            store,
            "always-further",
            "claude"
        ));

        // Different namespace must not match — guards against a third-
        // party pack that publishes a `claude` profile triggering
        // legacy cleanup.
        let third_party = Path::new("/store/some-other/claude/profile/claude.json");
        assert!(!profile_path_is_in_pack(
            third_party,
            store,
            "always-further",
            "claude"
        ));

        // Different pack name in the same namespace must not match.
        let codex = Path::new("/store/always-further/codex/profile/codex.json");
        assert!(!profile_path_is_in_pack(
            codex,
            store,
            "always-further",
            "claude"
        ));

        // Path outside the store entirely must not match.
        let outside = Path::new("/elsewhere/always-further/claude/profile.json");
        assert!(!profile_path_is_in_pack(
            outside,
            store,
            "always-further",
            "claude"
        ));
    }

    #[test]
    fn test_valid_profile_names() {
        assert!(is_valid_profile_name("claude-code"));
        assert!(is_valid_profile_name("openclaw"));
        assert!(is_valid_profile_name("my-app-2"));
        assert!(!is_valid_profile_name(""));
        assert!(!is_valid_profile_name("-invalid"));
        assert!(!is_valid_profile_name("invalid-"));
        assert!(!is_valid_profile_name("../escape"));
        assert!(!is_valid_profile_name("path/traversal"));
    }

    #[test]
    fn test_expand_vars() {
        let _guard = match crate::test_env::ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let _env = crate::test_env::EnvVarGuard::set_all(&[("HOME", "/home/user")]);

        let workdir = PathBuf::from("/projects/myapp");

        let expanded = expand_vars("$WORKDIR/src", &workdir).expect("valid env");
        assert_eq!(expanded, PathBuf::from("/projects/myapp/src"));

        let expanded = expand_vars("$HOME/.config", &workdir).expect("valid env");
        assert_eq!(expanded, PathBuf::from("/home/user/.config"));
    }

    #[test]
    fn test_expand_vars_xdg_state_home() {
        let _guard = match crate::test_env::ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        // $XDG_STATE_HOME must be expanded so that profiles and deny rules
        // can reference it portably. Without this, users cannot write
        // add_deny_access: ["$XDG_STATE_HOME"] and the variable is treated
        // as a literal string that matches nothing.
        let _env = crate::test_env::EnvVarGuard::set_all(&[
            ("HOME", "/home/user"),
            ("XDG_STATE_HOME", "/custom/state"),
        ]);

        let workdir = PathBuf::from("/projects/myapp");
        let expanded = expand_vars("$XDG_STATE_HOME/history", &workdir).expect("valid env");
        assert_eq!(expanded, PathBuf::from("/custom/state/history"));

        // Fallback when env var is unset
        _env.remove("XDG_STATE_HOME");
        let expanded = expand_vars("$XDG_STATE_HOME/history", &workdir).expect("valid env");
        assert_eq!(expanded, PathBuf::from("/home/user/.local/state/history"));
    }

    #[test]
    fn test_expand_vars_xdg_cache_home() {
        let _guard = match crate::test_env::ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let _env = crate::test_env::EnvVarGuard::set_all(&[
            ("HOME", "/home/user"),
            ("XDG_CACHE_HOME", "/custom/cache"),
        ]);

        let workdir = PathBuf::from("/projects/myapp");
        let expanded = expand_vars("$XDG_CACHE_HOME/pip", &workdir).expect("valid env");
        assert_eq!(expanded, PathBuf::from("/custom/cache/pip"));

        // Fallback when env var is unset
        _env.remove("XDG_CACHE_HOME");
        let expanded = expand_vars("$XDG_CACHE_HOME/pip", &workdir).expect("valid env");
        assert_eq!(expanded, PathBuf::from("/home/user/.cache/pip"));
    }

    #[test]
    fn test_expand_vars_xdg_runtime_dir() {
        let _guard = match crate::test_env::ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let _env = crate::test_env::EnvVarGuard::set_all(&[("XDG_RUNTIME_DIR", "/run/user/1000")]);

        let workdir = PathBuf::from("/projects/myapp");
        let expanded = expand_vars("$XDG_RUNTIME_DIR/pulse", &workdir).expect("valid env");
        assert_eq!(expanded, PathBuf::from("/run/user/1000/pulse"));

        // When unset, $XDG_RUNTIME_DIR has no default per the spec — the
        // variable should be left unexpanded so the path won't resolve.
        _env.remove("XDG_RUNTIME_DIR");
        let expanded = expand_vars("$XDG_RUNTIME_DIR/pulse", &workdir).expect("valid env");
        assert_eq!(
            expanded,
            PathBuf::from("$XDG_RUNTIME_DIR/pulse"),
            "unset XDG_RUNTIME_DIR should leave variable unexpanded"
        );
    }

    #[test]
    fn test_resolve_user_config_dir_uses_valid_absolute_xdg() {
        let _guard = match crate::test_env::ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let tmp = tempdir().expect("tmpdir");
        let _env = crate::test_env::EnvVarGuard::set_all(&[(
            "XDG_CONFIG_HOME",
            tmp.path().to_str().expect("tmp path"),
        )]);
        let resolved = resolve_user_config_dir().expect("resolve user config dir");
        assert_eq!(
            resolved,
            tmp.path().canonicalize().expect("canonicalize tmp")
        );
    }

    #[test]
    fn test_resolve_user_config_dir_falls_back_on_relative_xdg() {
        let _guard = match crate::test_env::ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let expected_home = home_dir().expect("home dir");
        let _env = crate::test_env::EnvVarGuard::set_all(&[("XDG_CONFIG_HOME", "relative/path")]);

        let resolved = resolve_user_config_dir().expect("resolve with fallback");
        assert_eq!(resolved, expected_home.join(".config"));
    }

    #[test]
    fn test_load_builtin_profile() {
        let profile = load_profile("opencode").expect("Failed to load profile");
        assert_eq!(profile.meta.name, "opencode");
        assert!(!profile.network.block); // network allowed by default
    }

    #[test]
    fn test_load_nonexistent_profile() {
        let result = load_profile("nonexistent-profile-12345");
        assert!(matches!(result, Err(NonoError::ProfileNotFound(_))));
    }

    #[test]
    fn test_load_profile_from_file_path() {
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("custom.json");
        std::fs::write(
            &profile_path,
            r#"{
                "meta": { "name": "custom-test" },
                "security": { "groups": ["node_runtime"] },
                "network": { "block": true }
            }"#,
        )
        .expect("write profile");

        let profile =
            load_profile(profile_path.to_str().expect("valid utf8")).expect("load from path");
        assert_eq!(profile.meta.name, "custom-test");
        assert!(profile.network.block);
        // implicit default profile groups should be merged in
        assert!(profile
            .security
            .groups
            .contains(&"deny_credentials".to_string()));
        assert!(profile
            .security
            .groups
            .contains(&"node_runtime".to_string()));
    }

    #[test]
    fn test_load_profile_from_nonexistent_path() {
        let result = load_profile("/tmp/does-not-exist-nono-test.json");
        assert!(result.is_err());
    }

    #[test]
    fn test_list_profiles() {
        let profiles = list_profiles();
        assert!(profiles.contains(&"opencode".to_string()));
        // Profiles removed from built-ins; now ship via registry packs:
        //   claude-code → always-further/claude   (removed v0.43.0)
        //   codex       → always-further/codex    (removed v0.43.0)
        //   openclaw    → always-further/openclaw (removed v0.44.0)
        assert!(!profiles.contains(&"claude-code".to_string()));
        assert!(!profiles.contains(&"codex".to_string()));
        assert!(!profiles.contains(&"openclaw".to_string()));
    }

    #[test]
    fn test_env_credentials_config_parsing() {
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "env_credentials": {
                "openai_api_key": "OPENAI_API_KEY",
                "anthropic_api_key": "ANTHROPIC_API_KEY"
            }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        assert_eq!(profile.env_credentials.mappings.len(), 2);
        assert_eq!(
            profile.env_credentials.mappings.get("openai_api_key"),
            Some(&"OPENAI_API_KEY".to_string())
        );
        assert_eq!(
            profile.env_credentials.mappings.get("anthropic_api_key"),
            Some(&"ANTHROPIC_API_KEY".to_string())
        );
    }

    #[test]
    fn test_environment_config_default() {
        let json_str = r#"{
            "meta": { "name": "test-profile" }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        assert!(profile.environment.is_none());
    }

    #[test]
    fn test_environment_config_with_allow_vars() {
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "environment": {
                "allow_vars": ["PATH", "HOME", "AWS_*"]
            }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        assert_eq!(
            profile
                .environment
                .as_ref()
                .expect("environment")
                .allow_vars,
            vec!["PATH", "HOME", "AWS_*"]
        );
    }

    #[test]
    fn test_environment_config_deny_unknown_fields() {
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "environment": {
                "allow_vars": ["PATH"],
                "unknown_field": true
            }
        }"#;

        let result = serde_json::from_str::<Profile>(json_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_environment_config_empty_allow_vars() {
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "environment": {
                "allow_vars": []
            }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        let env_config = profile
            .environment
            .as_ref()
            .expect("environment should be Some");
        assert!(env_config.allow_vars.is_empty());
    }

    #[test]
    fn test_validate_env_credentials_accepts_apple_password_uri() {
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "env_credentials": {
                "apple-password://github.com/alice@example.com": "GITHUB_PASSWORD"
            }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        assert!(validate_env_credential_keys(&profile).is_ok());
    }

    #[test]
    fn test_validate_env_credentials_rejects_invalid_apple_password_uri() {
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "env_credentials": {
                "apple-password://github.com": "GITHUB_PASSWORD"
            }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        let err = validate_env_credential_keys(&profile).expect_err("should reject");
        assert!(err.to_string().contains("Apple Passwords URI"));
    }

    #[test]
    fn test_validate_env_credentials_accepts_keyring_uri() {
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "env_credentials": {
                "keyring://gh:github.com/alice": "GH_TOKEN"
            }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        assert!(validate_env_credential_keys(&profile).is_ok());
    }

    #[test]
    fn test_validate_env_credentials_accepts_keyring_uri_with_decode() {
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "env_credentials": {
                "keyring://gh:github.com/alice?decode=go-keyring": "GH_TOKEN"
            }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        assert!(validate_env_credential_keys(&profile).is_ok());
    }

    #[test]
    fn test_validate_env_credentials_rejects_invalid_keyring_uri() {
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "env_credentials": {
                "keyring://gh:github.com": "GH_TOKEN"
            }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        let err = validate_env_credential_keys(&profile).expect_err("should reject");
        assert!(err.to_string().contains("keyring URI"));
    }

    #[test]
    fn test_secrets_alias_backward_compat() {
        // "secrets" should still work as an alias for "env_credentials"
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "secrets": {
                "openai_api_key": "OPENAI_API_KEY"
            }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        assert_eq!(profile.env_credentials.mappings.len(), 1);
        assert_eq!(
            profile.env_credentials.mappings.get("openai_api_key"),
            Some(&"OPENAI_API_KEY".to_string())
        );
    }

    #[test]
    fn test_empty_env_credentials_config() {
        let json_str = r#"{ "meta": { "name": "test-profile" } }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        assert!(profile.env_credentials.mappings.is_empty());
    }

    #[test]
    fn test_merge_implicit_default_groups_into_user_profile() {
        let mut profile = Profile {
            security: SecurityConfig {
                groups: vec!["node_runtime".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        merge_implicit_default_groups(&mut profile).expect("merge should succeed");

        // Should contain base groups
        assert!(
            profile
                .security
                .groups
                .contains(&"deny_credentials".to_string()),
            "Expected base group 'deny_credentials'"
        );
        assert!(
            profile
                .security
                .groups
                .contains(&"system_read_macos".to_string())
                || profile
                    .security
                    .groups
                    .contains(&"system_read_linux_core".to_string()),
            "Expected platform system_read group"
        );

        // Should still contain the profile's own group
        assert!(
            profile
                .security
                .groups
                .contains(&"node_runtime".to_string()),
            "Expected profile group 'node_runtime'"
        );

        // No duplicates
        let unique: std::collections::HashSet<_> = profile.security.groups.iter().collect();
        assert_eq!(
            unique.len(),
            profile.security.groups.len(),
            "Groups should have no duplicates"
        );
    }

    #[test]
    fn test_merge_implicit_default_groups_respects_policy_exclude_groups() {
        let mut profile = Profile {
            security: SecurityConfig {
                groups: vec!["node_runtime".to_string()],
                ..Default::default()
            },
            policy: PolicyPatchConfig {
                exclude_groups: vec!["dangerous_commands".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        merge_implicit_default_groups(&mut profile).expect("merge should succeed");

        assert!(
            !profile
                .security
                .groups
                .contains(&"dangerous_commands".to_string()),
            "excluded group 'dangerous_commands' should be removed"
        );
    }

    #[test]
    fn test_load_profile_extends_default_respects_excluded_groups() {
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("no-dangerous-commands.json");
        std::fs::write(
            &profile_path,
            r#"{
                "meta": { "name": "no-dangerous-commands", "version": "1.0.0" },
                "extends": "default",
                "policy": {
                    "exclude_groups": [
                        "dangerous_commands",
                        "dangerous_commands_linux",
                        "dangerous_commands_macos"
                    ]
                },
                "workdir": { "access": "readwrite" }
            }"#,
        )
        .expect("write profile");

        let profile = load_profile_from_path(&profile_path).expect("load profile");

        assert!(
            !profile
                .security
                .groups
                .contains(&"dangerous_commands".to_string()),
            "excluded dangerous_commands should not be present in finalized groups"
        );
        assert!(
            !profile
                .security
                .groups
                .contains(&"dangerous_commands_macos".to_string()),
            "excluded dangerous_commands_macos should not be present in finalized groups"
        );
    }

    #[test]
    fn test_workdir_config_readwrite() {
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "workdir": { "access": "readwrite" }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        assert_eq!(profile.workdir.access, WorkdirAccess::ReadWrite);
    }

    #[test]
    fn test_workdir_config_read() {
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "workdir": { "access": "read" }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        assert_eq!(profile.workdir.access, WorkdirAccess::Read);
    }

    #[test]
    fn test_workdir_config_none() {
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "workdir": { "access": "none" }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        assert_eq!(profile.workdir.access, WorkdirAccess::None);
    }

    #[test]
    fn test_workdir_config_default() {
        let json_str = r#"{ "meta": { "name": "test-profile" } }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        assert_eq!(profile.workdir.access, WorkdirAccess::None);
    }

    // ============================================================================
    // is_http_token_char tests (RFC 7230)
    // ============================================================================

    #[test]
    fn test_http_token_char_alphanumeric() {
        assert!(is_http_token_char('a'));
        assert!(is_http_token_char('Z'));
        assert!(is_http_token_char('0'));
        assert!(is_http_token_char('9'));
    }

    #[test]
    fn test_http_token_char_special_chars() {
        // RFC 7230 tchar: !#$%&'*+-.^_`|~
        for c in "!#$%&'*+-.^_`|~".chars() {
            assert!(is_http_token_char(c), "Expected '{}' to be valid tchar", c);
        }
    }

    #[test]
    fn test_http_token_char_rejects_invalid() {
        // Control chars, space, colon, parentheses should be rejected
        assert!(!is_http_token_char(' '));
        assert!(!is_http_token_char(':'));
        assert!(!is_http_token_char('('));
        assert!(!is_http_token_char(')'));
        assert!(!is_http_token_char('\r'));
        assert!(!is_http_token_char('\n'));
    }

    // ============================================================================
    // Custom credential validation integration tests
    //
    // These test the full validation chain including:
    // - inject_header (RFC 7230 token validation)
    // - credential_format (CRLF injection prevention)
    // - credential_key (alphanumeric + underscore)
    // - upstream URL (HTTPS required, HTTP only for loopback)
    // ============================================================================

    fn header_cred_builder() -> CustomCredentialDef {
        CustomCredentialDef {
            upstream: "https://api.example.com".to_string(),
            credential_key: Some("api_key".to_string()),
            auth: None,
            inject_mode: InjectMode::Header,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: None,
            endpoint_rules: vec![],
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
        }
    }

    #[test]
    fn test_validate_custom_credential_valid() {
        let cred = header_cred_builder();
        assert!(validate_custom_credential("test", &cred).is_ok());
    }

    #[test]
    fn test_validate_custom_credential_http_loopback_allowed() {
        let mut cred = header_cred_builder();
        cred.upstream = "http://127.0.0.1:8080/api".to_string();
        cred.credential_key = Some("local_key".to_string());
        assert!(validate_custom_credential("local", &cred).is_ok());
    }

    #[test]
    fn test_validate_custom_credential_http_remote_rejected() {
        let mut cred = header_cred_builder();
        cred.upstream = "http://api.example.com".to_string();
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("HTTP to remote should be rejected");
        assert!(err.to_string().contains("HTTPS"));
    }

    #[test]
    fn test_validate_custom_credential_invalid_header_rejected() {
        let mut cred = header_cred_builder();
        cred.inject_header = "X-Header\r\nEvil: injected".to_string();
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("CRLF in header should be rejected");
        assert!(err.to_string().contains("invalid characters"));
    }

    #[test]
    fn test_validate_custom_credential_invalid_format_rejected() {
        let mut cred = header_cred_builder();
        cred.credential_format = "Bearer {}\r\nEvil: header".to_string();
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("CRLF in format should be rejected");
        assert!(err.to_string().contains("CRLF"));
    }

    #[test]
    fn test_validate_custom_credential_invalid_key_rejected() {
        let mut cred = header_cred_builder();
        cred.credential_key = Some("api-key".to_string()); // hyphens not allowed
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("hyphen in key should be rejected");
        assert!(err.to_string().contains("alphanumeric"));
    }

    #[test]
    fn test_validate_custom_credential_empty_header_rejected() {
        let mut cred = header_cred_builder();
        cred.inject_header = "".to_string();
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("empty header should be rejected");
        assert!(err.to_string().contains("cannot be empty"));
    }

    #[test]
    fn test_validate_custom_credential_header_with_space_rejected() {
        let mut cred = header_cred_builder();
        cred.inject_header = "X Header".to_string();
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("space in header should be rejected");
        assert!(err.to_string().contains("invalid characters"));
    }

    #[test]
    fn test_validate_custom_credential_header_with_colon_rejected() {
        let mut cred = header_cred_builder();
        cred.inject_header = "X-Header:".to_string();
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("colon in header should be rejected");
        assert!(err.to_string().contains("invalid characters"));
    }

    #[test]
    fn test_validate_custom_credential_valid_special_header_chars() {
        let mut cred = header_cred_builder();
        cred.inject_header = "X-Header!".to_string(); // ! is valid tchar
        assert!(validate_custom_credential("test", &cred).is_ok());
    }

    #[test]
    fn test_validate_custom_credential_format_with_cr_rejected() {
        let mut cred = header_cred_builder();
        cred.credential_format = "Bearer {}\rEvil: header".to_string();
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("CR in format should be rejected");
        assert!(err.to_string().contains("CRLF"));
    }

    #[test]
    fn test_validate_custom_credential_format_with_lf_rejected() {
        let mut cred = header_cred_builder();
        cred.credential_format = "Bearer {}\nEvil: header".to_string();
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("LF in format should be rejected");
        assert!(err.to_string().contains("CRLF"));
    }

    #[test]
    fn test_validate_custom_credential_various_valid_formats() {
        for format in ["Bearer {}", "Token {}", "{}", "Basic {}", "ApiKey={}"] {
            let mut cred = header_cred_builder();
            cred.credential_format = format.to_string();
            assert!(
                validate_custom_credential("test", &cred).is_ok(),
                "Expected format '{}' to be valid",
                format
            );
        }
    }

    #[test]
    fn test_validate_custom_credential_http_localhost_allowed() {
        let mut cred = header_cred_builder();
        cred.upstream = "http://localhost:3000/api".to_string();
        cred.credential_key = Some("local_key".to_string());
        assert!(validate_custom_credential("local", &cred).is_ok());
    }

    #[test]
    fn test_validate_custom_credential_http_ipv6_loopback_allowed() {
        let mut cred = header_cred_builder();
        cred.upstream = "http://[::1]:8080/api".to_string();
        cred.credential_key = Some("local_key".to_string());
        assert!(validate_custom_credential("local", &cred).is_ok());
    }

    #[test]
    fn test_validate_custom_credential_http_0_0_0_0_allowed() {
        let mut cred = header_cred_builder();
        cred.upstream = "http://0.0.0.0:3000/api".to_string();
        cred.credential_key = Some("local_key".to_string());
        assert!(validate_custom_credential("local", &cred).is_ok());
    }

    // ============================================================================
    // Injection Mode Validation Tests
    // ============================================================================

    #[test]
    fn test_validate_url_path_mode_valid() {
        let cred = CustomCredentialDef {
            upstream: "https://api.telegram.org".to_string(),
            credential_key: Some("telegram_token".to_string()),
            auth: None,
            inject_mode: InjectMode::UrlPath,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: Some("/bot{}/".to_string()),
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: None,
            endpoint_rules: vec![],
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
        };
        assert!(validate_custom_credential("telegram", &cred).is_ok());
    }

    #[test]
    fn test_validate_url_path_mode_missing_pattern() {
        let cred = CustomCredentialDef {
            upstream: "https://api.telegram.org".to_string(),
            credential_key: Some("telegram_token".to_string()),
            auth: None,
            inject_mode: InjectMode::UrlPath,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: None, // Missing required field
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: None,
            endpoint_rules: vec![],
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
        };
        let result = validate_custom_credential("telegram", &cred);
        let err = result.expect_err("missing path_pattern should be rejected");
        assert!(err.to_string().contains("path_pattern is required"));
    }

    #[test]
    fn test_validate_url_path_mode_pattern_without_placeholder() {
        let cred = CustomCredentialDef {
            upstream: "https://api.telegram.org".to_string(),
            credential_key: Some("telegram_token".to_string()),
            auth: None,
            inject_mode: InjectMode::UrlPath,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: Some("/bot/token/".to_string()), // No {} placeholder
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: None,
            endpoint_rules: vec![],
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
        };
        let result = validate_custom_credential("telegram", &cred);
        let err = result.expect_err("pattern without {} should be rejected");
        assert!(err.to_string().contains("{}"));
    }

    #[test]
    fn test_validate_url_path_mode_with_replacement() {
        let cred = CustomCredentialDef {
            upstream: "https://api.telegram.org".to_string(),
            credential_key: Some("telegram_token".to_string()),
            auth: None,
            inject_mode: InjectMode::UrlPath,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: Some("/bot{}/".to_string()),
            path_replacement: Some("/v2/bot{}/".to_string()),
            query_param_name: None,
            proxy: None,
            env_var: None,
            endpoint_rules: vec![],
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
        };
        assert!(validate_custom_credential("telegram", &cred).is_ok());
    }

    #[test]
    fn test_validate_url_path_mode_replacement_without_placeholder() {
        let cred = CustomCredentialDef {
            upstream: "https://api.telegram.org".to_string(),
            credential_key: Some("telegram_token".to_string()),
            auth: None,
            inject_mode: InjectMode::UrlPath,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: Some("/bot{}/".to_string()),
            path_replacement: Some("/v2/bot/fixed/".to_string()), // No {} placeholder
            query_param_name: None,
            proxy: None,
            env_var: None,
            endpoint_rules: vec![],
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
        };
        let result = validate_custom_credential("telegram", &cred);
        let err = result.expect_err("replacement without {} should be rejected");
        assert!(err.to_string().contains("{}"));
    }

    #[test]
    fn test_validate_query_param_mode_valid() {
        let cred = CustomCredentialDef {
            upstream: "https://maps.googleapis.com".to_string(),
            credential_key: Some("google_maps_key".to_string()),
            auth: None,
            inject_mode: InjectMode::QueryParam,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: None,
            path_replacement: None,
            query_param_name: Some("key".to_string()),
            proxy: None,
            env_var: None,
            endpoint_rules: vec![],
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
        };
        assert!(validate_custom_credential("google_maps", &cred).is_ok());
    }

    #[test]
    fn test_validate_query_param_mode_missing_param_name() {
        let cred = CustomCredentialDef {
            upstream: "https://maps.googleapis.com".to_string(),
            credential_key: Some("google_maps_key".to_string()),
            auth: None,
            inject_mode: InjectMode::QueryParam,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None, // Missing required field
            proxy: None,
            env_var: None,
            endpoint_rules: vec![],
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
        };
        let result = validate_custom_credential("google_maps", &cred);
        let err = result.expect_err("missing query_param_name should be rejected");
        assert!(err.to_string().contains("query_param_name is required"));
    }

    #[test]
    fn test_validate_query_param_mode_empty_param_name() {
        let cred = CustomCredentialDef {
            upstream: "https://maps.googleapis.com".to_string(),
            credential_key: Some("google_maps_key".to_string()),
            auth: None,
            inject_mode: InjectMode::QueryParam,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: None,
            path_replacement: None,
            query_param_name: Some("".to_string()), // Empty
            proxy: None,
            env_var: None,
            endpoint_rules: vec![],
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
        };
        let result = validate_custom_credential("google_maps", &cred);
        let err = result.expect_err("empty query_param_name should be rejected");
        assert!(err.to_string().contains("cannot be empty"));
    }

    #[test]
    fn test_validate_basic_auth_mode_valid() {
        let cred = CustomCredentialDef {
            upstream: "https://api.example.com".to_string(),
            credential_key: Some("example_basic_auth".to_string()),
            auth: None,
            inject_mode: InjectMode::BasicAuth,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: None,
            endpoint_rules: vec![],
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
        };
        // BasicAuth mode doesn't require additional fields
        // Credential value is expected to be "username:password" format
        assert!(validate_custom_credential("example", &cred).is_ok());
    }

    #[test]
    fn test_validate_proxy_override_query_param_requires_name() {
        let mut cred = header_cred_builder();
        cred.proxy = Some(nono_proxy::config::ProxyInjectConfig {
            inject_mode: Some(InjectMode::QueryParam),
            inject_header: None,
            credential_format: None,
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
        });

        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("proxy query_param_name should be required");
        assert!(err
            .to_string()
            .contains("proxy.query_param_name is required"));
    }

    #[test]
    fn test_validate_proxy_override_query_param_with_fallback_name() {
        let mut cred = header_cred_builder();
        cred.query_param_name = Some("api_key".to_string());
        cred.proxy = Some(nono_proxy::config::ProxyInjectConfig {
            inject_mode: Some(InjectMode::QueryParam),
            inject_header: None,
            credential_format: None,
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
        });

        assert!(validate_custom_credential("test", &cred).is_ok());
    }

    #[test]
    fn test_validate_proxy_override_url_path_with_fallback_pattern() {
        let mut cred = header_cred_builder();
        cred.path_pattern = Some("/bot/{}/".to_string());
        cred.proxy = Some(nono_proxy::config::ProxyInjectConfig {
            inject_mode: Some(InjectMode::UrlPath),
            inject_header: None,
            credential_format: None,
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
        });

        assert!(validate_custom_credential("test", &cred).is_ok());
    }

    // ============================================================================
    // env_var validation tests
    // ============================================================================

    #[test]
    fn test_validate_env_var_with_op_uri_requires_env_var() {
        // When credential_key is a URI manager ref, env_var must be set because
        // uppercasing the URI produces a nonsensical env var name.
        let mut cred = header_cred_builder();
        cred.credential_key = Some("op://Development/OpenAI/credential".to_string());
        cred.env_var = None;
        let result = validate_custom_credential("openai", &cred);
        let err = result.expect_err("op:// URI without env_var should be rejected");
        assert!(err.to_string().contains("env_var is required"));
    }

    #[test]
    fn test_validate_env_var_with_op_uri_and_env_var_ok() {
        let mut cred = header_cred_builder();
        cred.credential_key = Some("op://Development/OpenAI/credential".to_string());
        cred.env_var = Some("OPENAI_API_KEY".to_string());
        assert!(validate_custom_credential("openai", &cred).is_ok());
    }

    #[test]
    fn test_validate_env_var_with_apple_password_uri_requires_env_var() {
        let mut cred = header_cred_builder();
        cred.credential_key = Some("apple-password://github.com/alice@example.com".to_string());
        cred.env_var = None;
        let result = validate_custom_credential("github", &cred);
        let err = result.expect_err("apple-password URI without env_var should be rejected");
        assert!(err.to_string().contains("env_var is required"));
    }

    #[test]
    fn test_validate_env_var_with_apple_password_uri_and_env_var_ok() {
        let mut cred = header_cred_builder();
        cred.credential_key = Some("apple-password://github.com/alice@example.com".to_string());
        cred.env_var = Some("GITHUB_PASSWORD".to_string());
        assert!(validate_custom_credential("github", &cred).is_ok());
    }

    #[test]
    fn test_validate_env_var_empty_rejected() {
        let mut cred = header_cred_builder();
        cred.env_var = Some("".to_string());
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("empty env_var should be rejected");
        assert!(err.to_string().contains("cannot be empty"));
    }

    #[test]
    fn test_validate_env_var_invalid_chars_rejected() {
        let mut cred = header_cred_builder();
        cred.env_var = Some("OPEN-AI_KEY".to_string()); // hyphens not allowed
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("env_var with hyphens should be rejected");
        assert!(err.to_string().contains("alphanumeric"));
    }

    #[test]
    fn test_validate_env_var_optional_for_keyring_keys() {
        // When credential_key is a plain keyring name, env_var is optional
        // (backward compat: falls back to cred_key.to_uppercase())
        let mut cred = header_cred_builder();
        cred.env_var = None;
        assert!(validate_custom_credential("test", &cred).is_ok());
    }

    #[test]
    fn test_validate_env_var_with_keyring_key_ok() {
        // Explicit env_var with a keyring key is allowed (overrides default)
        let mut cred = header_cred_builder();
        cred.env_var = Some("MY_CUSTOM_VAR".to_string());
        assert!(validate_custom_credential("test", &cred).is_ok());
    }

    // ============================================================================
    // OAuth2 auth validation tests
    // ============================================================================

    fn oauth2_cred_builder() -> CustomCredentialDef {
        CustomCredentialDef {
            upstream: "https://api.example.com".to_string(),
            credential_key: None,
            auth: Some(OAuth2Config {
                token_url: "https://auth.example.com/oauth/token".to_string(),
                client_id: "my-client".to_string(),
                client_secret: "env://CLIENT_SECRET".to_string(),
                scope: "read write".to_string(),
            }),
            inject_mode: InjectMode::Header,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: None,
            endpoint_rules: vec![],
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
        }
    }

    #[test]
    fn test_validate_oauth2_auth_valid() {
        let cred = oauth2_cred_builder();
        assert!(validate_custom_credential("test", &cred).is_ok());
    }

    #[test]
    fn test_validate_oauth2_auth_and_credential_key_mutually_exclusive() {
        let mut cred = oauth2_cred_builder();
        cred.credential_key = Some("some_key".to_string());
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("both auth and credential_key should be rejected");
        assert!(err.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn test_validate_oauth2_neither_auth_nor_credential_key_rejected() {
        let mut cred = oauth2_cred_builder();
        cred.credential_key = None;
        cred.auth = None;
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("neither auth nor credential_key should be rejected");
        assert!(err.to_string().contains("must have either"));
    }

    #[test]
    fn test_validate_oauth2_token_url_http_remote_rejected() {
        let mut cred = oauth2_cred_builder();
        cred.auth = Some(OAuth2Config {
            token_url: "http://auth.remote.com/oauth/token".to_string(),
            client_id: "my-client".to_string(),
            client_secret: "env://SECRET".to_string(),
            scope: String::new(),
        });
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("HTTP to remote token_url should be rejected");
        assert!(err.to_string().contains("HTTPS"));
    }

    #[test]
    fn test_validate_oauth2_token_url_http_localhost_allowed() {
        let mut cred = oauth2_cred_builder();
        cred.auth = Some(OAuth2Config {
            token_url: "http://localhost:8080/oauth/token".to_string(),
            client_id: "my-client".to_string(),
            client_secret: "env://SECRET".to_string(),
            scope: String::new(),
        });
        assert!(validate_custom_credential("test", &cred).is_ok());
    }

    #[test]
    fn test_validate_oauth2_empty_client_id_rejected() {
        let mut cred = oauth2_cred_builder();
        cred.auth = Some(OAuth2Config {
            token_url: "https://auth.example.com/oauth/token".to_string(),
            client_id: "".to_string(),
            client_secret: "env://SECRET".to_string(),
            scope: String::new(),
        });
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("empty client_id should be rejected");
        assert!(err.to_string().contains("client_id"));
        assert!(err.to_string().contains("cannot be empty"));
    }

    #[test]
    fn test_validate_oauth2_empty_client_secret_rejected() {
        let mut cred = oauth2_cred_builder();
        cred.auth = Some(OAuth2Config {
            token_url: "https://auth.example.com/oauth/token".to_string(),
            client_id: "my-client".to_string(),
            client_secret: "".to_string(),
            scope: String::new(),
        });
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("empty client_secret should be rejected");
        assert!(err.to_string().contains("client_secret"));
        assert!(err.to_string().contains("cannot be empty"));
    }

    #[test]
    fn test_validate_oauth2_scope_optional() {
        let mut cred = oauth2_cred_builder();
        cred.auth = Some(OAuth2Config {
            token_url: "https://auth.example.com/oauth/token".to_string(),
            client_id: "my-client".to_string(),
            client_secret: "env://SECRET".to_string(),
            scope: String::new(),
        });
        assert!(validate_custom_credential("test", &cred).is_ok());
    }

    #[test]
    fn test_parse_profile_with_oauth2_auth() {
        let json = r#"{
            "meta": { "name": "oauth2-test" },
            "network": {
                "custom_credentials": {
                    "my_api": {
                        "upstream": "https://api.example.com",
                        "auth": {
                            "token_url": "https://auth.example.com/oauth/token",
                            "client_id": "my-client",
                            "client_secret": "env://CLIENT_SECRET",
                            "scope": "api.read"
                        }
                    }
                }
            }
        }"#;
        let dir = tempdir().expect("tmpdir");
        let path = dir.path().join("oauth2-test.json");
        std::fs::write(&path, json).expect("write profile");
        let profile = load_profile_from_path(&path).expect("parse profile");
        let cred = &profile.network.custom_credentials["my_api"];
        assert!(cred.credential_key.is_none());
        assert!(cred.auth.is_some());
        let auth = cred.auth.as_ref().unwrap();
        assert_eq!(auth.token_url, "https://auth.example.com/oauth/token");
        assert_eq!(auth.client_id, "my-client");
        assert_eq!(auth.client_secret, "env://CLIENT_SECRET");
        assert_eq!(auth.scope, "api.read");
    }

    #[test]
    fn test_parse_profile_with_oauth2_auth_and_credential_key_rejected() {
        let json = r#"{
            "meta": { "name": "invalid-test" },
            "network": {
                "custom_credentials": {
                    "my_api": {
                        "upstream": "https://api.example.com",
                        "credential_key": "some_key",
                        "auth": {
                            "token_url": "https://auth.example.com/oauth/token",
                            "client_id": "my-client",
                            "client_secret": "env://CLIENT_SECRET"
                        }
                    }
                }
            }
        }"#;
        let dir = tempdir().expect("tmpdir");
        let path = dir.path().join("invalid-test.json");
        std::fs::write(&path, json).expect("write profile");
        let result = load_profile_from_path(&path);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("mutually exclusive"));
    }

    #[test]
    fn test_security_config_allowed_commands_deserializes() {
        let json = r#"{
            "meta": { "name": "rm-test" },
            "filesystem": { "allow": ["/tmp"] },
            "security": { "allowed_commands": ["rm", "dd"] }
        }"#;
        let dir = tempdir().expect("tmpdir");
        let path = dir.path().join("rm-test.json");
        std::fs::write(&path, json).expect("write profile");
        let profile = load_profile_from_path(&path).expect("parse profile");
        assert_eq!(profile.security.allowed_commands, vec!["rm", "dd"]);
    }

    #[test]
    fn test_security_config_allowed_commands_defaults_empty() {
        let json = r#"{
            "meta": { "name": "no-cmds" },
            "filesystem": { "allow": ["/tmp"] }
        }"#;
        let dir = tempdir().expect("tmpdir");
        let path = dir.path().join("no-cmds.json");
        std::fs::write(&path, json).expect("write profile");
        let profile = load_profile_from_path(&path).expect("parse profile");
        assert!(profile.security.allowed_commands.is_empty());
    }
    // ============================================================================
    // Profile inheritance (extends) tests
    // ============================================================================

    /// Helper: build a minimal Profile for merge testing.
    fn base_profile() -> Profile {
        Profile {
            extends: None,
            meta: ProfileMeta {
                name: "base".to_string(),
                version: "1.0".to_string(),
                description: Some("Base profile".to_string()),
                author: None,
            },
            security: SecurityConfig {
                groups: vec!["base_group".to_string()],
                ..Default::default()
            },
            filesystem: FilesystemConfig {
                allow: vec!["/base/rw".to_string()],
                read: vec!["/base/read".to_string()],
                write: vec![],
                allow_file: vec![],
                read_file: vec!["/base/file.txt".to_string()],
                write_file: vec![],
                unix_socket: vec![],
                unix_socket_bind: vec![],
                unix_socket_dir: vec![],
                unix_socket_dir_bind: vec![],
            },
            policy: PolicyPatchConfig {
                exclude_groups: vec!["base_excluded".to_string()],
                add_allow_read: vec!["/base/policy-read".to_string()],
                add_allow_write: vec![],
                add_allow_readwrite: vec![],
                add_deny_access: vec!["/base/policy-deny".to_string()],
                add_deny_commands: vec![],
                override_deny: vec!["/base/override-deny".to_string()],
            },
            network: NetworkConfig {
                block: false,
                network_profile: InheritableValue::Set("base-net".to_string()),
                allow_domain: vec!["base.example.com".to_string()],
                open_port: vec![3000],
                listen_port: vec![4000],
                connect_port: vec![],
                credentials: Some(vec!["base_cred".to_string()]),
                custom_credentials: HashMap::new(),
                upstream_proxy: None,
                upstream_bypass: Vec::new(),
            },
            env_credentials: SecretsConfig {
                mappings: {
                    let mut m = HashMap::new();
                    m.insert("base_key".to_string(), "BASE_VAR".to_string());
                    m
                },
            },
            environment: None,
            workdir: WorkdirConfig {
                access: WorkdirAccess::ReadWrite,
            },
            hooks: HooksConfig {
                hooks: HashMap::new(),
            },
            rollback: RollbackConfig {
                exclude_patterns: vec!["node_modules".to_string()],
                exclude_globs: vec!["*.pyc".to_string()],
            },
            open_urls: Some(OpenUrlConfig {
                allow_origins: vec!["https://base.example.com".to_string()],
                allow_localhost: false,
            }),
            allow_launch_services: Some(false),
            allow_gpu: Some(false),
            allow_parent_of_protected: None,
            interactive: false,
            skipdirs: vec!["vendor".to_string()],
            packs: vec![],
            command_args: vec![],
            unsafe_macos_seatbelt_rules: vec![],
        }
    }

    fn child_profile() -> Profile {
        Profile {
            extends: Some(vec!["base".to_string()]),
            meta: ProfileMeta {
                name: "child".to_string(),
                version: "2.0".to_string(),
                description: Some("Child profile".to_string()),
                author: None,
            },
            security: SecurityConfig {
                groups: vec!["child_group".to_string()],
                ..Default::default()
            },
            filesystem: FilesystemConfig {
                allow: vec!["/child/rw".to_string()],
                read: vec![],
                write: vec![],
                allow_file: vec![],
                read_file: vec![],
                write_file: vec![],
                unix_socket: vec![],
                unix_socket_bind: vec![],
                unix_socket_dir: vec![],
                unix_socket_dir_bind: vec![],
            },
            policy: PolicyPatchConfig {
                exclude_groups: vec!["child_excluded".to_string()],
                add_allow_read: vec![],
                add_allow_write: vec!["/child/policy-write".to_string()],
                add_allow_readwrite: vec!["/child/policy-rw".to_string()],
                add_deny_access: vec!["/child/policy-deny".to_string()],
                add_deny_commands: vec![],
                override_deny: vec!["/child/override-deny".to_string()],
            },
            network: NetworkConfig {
                block: false,
                network_profile: InheritableValue::Inherit,
                allow_domain: vec!["child.example.com".to_string()],
                open_port: vec![3000, 5000],
                listen_port: vec![4000, 6000],
                connect_port: vec![],
                credentials: None,
                custom_credentials: HashMap::new(),
                upstream_proxy: None,
                upstream_bypass: Vec::new(),
            },
            env_credentials: SecretsConfig {
                mappings: {
                    let mut m = HashMap::new();
                    m.insert("child_key".to_string(), "CHILD_VAR".to_string());
                    m
                },
            },
            environment: None,
            workdir: WorkdirConfig {
                access: WorkdirAccess::None,
            },
            hooks: HooksConfig {
                hooks: HashMap::new(),
            },
            rollback: RollbackConfig {
                exclude_patterns: vec![],
                exclude_globs: vec![],
            },
            open_urls: Some(OpenUrlConfig {
                allow_origins: vec!["https://child.example.com".to_string()],
                allow_localhost: true,
            }),
            allow_launch_services: Some(true),
            allow_gpu: Some(true),
            allow_parent_of_protected: Some(true),
            interactive: false,
            skipdirs: vec!["dist".to_string()],
            packs: vec![],
            command_args: vec![],
            unsafe_macos_seatbelt_rules: vec![],
        }
    }

    // --- merge_profiles unit tests ---

    #[test]
    fn test_merge_profiles_appends_filesystem_paths() {
        let merged = merge_profiles(base_profile(), child_profile());
        assert!(merged.filesystem.allow.contains(&"/base/rw".to_string()));
        assert!(merged.filesystem.allow.contains(&"/child/rw".to_string()));
        assert!(merged.filesystem.read.contains(&"/base/read".to_string()));
        assert!(merged
            .filesystem
            .read_file
            .contains(&"/base/file.txt".to_string()));
    }

    #[test]
    fn test_merge_profiles_deduplicates_open_port() {
        let merged = merge_profiles(base_profile(), child_profile());
        // base has [3000], child has [3000, 5000] — merged should dedup to [3000, 5000]
        assert_eq!(merged.network.open_port, vec![3000, 5000]);
    }

    #[test]
    fn test_merge_profiles_appends_security_groups() {
        let merged = merge_profiles(base_profile(), child_profile());
        assert!(merged.security.groups.contains(&"base_group".to_string()));
        assert!(merged.security.groups.contains(&"child_group".to_string()));
    }

    #[test]
    fn test_merge_profiles_deduplicates_vecs() {
        let mut base = base_profile();
        let mut child = child_profile();
        // Both have the same group
        base.security.groups = vec!["shared_group".to_string(), "base_only".to_string()];
        child.security.groups = vec!["shared_group".to_string(), "child_only".to_string()];

        let merged = merge_profiles(base, child);
        assert_eq!(
            merged.security.groups,
            vec![
                "shared_group".to_string(),
                "base_only".to_string(),
                "child_only".to_string()
            ]
        );
    }

    #[test]
    fn test_merge_profiles_replaces_meta() {
        let merged = merge_profiles(base_profile(), child_profile());
        assert_eq!(merged.meta.name, "child");
        assert_eq!(merged.meta.version, "2.0");
    }

    #[test]
    fn test_merge_profiles_merges_custom_credentials() {
        let mut base = base_profile();
        base.network.custom_credentials.insert(
            "svc_a".to_string(),
            CustomCredentialDef {
                upstream: "https://a.example.com".to_string(),
                credential_key: Some("key_a".to_string()),
                auth: None,
                inject_mode: InjectMode::Header,
                inject_header: "Authorization".to_string(),
                credential_format: "Bearer {}".to_string(),
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                proxy: None,
                env_var: None,
                endpoint_rules: vec![],
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
            },
        );

        let mut child = child_profile();
        child.network.custom_credentials.insert(
            "svc_b".to_string(),
            CustomCredentialDef {
                upstream: "https://b.example.com".to_string(),
                credential_key: Some("key_b".to_string()),
                auth: None,
                inject_mode: InjectMode::Header,
                inject_header: "Authorization".to_string(),
                credential_format: "Token {}".to_string(),
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                proxy: None,
                env_var: None,
                endpoint_rules: vec![],
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
            },
        );

        let merged = merge_profiles(base, child);
        assert!(merged.network.custom_credentials.contains_key("svc_a"));
        assert!(merged.network.custom_credentials.contains_key("svc_b"));
    }

    #[test]
    fn test_merge_profiles_network_profile_override() {
        let base = base_profile(); // has network_profile = Set("base-net")
        let child = child_profile(); // has network_profile = Inherit

        // Child Inherit -> inherit base
        let merged = merge_profiles(base.clone(), child);
        assert_eq!(merged.network.resolved_network_profile(), Some("base-net"));

        // Child has explicit value -> override
        let mut overriding_child = child_profile();
        overriding_child.network.network_profile = InheritableValue::Set("child-net".to_string());
        let merged = merge_profiles(base, overriding_child);
        assert_eq!(merged.network.resolved_network_profile(), Some("child-net"));
    }

    #[test]
    fn test_merge_profiles_network_profile_null_clears_base() {
        let base = base_profile();
        let mut child = child_profile();
        child.network.network_profile = InheritableValue::Clear;

        let merged = merge_profiles(base, child);
        assert_eq!(merged.network.resolved_network_profile(), None);
    }

    #[test]
    fn test_merge_profiles_inherits_network_block() {
        let mut base = base_profile();
        base.network.block = true;
        let child = child_profile(); // block = false

        let merged = merge_profiles(base, child);
        assert!(merged.network.block, "base block=true must be inherited");
    }

    #[test]
    fn test_merge_profiles_workdir_inherit_from_base() {
        let base = base_profile(); // ReadWrite
        let child = child_profile(); // None (not specified)

        let merged = merge_profiles(base, child);
        assert_eq!(merged.workdir.access, WorkdirAccess::ReadWrite);
    }

    #[test]
    fn test_merge_profiles_workdir_override() {
        let base = base_profile(); // ReadWrite
        let mut child = child_profile();
        child.workdir.access = WorkdirAccess::Read;

        let merged = merge_profiles(base, child);
        assert_eq!(merged.workdir.access, WorkdirAccess::Read);
    }

    #[test]
    fn test_merge_profiles_merges_hooks() {
        let mut base = base_profile();
        base.hooks.hooks.insert(
            "claude-code".to_string(),
            HookConfig {
                event: "PostToolUseFailure".to_string(),
                matcher: "Bash".to_string(),
                script: "base-hook.sh".to_string(),
            },
        );

        let mut child = child_profile();
        child.hooks.hooks.insert(
            "opencode".to_string(),
            HookConfig {
                event: "PreToolUse".to_string(),
                matcher: "Write".to_string(),
                script: "child-hook.sh".to_string(),
            },
        );

        let merged = merge_profiles(base, child);
        assert!(merged.hooks.hooks.contains_key("claude-code"));
        assert!(merged.hooks.hooks.contains_key("opencode"));

        // Same-key collision: child wins
        let mut base2 = base_profile();
        base2.hooks.hooks.insert(
            "claude-code".to_string(),
            HookConfig {
                event: "PostToolUseFailure".to_string(),
                matcher: "Bash".to_string(),
                script: "base-hook.sh".to_string(),
            },
        );

        let mut child2 = child_profile();
        child2.hooks.hooks.insert(
            "claude-code".to_string(),
            HookConfig {
                event: "PreToolUse".to_string(),
                matcher: "Read".to_string(),
                script: "child-hook.sh".to_string(),
            },
        );

        let merged2 = merge_profiles(base2, child2);
        let hook = &merged2.hooks.hooks["claude-code"];
        assert_eq!(
            hook.script, "child-hook.sh",
            "child should win on collision"
        );
        assert_eq!(hook.event, "PreToolUse");
    }

    #[test]
    fn test_merge_profiles_custom_credentials_child_wins_on_collision() {
        let mut base = base_profile();
        base.network.custom_credentials.insert(
            "svc_shared".to_string(),
            CustomCredentialDef {
                upstream: "https://base.example.com".to_string(),
                credential_key: Some("key_base".to_string()),
                auth: None,
                inject_mode: InjectMode::Header,
                inject_header: "Authorization".to_string(),
                credential_format: "Bearer {}".to_string(),
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                proxy: None,
                env_var: None,
                endpoint_rules: vec![],
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
            },
        );

        let mut child = child_profile();
        child.network.custom_credentials.insert(
            "svc_shared".to_string(),
            CustomCredentialDef {
                upstream: "https://child.example.com".to_string(),
                credential_key: Some("key_child".to_string()),
                auth: None,
                inject_mode: InjectMode::Header,
                inject_header: "Authorization".to_string(),
                credential_format: "Token {}".to_string(),
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                proxy: None,
                env_var: None,
                endpoint_rules: vec![],
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
            },
        );

        let merged = merge_profiles(base, child);
        let cred = &merged.network.custom_credentials["svc_shared"];
        assert_eq!(
            cred.upstream, "https://child.example.com",
            "child should win on same-key collision"
        );
        assert_eq!(cred.credential_key, Some("key_child".to_string()));
    }

    // --- Loading pipeline tests ---

    #[test]
    fn test_extends_builtin_profile() {
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("ext.json");
        std::fs::write(
            &profile_path,
            r#"{
                "extends": "opencode",
                "meta": { "name": "ext-test" },
                "filesystem": { "allow": ["/tmp/ext-test"] }
            }"#,
        )
        .expect("write profile");

        let profile = load_from_file(&profile_path).expect("load extended profile");
        assert_eq!(profile.meta.name, "ext-test");
        // Should inherit codex's filesystem paths
        assert!(
            profile.filesystem.allow.len() > 1,
            "Expected inherited paths from codex, got: {:?}",
            profile.filesystem.allow
        );
        assert!(profile
            .filesystem
            .allow
            .contains(&"/tmp/ext-test".to_string()));
        // extends should be consumed
        assert!(profile.extends.is_none());
    }

    #[test]
    fn test_extends_user_profile() {
        // Test user-to-user file-based inheritance by parsing two temp files
        // and running resolve_extends + merge_profiles — the same pipeline
        // that load_from_file uses. We avoid setting XDG_CONFIG_HOME because
        // env::set_var is process-global and races with parallel tests.
        let dir = tempdir().expect("tmpdir");

        // Write base profile (no extends)
        let base_path = dir.path().join("base.json");
        std::fs::write(
            &base_path,
            r#"{
                "meta": { "name": "base-user" },
                "filesystem": { "allow": ["/base/path"], "read": ["/base/read"] },
                "network": { "block": true }
            }"#,
        )
        .expect("write base");

        // Write child profile (no extends in file — we set it after parsing)
        let child_path = dir.path().join("child.json");
        std::fs::write(
            &child_path,
            r#"{
                "meta": { "name": "child-user" },
                "filesystem": { "allow": ["/child/path"] }
            }"#,
        )
        .expect("write child");

        // Simulate the load_from_file pipeline: parse both, then merge
        let base = parse_profile_file(&base_path).expect("parse base");
        let child = parse_profile_file(&child_path).expect("parse child");
        let merged = merge_profiles(base, child);

        assert_eq!(merged.meta.name, "child-user");
        assert!(merged.filesystem.allow.contains(&"/base/path".to_string()));
        assert!(merged.filesystem.allow.contains(&"/child/path".to_string()));
        assert!(merged.filesystem.read.contains(&"/base/read".to_string()));
        assert!(merged.network.block, "base block=true must be inherited");
        assert!(merged.extends.is_none());
    }

    #[test]
    fn test_extends_chain_three_levels() {
        // Test A -> B -> codex (built-in)
        let dir = tempdir().expect("tmpdir");

        // B extends codex
        let b_path = dir.path().join("b.json");
        std::fs::write(
            &b_path,
            r#"{
                "extends": "opencode",
                "meta": { "name": "b-profile" },
                "filesystem": { "allow": ["/b/path"] }
            }"#,
        )
        .expect("write b");

        // A extends B via direct file load (since B is a temp file,
        // we test the resolve_extends logic directly)
        let b_profile = parse_profile_file(&b_path).expect("parse b");
        let a_profile = Profile {
            extends: None, // We'll manually chain
            meta: ProfileMeta {
                name: "a-profile".to_string(),
                ..Default::default()
            },
            filesystem: FilesystemConfig {
                allow: vec!["/a/path".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        // Resolve B first
        let resolved_b = resolve_extends(b_profile, &mut Vec::new(), 0).expect("resolve b");
        // Then merge A on top
        let merged = merge_profiles(resolved_b, a_profile);

        assert_eq!(merged.meta.name, "a-profile");
        assert!(merged.filesystem.allow.contains(&"/a/path".to_string()));
        assert!(merged.filesystem.allow.contains(&"/b/path".to_string()));
    }

    #[test]
    fn test_extends_missing_base_error() {
        let profile = Profile {
            extends: Some(vec!["nonexistent-profile-xyz".to_string()]),
            ..Default::default()
        };

        let result = resolve_extends(profile, &mut Vec::new(), 0);
        assert!(result.is_err());
        let err = result.expect_err("missing base should error");
        assert!(
            err.to_string().contains("not found"),
            "Error should mention 'not found': {}",
            err
        );
    }

    #[test]
    fn test_extends_circular_dependency_error() {
        // Simulate: visited already has "b", and we try to extend "b" again
        let profile = Profile {
            extends: Some(vec!["b".to_string()]),
            ..Default::default()
        };

        let mut visited = vec!["a".to_string(), "b".to_string()];
        let result = resolve_extends(profile, &mut visited, 2);
        assert!(result.is_err());
        let err = result.expect_err("circular dep should error");
        assert!(
            err.to_string().contains("circular"),
            "Error should mention 'circular': {}",
            err
        );
    }

    #[test]
    fn test_extends_self_reference_error() {
        let profile = Profile {
            extends: Some(vec!["self-ref".to_string()]),
            ..Default::default()
        };

        let mut visited = vec!["self-ref".to_string()];
        let result = resolve_extends(profile, &mut visited, 1);
        assert!(result.is_err());
        let err = result.expect_err("self-reference should error");
        assert!(
            err.to_string().contains("circular"),
            "Error should mention 'circular': {}",
            err
        );
    }

    #[test]
    fn test_extends_depth_limit_error() {
        let profile = Profile {
            extends: Some(vec!["deep".to_string()]),
            ..Default::default()
        };

        let visited: Vec<String> = (0..MAX_INHERITANCE_DEPTH)
            .map(|i| format!("level-{}", i))
            .collect();
        let result = resolve_extends(profile, &mut visited.clone(), MAX_INHERITANCE_DEPTH);
        assert!(result.is_err());
        let err = result.expect_err("depth limit should error");
        assert!(
            err.to_string().contains("too deep"),
            "Error should mention 'too deep': {}",
            err
        );
    }

    #[test]
    fn test_extends_empty_child_inherits_all() {
        let base = base_profile();
        let empty_child = Profile {
            extends: Some(vec!["base".to_string()]),
            ..Default::default()
        };

        let merged = merge_profiles(base.clone(), empty_child);
        // Should inherit all base filesystem paths
        assert_eq!(merged.filesystem.allow, base.filesystem.allow);
        assert_eq!(merged.filesystem.read, base.filesystem.read);
        assert_eq!(merged.filesystem.read_file, base.filesystem.read_file);
        // Should inherit base security groups
        assert_eq!(merged.security.groups, base.security.groups);
        // Should inherit base workdir
        assert_eq!(merged.workdir.access, base.workdir.access);
        // Should inherit base network settings
        assert_eq!(
            merged.network.resolved_network_profile(),
            base.network.resolved_network_profile()
        );
        assert_eq!(merged.network.allow_domain, base.network.allow_domain);
        // Should inherit rollback config
        assert_eq!(
            merged.rollback.exclude_patterns,
            base.rollback.exclude_patterns
        );
        assert_eq!(merged.rollback.exclude_globs, base.rollback.exclude_globs);
    }

    #[test]
    fn test_dedup_append_preserves_order() {
        let base = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let child = vec!["b".to_string(), "d".to_string(), "a".to_string()];
        let result = dedup_append(&base, &child);
        assert_eq!(
            result,
            vec![
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
                "d".to_string()
            ]
        );
    }

    #[test]
    fn test_dedup_append_empty_vecs() {
        let empty: Vec<String> = vec![];
        assert!(dedup_append(&empty, &empty).is_empty());

        let items = vec!["x".to_string()];
        assert_eq!(dedup_append(&empty, &items), items);
        assert_eq!(dedup_append(&items, &empty), items);
    }

    #[test]
    fn test_merge_profiles_env_credentials_child_wins() {
        let mut base = base_profile();
        base.env_credentials
            .mappings
            .insert("shared_key".to_string(), "BASE_VALUE".to_string());

        let mut child = child_profile();
        child
            .env_credentials
            .mappings
            .insert("shared_key".to_string(), "CHILD_VALUE".to_string());

        let merged = merge_profiles(base, child);
        assert_eq!(
            merged.env_credentials.mappings.get("shared_key"),
            Some(&"CHILD_VALUE".to_string()),
            "child should win for same key"
        );
        assert!(merged.env_credentials.mappings.contains_key("base_key"));
        assert!(merged.env_credentials.mappings.contains_key("child_key"));
    }

    #[test]
    fn test_merge_profiles_interactive_or_semantics() {
        // base=false, child=false -> false
        let merged = merge_profiles(base_profile(), child_profile());
        assert!(!merged.interactive);

        // base=true, child=false -> true
        let mut base = base_profile();
        base.interactive = true;
        let merged = merge_profiles(base, child_profile());
        assert!(merged.interactive);

        // base=false, child=true -> true
        let mut child = child_profile();
        child.interactive = true;
        let merged = merge_profiles(base_profile(), child);
        assert!(merged.interactive);
    }

    #[test]
    fn test_merge_profiles_extends_consumed() {
        let child = child_profile(); // has extends = Some(vec!["base"])
        let merged = merge_profiles(base_profile(), child);
        assert!(
            merged.extends.is_none(),
            "extends should be consumed after merge"
        );
    }

    #[test]
    fn test_merge_profiles_open_urls_child_replaces_base() {
        // When child has open_urls, it replaces base entirely
        let merged = merge_profiles(base_profile(), child_profile());
        let urls = merged.open_urls.expect("should have open_urls");
        assert_eq!(urls.allow_origins, vec!["https://child.example.com"]);
        assert!(!urls
            .allow_origins
            .contains(&"https://base.example.com".to_string()));
        assert!(urls.allow_localhost);
    }

    #[test]
    fn test_merge_profiles_open_urls_child_absent_inherits_base() {
        // When child has no open_urls, base is inherited
        let mut child = child_profile();
        child.open_urls = None;
        let merged = merge_profiles(base_profile(), child);
        let urls = merged.open_urls.expect("should inherit base open_urls");
        assert_eq!(urls.allow_origins, vec!["https://base.example.com"]);
        assert!(!urls.allow_localhost);
    }

    #[test]
    fn test_merge_profiles_open_urls_child_narrows() {
        // A derived profile can restrict to fewer origins than base
        let mut child = child_profile();
        child.open_urls = Some(OpenUrlConfig {
            allow_origins: vec![],
            allow_localhost: false,
        });
        let merged = merge_profiles(base_profile(), child);
        let urls = merged.open_urls.expect("should have open_urls");
        assert!(urls.allow_origins.is_empty());
        assert!(!urls.allow_localhost);
    }

    #[test]
    fn test_merge_profiles_allow_launch_services_child_overrides_base() {
        let merged = merge_profiles(base_profile(), child_profile());
        assert_eq!(merged.allow_launch_services, Some(true));

        let mut child = child_profile();
        child.allow_launch_services = Some(false);
        let merged = merge_profiles(base_profile(), child);
        assert_eq!(merged.allow_launch_services, Some(false));
    }

    #[test]
    fn test_merge_profiles_allow_gpu() {
        // 1. Child inherits from base when child's value is None.
        let mut child = child_profile();
        child.allow_gpu = None;
        let merged = merge_profiles(base_profile(), child);
        assert_eq!(
            merged.allow_gpu,
            Some(false),
            "Child should inherit allow_gpu from base"
        );

        // 2. Child overrides base when child has a value.
        let merged = merge_profiles(base_profile(), child_profile());
        assert_eq!(
            merged.allow_gpu,
            Some(true),
            "Child should override base allow_gpu"
        );

        // 3. Child's value is used when base has no value.
        let mut base = base_profile();
        base.allow_gpu = None;
        let merged = merge_profiles(base, child_profile());
        assert_eq!(
            merged.allow_gpu,
            Some(true),
            "Child value should be used when base is None"
        );
    }

    #[test]
    fn test_merge_profiles_allow_parent_of_protected_child_overrides_base() {
        let merged = merge_profiles(base_profile(), child_profile());
        assert_eq!(merged.allow_parent_of_protected, Some(true));

        let mut child = child_profile();
        child.allow_parent_of_protected = Some(false);
        let merged = merge_profiles(base_profile(), child);
        assert_eq!(merged.allow_parent_of_protected, Some(false));
    }

    #[test]
    fn test_merge_profiles_merges_policy_patches() {
        let merged = merge_profiles(base_profile(), child_profile());
        assert!(merged
            .policy
            .exclude_groups
            .contains(&"base_excluded".to_string()));
        assert!(merged
            .policy
            .exclude_groups
            .contains(&"child_excluded".to_string()));
        assert!(merged
            .policy
            .add_allow_read
            .contains(&"/base/policy-read".to_string()));
        assert!(merged
            .policy
            .add_allow_write
            .contains(&"/child/policy-write".to_string()));
        assert!(merged
            .policy
            .add_allow_readwrite
            .contains(&"/child/policy-rw".to_string()));
        assert!(merged
            .policy
            .add_deny_access
            .contains(&"/base/policy-deny".to_string()));
        assert!(merged
            .policy
            .add_deny_access
            .contains(&"/child/policy-deny".to_string()));
        assert!(merged
            .policy
            .override_deny
            .contains(&"/base/override-deny".to_string()));
        assert!(merged
            .policy
            .override_deny
            .contains(&"/child/override-deny".to_string()));
    }

    #[test]
    fn test_merge_profiles_credentials_none_inherits_base() {
        let base = base_profile(); // credentials: Some(["base_cred"])
        let child = child_profile(); // credentials: None
        let merged = merge_profiles(base, child);
        // None child inherits base credentials
        assert_eq!(
            merged.network.resolved_credentials(),
            &["base_cred".to_string()]
        );
    }

    #[test]
    fn test_merge_profiles_credentials_empty_overrides_base() {
        let base = base_profile(); // credentials: Some(["base_cred"])
        let mut child = child_profile();
        child.network.credentials = Some(Vec::new()); // Explicitly empty
        let merged = merge_profiles(base, child);
        // Some([]) overrides base — no credentials
        assert!(merged.network.resolved_credentials().is_empty());
        assert_eq!(merged.network.credentials, Some(Vec::new()));
    }

    #[test]
    fn test_merge_profiles_credentials_some_merges_with_base() {
        let base = base_profile(); // credentials: Some(["base_cred"])
        let mut child = child_profile();
        child.network.credentials = Some(vec!["child_cred".to_string()]);
        let merged = merge_profiles(base, child);
        // Some([...]) merges with base
        let creds = merged.network.resolved_credentials();
        assert!(creds.contains(&"base_cred".to_string()));
        assert!(creds.contains(&"child_cred".to_string()));
    }

    #[test]
    fn test_credentials_none_does_not_activate_proxy() {
        let mut config = NetworkConfig::default();
        assert!(!config.has_proxy_flags()); // None = no proxy
        config.credentials = Some(Vec::new());
        assert!(!config.has_proxy_flags()); // Some([]) = no proxy
        config.credentials = Some(vec!["openai".to_string()]);
        assert!(config.has_proxy_flags()); // Some(["openai"]) = proxy
    }

    #[test]
    fn test_credentials_deserialization_absent_vs_empty() {
        // Absent field → None (inherit)
        let json = r#"{ "meta": { "name": "no-creds" }, "network": {} }"#;
        let profile: Profile = serde_json::from_str(json).expect("parse");
        assert!(profile.network.credentials.is_none());

        // Explicit empty array → Some([]) (override to empty)
        let json = r#"{ "meta": { "name": "empty-creds" }, "network": { "credentials": [] } }"#;
        let profile: Profile = serde_json::from_str(json).expect("parse");
        assert_eq!(profile.network.credentials, Some(Vec::<String>::new()));

        // With values → Some(["openai"])
        let json =
            r#"{ "meta": { "name": "has-creds" }, "network": { "credentials": ["openai"] } }"#;
        let profile: Profile = serde_json::from_str(json).expect("parse");
        assert_eq!(
            profile.network.credentials,
            Some(vec!["openai".to_string()])
        );
    }

    #[test]
    fn test_extends_field_deserialization() {
        // Single string form
        let json_str = r#"{
            "extends": "claude-code",
            "meta": { "name": "ext-test" }
        }"#;
        let profile: Profile = serde_json::from_str(json_str).expect("parse single");
        assert_eq!(profile.extends, Some(vec!["claude-code".to_string()]));

        // Array form
        let json_str = r#"{
            "extends": ["claude-code", "opencode"],
            "meta": { "name": "ext-multi" }
        }"#;
        let profile: Profile = serde_json::from_str(json_str).expect("parse array");
        assert_eq!(
            profile.extends,
            Some(vec!["claude-code".to_string(), "opencode".to_string()])
        );

        // Absent field
        let json_str = r#"{ "meta": { "name": "no-ext" } }"#;
        let profile: Profile = serde_json::from_str(json_str).expect("parse absent");
        assert!(profile.extends.is_none());

        // Empty array
        let json_str = r#"{ "extends": [], "meta": { "name": "empty-ext" } }"#;
        let profile: Profile = serde_json::from_str(json_str).expect("parse empty array");
        assert!(
            profile.extends.is_none(),
            "empty array should normalize to None"
        );
    }

    #[test]
    fn test_extends_empty_string_in_array_rejected() {
        // An empty string passes deserialization but is caught by load_base_profile_raw
        let profile = Profile {
            extends: Some(vec!["".to_string()]),
            ..Default::default()
        };

        let result = resolve_extends(profile, &mut Vec::new(), 0);
        assert!(result.is_err());
        let err = result.expect_err("empty string base should error");
        assert!(
            err.to_string().contains("invalid base profile name"),
            "Error should mention invalid name: {}",
            err
        );
    }

    // --- Multiple extends tests ---

    #[test]
    fn test_extends_multiple_bases() {
        // Child extends ["a", "b"] — gets merged groups/filesystem from both
        let base_a = Profile {
            extends: None,
            meta: ProfileMeta {
                name: "a".to_string(),
                ..Default::default()
            },
            security: SecurityConfig {
                groups: vec!["group_a".to_string()],
                ..Default::default()
            },
            filesystem: FilesystemConfig {
                allow: vec!["/a/path".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        let base_b = Profile {
            extends: None,
            meta: ProfileMeta {
                name: "b".to_string(),
                ..Default::default()
            },
            security: SecurityConfig {
                groups: vec!["group_b".to_string()],
                ..Default::default()
            },
            filesystem: FilesystemConfig {
                allow: vec!["/b/path".to_string()],
                read: vec!["/b/read".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        let child = Profile {
            extends: Some(vec!["a".to_string(), "b".to_string()]),
            meta: ProfileMeta {
                name: "child".to_string(),
                ..Default::default()
            },
            filesystem: FilesystemConfig {
                allow: vec!["/child/path".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        // Simulate what resolve_extends does: merge a + b, then merge with child
        let merged_bases = merge_profiles(base_a, base_b);
        let merged = merge_profiles(merged_bases, child);

        assert_eq!(merged.meta.name, "child");
        assert!(merged.filesystem.allow.contains(&"/a/path".to_string()));
        assert!(merged.filesystem.allow.contains(&"/b/path".to_string()));
        assert!(merged.filesystem.allow.contains(&"/child/path".to_string()));
        assert!(merged.filesystem.read.contains(&"/b/read".to_string()));
        assert!(merged.security.groups.contains(&"group_a".to_string()));
        assert!(merged.security.groups.contains(&"group_b".to_string()));
        assert!(merged.extends.is_none());
    }

    #[test]
    fn test_extends_multiple_ordering() {
        // Later bases override earlier for scalar fields (network_profile, workdir)
        let base_a = Profile {
            extends: None,
            network: NetworkConfig {
                network_profile: InheritableValue::Set("net-a".to_string()),
                ..Default::default()
            },
            workdir: WorkdirConfig {
                access: WorkdirAccess::Read,
            },
            interactive: false,
            ..Default::default()
        };

        let base_b = Profile {
            extends: None,
            network: NetworkConfig {
                network_profile: InheritableValue::Set("net-b".to_string()),
                ..Default::default()
            },
            workdir: WorkdirConfig {
                access: WorkdirAccess::ReadWrite,
            },
            interactive: true,
            ..Default::default()
        };

        // Merge a then b: b should win for scalars
        let merged = merge_profiles(base_a, base_b);
        assert_eq!(
            merged.network.network_profile,
            InheritableValue::Set("net-b".to_string()),
            "later base should override network_profile"
        );
        assert_eq!(
            merged.workdir.access,
            WorkdirAccess::ReadWrite,
            "later base should override workdir"
        );
        assert!(merged.interactive, "interactive should be OR'd");
    }

    #[test]
    fn test_extends_duplicate_base_deduplicates() {
        // extends: ["opencode", "opencode"] — duplicate is silently skipped
        let profile = Profile {
            extends: Some(vec!["opencode".to_string(), "opencode".to_string()]),
            ..Default::default()
        };

        let result = resolve_extends(profile, &mut Vec::new(), 0);
        assert!(
            result.is_ok(),
            "duplicate base should be deduplicated, not error: {:?}",
            result
        );
    }

    #[test]
    fn test_extends_multiple_builtin_default() {
        // Test extending a single built-in profile (default) via array syntax
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("multi-ext.json");
        std::fs::write(
            &profile_path,
            r#"{
                "extends": ["default"],
                "meta": { "name": "multi-ext-test" },
                "filesystem": { "allow": ["/tmp/multi-ext"] }
            }"#,
        )
        .expect("write profile");

        let profile = load_from_file(&profile_path).expect("load extended profile");
        assert_eq!(profile.meta.name, "multi-ext-test");
        assert!(profile
            .filesystem
            .allow
            .contains(&"/tmp/multi-ext".to_string()));
        assert!(profile.extends.is_none());
    }

    #[test]
    fn test_extends_multiple_shared_transitive_base_deduplicates() {
        // Two built-in profiles that both extend "default" — shared base is deduplicated
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("shared-base.json");
        std::fs::write(
            &profile_path,
            r#"{
                "extends": ["opencode", "opencode"],
                "meta": { "name": "shared-base-test" }
            }"#,
        )
        .expect("write profile");

        let result = load_from_file(&profile_path);
        assert!(
            result.is_ok(),
            "shared transitive base should be deduplicated, not error: {:?}",
            result
        );
        let profile = result.expect("shared base profile");
        assert_eq!(profile.meta.name, "shared-base-test");
    }

    #[test]
    fn test_network_profile_deserialization_distinguishes_absent_null_and_value() {
        let absent: Profile = serde_json::from_str(r#"{ "meta": { "name": "absent" } }"#)
            .expect("parse absent profile");
        assert_eq!(absent.network.network_profile, InheritableValue::Inherit);

        let cleared: Profile = serde_json::from_str(
            r#"{
                "meta": { "name": "cleared" },
                "network": { "network_profile": null }
            }"#,
        )
        .expect("parse cleared profile");
        assert_eq!(cleared.network.network_profile, InheritableValue::Clear);

        let set: Profile = serde_json::from_str(
            r#"{
                "meta": { "name": "set" },
                "network": { "network_profile": "developer" }
            }"#,
        )
        .expect("parse profile with network profile");
        assert_eq!(
            set.network.network_profile,
            InheritableValue::Set("developer".to_string())
        );
    }

    #[test]
    fn test_top_level_schema_field_allowed_in_profile() {
        let profile: Profile = serde_json::from_str(
            r#"{
                "$schema": "https://nono.dev/schemas/nono-profile.schema.json",
                "meta": { "name": "schema-ok" }
            }"#,
        )
        .expect("top-level $schema must be accepted");

        assert_eq!(profile.meta.name, "schema-ok");
    }

    #[test]
    fn test_unknown_fields_rejected_in_profile() {
        // A typo like "add_deny_acces" (missing 's') must be caught at parse
        // time. For a security tool, silently discarding unknown keys means a
        // single typo can void an entire security policy with no feedback.
        let json = r#"{
            "meta": { "name": "typo-test" },
            "policy": {
                "add_deny_acces": ["~/.local/state"]
            }
        }"#;
        let result: std::result::Result<Profile, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "unknown field 'add_deny_acces' must be rejected, not silently ignored"
        );
    }

    #[test]
    fn test_unknown_fields_rejected_in_top_level_profile() {
        // Unknown top-level keys must also be rejected.
        let json = r#"{
            "meta": { "name": "top-level-typo" },
            "polcy": {
                "add_deny_access": ["~/.local/state"]
            }
        }"#;
        let result: std::result::Result<Profile, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "unknown top-level field 'polcy' must be rejected, not silently ignored"
        );
    }

    #[test]
    fn test_policy_patch_deserialization() {
        let profile: Profile = serde_json::from_str(
            r#"{
                "meta": { "name": "patchy" },
                "policy": {
                    "exclude_groups": ["deny_shell_configs"],
                    "add_allow_read": ["/tmp/read"],
                    "add_allow_write": ["/tmp/write"],
                    "add_allow_readwrite": ["/tmp/rw"],
                    "add_deny_access": ["/tmp/deny"],
                    "override_deny": ["~/.docker"]
                }
            }"#,
        )
        .expect("parse profile with policy patch");

        assert_eq!(profile.policy.exclude_groups, vec!["deny_shell_configs"]);
        assert_eq!(profile.policy.add_allow_read, vec!["/tmp/read"]);
        assert_eq!(profile.policy.add_allow_write, vec!["/tmp/write"]);
        assert_eq!(profile.policy.add_allow_readwrite, vec!["/tmp/rw"]);
        assert_eq!(profile.policy.add_deny_access, vec!["/tmp/deny"]);
        assert_eq!(profile.policy.override_deny, vec!["~/.docker"]);
    }

    #[test]
    fn test_network_config_accepts_verb_noun_collection_aliases() {
        let profile: Profile = serde_json::from_str(
            r#"{
                "meta": { "name": "aliases" },
                "network": {
                    "block": true,
                    "allow_proxy": ["api.openai.com"],
                    "allow_port": [3000],
                    "external_proxy": "squid.corp:3128"
                }
            }"#,
        )
        .expect("parse profile with supported aliases");

        assert!(profile.network.block);
        assert_eq!(profile.network.allow_domain, vec!["api.openai.com"]);
        assert_eq!(profile.network.open_port, vec![3000]);
        assert_eq!(
            profile.network.upstream_proxy.as_deref(),
            Some("squid.corp:3128")
        );
    }

    #[test]
    fn test_network_config_serializes_new_names() {
        let profile: Profile = serde_json::from_str(
            r#"{
                "meta": { "name": "canonical" },
                "network": {
                    "allow_domain": ["api.openai.com"],
                    "credentials": ["openai"],
                    "open_port": [3000],
                    "listen_port": [4000],
                    "upstream_proxy": "squid.corp:3128",
                    "upstream_bypass": ["internal.corp"]
                }
            }"#,
        )
        .expect("parse profile with canonical names");

        let serialized = serde_json::to_value(&profile).expect("serialize profile");
        let network = serialized["network"].as_object().expect("network object");

        assert!(network.contains_key("allow_domain"));
        assert!(network.contains_key("credentials"));
        assert!(network.contains_key("open_port"));
        assert!(network.contains_key("listen_port"));
        assert!(network.contains_key("upstream_proxy"));
        assert!(network.contains_key("upstream_bypass"));
    }

    #[test]
    fn test_extends_can_clear_inherited_network_profile_with_null() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let profile_path = dir.path().join("codex-netopen.json");
        std::fs::write(
            &profile_path,
            r#"{
                "meta": { "name": "codex-netopen" },
                "extends": "opencode",
                "network": { "network_profile": null }
            }"#,
        )
        .expect("write profile");

        let profile = load_profile_from_path(&profile_path).expect("load profile");
        assert_eq!(profile.network.resolved_network_profile(), None);
        assert!(!profile.network.has_proxy_flags());
        assert!(
            profile
                .filesystem
                .allow
                .iter()
                .any(|path| path == "$HOME/.opencode"),
            "expected filesystem grants from opencode to still be inherited",
        );
    }

    #[test]
    fn test_signal_mode_allow_same_sandbox_deserializes() {
        let json = r#"{
            "meta": { "name": "sig-test" },
            "filesystem": { "allow": ["/tmp"] },
            "security": { "signal_mode": "allow_same_sandbox" }
        }"#;
        let dir = tempdir().expect("tmpdir");
        let path = dir.path().join("sig-test.json");
        std::fs::write(&path, json).expect("write profile");
        let profile = load_profile_from_path(&path).expect("parse profile");
        assert_eq!(
            profile.security.signal_mode,
            Some(ProfileSignalMode::AllowSameSandbox)
        );
    }

    #[test]
    fn test_security_config_process_info_mode_deserializes() {
        let json = r#"{
            "meta": { "name": "ps-test" },
            "filesystem": { "allow": ["/tmp"] },
            "security": { "process_info_mode": "allow_same_sandbox" }
        }"#;
        let dir = tempdir().expect("tmpdir");
        let path = dir.path().join("ps-test.json");
        std::fs::write(&path, json).expect("write profile");
        let profile = load_profile_from_path(&path).expect("parse profile");
        assert_eq!(
            profile.security.process_info_mode,
            Some(ProfileProcessInfoMode::AllowSameSandbox)
        );
    }

    #[test]
    fn test_security_config_process_info_mode_defaults_none() {
        let json = r#"{ "meta": { "name": "no-pim" }, "filesystem": { "allow": ["/tmp"] } }"#;
        let dir = tempdir().expect("tmpdir");
        let path = dir.path().join("no-pim.json");
        std::fs::write(&path, json).expect("write profile");
        let profile = load_profile_from_path(&path).expect("parse profile");
        assert!(profile.security.process_info_mode.is_none());
    }

    #[test]
    fn test_security_config_process_info_mode_allow_all() {
        let json = r#"{
            "meta": { "name": "pim-alias" },
            "filesystem": { "allow": ["/tmp"] },
            "security": { "process_info_mode": "allow_all" }
        }"#;
        let dir = tempdir().expect("tmpdir");
        let path = dir.path().join("pim-alias.json");
        std::fs::write(&path, json).expect("write profile");
        let profile = load_profile_from_path(&path).expect("parse profile");
        assert_eq!(
            profile.security.process_info_mode,
            Some(ProfileProcessInfoMode::AllowAll)
        );
    }

    #[test]
    fn test_security_config_ipc_mode_full_deserializes() {
        let json = r#"{
            "meta": { "name": "ipc-test" },
            "filesystem": { "allow": ["/tmp"] },
            "security": { "ipc_mode": "full" }
        }"#;
        let dir = tempdir().expect("tmpdir");
        let path = dir.path().join("ipc-test.json");
        std::fs::write(&path, json).expect("write profile");
        let profile = load_profile_from_path(&path).expect("parse profile");
        assert_eq!(profile.security.ipc_mode, Some(ProfileIpcMode::Full));
    }

    #[test]
    fn test_security_config_ipc_mode_defaults_none() {
        let json = r#"{ "meta": { "name": "no-ipc" }, "filesystem": { "allow": ["/tmp"] } }"#;
        let dir = tempdir().expect("tmpdir");
        let path = dir.path().join("no-ipc.json");
        std::fs::write(&path, json).expect("write profile");
        let profile = load_profile_from_path(&path).expect("parse profile");
        assert!(profile.security.ipc_mode.is_none());
    }

    #[test]
    fn test_security_config_ipc_mode_shared_memory_only() {
        let json = r#"{
            "meta": { "name": "ipc-shm" },
            "filesystem": { "allow": ["/tmp"] },
            "security": { "ipc_mode": "shared_memory_only" }
        }"#;
        let dir = tempdir().expect("tmpdir");
        let path = dir.path().join("ipc-shm.json");
        std::fs::write(&path, json).expect("write profile");
        let profile = load_profile_from_path(&path).expect("parse profile");
        assert_eq!(
            profile.security.ipc_mode,
            Some(ProfileIpcMode::SharedMemoryOnly)
        );
    }

    // --- JSON Schema validation tests ---

    /// Helper: validate a JSON string against the embedded profile schema.
    fn validate_against_schema(json_str: &str) -> std::result::Result<(), String> {
        let schema_str = crate::config::embedded::embedded_profile_schema();
        let schema: serde_json::Value =
            serde_json::from_str(schema_str).expect("schema is valid JSON");
        let instance: serde_json::Value =
            serde_json::from_str(json_str).expect("instance is valid JSON");
        let validator = jsonschema::validator_for(&schema).expect("schema compiles");
        let errors: Vec<_> = validator.iter_errors(&instance).collect();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors
                .iter()
                .map(|e| format!("{} at {}", e, e.instance_path()))
                .collect::<Vec<_>>()
                .join("; "))
        }
    }

    #[test]
    fn test_schema_validates_extends_as_string() {
        let json = r#"{
            "extends": "default",
            "meta": { "name": "str-extends" },
            "filesystem": { "allow": ["/tmp/test"] }
        }"#;
        validate_against_schema(json)
            .expect("extends as a single string should pass schema validation");
    }

    #[test]
    fn test_schema_validates_extends_as_array() {
        let json = r#"{
            "extends": ["default", "claude-code"],
            "meta": { "name": "arr-extends" },
            "filesystem": { "allow": ["/tmp/test"] }
        }"#;
        validate_against_schema(json)
            .expect("extends as an array of strings should pass schema validation");
    }

    #[test]
    fn test_schema_validates_extends_single_element_array() {
        let json = r#"{
            "extends": ["default"],
            "meta": { "name": "single-arr" }
        }"#;
        validate_against_schema(json)
            .expect("extends as single-element array should pass schema validation");
    }

    #[test]
    fn test_schema_rejects_extends_empty_array() {
        let json = r#"{
            "extends": [],
            "meta": { "name": "empty-arr" }
        }"#;
        let result = validate_against_schema(json);
        assert!(
            result.is_err(),
            "empty extends array should fail schema validation"
        );
    }

    #[test]
    fn test_schema_rejects_extends_numeric() {
        let json = r#"{
            "extends": 42,
            "meta": { "name": "bad-extends" }
        }"#;
        let result = validate_against_schema(json);
        assert!(
            result.is_err(),
            "numeric extends should fail schema validation"
        );
    }

    #[test]
    fn test_schema_rejects_extends_array_of_non_strings() {
        let json = r#"{
            "extends": [1, 2],
            "meta": { "name": "bad-arr" }
        }"#;
        let result = validate_against_schema(json);
        assert!(
            result.is_err(),
            "array of ints should fail schema validation"
        );
    }

    #[test]
    fn test_schema_validates_absent_extends() {
        let json = r#"{
            "meta": { "name": "no-extends" },
            "filesystem": { "allow": ["/tmp"] }
        }"#;
        validate_against_schema(json).expect("absent extends should pass schema validation");
    }

    #[test]
    fn test_schema_validates_full_profile() {
        let json = r#"{
            "extends": ["default"],
            "meta": {
                "name": "full-test",
                "version": "1.0.0",
                "description": "A test profile",
                "author": "test"
            },
            "security": {
                "groups": ["git_config", "node_runtime"],
                "signal_mode": "isolated",
                "capability_elevation": false
            },
            "filesystem": {
                "allow": ["/tmp/project"],
                "read": ["/etc"],
                "allow_file": ["/tmp/config.json"]
            },
            "policy": {
                "exclude_groups": ["dangerous_commands"],
                "add_allow_read": ["/opt/data"],
                "override_deny": ["/etc/hosts"]
            },
            "network": {
                "block": false,
                "network_profile": "anthropic",
                "proxy_allow": ["extra.example.com"],
                "allow_port": [8080]
            },
            "workdir": { "access": "readwrite" },
            "undo": {
                "exclude_patterns": ["node_modules"],
                "exclude_globs": ["*.tmp"]
            }
        }"#;
        validate_against_schema(json)
            .expect("full profile with array extends should pass schema validation");
    }

    #[test]
    fn test_schema_validates_builtin_profiles_in_policy_json() {
        // Validate that all built-in profiles in policy.json conform to the schema
        let policy_str = include_str!("../../data/policy.json");
        let policy: serde_json::Value =
            serde_json::from_str(policy_str).expect("policy.json is valid JSON");
        let profiles = policy["profiles"]
            .as_object()
            .expect("profiles is an object");

        for (name, profile_value) in profiles {
            let result = validate_against_schema(
                &serde_json::to_string(profile_value).expect("re-serialize"),
            );
            assert!(
                result.is_ok(),
                "built-in profile '{}' should conform to schema: {}",
                name,
                result.expect_err("already checked is_ok")
            );
        }
    }

    // ============================================================================
    // file:// credential key validation tests
    // ============================================================================

    #[test]
    fn test_validate_custom_credential_file_uri_accepted() {
        let cred = CustomCredentialDef {
            upstream: "https://api.example.com".to_string(),
            credential_key: Some("file:///run/secrets/api-token".to_string()),
            auth: None,
            inject_mode: InjectMode::Header,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            endpoint_rules: vec![],
            env_var: Some("EXAMPLE_API_KEY".to_string()),
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
        };
        assert!(
            validate_custom_credential("example", &cred).is_ok(),
            "file:// URI with env_var should be accepted"
        );
    }

    #[test]
    fn test_validate_custom_credential_file_uri_requires_env_var() {
        let cred = CustomCredentialDef {
            upstream: "https://api.example.com".to_string(),
            credential_key: Some("file:///run/secrets/api-token".to_string()),
            auth: None,
            inject_mode: InjectMode::Header,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            endpoint_rules: vec![],
            env_var: None,
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
        };
        let result = validate_custom_credential("example", &cred);
        let err = result.expect_err("file:// URI without env_var should be rejected");
        assert!(
            err.to_string().contains("env_var is required"),
            "error should mention env_var is required, got: {}",
            err
        );
    }

    #[test]
    fn test_validate_custom_credential_file_uri_invalid_rejected() {
        let cred = CustomCredentialDef {
            upstream: "https://api.example.com".to_string(),
            credential_key: Some("file://relative/path".to_string()),
            auth: None,
            inject_mode: InjectMode::Header,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            endpoint_rules: vec![],
            env_var: Some("EXAMPLE_API_KEY".to_string()),
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
        };
        let result = validate_custom_credential("example", &cred);
        let err = result.expect_err("file:// URI with relative path should be rejected");
        assert!(
            err.to_string().contains("file://"),
            "error should mention file://, got: {}",
            err
        );
    }

    #[test]
    fn test_validate_custom_credential_file_uri_traversal_rejected() {
        let cred = CustomCredentialDef {
            upstream: "https://api.example.com".to_string(),
            credential_key: Some("file:///run/secrets/../../../etc/shadow".to_string()),
            auth: None,
            inject_mode: InjectMode::Header,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            endpoint_rules: vec![],
            env_var: Some("EXAMPLE_API_KEY".to_string()),
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
        };
        let result = validate_custom_credential("example", &cred);
        assert!(
            result.is_err(),
            "file:// URI with path traversal should be rejected"
        );
    }

    #[test]
    fn test_validate_env_credentials_accepts_file_uri() {
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "env_credentials": {
                "file:///run/secrets/api-token": "API_TOKEN"
            }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        assert!(
            validate_env_credential_keys(&profile).is_ok(),
            "valid file:// URI in env_credentials should be accepted"
        );
    }

    #[test]
    fn test_validate_env_credentials_rejects_invalid_file_uri() {
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "env_credentials": {
                "file://relative/path": "API_TOKEN"
            }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        let err = validate_env_credential_keys(&profile).expect_err("should reject");
        assert!(
            err.to_string().contains("file://"),
            "error should mention file://, got: {}",
            err
        );
    }

    #[test]
    fn test_profile_json_with_file_uri_custom_credential_parses() {
        // End-to-end: parse a profile JSON with a file:// custom credential
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("file-cred.json");
        std::fs::write(
            &profile_path,
            r#"{
                "meta": { "name": "file-cred-test" },
                "network": {
                    "custom_credentials": {
                        "my_service": {
                            "upstream": "https://api.example.com",
                            "credential_key": "file:///run/secrets/api-token",
                            "env_var": "MY_API_KEY"
                        }
                    }
                }
            }"#,
        )
        .expect("write profile");

        let profile = parse_profile_file(&profile_path).expect("profile should parse");
        let cred = profile
            .network
            .custom_credentials
            .get("my_service")
            .expect("my_service credential should exist");
        assert_eq!(
            cred.credential_key,
            Some("file:///run/secrets/api-token".to_string())
        );
        assert_eq!(cred.env_var, Some("MY_API_KEY".to_string()));
    }
}
