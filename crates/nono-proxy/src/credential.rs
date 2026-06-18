//! Credential loading and management for reverse proxy mode.
//!
//! Loads API credentials from the system keystore or 1Password at proxy startup.
//! Credentials are stored in `Zeroizing<String>` and injected into
//! requests via headers, URL paths, query parameters, or Basic Auth.
//! The sandboxed agent never sees the real credentials.
//!
//! Route-level configuration (upstream URL, L7 endpoint rules, custom TLS CA)
//! is handled by [`crate::route::RouteStore`], which loads independently of
//! credentials. This module handles only credential-specific concerns.

use crate::config::{InjectMode, RouteConfig};
use crate::diagnostic::{ProxyDiagnostic, ProxyDiagnosticCode};
use crate::error::{ProxyError, Result};
use crate::oauth2::{OAuth2ExchangeConfig, TokenCache};
use base64::Engine;
use std::collections::HashMap;
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};
use zeroize::Zeroizing;

/// A loaded credential ready for injection.
///
/// Contains only credential-specific fields (injection mode, header name/value,
/// raw secret). Route-level configuration (upstream URL, L7 endpoint rules,
/// custom TLS CA) is stored in [`crate::route::LoadedRoute`].
pub struct LoadedCredential {
    /// Upstream injection mode
    pub inject_mode: InjectMode,
    /// Proxy-side injection mode used for phantom token parsing.
    pub proxy_inject_mode: InjectMode,
    /// Raw credential value from keystore (for modes that need it directly)
    pub raw_credential: Zeroizing<String>,

    // --- Header mode ---
    /// Header name to inject (e.g., "Authorization")
    pub header_name: String,
    /// Header name used for proxy-side phantom token validation.
    pub proxy_header_name: String,
    /// Formatted header value (e.g., "Bearer sk-...")
    pub header_value: Zeroizing<String>,

    // --- URL path mode ---
    /// Pattern to match in incoming path (with {} placeholder)
    pub path_pattern: Option<String>,
    /// Pattern to match in incoming proxy path (with {} placeholder)
    pub proxy_path_pattern: Option<String>,
    /// Pattern for outgoing path (with {} placeholder)
    pub path_replacement: Option<String>,

    // --- Query param mode ---
    /// Query parameter name
    pub query_param_name: Option<String>,
    /// Proxy-side query parameter name for phantom token validation.
    pub proxy_query_param_name: Option<String>,
}

/// Custom Debug impl that redacts secret values to prevent accidental leakage
/// in logs, panic messages, or debug output.
impl std::fmt::Debug for LoadedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedCredential")
            .field("inject_mode", &self.inject_mode)
            .field("proxy_inject_mode", &self.proxy_inject_mode)
            .field("raw_credential", &"[REDACTED]")
            .field("header_name", &self.header_name)
            .field("proxy_header_name", &self.proxy_header_name)
            .field("header_value", &"[REDACTED]")
            .field("path_pattern", &self.path_pattern)
            .field("proxy_path_pattern", &self.proxy_path_pattern)
            .field("path_replacement", &self.path_replacement)
            .field("query_param_name", &self.query_param_name)
            .field("proxy_query_param_name", &self.proxy_query_param_name)
            .finish()
    }
}

/// An OAuth2 route entry: token cache + upstream URL.
#[derive(Debug)]
pub struct OAuth2Route {
    /// Token cache for automatic refresh
    pub cache: TokenCache,
    /// Upstream URL (e.g., "https://api.example.com")
    pub upstream: String,
}

/// Result of loading credentials at proxy startup.
#[derive(Debug)]
pub struct CredentialLoadOutcome {
    /// Loaded store; may omit routes whose credentials were unavailable.
    pub store: CredentialStore,
    /// Per-route warnings for missing or unavailable credentials.
    pub diagnostics: Vec<ProxyDiagnostic>,
}

impl CredentialLoadOutcome {
    #[must_use]
    pub fn into_store(self) -> CredentialStore {
        self.store
    }
}

/// Credential store for all configured routes.
#[derive(Debug)]
pub struct CredentialStore {
    /// Map from route prefix to loaded credential
    credentials: HashMap<String, LoadedCredential>,
    /// Map from route prefix to OAuth2 route (token cache + upstream)
    oauth2_routes: HashMap<String, OAuth2Route>,
    /// Map from route prefix to AWS SigV4 route (placeholder until full
    /// SigV4 signing is implemented; value is () because no runtime state
    /// is needed yet).
    aws_routes: HashMap<String, ()>,
}

impl CredentialStore {
    /// Load credentials for all configured routes from the system keystore.
    ///
    /// Routes without a `credential_key` or `oauth2` block are skipped (no
    /// credential injection). Routes whose credential is not found remain
    /// configured but unavailable at request time, so managed-credential
    /// requests fail closed instead of silently accepting agent-supplied
    /// upstream credentials.
    ///
    /// OAuth2 routes perform an initial token exchange at startup. If the
    /// exchange fails, the route remains configured but unavailable until
    /// token acquisition succeeds.
    ///
    /// The `tls_connector` is required for OAuth2 token exchange HTTPS calls.
    ///
    /// Returns an error only for hard failures (config parse errors,
    /// non-UTF-8 values). Missing credentials are logged, recorded in
    /// `diagnostics`, and the route is skipped.
    pub fn load_with_diagnostics(
        routes: &[RouteConfig],
        tls_connector: &TlsConnector,
    ) -> Result<CredentialLoadOutcome> {
        let mut credentials = HashMap::new();
        let mut oauth2_routes = HashMap::new();
        let mut aws_routes = HashMap::new();
        let mut diagnostics = Vec::new();

        for route in routes {
            // Normalize prefix: strip leading/trailing slashes so it matches
            // the bare service name returned by parse_service_prefix() in
            // the reverse proxy path (e.g., "/anthropic" -> "anthropic").
            let normalized_prefix = route.prefix.trim_matches('/').to_string();
            if let Some(ref key) = route.credential_key {
                debug!(
                    "Loading credential for route prefix: {} (mode: {:?})",
                    normalized_prefix, route.inject_mode
                );

                let secret = match nono::keystore::load_secret_by_ref(KEYRING_SERVICE, key) {
                    Ok(s) => s,
                    Err(nono::NonoError::SecretNotFound(_)) => {
                        let hint = build_credential_miss_hint(key);
                        let redacted = redact_credential_ref(key);
                        let message = format!(
                            "Credential not found for route '{normalized_prefix}' — \
                             managed-credential requests on this route will be denied until \
                             the credential is available.{hint}"
                        );
                        warn!("{message}");
                        diagnostics.push(
                            ProxyDiagnostic::warning(
                                ProxyDiagnosticCode::CredentialNotFound,
                                &normalized_prefix,
                                message,
                            )
                            .with_credential_ref(redacted)
                            .with_hint(strip_tip_prefix(&hint)),
                        );
                        continue;
                    }
                    Err(nono::NonoError::KeystoreAccess(msg)) => {
                        push_secret_unavailable_diagnostic(
                            &mut diagnostics,
                            ProxyDiagnosticCode::CredentialUnavailable,
                            &normalized_prefix,
                            key,
                            &msg,
                            "Credential",
                            true,
                        );
                        continue;
                    }
                    Err(e) => return Err(ProxyError::Credential(e.to_string())),
                };

                let effective_format = crate::config::resolved_credential_format(
                    route.inject_header.as_str(),
                    route.credential_format.as_deref(),
                );

                let header_value = match route.inject_mode {
                    InjectMode::Header => Zeroizing::new(effective_format.replace("{}", &secret)),
                    InjectMode::BasicAuth => {
                        // Base64 encode the credential for Basic auth
                        let encoded =
                            base64::engine::general_purpose::STANDARD.encode(secret.as_bytes());
                        Zeroizing::new(format!("Basic {}", encoded))
                    }
                    // For url_path and query_param, header_value is not used
                    InjectMode::UrlPath | InjectMode::QueryParam => Zeroizing::new(String::new()),
                };

                credentials.insert(
                    normalized_prefix.clone(),
                    LoadedCredential {
                        inject_mode: route.inject_mode.clone(),
                        proxy_inject_mode: route
                            .proxy
                            .as_ref()
                            .and_then(|p| p.inject_mode.clone())
                            .unwrap_or_else(|| route.inject_mode.clone()),
                        raw_credential: secret,
                        header_name: route.inject_header.clone(),
                        proxy_header_name: route
                            .proxy
                            .as_ref()
                            .and_then(|p| p.inject_header.clone())
                            .unwrap_or_else(|| route.inject_header.clone()),
                        header_value,
                        path_pattern: route.path_pattern.clone(),
                        proxy_path_pattern: route
                            .proxy
                            .as_ref()
                            .and_then(|p| p.path_pattern.clone())
                            .or_else(|| route.path_pattern.clone()),
                        path_replacement: route.path_replacement.clone(),
                        query_param_name: route.query_param_name.clone(),
                        proxy_query_param_name: route
                            .proxy
                            .as_ref()
                            .and_then(|p| p.query_param_name.clone())
                            .or_else(|| route.query_param_name.clone()),
                    },
                );
                continue;
            }

            // OAuth2 client_credentials path
            if let Some(ref oauth2) = route.oauth2 {
                debug!(
                    "Loading OAuth2 credential for route prefix: {}",
                    route.prefix
                );

                let Some(client_id) = load_oauth_keystore_ref(
                    &mut diagnostics,
                    &route.prefix,
                    &oauth2.client_id,
                    "OAuth2 client_id",
                    ProxyDiagnosticCode::OAuthClientIdUnavailable,
                )?
                else {
                    continue;
                };

                let Some(client_secret) = load_oauth_keystore_ref(
                    &mut diagnostics,
                    &route.prefix,
                    &oauth2.client_secret,
                    "OAuth2 client_secret",
                    ProxyDiagnosticCode::OAuthClientSecretUnavailable,
                )?
                else {
                    continue;
                };

                let config = OAuth2ExchangeConfig {
                    token_url: oauth2.token_url.clone(),
                    client_id,
                    client_secret,
                    scope: oauth2.scope.clone(),
                };

                match TokenCache::new(config, tls_connector.clone()) {
                    Ok(cache) => {
                        oauth2_routes.insert(
                            route.prefix.clone(),
                            OAuth2Route {
                                cache,
                                upstream: route.upstream.clone(),
                            },
                        );
                    }
                    Err(e) => {
                        let message = format!(
                            "OAuth2 token exchange failed for route '{}': {e}. \
                             Managed-credential requests on this route will be denied.",
                            route.prefix
                        );
                        warn!("{message}");
                        diagnostics.push(ProxyDiagnostic::warning(
                            ProxyDiagnosticCode::OAuthTokenExchangeFailed,
                            &route.prefix,
                            message,
                        ));
                        continue;
                    }
                }
            } else if route.aws_auth.is_some() {
                // AWS SigV4 path — no credentials to load yet. Register the
                // prefix so get_aws() returns true and the proxy can return
                // 501 Not Implemented. The () value is a placeholder; the
                // real AwsRoute struct will replace it when SigV4 signing is
                // implemented.
                aws_routes.insert(normalized_prefix.clone(), ());
            }
        }

        Ok(CredentialLoadOutcome {
            store: Self {
                credentials,
                oauth2_routes,
                aws_routes,
            },
            diagnostics,
        })
    }

    /// Deprecated wrapper around [`Self::load_with_diagnostics`].
    #[deprecated(
        since = "0.64.0",
        note = "Use `load_with_diagnostics` instead. Will be removed in 1.0.0."
    )]
    pub fn load(routes: &[RouteConfig], tls_connector: &TlsConnector) -> Result<CredentialStore> {
        Self::load_with_diagnostics(routes, tls_connector).map(|outcome| outcome.store)
    }

    /// Create an empty credential store (no credential injection).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            credentials: HashMap::new(),
            oauth2_routes: HashMap::new(),
            aws_routes: HashMap::new(),
        }
    }

    /// Get a static credential for a route prefix, if configured.
    #[must_use]
    pub fn get(&self, prefix: &str) -> Option<&LoadedCredential> {
        self.credentials.get(prefix)
    }

    /// Get an OAuth2 route (token cache + upstream) for a route prefix, if configured.
    #[must_use]
    pub fn get_oauth2(&self, prefix: &str) -> Option<&OAuth2Route> {
        self.oauth2_routes.get(prefix)
    }

    /// Returns `Some(())` if an AWS SigV4 route is configured for the given
    /// prefix, `None` otherwise. The `Option<&()>` return mirrors `get_oauth2`
    /// so call sites can use `.is_some()` uniformly. The value will become
    /// `Option<&AwsRoute>` when SigV4 signing is implemented.
    #[must_use]
    pub fn get_aws(&self, prefix: &str) -> Option<&()> {
        self.aws_routes.get(prefix)
    }

    /// Check if any credentials (static, OAuth2, or AWS) are loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty() && self.oauth2_routes.is_empty() && self.aws_routes.is_empty()
    }

    /// Number of loaded credentials (static + OAuth2 + AWS).
    #[must_use]
    pub fn len(&self) -> usize {
        self.credentials.len() + self.oauth2_routes.len() + self.aws_routes.len()
    }

    /// Returns the set of route prefixes that have loaded credentials
    /// (static keystore, OAuth2, and AWS routes).
    #[must_use]
    pub fn loaded_prefixes(&self) -> std::collections::HashSet<String> {
        self.credentials
            .keys()
            .chain(self.oauth2_routes.keys())
            .chain(self.aws_routes.keys())
            .cloned()
            .collect()
    }
}

/// The keyring service name used by nono for all credentials.
/// Uses the same constant as `nono::keystore::DEFAULT_SERVICE` to ensure consistency.
const KEYRING_SERVICE: &str = nono::keystore::DEFAULT_SERVICE;

const KEYRING_TIMEOUT_HINT: &str = " Set NONO_KEYRING_TIMEOUT_SECS=N (default 120) to wait longer for keychain unlock; 0 disables the timeout.";

fn redact_credential_ref(key: &str) -> String {
    if nono::keystore::is_op_uri(key) {
        nono::keystore::redact_op_uri(key)
    } else if nono::keystore::is_apple_password_uri(key) {
        nono::keystore::redact_apple_password_uri(key)
    } else if nono::keystore::is_keyring_uri(key) {
        nono::keystore::redact_keyring_uri(key)
    } else if nono::keystore::is_bw_uri(key) {
        nono::keystore::redact_bw_uri(key)
    } else if nono::keystore::is_file_uri(key) {
        nono::keystore::redact_file_uri(key)
    } else {
        key.to_string()
    }
}

/// Redact a credential ref and any verbatim repeat of it in a keystore error.
fn keystore_error_detail(key: &str, msg: &str) -> (String, String) {
    let redacted = redact_credential_ref(key);
    let mut detail = msg.replace(key, &redacted);
    // file:// errors quote the absolute path, not the full URI.
    if nono::keystore::is_file_uri(key)
        && let Some(path) = key.strip_prefix("file://")
        && let Some(redacted_path) = redacted.strip_prefix("file://")
    {
        detail = detail.replace(path, redacted_path);
    }
    (redacted, detail)
}

fn push_secret_unavailable_diagnostic(
    diagnostics: &mut Vec<ProxyDiagnostic>,
    code: ProxyDiagnosticCode,
    route_prefix: &str,
    key: &str,
    msg: &str,
    subject: &str,
    keyring_hint: bool,
) {
    let (redacted, detail) = keystore_error_detail(key, msg);
    let timeout = if keyring_hint {
        KEYRING_TIMEOUT_HINT
    } else {
        ""
    };
    let denied = " Managed-credential requests on this route will be denied.";
    let message =
        format!("{subject} not available for route '{route_prefix}': {detail}.{denied}{timeout}");
    warn!(
        "{subject} '{redacted}' not available for route '{route_prefix}': {detail}.{denied}{timeout}"
    );
    diagnostics
        .push(ProxyDiagnostic::warning(code, route_prefix, message).with_credential_ref(redacted));
}

fn load_oauth_keystore_ref(
    diagnostics: &mut Vec<ProxyDiagnostic>,
    route_prefix: &str,
    key: &str,
    subject: &str,
    code: ProxyDiagnosticCode,
) -> Result<Option<Zeroizing<String>>> {
    match nono::keystore::load_secret_by_ref(KEYRING_SERVICE, key) {
        Ok(s) => Ok(Some(s)),
        Err(nono::NonoError::SecretNotFound(msg)) => {
            push_secret_unavailable_diagnostic(
                diagnostics,
                code,
                route_prefix,
                key,
                &msg,
                subject,
                false,
            );
            Ok(None)
        }
        Err(nono::NonoError::KeystoreAccess(msg)) => {
            push_secret_unavailable_diagnostic(
                diagnostics,
                code,
                route_prefix,
                key,
                &msg,
                subject,
                true,
            );
            Ok(None)
        }
        Err(e) => Err(ProxyError::Credential(e.to_string())),
    }
}

/// Remove the leading "Tip:" prefix from credential miss hints.
fn strip_tip_prefix(hint: &str) -> String {
    hint.trim()
        .strip_prefix("Tip:")
        .map(str::trim)
        .unwrap_or(hint.trim())
        .to_string()
}

/// Build a hint for the credential-not-found warning that probes other
/// credential sources for the same name.
///
/// Targets the most common confusion pattern in the wild: a route shipped
/// with `credential_key: env://X` while the user stored their secret in
/// the system keyring (or vice versa). When we detect the secret in a
/// *different* source, we name it explicitly so the user can fix the
/// route's URI in one edit.
///
/// The probe is deliberately scoped: we only check the obvious "you put
/// it in the wrong place" cases (env↔keyring), not URI-managed sources
/// like `op://` or `apple-password://` whose lookups have side effects.
fn build_credential_miss_hint(key: &str) -> String {
    // Case 1: `env://X` failed → the env var isn't set. Check whether a
    // bare-name keyring entry exists; if so, suggest dropping the prefix.
    if let Some(var) = key.strip_prefix("env://") {
        if nono::keystore::load_secret_by_ref(KEYRING_SERVICE, var).is_ok() {
            return format!(
                " Tip: a keyring entry exists for '{}'. Change credential_key to bare \
                 '{}' (no env:// prefix) to use the keyring, or set the env var.",
                var, var
            );
        }
        return format!(
            " Looked for env var '{}' (not set). To add to the macOS keychain: \
             security add-generic-password -s \"nono\" -a \"{}\" -w  — and set credential_key \
             to bare '{}' (no env:// prefix).",
            var, var, var
        );
    }

    // Case 2: bare key (default keyring) failed → check whether the env
    // var of the same name is set; if so, suggest the env:// URI.
    if !key.contains("://") {
        if std::env::var_os(key).is_some() {
            return format!(
                " Tip: env var '{}' is set on the host. Change credential_key to \
                 'env://{}' to use it, or add a keyring entry for '{}'.",
                key, key, key
            );
        }
        if cfg!(target_os = "macos") {
            return format!(
                " To add it to the macOS keychain: security add-generic-password \
                 -s \"nono\" -a \"{}\" -w",
                key
            );
        }
    }

    // URI-managed sources (op://, apple-password://, file://, keyring://)
    // — no automatic cross-probe; the URI scheme is itself an explicit
    // statement of where to look, so we trust the user's intent.
    String::new()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvVarGuard {
        original: Vec<(&'static str, Option<String>)>,
    }

    #[allow(clippy::disallowed_methods)]
    impl EnvVarGuard {
        fn set_all(vars: &[(&'static str, &str)]) -> Self {
            let original = vars
                .iter()
                .map(|(key, _)| (*key, std::env::var(key).ok()))
                .collect::<Vec<_>>();

            for (key, value) in vars {
                // SAFETY: test-only helper; tests using EnvVarGuard are
                // serialised via #[serial] so no concurrent env mutation.
                unsafe { std::env::set_var(key, value) };
            }

            Self { original }
        }
    }

    #[allow(clippy::disallowed_methods)]
    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            for (key, value) in self.original.iter().rev() {
                // SAFETY: test-only restore; same serialisation guarantee as set_all.
                match value {
                    Some(value) => unsafe { std::env::set_var(key, value) },
                    None => unsafe { std::env::remove_var(key) },
                }
            }
        }
    }

    /// Build a TLS connector for tests (never used for real connections).
    fn test_tls_connector() -> TlsConnector {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();
        TlsConnector::from(Arc::new(tls_config))
    }

    #[test]
    fn test_empty_credential_store() {
        let store = CredentialStore::empty();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        assert!(store.get("openai").is_none());
        assert!(store.get("/openai").is_none());
        assert!(store.get_oauth2("/openai").is_none());
    }

    /// `env://X` lookup misses but the env var IS set on the host (the
    /// "I think I added the keychain entry but the route is env://"
    /// case from issue #797): hint should suggest stripping the prefix.
    /// We simulate this by setting the env var inside the test.
    #[test]
    fn test_miss_hint_env_uri_with_keyring_fallback_message() {
        // We can't actually plant a keyring entry in tests, so this case
        // exercises the unconditional macOS fallback / cross-platform
        // suggestion path: the hint should still name the missing var.
        let hint = build_credential_miss_hint("env://NONONO_TEST_MISSING_VAR");
        assert!(
            hint.contains("NONONO_TEST_MISSING_VAR"),
            "hint should name the missing variable, got: {}",
            hint
        );
    }

    /// Bare key (default keyring lookup) misses but env var IS set —
    /// hint should suggest the `env://` URI form.
    #[test]
    fn test_miss_hint_bare_key_with_env_var_set() {
        let _lock = ENV_LOCK.lock().expect("env mutex poisoned");
        let _guard = EnvVarGuard::set_all(&[("NONONO_TEST_BARE_KEY", "secret-value")]);

        let hint = build_credential_miss_hint("NONONO_TEST_BARE_KEY");
        assert!(
            hint.contains("env://NONONO_TEST_BARE_KEY"),
            "hint should suggest env:// URI, got: {}",
            hint
        );
    }

    /// URI-managed sources should not get an automatic cross-probe.
    #[test]
    fn test_miss_hint_op_uri_returns_empty() {
        let hint = build_credential_miss_hint("op://Vault/Item/field");
        assert!(
            hint.is_empty(),
            "URI-managed sources should not get cross-probe hints, got: {}",
            hint
        );
    }

    #[test]
    fn test_loaded_credential_debug_redacts_secrets() {
        // Security: Debug output must NEVER contain real secret values.
        // This prevents accidental leakage in logs, panic messages, or
        // tracing output at debug level.
        let cred = LoadedCredential {
            inject_mode: InjectMode::Header,
            proxy_inject_mode: InjectMode::Header,
            raw_credential: Zeroizing::new("sk-secret-12345".to_string()),
            header_name: "Authorization".to_string(),
            proxy_header_name: "Authorization".to_string(),
            header_value: Zeroizing::new("Bearer sk-secret-12345".to_string()),
            path_pattern: None,
            proxy_path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy_query_param_name: None,
        };

        let debug_output = format!("{:?}", cred);

        // Must contain REDACTED markers
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug output should contain [REDACTED], got: {}",
            debug_output
        );
        // Must NOT contain the actual secret
        assert!(
            !debug_output.contains("sk-secret-12345"),
            "Debug output must not contain the real secret"
        );
        assert!(
            !debug_output.contains("Bearer sk-secret"),
            "Debug output must not contain the formatted secret"
        );
        // Non-secret fields should still be visible
        assert!(debug_output.contains("Authorization"));
    }

    fn oauth2_route_with_refs(
        prefix: &str,
        client_id: &str,
        client_secret: &str,
        token_url: &str,
    ) -> RouteConfig {
        use crate::config::OAuth2Config;

        RouteConfig {
            prefix: prefix.to_string(),
            upstream: "https://api.example.com".to_string(),
            credential_key: None,
            inject_mode: InjectMode::Header,
            inject_header: "Authorization".to_string(),
            credential_format: Some("Bearer {}".to_string()),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: Some("MY_API_KEY".to_string()),
            endpoint_rules: vec![],
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
            oauth2: Some(OAuth2Config {
                token_url: token_url.to_string(),
                client_id: client_id.to_string(),
                client_secret: client_secret.to_string(),
                scope: String::new(),
            }),
            aws_auth: None,
        }
    }

    #[test]
    fn test_load_missing_env_credential_records_credential_not_found() {
        let tls = test_tls_connector();
        let routes = vec![RouteConfig {
            prefix: "preview-missing".to_string(),
            upstream: "https://api.example.com".to_string(),
            credential_key: Some("env://NONO_PROXY_TEST_MISSING_CRED".to_string()),
            inject_mode: InjectMode::Header,
            inject_header: "Authorization".to_string(),
            credential_format: Some("Bearer {}".to_string()),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: None,
            endpoint_rules: vec![],
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
            oauth2: None,
            aws_auth: None,
        }];
        let outcome = CredentialStore::load_with_diagnostics(&routes, &tls).expect("load");
        assert!(outcome.store.is_empty());
        assert_eq!(outcome.diagnostics.len(), 1);
        assert_eq!(
            outcome.diagnostics[0].code,
            ProxyDiagnosticCode::CredentialNotFound
        );
        assert_eq!(
            outcome.diagnostics[0].credential_ref.as_deref(),
            Some("env://NONO_PROXY_TEST_MISSING_CRED")
        );
    }

    #[test]
    fn test_redact_credential_ref_op_uri() {
        assert_eq!(
            redact_credential_ref("op://vault/item/secret"),
            "op://vault/item/<redacted>"
        );
    }

    #[test]
    fn test_keystore_error_detail_redacts_credential_ref_in_message() {
        let cases = [
            (
                "op://Vault/Item/secret",
                "1Password lookup failed for 'op://Vault/Item/secret': timed out",
                "op://Vault/Item/<redacted>",
                "/secret",
            ),
            (
                "file:///run/secrets/api-token",
                "failed to read credential file '/run/secrets/api-token'",
                "/run/secrets/[REDACTED]",
                "api-token",
            ),
        ];
        for (key, msg, want, leak) in cases {
            let (_redacted, detail) = keystore_error_detail(key, msg);
            assert!(
                detail.contains(want),
                "expected redacted fragment '{want}' in '{detail}'"
            );
            assert!(
                !detail.contains(leak),
                "raw credential fragment '{leak}' leaked in '{detail}'"
            );
        }
    }

    #[test]
    fn test_load_oauth2_missing_client_id_records_diagnostic() {
        let tls = test_tls_connector();
        let routes = vec![oauth2_route_with_refs(
            "my-api",
            "env://NONO_PROXY_TEST_MISSING_CLIENT_ID",
            "env://NONO_PROXY_TEST_CLIENT_SECRET",
            "https://127.0.0.1:1/oauth/token",
        )];
        let outcome = CredentialStore::load_with_diagnostics(&routes, &tls).expect("load");
        assert!(outcome.store.is_empty());
        assert_eq!(outcome.diagnostics.len(), 1);
        assert_eq!(
            outcome.diagnostics[0].code,
            ProxyDiagnosticCode::OAuthClientIdUnavailable
        );
    }

    #[test]
    fn test_load_oauth2_missing_client_secret_records_diagnostic() {
        let _lock = ENV_LOCK.lock().expect("env mutex poisoned");
        let _env = EnvVarGuard::set_all(&[("NONO_PROXY_TEST_CLIENT_ID", "test-client")]);
        let tls = test_tls_connector();
        let routes = vec![oauth2_route_with_refs(
            "my-api",
            "env://NONO_PROXY_TEST_CLIENT_ID",
            "env://NONO_PROXY_TEST_MISSING_CLIENT_SECRET",
            "https://127.0.0.1:1/oauth/token",
        )];
        let outcome = CredentialStore::load_with_diagnostics(&routes, &tls).expect("load");
        assert!(outcome.store.is_empty());
        assert_eq!(outcome.diagnostics.len(), 1);
        assert_eq!(
            outcome.diagnostics[0].code,
            ProxyDiagnosticCode::OAuthClientSecretUnavailable
        );
    }

    #[test]
    fn test_load_no_credential_routes() {
        let tls = test_tls_connector();
        let routes = vec![RouteConfig {
            prefix: "/test".to_string(),
            upstream: "https://example.com".to_string(),
            credential_key: None,
            inject_mode: InjectMode::Header,
            inject_header: "Authorization".to_string(),
            credential_format: Some("Bearer {}".to_string()),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: None,
            endpoint_rules: vec![],
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
            oauth2: None,
            aws_auth: None,
        }];
        let outcome = CredentialStore::load_with_diagnostics(&routes, &tls);
        assert!(outcome.is_ok());
        let store = outcome
            .unwrap_or_else(|_| CredentialLoadOutcome {
                store: CredentialStore::empty(),
                diagnostics: Vec::new(),
            })
            .store;
        assert!(store.is_empty());
    }

    #[test]
    fn test_get_oauth2_returns_none_for_non_oauth2_routes() {
        let store = CredentialStore::empty();
        assert!(store.get_oauth2("openai").is_none());
        assert!(store.get_oauth2("my-api").is_none());
    }

    #[test]
    fn test_is_empty_false_with_only_oauth2_routes() {
        // Simulate a store with only OAuth2 routes by constructing directly.
        // We can't call load() with a real OAuth2 config (no token server),
        // so we build the struct manually to test the is_empty/len logic.
        use std::time::Duration;

        let cache = make_test_token_cache("test-token", Duration::from_secs(3600));
        let mut oauth2_routes = HashMap::new();
        oauth2_routes.insert(
            "my-api".to_string(),
            OAuth2Route {
                cache,
                upstream: "https://api.example.com".to_string(),
            },
        );

        let store = CredentialStore {
            credentials: HashMap::new(),
            oauth2_routes,
            aws_routes: HashMap::new(),
        };

        assert!(
            !store.is_empty(),
            "store with OAuth2 routes should not be empty"
        );
        assert_eq!(store.len(), 1);
        assert!(store.get_oauth2("my-api").is_some());
        assert!(store.get("my-api").is_none());
    }

    #[test]
    fn test_loaded_prefixes_includes_oauth2() {
        use std::time::Duration;

        let cache = make_test_token_cache("test-token", Duration::from_secs(3600));
        let mut oauth2_routes = HashMap::new();
        oauth2_routes.insert(
            "my-api".to_string(),
            OAuth2Route {
                cache,
                upstream: "https://api.example.com".to_string(),
            },
        );

        let store = CredentialStore {
            credentials: HashMap::new(),
            oauth2_routes,
            aws_routes: HashMap::new(),
        };

        let prefixes = store.loaded_prefixes();
        assert!(prefixes.contains("my-api"));
    }

    #[test]
    fn test_load_non_authorization_header_explicit_bearer_format() {
        let _lock = ENV_LOCK.lock().expect("env mutex poisoned");
        let _guard = EnvVarGuard::set_all(&[("NONO_PROXY_TEST_LITELLM_TOKEN", "sk-litellm-test")]);
        let tls = test_tls_connector();
        let routes = vec![RouteConfig {
            prefix: "litellm".to_string(),
            upstream: "https://litellm".to_string(),
            credential_key: Some("env://NONO_PROXY_TEST_LITELLM_TOKEN".to_string()),
            inject_mode: InjectMode::Header,
            inject_header: "x-litellm-api-key".to_string(),
            credential_format: Some("Bearer {}".to_string()),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: None,
            endpoint_rules: vec![],
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
            oauth2: None,
            aws_auth: None,
        }];
        let store = CredentialStore::load_with_diagnostics(&routes, &tls)
            .expect("credential load")
            .store;
        let cred = store.get("litellm").expect("route should be loaded");
        assert_eq!(cred.header_name, "x-litellm-api-key");
        assert_eq!(cred.header_value.as_str(), "Bearer sk-litellm-test");
    }

    #[test]
    fn test_load_non_authorization_header_omitted_format_injects_bare_secret() {
        let _lock = ENV_LOCK.lock().expect("env mutex poisoned");
        let _guard = EnvVarGuard::set_all(&[("NONO_PROXY_TEST_API_KEY", "secret-key")]);
        let tls = test_tls_connector();
        let routes = vec![RouteConfig {
            prefix: "api".to_string(),
            upstream: "https://api.example.com".to_string(),
            credential_key: Some("env://NONO_PROXY_TEST_API_KEY".to_string()),
            inject_mode: InjectMode::Header,
            inject_header: "x-api-key".to_string(),
            credential_format: None,
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: None,
            endpoint_rules: vec![],
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
            oauth2: None,
            aws_auth: None,
        }];
        let store = CredentialStore::load_with_diagnostics(&routes, &tls)
            .expect("credential load")
            .store;
        let cred = store.get("api").expect("route should be loaded");
        assert_eq!(cred.header_value.as_str(), "secret-key");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_load_oauth2_unreachable_endpoint_skips_route() {
        use crate::config::OAuth2Config;

        let _lock = ENV_LOCK.lock().unwrap();
        let _env = EnvVarGuard::set_all(&[
            ("TEST_OAUTH2_CLIENT_ID", "test-client"),
            ("TEST_OAUTH2_CLIENT_SECRET", "test-secret"),
        ]);
        let tls = test_tls_connector();
        let routes = vec![RouteConfig {
            prefix: "my-api".to_string(),
            upstream: "https://api.example.com".to_string(),
            credential_key: None,
            inject_mode: InjectMode::Header,
            inject_header: "Authorization".to_string(),
            credential_format: Some("Bearer {}".to_string()),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: Some("MY_API_KEY".to_string()),
            endpoint_rules: vec![],
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
            oauth2: Some(OAuth2Config {
                // Non-routable address: exchange will fail at TCP connect
                token_url: "https://127.0.0.1:1/oauth/token".to_string(),
                // Use env:// refs that point at test env vars
                client_id: "env://TEST_OAUTH2_CLIENT_ID".to_string(),
                client_secret: "env://TEST_OAUTH2_CLIENT_SECRET".to_string(),
                scope: String::new(),
            }),
            aws_auth: None,
        }];

        let outcome = CredentialStore::load_with_diagnostics(&routes, &tls);

        // load() should succeed (route skipped, not hard error)
        assert!(
            outcome.is_ok(),
            "load should not fail on unreachable OAuth2 endpoint"
        );
        let outcome = outcome.unwrap();
        let store = outcome.store;

        // The route should have been skipped (token exchange failed)
        assert!(
            store.is_empty(),
            "unreachable OAuth2 endpoint should result in skipped route"
        );
        assert!(store.get_oauth2("my-api").is_none());
        assert_eq!(outcome.diagnostics.len(), 1);
        assert_eq!(
            outcome.diagnostics[0].code,
            ProxyDiagnosticCode::OAuthTokenExchangeFailed
        );
    }

    /// Build a test `TokenCache` with a pre-populated token.
    fn make_test_token_cache(token: &str, ttl: std::time::Duration) -> TokenCache {
        use crate::oauth2::OAuth2ExchangeConfig;

        let config = OAuth2ExchangeConfig {
            token_url: "https://127.0.0.1:1/oauth/token".to_string(),
            client_id: Zeroizing::new("test-client".to_string()),
            client_secret: Zeroizing::new("test-secret".to_string()),
            scope: String::new(),
        };

        TokenCache::new_from_parts(config, test_tls_connector(), token, ttl)
    }
}
