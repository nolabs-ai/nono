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

/// Credential store for all configured routes.
#[derive(Debug)]
pub struct CredentialStore {
    /// Map from route prefix to loaded credential
    credentials: HashMap<String, LoadedCredential>,
    /// Map from route prefix to OAuth2 route (token cache + upstream)
    oauth2_routes: HashMap<String, OAuth2Route>,
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
    /// non-UTF-8 values). Missing or inaccessible credentials are logged
    /// as warnings and the route is skipped.
    pub fn load(routes: &[RouteConfig], tls_connector: &TlsConnector) -> Result<Self> {
        let mut credentials = HashMap::new();
        let mut oauth2_routes = HashMap::new();

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
                        warn!(
                            "Credential '{}' not found for route '{}' — managed-credential requests on this route will be denied until the credential is available.{}",
                            key, normalized_prefix, hint
                        );
                        continue;
                    }
                    Err(nono::NonoError::KeystoreAccess(msg)) => {
                        let redacted = redact_credential_ref(key);
                        warn!(
                            "Credential '{}' not available for route '{}': {}. \
                             Managed-credential requests on this route will be denied until the credential is available. \
                             Set NONO_KEYRING_TIMEOUT_SECS=N (default 120) to wait longer for keychain unlock; 0 disables the timeout.",
                            redacted, normalized_prefix, msg
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

                let client_id = match nono::keystore::load_secret_by_ref(
                    KEYRING_SERVICE,
                    &oauth2.client_id,
                ) {
                    Ok(s) => s,
                    Err(nono::NonoError::SecretNotFound(msg))
                    | Err(nono::NonoError::KeystoreAccess(msg)) => {
                        let redacted = redact_credential_ref(&oauth2.client_id);
                        warn!(
                            "OAuth2 client_id '{}' not available for route '{}': {}. \
                                 Managed-credential requests on this route will be denied. \
                                 Set NONO_KEYRING_TIMEOUT_SECS=N (default 120) to wait longer for keychain unlock; 0 disables the timeout.",
                            redacted, route.prefix, msg
                        );
                        continue;
                    }
                    Err(e) => return Err(ProxyError::Credential(e.to_string())),
                };

                let client_secret = match nono::keystore::load_secret_by_ref(
                    KEYRING_SERVICE,
                    &oauth2.client_secret,
                ) {
                    Ok(s) => s,
                    Err(nono::NonoError::SecretNotFound(msg))
                    | Err(nono::NonoError::KeystoreAccess(msg)) => {
                        let redacted = redact_credential_ref(&oauth2.client_secret);
                        warn!(
                            "OAuth2 client_secret '{}' not available for route '{}': {}. \
                             Managed-credential requests on this route will be denied. \
                             Set NONO_KEYRING_TIMEOUT_SECS=N (default 120) to wait longer for keychain unlock; 0 disables the timeout.",
                            redacted, route.prefix, msg
                        );
                        continue;
                    }
                    Err(e) => return Err(ProxyError::Credential(e.to_string())),
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
                        warn!(
                            "OAuth2 token exchange failed for route '{}': {}. \
                             Managed-credential requests on this route will be denied.",
                            route.prefix, e
                        );
                        continue;
                    }
                }
            }
        }

        Ok(Self {
            credentials,
            oauth2_routes,
        })
    }

    /// Create an empty credential store (no credential injection).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            credentials: HashMap::new(),
            oauth2_routes: HashMap::new(),
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

    /// Check if any credentials (static or OAuth2) are loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty() && self.oauth2_routes.is_empty()
    }

    /// Number of loaded credentials (static + OAuth2).
    #[must_use]
    pub fn len(&self) -> usize {
        self.credentials.len() + self.oauth2_routes.len()
    }

    /// Returns the set of route prefixes that have loaded credentials
    /// (both static keystore and OAuth2 routes).
    #[must_use]
    pub fn loaded_prefixes(&self) -> std::collections::HashSet<String> {
        self.credentials
            .keys()
            .chain(self.oauth2_routes.keys())
            .cloned()
            .collect()
    }
}

/// The keyring service name used by nono for all credentials.
/// Uses the same constant as `nono::keystore::DEFAULT_SERVICE` to ensure consistency.
const KEYRING_SERVICE: &str = nono::keystore::DEFAULT_SERVICE;

/// Redact a credential reference for safe display in warnings.
///
/// Delegates to the appropriate URI-specific redaction helper so that
/// secrets (account names, file paths, field names) are never echoed raw.
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
        }];
        let store = CredentialStore::load(&routes, &tls);
        assert!(store.is_ok());
        let store = store.unwrap_or_else(|_| CredentialStore::empty());
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
        }];
        let store = CredentialStore::load(&routes, &tls).expect("credential load");
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
        }];
        let store = CredentialStore::load(&routes, &tls).expect("credential load");
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
        }];

        let store = CredentialStore::load(&routes, &tls);

        // load() should succeed (route skipped, not hard error)
        assert!(
            store.is_ok(),
            "load should not fail on unreachable OAuth2 endpoint"
        );
        let store = store.unwrap();

        // The route should have been skipped (token exchange failed)
        assert!(
            store.is_empty(),
            "unreachable OAuth2 endpoint should result in skipped route"
        );
        assert!(store.get_oauth2("my-api").is_none());
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
