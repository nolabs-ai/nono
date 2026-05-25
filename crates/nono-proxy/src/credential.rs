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
use base64::Engine;
use std::collections::HashMap;
use tracing::{debug, warn};
use zeroize::Zeroizing;

/// A loaded credential ready for injection.
///
/// Contains only credential-specific fields (injection mode, header name/value,
/// raw secret). Route-level configuration (upstream URL, L7 endpoint rules,
/// custom TLS CA) is stored in [`crate::route::LoadedRoute`].
pub struct LoadedCredential {
    /// Injection mode
    pub inject_mode: InjectMode,
    /// Raw credential value from keystore (for modes that need it directly)
    pub raw_credential: Zeroizing<String>,

    // --- Header mode ---
    /// Header name to inject (e.g., "Authorization")
    pub header_name: String,
    /// Formatted header value (e.g., "Bearer sk-...")
    pub header_value: Zeroizing<String>,

    // --- URL path mode ---
    /// Pattern to match in incoming path (with {} placeholder)
    pub path_pattern: Option<String>,
    /// Pattern for outgoing path (with {} placeholder)
    pub path_replacement: Option<String>,

    // --- Query param mode ---
    /// Query parameter name
    pub query_param_name: Option<String>,
}

/// Custom Debug impl that redacts secret values to prevent accidental leakage
/// in logs, panic messages, or debug output.
impl std::fmt::Debug for LoadedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedCredential")
            .field("inject_mode", &self.inject_mode)
            .field("raw_credential", &"[REDACTED]")
            .field("header_name", &self.header_name)
            .field("header_value", &"[REDACTED]")
            .field("path_pattern", &self.path_pattern)
            .field("path_replacement", &self.path_replacement)
            .field("query_param_name", &self.query_param_name)
            .finish()
    }
}

/// Credential store for all configured routes.
///
/// # Credential-match policy (D-20 replay of upstream f77e0e3)
///
/// Upstream `f77e0e3` ("absolute match / 2 matches = deny / no match =
/// passthrough w no creds") defines selection semantics when **multiple
/// credential routes share the same upstream host** (e.g. two GitHub
/// orgs with different tokens injected at TLS-intercept time based on
/// the inner-request path). Per D-40-B2, the fork does NOT host the
/// `tls_intercept` module that owns that selection algorithm. Instead,
/// the fork's reverse proxy is **path-prefix routed**: each request's
/// service prefix is parsed from the path (see
/// [`crate::reverse::parse_service_prefix`]) and looked up directly in
/// [`CredentialStore::get`]. The three f77e0e3 cases collapse as
/// follows in the fork's architecture:
///
/// 1. **Absolute match** — one and only one credential per service
///    prefix is structurally enforced: `credentials` is a
///    `HashMap<String, LoadedCredential>` keyed by prefix, so each
///    prefix maps to at most one credential by construction. There is
///    no path through which two `LoadedCredential` values can be
///    selected for one request.
///
/// 2. **2-match-deny** — structurally impossible in this store. The
///    upstream "ambiguous selection" case only arises when multiple
///    routes share an upstream host AND the inner-request path can
///    match more than one route's `endpoint_rules`. Both preconditions
///    require the TLS-intercept multi-route dispatch surface that the
///    fork does not have.
///
/// 3. **No match → passthrough with no credentials** — already the
///    fork's behavior: `get(&prefix)` returns `None` when no
///    credential is configured for the service prefix, and the
///    downstream reverse-proxy code path forwards the request without
///    injecting any credential header / URL transform. This is
///    semantically Option A (uniform no-creds passthrough) from the
///    Plan 40-06 D-40-B2 Windows-fallback decision: see the disposition
///    commit body for the explicit Windows-side analysis (no
///    Windows-specific credential fallback exists in the fork; Windows
///    credential injection is a transitive consequence of
///    `nono::keystore::load_secret_by_ref` using the `keyring v3`
///    crate, which is cross-platform).
#[derive(Debug)]
pub struct CredentialStore {
    /// Map from route prefix to loaded credential.
    ///
    /// Single-credential-per-prefix is a structural invariant of
    /// `HashMap`; this guarantees the f77e0e3 "absolute match" case
    /// without runtime checks.
    credentials: HashMap<String, LoadedCredential>,
}

impl CredentialStore {
    /// Load credentials for all configured routes from the system keystore.
    ///
    /// Routes without a `credential_key` are skipped (no credential injection).
    /// Routes whose credential is not found (e.g. unset env var) are skipped
    /// with a warning — this allows profiles to declare optional credentials
    /// without failing when they are unavailable.
    ///
    /// Returns an error only for hard failures (config parse errors,
    /// non-UTF-8 values). Missing or inaccessible credentials are logged
    /// as warnings and the route is skipped.
    pub fn load(routes: &[RouteConfig]) -> Result<Self> {
        let mut credentials = HashMap::new();

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
                    Err(nono::NonoError::SecretNotFound(msg)) => {
                        debug!(
                            "Credential '{}' not available, skipping route: {}",
                            normalized_prefix, msg
                        );
                        continue;
                    }
                    Err(nono::NonoError::KeystoreAccess(msg)) => {
                        warn!(
                            "Credential '{}' not available for route '{}': {}. \
                             Managed-credential requests on this route will be denied until the credential is available.",
                            key, normalized_prefix, msg
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
                        raw_credential: secret,
                        header_name: route.inject_header.clone(),
                        header_value,
                        path_pattern: route.path_pattern.clone(),
                        path_replacement: route.path_replacement.clone(),
                        query_param_name: route.query_param_name.clone(),
                    },
                );
            }
        }

        Ok(Self { credentials })
    }

    /// Create an empty credential store (no credential injection).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            credentials: HashMap::new(),
        }
    }

    /// Get a credential for a route prefix, if configured.
    ///
    /// Returns `None` for a no-match lookup; callers MUST treat that as
    /// **passthrough with no credentials injected** (per the D-20 replay
    /// of upstream f77e0e3 "no match = passthrough w no creds"). This
    /// fail-secure default applies uniformly across Linux / macOS /
    /// Windows — the fork has no Windows-specific credential fallback
    /// path that could silently inject a credential on a no-prefix-match
    /// (Windows credential injection is a transitive property of
    /// `nono::keystore::load_secret_by_ref` invoked from
    /// [`CredentialStore::load`], not a separate "if Windows, try
    /// Credential Manager again" branch). See the `CredentialStore`
    /// struct-level doc for the full policy analysis.
    #[must_use]
    pub fn get(&self, prefix: &str) -> Option<&LoadedCredential> {
        self.credentials.get(prefix)
    }

    /// Check if any credentials are loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty()
    }

    /// Number of loaded credentials.
    #[must_use]
    pub fn len(&self) -> usize {
        self.credentials.len()
    }

    /// Returns the set of route prefixes that have loaded credentials.
    #[must_use]
    pub fn loaded_prefixes(&self) -> std::collections::HashSet<String> {
        self.credentials.keys().cloned().collect()
    }
}

/// The keyring service name used by nono for all credentials.
/// Uses the same constant as `nono::keystore::DEFAULT_SERVICE` to ensure consistency.
const KEYRING_SERVICE: &str = nono::keystore::DEFAULT_SERVICE;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_credential_store() {
        let store = CredentialStore::empty();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        assert!(store.get("openai").is_none());
    }

    #[test]
    fn test_loaded_credential_debug_redacts_secrets() {
        // Security: Debug output must NEVER contain real secret values.
        // This prevents accidental leakage in logs, panic messages, or
        // tracing output at debug level.
        let cred = LoadedCredential {
            inject_mode: InjectMode::Header,
            raw_credential: Zeroizing::new("sk-secret-12345".to_string()),
            header_name: "Authorization".to_string(),
            header_value: Zeroizing::new("Bearer sk-secret-12345".to_string()),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
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
            env_var: None,
            endpoint_rules: vec![],
            tls_ca: None,
            oauth2: None,
        }];
        let store = CredentialStore::load(&routes);
        assert!(store.is_ok());
        let store = store.unwrap_or_else(|_| CredentialStore::empty());
        assert!(store.is_empty());
    }

    // Minimal env-var save/restore helper for tests in this module.
    // Fork: nono-proxy does not depend on nono-cli's test_env module.
    // CLAUDE.md: env vars modified in tests must be saved and restored;
    // tests are run in parallel within the same process.
    struct TestEnvGuard {
        key: &'static str,
        prior: Option<String>,
    }
    impl TestEnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let prior = std::env::var(key).ok();
            // SAFETY: test-only; no threads spawned between set and restore.
            #[allow(unsafe_code)]
            unsafe {
                std::env::set_var(key, value);
            }
            Self { key, prior }
        }
    }
    impl Drop for TestEnvGuard {
        fn drop(&mut self) {
            // SAFETY: symmetric restore in Drop; matches the set_var above.
            #[allow(unsafe_code)]
            unsafe {
                match &self.prior {
                    Some(v) => std::env::set_var(self.key, v),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }

    #[test]
    fn test_load_non_authorization_header_explicit_bearer_format() {
        // Test Case B: explicit 'Bearer {}' on custom inject header → honored exactly.
        // Fork adaptation: uses inline env guard (no nono-cli test_env dependency);
        // RouteConfig uses fork struct (no proxy/tls_client_cert/tls_client_key fields).
        let _guard = TestEnvGuard::set("NONO_PROXY_TEST_LITELLM_TOKEN", "sk-litellm-test");
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
            env_var: None,
            endpoint_rules: vec![],
            tls_ca: None,
            oauth2: None,
        }];
        // Fork: CredentialStore::load takes only routes (no TLS connector arg)
        let store = CredentialStore::load(&routes).expect("credential load");
        let cred = store.get("litellm").expect("route should be loaded");
        assert_eq!(cred.header_name, "x-litellm-api-key");
        assert_eq!(cred.header_value.as_str(), "Bearer sk-litellm-test");
    }

    #[test]
    fn test_load_non_authorization_header_omitted_format_injects_bare_secret() {
        // Test Case C: credential_format omitted on non-Authorization header → bare secret.
        // Fork adaptation: uses inline env guard; RouteConfig uses fork struct.
        let _guard = TestEnvGuard::set("NONO_PROXY_TEST_API_KEY", "secret-key");
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
            env_var: None,
            endpoint_rules: vec![],
            tls_ca: None,
            oauth2: None,
        }];
        // Fork: CredentialStore::load takes only routes (no TLS connector arg)
        let store = CredentialStore::load(&routes).expect("credential load");
        let cred = store.get("api").expect("route should be loaded");
        assert_eq!(cred.header_value.as_str(), "secret-key");
    }
}
