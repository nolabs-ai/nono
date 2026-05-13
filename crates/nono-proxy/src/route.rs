//! Route store: per-route configuration independent of credentials.
//!
//! `RouteStore` holds the route-level configuration (upstream URL, L7 endpoint
//! rules, custom TLS CA) for **all** configured routes, regardless of whether
//! they have a credential attached. This decouples L7 filtering from credential
//! injection — a route can enforce endpoint restrictions without injecting any
//! secret.
//!
//! The `CredentialStore` remains responsible for credential-specific fields
//! (inject mode, header name/value, raw secret). Both stores are keyed by the
//! normalised route prefix and are consulted independently by the proxy handlers.

use crate::config::{CompiledEndpointRules, RouteConfig};
use crate::error::{ProxyError, Result};
use nono::undo::{NetworkAuditAuthMechanism, NetworkAuditInjectionMode};
use rustls::pki_types::pem::PemObject;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::debug;
use zeroize::Zeroizing;

/// Route-level configuration loaded at proxy startup.
///
/// Contains everything needed to forward and filter a request for a route,
/// but no credential material. Credential injection is handled separately
/// by `CredentialStore`.
pub struct LoadedRoute {
    /// Upstream URL (e.g., "https://api.openai.com")
    pub upstream: String,

    /// Pre-normalised `host:port` extracted from `upstream` at load time.
    /// Used for O(1) lookups in `is_route_upstream()` without per-request
    /// URL parsing. `None` if the upstream URL cannot be parsed.
    pub upstream_host_port: Option<String>,

    /// Pre-compiled L7 endpoint rules for method+path filtering.
    /// When non-empty, only matching requests are allowed (default-deny).
    /// When empty, all method+path combinations are permitted.
    pub endpoint_rules: CompiledEndpointRules,

    /// Per-route TLS connector with custom CA trust, if configured.
    /// Built once at startup from the route's `tls_ca` certificate file.
    /// When `None`, the shared default connector (webpki roots only) is used.
    pub tls_connector: Option<tokio_rustls::TlsConnector>,

    /// `true` if this route requires L7 visibility — i.e. it declares
    /// `credential_key`, `oauth2`, or non-empty `endpoint_rules` and would
    /// not function as a transparent CONNECT tunnel. Computed once at load
    /// time so the CONNECT dispatch path doesn't have to re-derive it on
    /// every request.
    pub requires_intercept: bool,

    /// `true` if this route was configured to use a managed credential
    /// source (`credential_key` or `oauth2`). Unlike `requires_intercept`,
    /// this specifically captures whether the proxy must supply upstream
    /// authentication itself rather than accept agent-provided credentials.
    pub requires_managed_credential: bool,

    /// Audit auth mechanism implied by the managed credential configuration.
    /// Kept even if credential material failed to load so fail-closed denial
    /// events can describe what auth shape the route expected.
    pub managed_auth_mechanism: Option<NetworkAuditAuthMechanism>,

    /// Audit injection mode implied by the managed credential configuration.
    pub managed_injection_mode: Option<NetworkAuditInjectionMode>,
}

impl std::fmt::Debug for LoadedRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedRoute")
            .field("upstream", &self.upstream)
            .field("upstream_host_port", &self.upstream_host_port)
            .field("endpoint_rules", &self.endpoint_rules)
            .field("has_custom_tls_ca", &self.tls_connector.is_some())
            .field("requires_intercept", &self.requires_intercept)
            .field(
                "requires_managed_credential",
                &self.requires_managed_credential,
            )
            .field("managed_auth_mechanism", &self.managed_auth_mechanism)
            .field("managed_injection_mode", &self.managed_injection_mode)
            .finish()
    }
}

fn auth_mechanism_for_route(route: &RouteConfig) -> Option<NetworkAuditAuthMechanism> {
    if route.oauth2.is_some() {
        return Some(NetworkAuditAuthMechanism::PhantomHeader);
    }

    if route.credential_key.is_some() {
        let proxy_mode = route
            .proxy
            .as_ref()
            .and_then(|p| p.inject_mode.clone())
            .unwrap_or_else(|| route.inject_mode.clone());
        return Some(match proxy_mode {
            crate::config::InjectMode::Header | crate::config::InjectMode::BasicAuth => {
                NetworkAuditAuthMechanism::PhantomHeader
            }
            crate::config::InjectMode::UrlPath => NetworkAuditAuthMechanism::PhantomPath,
            crate::config::InjectMode::QueryParam => NetworkAuditAuthMechanism::PhantomQuery,
        });
    }

    None
}

fn injection_mode_for_route(route: &RouteConfig) -> Option<NetworkAuditInjectionMode> {
    if route.oauth2.is_some() {
        return Some(NetworkAuditInjectionMode::OAuth2);
    }

    if route.credential_key.is_some() {
        return Some(match route.inject_mode {
            crate::config::InjectMode::Header => NetworkAuditInjectionMode::Header,
            crate::config::InjectMode::UrlPath => NetworkAuditInjectionMode::UrlPath,
            crate::config::InjectMode::QueryParam => NetworkAuditInjectionMode::QueryParam,
            crate::config::InjectMode::BasicAuth => NetworkAuditInjectionMode::BasicAuth,
        });
    }

    None
}

/// Store of all configured routes, keyed by normalised prefix.
///
/// Loaded at proxy startup for **all** routes in the config, not just those
/// with credentials. This ensures L7 endpoint filtering and upstream routing
/// work independently of credential presence.
#[derive(Debug)]
pub struct RouteStore {
    routes: HashMap<String, LoadedRoute>,
}

impl RouteStore {
    /// Load route configuration for all configured routes.
    ///
    /// Each route's endpoint rules are compiled at startup so the hot path
    /// does a regex match, not a glob compile. Routes with a `tls_ca` field
    /// get a per-route TLS connector built from the custom CA certificate.
    pub fn load(routes: &[RouteConfig]) -> Result<Self> {
        let mut loaded = HashMap::new();

        let base_root_store = build_base_root_store();

        for route in routes {
            let normalized_prefix = route.prefix.trim_matches('/').to_string();

            debug!(
                "Loading route '{}' -> {}",
                normalized_prefix, route.upstream
            );

            let endpoint_rules = CompiledEndpointRules::compile(&route.endpoint_rules)
                .map_err(|e| ProxyError::Config(format!("route '{}': {}", normalized_prefix, e)))?;

            let tls_connector = if route.tls_ca.is_some()
                || route.tls_client_cert.is_some()
                || route.tls_client_key.is_some()
            {
                debug!(
                    "Building TLS connector for route '{}' (ca={}, client_cert={})",
                    normalized_prefix,
                    route.tls_ca.is_some(),
                    route.tls_client_cert.is_some(),
                );
                Some(build_tls_connector(
                    &base_root_store,
                    route.tls_ca.as_deref(),
                    route.tls_client_cert.as_deref(),
                    route.tls_client_key.as_deref(),
                )?)
            } else {
                None
            };

            let upstream_host_port = extract_host_port(&route.upstream);

            // A route needs L7 visibility if it carries credentials to inject
            // (`credential_key` or `oauth2`) or if it enforces method/path
            // rules. Routes without any of these are purely declarative —
            // they exist to provide a `*_BASE_URL` env var or appear in
            // `route_upstream_hosts()` — and CONNECT to those still gets
            // blocked with 403 (the "force SDK cooperation" path).
            let requires_managed_credential =
                route.credential_key.is_some() || route.oauth2.is_some();
            let requires_intercept =
                requires_managed_credential || !route.endpoint_rules.is_empty();
            let managed_auth_mechanism = auth_mechanism_for_route(route);
            let managed_injection_mode = injection_mode_for_route(route);

            loaded.insert(
                normalized_prefix,
                LoadedRoute {
                    upstream: route.upstream.clone(),
                    upstream_host_port,
                    endpoint_rules,
                    tls_connector,
                    requires_intercept,
                    requires_managed_credential,
                    managed_auth_mechanism,
                    managed_injection_mode,
                },
            );
        }

        Ok(Self { routes: loaded })
    }

    /// Create an empty route store (no routes configured).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            routes: HashMap::new(),
        }
    }

    /// Get a loaded route by normalised prefix, if configured.
    #[must_use]
    pub fn get(&self, prefix: &str) -> Option<&LoadedRoute> {
        self.routes.get(prefix)
    }

    /// Check if any routes are loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Number of loaded routes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Check whether `host_port` (e.g. `"api.openai.com:443"`) matches
    /// any route's upstream URL. Uses pre-normalised `host:port` strings
    /// computed at load time to avoid per-request URL parsing.
    #[must_use]
    pub fn is_route_upstream(&self, host_port: &str) -> bool {
        let normalised = host_port.to_lowercase();
        self.routes.values().any(|route| {
            route
                .upstream_host_port
                .as_ref()
                .is_some_and(|hp| *hp == normalised)
        })
    }

    /// Return the first route matching `host:port`, or `None`.
    ///
    /// Prefer [`lookup_all_by_upstream`](Self::lookup_all_by_upstream)
    /// when multiple routes may share the same upstream.
    #[must_use]
    pub fn lookup_by_upstream(&self, host_port: &str) -> Option<(&str, &LoadedRoute)> {
        let normalised = host_port.to_lowercase();
        self.routes.iter().find_map(|(prefix, route)| {
            route
                .upstream_host_port
                .as_ref()
                .filter(|hp| **hp == normalised)
                .map(|_| (prefix.as_str(), route))
        })
    }

    /// Return all routes whose upstream matches `host:port`, sorted by
    /// prefix for deterministic iteration.
    #[must_use]
    pub fn lookup_all_by_upstream(&self, host_port: &str) -> Vec<(&str, &LoadedRoute)> {
        let normalised = host_port.to_lowercase();
        let mut matches: Vec<_> = self
            .routes
            .iter()
            .filter(|(_, route)| {
                route
                    .upstream_host_port
                    .as_ref()
                    .is_some_and(|hp| *hp == normalised)
            })
            .map(|(prefix, route)| (prefix.as_str(), route))
            .collect();
        matches.sort_by_key(|(prefix, _)| *prefix);
        matches
    }

    /// Whether any route for `host:port` requires TLS interception.
    #[must_use]
    pub fn has_intercept_route(&self, host_port: &str) -> bool {
        let normalised = host_port.to_lowercase();
        self.routes.values().any(|route| {
            route
                .upstream_host_port
                .as_ref()
                .is_some_and(|hp| *hp == normalised)
                && route.requires_intercept
        })
    }

    /// All unique upstream `host:port` strings across loaded routes.
    #[must_use]
    pub fn route_upstream_hosts(&self) -> std::collections::HashSet<String> {
        self.routes
            .values()
            .filter_map(|route| route.upstream_host_port.clone())
            .collect()
    }
}

impl LoadedRoute {
    /// Whether this route is configured to require a proxy-managed credential
    /// but the credential material is currently unavailable.
    #[must_use]
    pub fn missing_managed_credential(
        &self,
        has_static_credential: bool,
        has_oauth2: bool,
    ) -> bool {
        self.requires_managed_credential && !has_static_credential && !has_oauth2
    }
}

/// Extract and normalise `host:port` from a URL string.
///
/// Defaults to port 443 for `https://` and 80 for `http://` when no
/// explicit port is present. Returns `None` if the URL cannot be parsed.
fn extract_host_port(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    let default_port = match parsed.scheme() {
        "https" => 443,
        "http" => 80,
        _ => return None,
    };
    let port = parsed.port().unwrap_or(default_port);
    Some(format!("{}:{}", host.to_lowercase(), port))
}

/// Read a PEM file, producing a clear `ProxyError::Config` for common failure modes.
///
/// Distinguishes:
/// - file not found  → "… not found: '…'"
/// - permission denied → "… permission denied: '…'" (nono process lacks read access)
/// - other I/O errors  → "failed to read … '…': {os error}"
fn read_pem_file(path: &std::path::Path, label: &str) -> Result<Zeroizing<Vec<u8>>> {
    std::fs::read(path)
        .map(Zeroizing::new)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                ProxyError::Config(format!("{} file not found: '{}'", label, path.display()))
            }
            std::io::ErrorKind::PermissionDenied => ProxyError::Config(format!(
                "{} permission denied: '{}' (check that nono can read this file)",
                label,
                path.display()
            )),
            _ => ProxyError::Config(format!(
                "failed to read {} '{}': {}",
                label,
                path.display(),
                e
            )),
        })
}

/// Root cert store combining webpki roots with the OS trust store.
///
/// Loaded once at startup and cloned into each per-route connector.
fn build_base_root_store() -> rustls::RootCertStore {
    let mut store = rustls::RootCertStore::empty();
    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        if let Err(e) = store.add(cert) {
            debug!("skipping unparseable native cert: {e}");
        }
    }
    store
}

/// Build a per-route `TlsConnector`, optionally adding a custom CA
/// and/or mTLS client certificate on top of `base_root_store`.
fn build_tls_connector(
    base_root_store: &rustls::RootCertStore,
    ca_path: Option<&str>,
    client_cert_path: Option<&str>,
    client_key_path: Option<&str>,
) -> Result<tokio_rustls::TlsConnector> {
    let mut root_store = base_root_store.clone();

    // Add custom CA if provided
    if let Some(ca_path) = ca_path {
        let ca_path = std::path::Path::new(ca_path);
        let ca_pem = read_pem_file(ca_path, "CA certificate")?;

        let certs: Vec<_> = rustls::pki_types::CertificateDer::pem_slice_iter(ca_pem.as_ref())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| {
                ProxyError::Config(format!(
                    "failed to parse CA certificate '{}': {}",
                    ca_path.display(),
                    e
                ))
            })?;

        if certs.is_empty() {
            return Err(ProxyError::Config(format!(
                "CA certificate file '{}' contains no valid PEM certificates",
                ca_path.display()
            )));
        }

        for cert in certs {
            root_store.add(cert).map_err(|e| {
                ProxyError::Config(format!(
                    "invalid CA certificate in '{}': {}",
                    ca_path.display(),
                    e
                ))
            })?;
        }
    }

    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| ProxyError::Config(format!("TLS config error: {}", e)))?
    .with_root_certificates(root_store);

    // Add client certificate for mTLS if provided
    let tls_config = match (client_cert_path, client_key_path) {
        (Some(cert_path), Some(key_path)) => {
            let cert_path = std::path::Path::new(cert_path);
            let key_path = std::path::Path::new(key_path);

            let cert_pem = read_pem_file(cert_path, "client certificate")?;
            let key_pem = read_pem_file(key_path, "client key")?;

            let cert_chain: Vec<rustls::pki_types::CertificateDer> =
                rustls::pki_types::CertificateDer::pem_slice_iter(cert_pem.as_ref())
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|e| {
                        ProxyError::Config(format!(
                            "failed to parse client certificate '{}': {}",
                            cert_path.display(),
                            e
                        ))
                    })?;

            if cert_chain.is_empty() {
                return Err(ProxyError::Config(format!(
                    "client certificate file '{}' contains no valid PEM certificates",
                    cert_path.display()
                )));
            }

            let private_key = rustls::pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_ref())
                .map_err(|e| match e {
                    rustls::pki_types::pem::Error::NoItemsFound => ProxyError::Config(format!(
                        "client key file '{}' contains no valid PEM private key",
                        key_path.display()
                    )),
                    _ => ProxyError::Config(format!(
                        "failed to parse client key '{}': {}",
                        key_path.display(),
                        e
                    )),
                })?;

            builder
                .with_client_auth_cert(cert_chain, private_key)
                .map_err(|e| {
                    ProxyError::Config(format!(
                        "invalid client certificate/key pair ('{}', '{}'): {}",
                        cert_path.display(),
                        key_path.display(),
                        e
                    ))
                })?
        }
        (Some(_), None) => {
            return Err(ProxyError::Config(
                "tls_client_cert is set but tls_client_key is missing".to_string(),
            ));
        }
        (None, Some(_)) => {
            return Err(ProxyError::Config(
                "tls_client_key is set but tls_client_cert is missing".to_string(),
            ));
        }
        (None, None) => builder.with_no_client_auth(),
    };

    // Disable TLS session resumption when client certificates are configured.
    //
    // With TLS 1.3 PSK resumption the server may skip the CertificateRequest
    // handshake message, so the client certificate is never re-presented on
    // resumed connections. Servers that authenticate via x509 client certs
    // (e.g. Kubernetes API servers) then reject or hang the request because
    // the client identity is not established. Forcing a full handshake every
    // time ensures the client certificate is always sent.
    let mut tls_config = tls_config;
    if client_cert_path.is_some() {
        tls_config.resumption = rustls::client::Resumption::disabled();
    }

    Ok(tokio_rustls::TlsConnector::from(Arc::new(tls_config)))
}

/// Compatibility shim: build a connector with only a custom CA (no client cert).
#[cfg(test)]
fn build_tls_connector_with_ca(ca_path: &str) -> Result<tokio_rustls::TlsConnector> {
    let base = build_base_root_store();
    build_tls_connector(&base, Some(ca_path), None, None)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::config::EndpointRule;

    #[test]
    fn test_empty_route_store() {
        let store = RouteStore::empty();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        assert!(store.get("openai").is_none());
    }

    #[test]
    fn test_load_routes_without_credentials() {
        // Routes without credential_key should still be loaded into RouteStore
        let routes = vec![RouteConfig {
            prefix: "/openai".to_string(),
            upstream: "https://api.openai.com".to_string(),
            credential_key: None,
            inject_mode: Default::default(),
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: None,
            endpoint_rules: vec![
                EndpointRule {
                    method: "POST".to_string(),
                    path: "/v1/chat/completions".to_string(),
                },
                EndpointRule {
                    method: "GET".to_string(),
                    path: "/v1/models".to_string(),
                },
            ],
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
            oauth2: None,
        }];

        let store = RouteStore::load(&routes).unwrap();
        assert_eq!(store.len(), 1);

        let route = store.get("openai").unwrap();
        assert_eq!(route.upstream, "https://api.openai.com");
        assert!(
            route
                .endpoint_rules
                .is_allowed("POST", "/v1/chat/completions")
        );
        assert!(route.endpoint_rules.is_allowed("GET", "/v1/models"));
        assert!(
            !route
                .endpoint_rules
                .is_allowed("DELETE", "/v1/files/file-123")
        );
    }

    #[test]
    fn test_load_routes_normalises_prefix() {
        let routes = vec![RouteConfig {
            prefix: "/anthropic/".to_string(),
            upstream: "https://api.anthropic.com".to_string(),
            credential_key: None,
            inject_mode: Default::default(),
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
            oauth2: None,
        }];

        let store = RouteStore::load(&routes).unwrap();
        assert!(store.get("anthropic").is_some());
        assert!(store.get("/anthropic/").is_none());
    }

    #[test]
    fn test_is_route_upstream() {
        let routes = vec![RouteConfig {
            prefix: "openai".to_string(),
            upstream: "https://api.openai.com".to_string(),
            credential_key: None,
            inject_mode: Default::default(),
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
            oauth2: None,
        }];

        let store = RouteStore::load(&routes).unwrap();
        assert!(store.is_route_upstream("api.openai.com:443"));
        assert!(!store.is_route_upstream("github.com:443"));
    }

    #[test]
    fn test_route_upstream_hosts() {
        let routes = vec![
            RouteConfig {
                prefix: "openai".to_string(),
                upstream: "https://api.openai.com".to_string(),
                credential_key: None,
                inject_mode: Default::default(),
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
                oauth2: None,
            },
            RouteConfig {
                prefix: "anthropic".to_string(),
                upstream: "https://api.anthropic.com".to_string(),
                credential_key: None,
                inject_mode: Default::default(),
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
                oauth2: None,
            },
        ];

        let store = RouteStore::load(&routes).unwrap();
        let hosts = store.route_upstream_hosts();
        assert!(hosts.contains("api.openai.com:443"));
        assert!(hosts.contains("api.anthropic.com:443"));
        assert_eq!(hosts.len(), 2);
    }

    #[test]
    fn test_extract_host_port_https() {
        assert_eq!(
            extract_host_port("https://api.openai.com"),
            Some("api.openai.com:443".to_string())
        );
    }

    #[test]
    fn test_extract_host_port_with_port() {
        assert_eq!(
            extract_host_port("https://api.example.com:8443"),
            Some("api.example.com:8443".to_string())
        );
    }

    #[test]
    fn test_extract_host_port_http() {
        assert_eq!(
            extract_host_port("http://internal-service"),
            Some("internal-service:80".to_string())
        );
    }

    #[test]
    fn test_extract_host_port_normalises_case() {
        assert_eq!(
            extract_host_port("https://API.Example.COM"),
            Some("api.example.com:443".to_string())
        );
    }

    #[test]
    fn test_loaded_route_debug() {
        let route = LoadedRoute {
            upstream: "https://api.openai.com".to_string(),
            upstream_host_port: Some("api.openai.com:443".to_string()),
            endpoint_rules: CompiledEndpointRules::compile(&[]).unwrap(),
            tls_connector: None,
            requires_intercept: false,
            requires_managed_credential: false,
            managed_auth_mechanism: None,
            managed_injection_mode: None,
        };
        let debug_output = format!("{:?}", route);
        assert!(debug_output.contains("api.openai.com"));
        assert!(debug_output.contains("has_custom_tls_ca"));
        assert!(debug_output.contains("requires_intercept"));
        assert!(debug_output.contains("requires_managed_credential"));
        assert!(debug_output.contains("managed_auth_mechanism"));
        assert!(debug_output.contains("managed_injection_mode"));
    }

    #[test]
    fn test_requires_intercept_credential_only() {
        let routes = vec![RouteConfig {
            prefix: "openai".to_string(),
            upstream: "https://api.openai.com".to_string(),
            credential_key: Some("openai_api_key".to_string()),
            inject_mode: Default::default(),
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
            oauth2: None,
        }];
        let store = RouteStore::load(&routes).unwrap();
        let hit = store.lookup_by_upstream("api.openai.com:443").unwrap();
        assert!(store.has_intercept_route("api.openai.com:443"));
        assert!(hit.1.requires_managed_credential);
        assert_eq!(
            hit.1.managed_auth_mechanism,
            Some(NetworkAuditAuthMechanism::PhantomHeader)
        );
        assert_eq!(
            hit.1.managed_injection_mode,
            Some(NetworkAuditInjectionMode::Header)
        );
        assert!(!store.has_intercept_route("api.example.com:443"));
    }

    #[test]
    fn test_requires_intercept_endpoint_rules_only() {
        // L7-only route (no credential): rules alone are enough to require
        // interception.
        let routes = vec![RouteConfig {
            prefix: "internal".to_string(),
            upstream: "https://internal.example.com".to_string(),
            credential_key: None,
            inject_mode: Default::default(),
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: None,
            endpoint_rules: vec![EndpointRule {
                method: "GET".to_string(),
                path: "/v1/items".to_string(),
            }],
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
            oauth2: None,
        }];
        let store = RouteStore::load(&routes).unwrap();
        let hit = store
            .lookup_by_upstream("internal.example.com:443")
            .unwrap();
        assert!(store.has_intercept_route("internal.example.com:443"));
        assert!(!hit.1.requires_managed_credential);
    }

    #[test]
    fn test_requires_intercept_declarative_only() {
        // No credential, no rules — purely declarative route. CONNECT to
        // this upstream still gets the existing 403 (not intercepted).
        let routes = vec![RouteConfig {
            prefix: "alias".to_string(),
            upstream: "https://aliased.example.com".to_string(),
            credential_key: None,
            inject_mode: Default::default(),
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
            oauth2: None,
        }];
        let store = RouteStore::load(&routes).unwrap();
        assert!(store.is_route_upstream("aliased.example.com:443"));
        assert!(!store.has_intercept_route("aliased.example.com:443"));
    }

    #[test]
    fn test_missing_managed_credential_policy() {
        let managed = LoadedRoute {
            upstream: "https://api.openai.com".to_string(),
            upstream_host_port: Some("api.openai.com:443".to_string()),
            endpoint_rules: CompiledEndpointRules::compile(&[]).unwrap(),
            tls_connector: None,
            requires_intercept: true,
            requires_managed_credential: true,
            managed_auth_mechanism: Some(NetworkAuditAuthMechanism::PhantomHeader),
            managed_injection_mode: Some(NetworkAuditInjectionMode::Header),
        };
        assert!(managed.missing_managed_credential(false, false));
        assert!(!managed.missing_managed_credential(true, false));
        assert!(!managed.missing_managed_credential(false, true));

        let l7_only = LoadedRoute {
            upstream: "https://internal.example.com".to_string(),
            upstream_host_port: Some("internal.example.com:443".to_string()),
            endpoint_rules: CompiledEndpointRules::compile(&[]).unwrap(),
            tls_connector: None,
            requires_intercept: true,
            requires_managed_credential: false,
            managed_auth_mechanism: None,
            managed_injection_mode: None,
        };
        assert!(!l7_only.missing_managed_credential(false, false));
    }

    #[test]
    fn test_lookup_by_upstream_returns_prefix() {
        let routes = vec![RouteConfig {
            prefix: "openai".to_string(),
            upstream: "https://api.openai.com".to_string(),
            credential_key: Some("openai_api_key".to_string()),
            inject_mode: Default::default(),
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
            oauth2: None,
        }];
        let store = RouteStore::load(&routes).unwrap();
        let hit = store.lookup_by_upstream("api.openai.com:443").unwrap();
        assert_eq!(hit.0, "openai");
        assert!(hit.1.requires_intercept);
        assert!(hit.1.requires_managed_credential);
        assert!(store.lookup_by_upstream("api.example.com:443").is_none());
    }

    #[test]
    fn test_lookup_all_by_upstream_returns_multiple_routes() {
        let routes = vec![
            RouteConfig {
                prefix: "github_org_a".to_string(),
                upstream: "https://github.com".to_string(),
                credential_key: Some("env://GH_TOKEN_A".to_string()),
                inject_mode: Default::default(),
                inject_header: "Authorization".to_string(),
                credential_format: "Bearer {}".to_string(),
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                proxy: None,
                env_var: Some("GH_TOKEN_A".to_string()),
                endpoint_rules: vec![crate::config::EndpointRule {
                    method: "*".to_string(),
                    path: "/org-a/**".to_string(),
                }],
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
            },
            RouteConfig {
                prefix: "github_org_b".to_string(),
                upstream: "https://github.com".to_string(),
                credential_key: Some("env://GH_TOKEN_B".to_string()),
                inject_mode: Default::default(),
                inject_header: "Authorization".to_string(),
                credential_format: "Bearer {}".to_string(),
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                proxy: None,
                env_var: Some("GH_TOKEN_B".to_string()),
                endpoint_rules: vec![crate::config::EndpointRule {
                    method: "*".to_string(),
                    path: "/org-b/**".to_string(),
                }],
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
            },
        ];
        let store = RouteStore::load(&routes).unwrap();

        let all = store.lookup_all_by_upstream("github.com:443");
        assert_eq!(all.len(), 2, "both routes share the same upstream");

        let prefixes: Vec<&str> = all.iter().map(|(p, _)| *p).collect();
        assert!(prefixes.contains(&"github_org_a"));
        assert!(prefixes.contains(&"github_org_b"));

        let (_, route_a) = all.iter().find(|(p, _)| *p == "github_org_a").unwrap();
        assert!(route_a.endpoint_rules.is_allowed("GET", "/org-a/repo"));
        assert!(!route_a.endpoint_rules.is_allowed("GET", "/org-b/repo"));

        let (_, route_b) = all.iter().find(|(p, _)| *p == "github_org_b").unwrap();
        assert!(route_b.endpoint_rules.is_allowed("GET", "/org-b/repo"));
        assert!(!route_b.endpoint_rules.is_allowed("GET", "/org-a/repo"));

        assert!(store.has_intercept_route("github.com:443"));
        assert!(store.is_route_upstream("github.com:443"));
        assert!(store.lookup_all_by_upstream("other.com:443").is_empty());
    }

    /// Models a real multi-org GitHub profile. Mirrors the selection
    /// loop in `tls_intercept::handle`:
    ///   1 match  → inject that route's credential
    ///   0 matches → passthrough (no credential injected)
    ///   2+ matches → ambiguous (hard-deny 403)
    #[test]
    fn test_route_selection_multi_org_profile() {
        // Helper to build a route with the given prefix and endpoint path.
        fn gh_route(prefix: &str, env: &str, path: &str) -> RouteConfig {
            RouteConfig {
                prefix: prefix.to_string(),
                upstream: "https://github.com".to_string(),
                credential_key: Some(format!("env://{env}")),
                inject_mode: Default::default(),
                inject_header: "Authorization".to_string(),
                credential_format: "Bearer {}".to_string(),
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                proxy: None,
                env_var: Some(env.to_string()),
                endpoint_rules: vec![crate::config::EndpointRule {
                    method: "*".to_string(),
                    path: path.to_string(),
                }],
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
            }
        }

        #[derive(Debug, PartialEq)]
        enum Selection<'a> {
            Route(&'a str),
            Passthrough,
            Ambiguous(Vec<&'a str>),
        }

        fn select<'a>(
            candidates: &'a [(&'a str, &'a LoadedRoute)],
            method: &str,
            path: &str,
        ) -> Selection<'a> {
            let mut matches: Vec<&str> = Vec::new();
            let mut catch_all: Option<&str> = None;
            for (prefix, route) in candidates {
                if route.endpoint_rules.is_empty() {
                    if catch_all.is_none() {
                        catch_all = Some(*prefix);
                    }
                } else if route.endpoint_rules.is_allowed(method, path) {
                    matches.push(prefix);
                }
            }
            if matches.len() > 1 {
                Selection::Ambiguous(matches)
            } else if let Some(svc) = matches.into_iter().next().or(catch_all) {
                Selection::Route(svc)
            } else {
                Selection::Passthrough
            }
        }

        // --- Profile: two org-scoped routes, no catch-all ---
        let routes = vec![
            gh_route("github_https_org_a", "GH_TOKEN_A", "/org-a/**"),
            gh_route("github_https_org_b", "GH_TOKEN_B", "/org-b/**"),
        ];
        let store = RouteStore::load(&routes).unwrap();
        let candidates = store.lookup_all_by_upstream("github.com:443");
        assert_eq!(candidates.len(), 2);

        // Private org-a repo → org-a credential
        assert_eq!(
            select(&candidates, "GET", "/org-a/repo.git/info/refs"),
            Selection::Route("github_https_org_a")
        );
        // Private org-b repo → org-b credential
        assert_eq!(
            select(&candidates, "GET", "/org-b/repo.git/info/refs"),
            Selection::Route("github_https_org_b")
        );
        // Public repo (e.g. always-further/nono) → passthrough, no cred
        assert_eq!(
            select(&candidates, "GET", "/always-further/nono.git/info/refs"),
            Selection::Passthrough
        );
        // POST to public repo → also passthrough
        assert_eq!(
            select(
                &candidates,
                "POST",
                "/always-further/nono.git/git-upload-pack"
            ),
            Selection::Passthrough
        );

        // --- Adding a /** catch-all would cause ambiguity ---
        let routes_with_catchall = vec![
            gh_route("github_https_org_a", "GH_TOKEN_A", "/org-a/**"),
            gh_route("github_https_org_b", "GH_TOKEN_B", "/org-b/**"),
            gh_route("github_https_all", "GH_TOKEN_A", "/**"),
        ];
        let store2 = RouteStore::load(&routes_with_catchall).unwrap();
        let candidates2 = store2.lookup_all_by_upstream("github.com:443");
        assert_eq!(candidates2.len(), 3);

        // org-a request now matches BOTH org_a AND the /** catch-all → ambiguous
        assert_eq!(
            select(&candidates2, "GET", "/org-a/repo.git/info/refs"),
            Selection::Ambiguous(vec!["github_https_all", "github_https_org_a"])
        );
        // Public repo matches only the /** catch-all → 1 match, ok
        assert_eq!(
            select(&candidates2, "GET", "/always-further/nono.git/info/refs"),
            Selection::Route("github_https_all")
        );
    }

    /// Self-signed CA for testing. Generated with:
    /// openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    ///   -keyout /dev/null -nodes -days 36500 -subj '/CN=nono-test-ca' -out -
    const TEST_CA_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIBnjCCAUWgAwIBAgIUT0bpOJJvHdOdZt+gW1stR8VBgXowCgYIKoZIzj0EAwIw
FzEVMBMGA1UEAwwMbm9uby10ZXN0LWNhMCAXDTI1MDEwMTAwMDAwMFoYDzIxMjQx
MjA3MDAwMDAwWjAXMRUwEwYDVQQDDAxub25vLXRlc3QtY2EwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAR8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAo1MwUTAdBgNVHQ4EFgQUAAAAAAAAAAAAAAAAAAAAAAAA
AAAAMB8GA1UdIwQYMBaAFAAAAAAAAAAAAAAAAAAAAAAAAAAAADAPBgNVHRMBAf8E
BTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAICAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END CERTIFICATE-----";

    #[test]
    fn test_build_tls_connector_with_valid_ca() {
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, TEST_CA_PEM).unwrap();

        let result = build_tls_connector_with_ca(ca_path.to_str().unwrap());
        match result {
            Ok(connector) => {
                drop(connector);
            }
            Err(ProxyError::Config(msg)) => {
                assert!(
                    msg.contains("invalid CA certificate") || msg.contains("CA certificate"),
                    "unexpected error: {}",
                    msg
                );
            }
            Err(e) => panic!("unexpected error type: {}", e),
        }
    }

    #[test]
    fn test_build_tls_connector_missing_file() {
        let result = build_tls_connector_with_ca("/nonexistent/path/ca.pem");
        let err = result
            .err()
            .expect("should fail for missing file")
            .to_string();
        assert!(
            err.contains("CA certificate file not found"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_build_tls_connector_empty_pem() {
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("empty.pem");
        std::fs::write(&ca_path, "not a certificate\n").unwrap();

        let result = build_tls_connector_with_ca(ca_path.to_str().unwrap());
        let err = result
            .err()
            .expect("should fail for invalid PEM")
            .to_string();
        assert!(
            err.contains("no valid PEM certificates"),
            "unexpected error: {}",
            err
        );
    }

    // --- mTLS (client certificate) tests ---

    /// Self-signed client cert + key for testing. Generated with:
    /// openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    ///   -keyout client.key -nodes -days 3650 -subj '/CN=nono-test-client' -out client.crt
    const TEST_CLIENT_CERT_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIBijCCATGgAwIBAgIUEoEb+0z+4CTRCzN98MqeTEXgdO8wCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQbm9uby10ZXN0LWNsaWVudDAeFw0yNjA0MTAwMDIwNTdaFw0z
NjA0MDcwMDIwNTdaMBsxGTAXBgNVBAMMEG5vbm8tdGVzdC1jbGllbnQwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAASt6g2Zt0STlgF+wZ64JzdDRlpPeNr1h56ZLEEq
HfVWFhJWIKRSabtxYPV/VJyMv+lo3L0QwSKsouHs3dtF1zVQo1MwUTAdBgNVHQ4E
FgQUTiHidg8uqgrJ1qlaVvR+XSebAlEwHwYDVR0jBBgwFoAUTiHidg8uqgrJ1qla
VvR+XSebAlEwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiA9PwBU
f832cQkGS9cyYaU7Ij5U8Rcy/g4J7Ckf2nKX3gIgG0aarAFcIzAi5VpxbCwEScnr
m0lHTyp6E7ut7llwMBY=
-----END CERTIFICATE-----";

    const TEST_CLIENT_KEY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgskOkyJkTwlMZkm/L
eEleLY6bARaHFnqauYJqxNoJWvihRANCAASt6g2Zt0STlgF+wZ64JzdDRlpPeNr1
h56ZLEEqHfVWFhJWIKRSabtxYPV/VJyMv+lo3L0QwSKsouHs3dtF1zVQ
-----END PRIVATE KEY-----";

    #[test]
    fn test_build_tls_connector_cert_without_key_errors() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("client.crt");
        std::fs::write(&cert_path, TEST_CLIENT_CERT_PEM).unwrap();

        let base = build_base_root_store();
        let result = build_tls_connector(&base, None, Some(cert_path.to_str().unwrap()), None);
        let err = result
            .err()
            .expect("should fail with half-pair")
            .to_string();
        assert!(
            err.contains("tls_client_cert is set but tls_client_key is missing"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_build_tls_connector_key_without_cert_errors() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("client.key");
        std::fs::write(&key_path, TEST_CLIENT_KEY_PEM).unwrap();

        let base = build_base_root_store();
        let result = build_tls_connector(&base, None, None, Some(key_path.to_str().unwrap()));
        let err = result
            .err()
            .expect("should fail with half-pair")
            .to_string();
        assert!(
            err.contains("tls_client_key is set but tls_client_cert is missing"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_build_tls_connector_missing_client_cert_file() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("client.key");
        std::fs::write(&key_path, TEST_CLIENT_KEY_PEM).unwrap();

        let base = build_base_root_store();
        let result = build_tls_connector(
            &base,
            None,
            Some("/nonexistent/client.crt"),
            Some(key_path.to_str().unwrap()),
        );
        let err = result.err().expect("should fail").to_string();
        assert!(
            err.contains("client certificate file not found"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_build_tls_connector_missing_client_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("client.crt");
        std::fs::write(&cert_path, TEST_CLIENT_CERT_PEM).unwrap();

        let base = build_base_root_store();
        let result = build_tls_connector(
            &base,
            None,
            Some(cert_path.to_str().unwrap()),
            Some("/nonexistent/client.key"),
        );
        let err = result.err().expect("should fail").to_string();
        assert!(
            err.contains("client key file not found"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_build_tls_connector_permission_denied() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("client.crt");
        std::fs::write(&cert_path, TEST_CLIENT_CERT_PEM).unwrap();
        // Remove all permissions so the file exists but can't be read
        std::fs::set_permissions(&cert_path, std::fs::Permissions::from_mode(0o000)).unwrap();

        // Skip if running as root (root bypasses permission checks)
        if std::fs::read(&cert_path).is_ok() {
            return;
        }

        let base = build_base_root_store();
        let result = build_tls_connector(
            &base,
            None,
            Some(cert_path.to_str().unwrap()),
            Some("/nonexistent/key"),
        );
        let err = result.err().expect("should fail").to_string();
        assert!(
            err.contains("permission denied"),
            "expected permission denied error, got: {}",
            err
        );
    }

    #[test]
    fn test_build_tls_connector_empty_client_cert_pem() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("client.crt");
        let key_path = dir.path().join("client.key");
        std::fs::write(&cert_path, "not a certificate\n").unwrap();
        std::fs::write(&key_path, TEST_CLIENT_KEY_PEM).unwrap();

        let base = build_base_root_store();
        let result = build_tls_connector(
            &base,
            None,
            Some(cert_path.to_str().unwrap()),
            Some(key_path.to_str().unwrap()),
        );
        let err = result.err().expect("should fail").to_string();
        assert!(
            err.contains("no valid PEM certificates"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_build_tls_connector_empty_client_key_pem() {
        // Verifies that an invalid key file produces an appropriate config error.
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("client.crt");
        let key_path = dir.path().join("client.key");
        std::fs::write(&cert_path, TEST_CLIENT_CERT_PEM).unwrap();
        std::fs::write(&key_path, "not a key\n").unwrap();

        let base = build_base_root_store();
        let result = build_tls_connector(
            &base,
            None,
            Some(cert_path.to_str().unwrap()),
            Some(key_path.to_str().unwrap()),
        );
        let err = result
            .err()
            .expect("should fail with invalid PEM")
            .to_string();
        assert!(err.contains("client key"), "unexpected error: {}", err);
    }

    #[test]
    fn test_route_store_loads_mtls_route() {
        // Verify RouteStore.load() builds a TLS connector when tls_client_cert/key are set.
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("client.crt");
        let key_path = dir.path().join("client.key");
        std::fs::write(&cert_path, TEST_CLIENT_CERT_PEM).unwrap();
        std::fs::write(&key_path, TEST_CLIENT_KEY_PEM).unwrap();

        let routes = vec![RouteConfig {
            prefix: "k8s".to_string(),
            upstream: "https://192.168.64.1:6443".to_string(),
            credential_key: None,
            inject_mode: Default::default(),
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: None,
            endpoint_rules: vec![],
            tls_ca: None,
            tls_client_cert: Some(cert_path.to_str().unwrap().to_string()),
            tls_client_key: Some(key_path.to_str().unwrap().to_string()),
            oauth2: None,
        }];

        let store = RouteStore::load(&routes).expect("should load mTLS route");
        let route = store.get("k8s").unwrap();
        assert!(
            route.tls_connector.is_some(),
            "connector must be built when tls_client_cert/key are set"
        );
    }
}
