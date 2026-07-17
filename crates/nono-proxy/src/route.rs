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

use crate::config::{
    CompiledEndpointPolicy, CompiledEndpointRules, CompiledUpgradeRules, RouteConfig,
    SpiffeAuthConfig,
};
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
    /// URL parsing. `RouteStore::load` rejects routes where this cannot be
    /// parsed so route-protection checks never silently drop an upstream.
    pub upstream_host_port: Option<String>,

    /// Pre-compiled L7 endpoint rules for method+path filtering.
    /// When non-empty, only matching requests are allowed (default-deny).
    /// When empty, all method+path combinations are permitted.
    pub endpoint_rules: CompiledEndpointRules,

    /// Pre-compiled explicit endpoint policy. When no explicit policy is
    /// configured this preserves legacy `endpoint_rules` semantics.
    pub endpoint_policy: CompiledEndpointPolicy,

    /// Pre-compiled WebSocket upgrade allow-list. When empty (the default),
    /// no upgrade requests are tunneled for this route.
    pub upgrade_rules: CompiledUpgradeRules,

    /// Per-route TLS connector with custom CA trust, if configured.
    /// Built once at startup from the route's `tls_ca` certificate file.
    /// When `None`, the shared default connector (webpki roots only) is used.
    pub tls_connector: Option<tokio_rustls::TlsConnector>,

    /// Per-route TLS client config (same config backing `tls_connector`).
    /// Stored separately so the upstream pool can build per-route pooled
    /// clients without needing to extract the config from the connector.
    pub tls_client_config: Option<std::sync::Arc<rustls::ClientConfig>>,

    /// Stable identity for route TLS settings. Two routes with the same key can
    /// share one HTTP/2 upstream connection without changing trust roots or
    /// client certificate behavior between streams.
    pub tls_config_key: Option<String>,

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

    /// Live SPIFFE auth source for this route, if configured.
    /// Either X.509 mTLS or JWT bearer, chosen at load time from the route's
    /// `spiffe` config block. `None` for non-SPIFFE routes.
    pub managed_auth: Option<Arc<crate::auth::ManagedUpstreamAuth>>,
}

impl std::fmt::Debug for LoadedRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("LoadedRoute");
        s.field("upstream", &self.upstream)
            .field("upstream_host_port", &self.upstream_host_port)
            .field("endpoint_rules", &self.endpoint_rules)
            .field("endpoint_policy", &self.endpoint_policy)
            .field("upgrade_rules", &self.upgrade_rules)
            .field("has_custom_tls_ca", &self.tls_connector.is_some())
            .field("requires_intercept", &self.requires_intercept)
            .field(
                "requires_managed_credential",
                &self.requires_managed_credential,
            )
            .field("managed_auth_mechanism", &self.managed_auth_mechanism)
            .field("managed_injection_mode", &self.managed_injection_mode);
        let managed_auth_type = self.managed_auth.as_ref().map(|a| match a.as_ref() {
            crate::auth::ManagedUpstreamAuth::SpiffeJwt(_) => "spiffe_jwt",
        });
        s.field("managed_auth_type", &managed_auth_type);
        s.finish()
    }
}

fn auth_mechanism_for_route(route: &RouteConfig) -> Option<NetworkAuditAuthMechanism> {
    if let Some(spiffe) = &route.spiffe {
        let SpiffeAuthConfig::Jwt { .. } = spiffe;
        return Some(NetworkAuditAuthMechanism::SpiffeJwtBearer);
    }

    if route.oauth2.is_some() {
        return Some(NetworkAuditAuthMechanism::PhantomHeader);
    }

    if route.aws_auth.is_some() {
        // SigV4 signs via the Authorization header — same phantom token shape.
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
    if let Some(spiffe) = &route.spiffe {
        let SpiffeAuthConfig::Jwt { .. } = spiffe;
        return Some(NetworkAuditInjectionMode::SpiffeJwt);
    }

    if route.oauth2.is_some() {
        return Some(NetworkAuditInjectionMode::OAuth2);
    }

    if route.aws_auth.is_some() {
        // SigV4 injects via the Authorization header.
        return Some(NetworkAuditInjectionMode::Header);
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
    pub async fn load(routes: &[RouteConfig]) -> Result<Self> {
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
            let endpoint_policy = CompiledEndpointPolicy::compile(
                route.endpoint_policy.as_ref(),
                &route.endpoint_rules,
            )
            .map_err(|e| ProxyError::Config(format!("route '{}': {}", normalized_prefix, e)))?;
            let upgrade_rules = CompiledUpgradeRules::compile(&route.upgrades)
                .map_err(|e| ProxyError::Config(format!("route '{}': {}", normalized_prefix, e)))?;

            let tls_config_key = route_tls_config_key(route);
            let (tls_connector, tls_client_config) = if route.tls_ca.is_some()
                || route.tls_client_cert.is_some()
                || route.tls_client_key.is_some()
            {
                debug!(
                    "Building TLS connector for route '{}' (ca={}, client_cert={})",
                    normalized_prefix,
                    route.tls_ca.is_some(),
                    route.tls_client_cert.is_some(),
                );
                let (connector, config) = build_tls_connector(
                    &base_root_store,
                    route.tls_ca.as_deref(),
                    route.tls_client_cert.as_deref(),
                    route.tls_client_key.as_deref(),
                )?;
                (Some(connector), Some(config))
            } else {
                (None, None)
            };

            let upstream_host_port = extract_host_port(&route.upstream).map_err(|err| {
                ProxyError::Config(format!(
                    "route '{}': invalid upstream '{}': {}",
                    normalized_prefix, route.upstream, err
                ))
            })?;

            // A route needs L7 visibility if it carries credentials to inject
            // (`credential_key` or `oauth2`) or if it enforces method/path
            // rules. Routes without any of these are purely declarative —
            // they exist to provide a `*_BASE_URL` env var or appear in
            // `route_upstream_hosts()` — and CONNECT to those still gets
            // blocked with 403 (the "force SDK cooperation" path).
            // Managed credential sources are mutually exclusive.
            let managed_count = [
                route.spiffe.is_some(),
                route.credential_key.is_some(),
                route.oauth2.is_some(),
                route.aws_auth.is_some(),
            ]
            .iter()
            .filter(|&&v| v)
            .count();
            if managed_count > 1 {
                return Err(ProxyError::Config(format!(
                    "route '{}': `spiffe`, `credential_key`, `oauth2`, and `aws_auth` are mutually exclusive",
                    normalized_prefix
                )));
            }

            // Connect to the SPIRE Workload API for SPIFFE routes. This blocks
            // startup (fail-closed) if the socket is unreachable within the
            // initial_sync_timeout configured on the source builder.
            let managed_auth: Option<Arc<crate::auth::ManagedUpstreamAuth>> =
                if let Some(SpiffeAuthConfig::Jwt {
                    workload_api_socket,
                    audience,
                    inject_header,
                    credential_format,
                    svid_hint,
                }) = &route.spiffe
                {
                    debug!(
                        "Connecting SPIFFE JWT source for route '{}'",
                        normalized_prefix
                    );
                    let src = crate::spiffe::SpiffeJwtSource::connect(
                        workload_api_socket,
                        audience.clone(),
                        inject_header.clone(),
                        credential_format.clone(),
                        svid_hint.as_deref(),
                    )
                    .await
                    .map_err(|e| {
                        ProxyError::Config(format!("route '{}': {e}", normalized_prefix))
                    })?;
                    Some(Arc::new(crate::auth::ManagedUpstreamAuth::SpiffeJwt(
                        Arc::new(src),
                    )))
                } else {
                    None
                };

            let requires_managed_credential = route.credential_key.is_some()
                || route.oauth2.is_some()
                || route.aws_auth.is_some()
                || route.spiffe.is_some();
            let requires_intercept = requires_managed_credential
                || !endpoint_policy.allows_all_without_l7()
                || !upgrade_rules.is_empty();
            let managed_auth_mechanism = auth_mechanism_for_route(route);
            let managed_injection_mode = injection_mode_for_route(route);

            loaded.insert(
                normalized_prefix,
                LoadedRoute {
                    upstream: route.upstream.clone(),
                    upstream_host_port: Some(upstream_host_port),
                    endpoint_rules,
                    endpoint_policy,
                    upgrade_rules,
                    tls_connector,
                    tls_client_config,
                    tls_config_key,
                    requires_intercept,
                    requires_managed_credential,
                    managed_auth_mechanism,
                    managed_injection_mode,
                    managed_auth,
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
        let normalised = normalise_host_port(host_port);
        self.routes.values().any(|route| {
            route
                .upstream_host_port
                .as_ref()
                .is_some_and(|hp| host_port_matches(hp, &normalised))
        })
    }

    /// Return the first route matching `host:port`, or `None`.
    ///
    /// Prefer [`lookup_all_by_upstream`](Self::lookup_all_by_upstream)
    /// when multiple routes may share the same upstream.
    #[must_use]
    pub fn lookup_by_upstream(&self, host_port: &str) -> Option<(&str, &LoadedRoute)> {
        let normalised = normalise_host_port(host_port);
        self.routes.iter().find_map(|(prefix, route)| {
            route
                .upstream_host_port
                .as_ref()
                .filter(|hp| host_port_matches(hp, &normalised))
                .map(|_| (prefix.as_str(), route))
        })
    }

    /// Return all routes whose upstream matches `host:port`, sorted by
    /// prefix for deterministic iteration.
    #[must_use]
    pub fn lookup_all_by_upstream(&self, host_port: &str) -> Vec<(&str, &LoadedRoute)> {
        let normalised = normalise_host_port(host_port);
        let mut matches: Vec<_> = self
            .routes
            .iter()
            .filter(|(_, route)| {
                route
                    .upstream_host_port
                    .as_ref()
                    .is_some_and(|hp| host_port_matches(hp, &normalised))
            })
            .map(|(prefix, route)| (prefix.as_str(), route))
            .collect();
        matches.sort_by_key(|(prefix, _)| *prefix);
        matches
    }

    /// Whether any route for `host:port` requires TLS interception.
    #[must_use]
    pub fn has_intercept_route(&self, host_port: &str) -> bool {
        let normalised = normalise_host_port(host_port);
        self.routes.values().any(|route| {
            route
                .upstream_host_port
                .as_ref()
                .is_some_and(|hp| host_port_matches(hp, &normalised))
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

    /// Route prefixes with successfully loaded SPIFFE sources.
    #[must_use]
    pub fn spiffe_loaded_prefixes(&self) -> std::collections::HashSet<String> {
        self.routes
            .iter()
            .filter(|(_, route)| route.has_spiffe_source())
            .map(|(prefix, _)| prefix.clone())
            .collect()
    }

    /// Whether any managed-credential route targets a loopback upstream host.
    ///
    /// When true, loopback must not appear in `NO_PROXY` so traffic to the
    /// credential upstream goes through the proxy (for SPIFFE injection etc.).
    #[must_use]
    pub fn has_managed_loopback_upstream(&self) -> bool {
        self.routes.iter().any(|(_, route)| {
            if !(route.requires_managed_credential || route.requires_intercept) {
                return false;
            }
            route
                .upstream_host_port
                .as_deref()
                .is_some_and(is_loopback_host_port)
        })
    }
}

/// Whether any configured route targets a loopback upstream that must traverse
/// the proxy (managed credentials, SPIFFE, or TLS-intercepted custom upstreams).
#[must_use]
pub fn config_has_loopback_proxy_route(routes: &[RouteConfig]) -> bool {
    routes.iter().any(|route| {
        let loopback =
            extract_host_port(&route.upstream).is_ok_and(|hp| is_loopback_host_port(&hp));
        if !loopback {
            return false;
        }
        route.spiffe.is_some()
            || route.credential_key.is_some()
            || route.oauth2.is_some()
            || route.aws_auth.is_some()
            || route.tls_ca.is_some()
    })
}

pub(crate) fn is_loopback_host_port(host_port: &str) -> bool {
    let host = host_port
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(host_port);
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    host == "localhost"
        || bare
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|ip| ip.is_loopback())
        || bare
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Outcome of route selection for an intercepted request.
///
/// The shipping selection logic lives inline in `tls_intercept::handle`
/// (`handle_inner_request`) because it is interleaved with the asynchronous
/// `endpoint_policy` approval workflow, which cannot run inside this synchronous
/// helper. `select_route` is retained as the unit-tested reference for the
/// endpoint-authorization gate, ambiguity check, and credential-first priority
/// (commit b0b2c743); keep it in sync with the loop in `handle_inner_request`.
#[cfg(test)]
#[derive(Debug)]
pub(crate) enum RouteSelection<'a> {
    /// An `_ep_` endpoint-authorization route exists for the upstream but no
    /// rule matched: hard-deny (403). Gates access before credential selection.
    EndpointDenied,
    /// More than one credential route matched the request: ambiguous (403).
    /// Carries the matched route prefixes for the diagnostic.
    Ambiguous(Vec<&'a str>),
    /// A route was selected (`Some`) or the request is an un-credentialed
    /// passthrough (`None`).
    Selected(Option<(&'a str, &'a LoadedRoute)>),
}

/// Select the route for an intercepted request from `candidates` sharing one
/// upstream, applying the endpoint-authorization gate, the ambiguity check, and
/// credential-first priority.
///
/// Candidates are partitioned into four buckets by whether their endpoint rules
/// matched this request and whether they carry a managed credential:
///   * `matched_cred` / `matched_passthrough` — endpoint rules matched,
///   * `catchall_cred` / `catchall_passthrough` — no endpoint rules (every path).
///
/// The *credential layer* is `matched_cred` when any credential route matched,
/// otherwise `catchall_cred` (so a credential catch-all is still in play when
/// only credential-less `_ep_` routes matched). Two credential routes in the
/// active layer are ambiguous (the proxy must not silently pick one). Otherwise
/// selection prefers, in order:
/// 1. the single credential route from the active layer — a credential catch-all
///    thus wins over a credential-less `_ep_` match so the managed token is
///    injected rather than silently dropped,
/// 2. a matched credential-less route (bare endpoint authorization),
/// 3. a credential-less catch-all (un-credentialed passthrough).
#[cfg(test)]
#[must_use]
pub(crate) fn select_route<'a>(
    candidates: &'a [(&'a str, &'a LoadedRoute)],
    method: &str,
    path: &str,
) -> RouteSelection<'a> {
    let mut matched_cred: Vec<(&str, &LoadedRoute)> = Vec::new();
    let mut matched_passthrough: Vec<(&str, &LoadedRoute)> = Vec::new();
    let mut catchall_cred: Vec<(&str, &LoadedRoute)> = Vec::new();
    let mut catchall_passthrough: Vec<(&str, &LoadedRoute)> = Vec::new();
    let mut has_endpoint_only_route = false;
    let mut endpoint_authorized = false;
    for (prefix, route) in candidates {
        if route.endpoint_rules.is_empty() {
            if route.requires_managed_credential {
                catchall_cred.push((prefix, route));
            } else {
                catchall_passthrough.push((prefix, route));
            }
        } else if route.endpoint_rules.is_allowed(method, path) {
            if route.requires_managed_credential {
                matched_cred.push((prefix, route));
            } else {
                matched_passthrough.push((prefix, route));
                endpoint_authorized = true;
            }
        } else if !route.requires_managed_credential {
            has_endpoint_only_route = true;
        }
    }

    // Endpoint-only authorization layer: a credential catch-all cannot bypass
    // endpoint restrictions imposed by `_ep_` routes.
    if has_endpoint_only_route && !endpoint_authorized {
        return RouteSelection::EndpointDenied;
    }

    // Ambiguity applies only to credential-injection routes within the active
    // layer; multiple endpoint-only authorization routes matching is fine (they
    // all just allow). This catches both overlapping endpoint credential routes
    // and overlapping credential catch-alls (e.g. two equally-specific wildcard
    // upstreams).
    let credential_layer: &[(&str, &LoadedRoute)] = if matched_cred.is_empty() {
        &catchall_cred
    } else {
        &matched_cred
    };
    if credential_layer.len() > 1 {
        let names = credential_layer.iter().map(|(p, _)| *p).collect();
        return RouteSelection::Ambiguous(names);
    }

    let selected = credential_layer
        .first()
        .copied()
        .or_else(|| matched_passthrough.first().copied())
        .or_else(|| catchall_passthrough.first().copied());
    RouteSelection::Selected(selected)
}

impl LoadedRoute {
    /// Whether this route has a live SPIFFE Workload API source configured.
    #[must_use]
    pub fn has_spiffe_source(&self) -> bool {
        self.managed_auth.is_some()
    }

    /// Whether this route is configured to require a proxy-managed credential
    /// but the credential material is currently unavailable.
    #[must_use]
    pub fn missing_managed_credential(
        &self,
        has_static_credential: bool,
        has_oauth2: bool,
        has_aws: bool,
        has_spiffe: bool,
    ) -> bool {
        self.requires_managed_credential
            && !has_static_credential
            && !has_oauth2
            && !has_aws
            && !has_spiffe
    }
}

/// Extract and normalise `host:port` from a URL string.
///
/// Defaults to port 443 for `https://` and 80 for `http://` when no
/// explicit port is present.
#[must_use = "route upstream host:port extraction result must be handled"]
pub(crate) fn extract_host_port(url: &str) -> std::result::Result<String, String> {
    let parsed = url::Url::parse(url).map_err(|err| format!("URL parse error: {err}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "upstream URL must include a host".to_string())?;
    let default_port = match parsed.scheme() {
        "https" => 443,
        "http" => 80,
        scheme => {
            return Err(format!(
                "unsupported upstream scheme '{scheme}' (expected http or https)"
            ));
        }
    };
    let port = parsed.port().unwrap_or(default_port);
    Ok(format_host_port(host, port))
}

pub(crate) fn format_host_port(host: &str, port: u16) -> String {
    let host = host.to_lowercase();
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => format!("{v4}:{port}"),
            std::net::IpAddr::V6(v6) => format!("[{v6}]:{port}"),
        }
    } else {
        format!("{host}:{port}")
    }
}

fn normalise_host_port(host_port: &str) -> String {
    split_host_port(host_port)
        .map(|(host, port)| format_host_port(host, port))
        .unwrap_or_else(|| host_port.to_lowercase())
}

fn split_host_port(host_port: &str) -> Option<(&str, u16)> {
    if let Some(rest) = host_port.strip_prefix('[') {
        let (host, remainder) = rest.split_once(']')?;
        let port = remainder.strip_prefix(':')?.parse::<u16>().ok()?;
        return Some((host, port));
    }

    let (host, port) = host_port.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    if host.contains(':') && host.parse::<std::net::Ipv6Addr>().is_err() {
        return None;
    }
    Some((host, port))
}

fn route_tls_config_key(route: &RouteConfig) -> Option<String> {
    if route.tls_ca.is_none() && route.tls_client_cert.is_none() && route.tls_client_key.is_none() {
        return None;
    }

    Some(format!(
        "ca={};cert={};key={}",
        route.tls_ca.as_deref().unwrap_or(""),
        route.tls_client_cert.as_deref().unwrap_or(""),
        route.tls_client_key.as_deref().unwrap_or("")
    ))
}

pub(crate) fn host_port_matches(pattern: &str, target: &str) -> bool {
    if pattern == target {
        return true;
    }
    if !pattern.starts_with("*.") {
        return false;
    }

    let Some((pattern_host, pattern_port)) = pattern.rsplit_once(':') else {
        return false;
    };
    let Some((target_host, target_port)) = target.rsplit_once(':') else {
        return false;
    };
    if pattern_port != target_port {
        return false;
    }

    let Some(suffix) = pattern_host.strip_prefix("*.") else {
        return false;
    };
    target_host
        .strip_suffix(suffix)
        .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1)
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

/// Add PEM CA certificate(s) from `ca_path` into `root_store`.
pub(crate) fn add_ca_file_to_store(
    root_store: &mut rustls::RootCertStore,
    ca_path: &str,
) -> Result<()> {
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

    Ok(())
}

/// Build a per-route `TlsConnector`, optionally adding a custom CA
/// and/or mTLS client certificate on top of `base_root_store`.
/// Returns both the connector and the underlying `Arc<ClientConfig>` so the
/// upstream pool can build per-route pooled clients.
fn build_tls_connector(
    base_root_store: &rustls::RootCertStore,
    ca_path: Option<&str>,
    client_cert_path: Option<&str>,
    client_key_path: Option<&str>,
) -> Result<(tokio_rustls::TlsConnector, Arc<rustls::ClientConfig>)> {
    let mut root_store = base_root_store.clone();

    if let Some(ca_path) = ca_path {
        add_ca_file_to_store(&mut root_store, ca_path)?;
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

    let config_arc = Arc::new(tls_config);
    let connector = tokio_rustls::TlsConnector::from(Arc::clone(&config_arc));
    Ok((connector, config_arc))
}

/// Compatibility shim: build a connector with only a custom CA (no client cert).
#[cfg(test)]
fn build_tls_connector_with_ca(ca_path: &str) -> Result<tokio_rustls::TlsConnector> {
    let base = build_base_root_store();
    let (connector, _config) = build_tls_connector(&base, Some(ca_path), None, None)?;
    Ok(connector)
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

    #[tokio::test]
    async fn test_load_routes_without_credentials() {
        // Routes without credential_key should still be loaded into RouteStore
        let routes = vec![RouteConfig {
            prefix: "/openai".to_string(),
            upstream: "https://api.openai.com".to_string(),
            credential_key: None,
            inject_mode: Default::default(),
            inject_header: "Authorization".to_string(),
            credential_format: Some("Bearer {}".to_string()),
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
            endpoint_policy: None,
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
            oauth2: None,
            aws_auth: None,
            spiffe: None,
            upgrades: vec![],
        }];

        let store = RouteStore::load(&routes).await.unwrap();
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

    #[tokio::test]
    async fn test_load_routes_normalises_prefix() {
        let routes = vec![RouteConfig {
            prefix: "/anthropic/".to_string(),
            upstream: "https://api.anthropic.com".to_string(),
            credential_key: None,
            inject_mode: Default::default(),
            inject_header: "Authorization".to_string(),
            credential_format: Some("Bearer {}".to_string()),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: None,
            endpoint_rules: vec![],
            endpoint_policy: None,
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
            oauth2: None,
            aws_auth: None,
            spiffe: None,
            upgrades: vec![],
        }];

        let store = RouteStore::load(&routes).await.unwrap();
        assert!(store.get("anthropic").is_some());
        assert!(store.get("/anthropic/").is_none());
    }

    #[tokio::test]
    async fn test_is_route_upstream() {
        let routes = vec![RouteConfig {
            prefix: "openai".to_string(),
            upstream: "https://api.openai.com".to_string(),
            credential_key: None,
            inject_mode: Default::default(),
            inject_header: "Authorization".to_string(),
            credential_format: Some("Bearer {}".to_string()),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: None,
            endpoint_rules: vec![],
            endpoint_policy: None,
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
            oauth2: None,
            aws_auth: None,
            spiffe: None,
            upgrades: vec![],
        }];

        let store = RouteStore::load(&routes).await.unwrap();
        assert!(store.is_route_upstream("api.openai.com:443"));
        assert!(!store.is_route_upstream("github.com:443"));
    }

    #[tokio::test]
    async fn test_route_upstream_hosts() {
        let routes = vec![
            RouteConfig {
                prefix: "openai".to_string(),
                upstream: "https://api.openai.com".to_string(),
                credential_key: None,
                inject_mode: Default::default(),
                inject_header: "Authorization".to_string(),
                credential_format: Some("Bearer {}".to_string()),
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                proxy: None,
                env_var: None,
                endpoint_rules: vec![],
                endpoint_policy: None,
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
                aws_auth: None,
                spiffe: None,
                upgrades: vec![],
            },
            RouteConfig {
                prefix: "anthropic".to_string(),
                upstream: "https://api.anthropic.com".to_string(),
                credential_key: None,
                inject_mode: Default::default(),
                inject_header: "Authorization".to_string(),
                credential_format: Some("Bearer {}".to_string()),
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                proxy: None,
                env_var: None,
                endpoint_rules: vec![],
                endpoint_policy: None,
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
                aws_auth: None,
                spiffe: None,
                upgrades: vec![],
            },
        ];

        let store = RouteStore::load(&routes).await.unwrap();
        let hosts = store.route_upstream_hosts();
        assert!(hosts.contains("api.openai.com:443"));
        assert!(hosts.contains("api.anthropic.com:443"));
        assert_eq!(hosts.len(), 2);
    }

    #[test]
    fn test_extract_host_port_https() {
        assert_eq!(
            extract_host_port("https://api.openai.com"),
            Ok("api.openai.com:443".to_string())
        );
    }

    #[test]
    fn test_extract_host_port_with_port() {
        assert_eq!(
            extract_host_port("https://api.example.com:8443"),
            Ok("api.example.com:8443".to_string())
        );
    }

    #[test]
    fn test_extract_host_port_http() {
        assert_eq!(
            extract_host_port("http://internal-service"),
            Ok("internal-service:80".to_string())
        );
    }

    #[test]
    fn test_extract_host_port_normalises_case() {
        assert_eq!(
            extract_host_port("https://API.Example.COM"),
            Ok("api.example.com:443".to_string())
        );
    }

    #[test]
    fn test_extract_host_port_preserves_wildcard_host() {
        assert_eq!(
            extract_host_port("https://*.dev.example.net"),
            Ok("*.dev.example.net:443".to_string())
        );
    }

    #[test]
    fn test_extract_host_port_brackets_ipv6_host() {
        assert_eq!(
            extract_host_port("http://[::1]:8080/v1"),
            Ok("[::1]:8080".to_string())
        );
        assert_eq!(
            extract_host_port("http://[0:0:0:0:0:0:0:1]:8080/v1"),
            Ok("[::1]:8080".to_string())
        );
    }

    #[tokio::test]
    async fn test_route_store_matches_bracketed_ipv6_authority() -> Result<()> {
        let routes = vec![RouteConfig {
            prefix: "local".to_string(),
            upstream: "http://[::1]:8080/v1".to_string(),
            credential_key: Some("local".to_string()),
            inject_mode: Default::default(),
            inject_header: "Authorization".to_string(),
            credential_format: Some("Bearer {}".to_string()),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: None,
            endpoint_rules: vec![],
            endpoint_policy: None,
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
            oauth2: None,
            aws_auth: None,
            spiffe: None,
            upgrades: vec![],
        }];

        let store = RouteStore::load(&routes).await?;

        assert!(store.route_upstream_hosts().contains("[::1]:8080"));
        assert!(store.is_route_upstream("[::1]:8080"));
        assert!(store.is_route_upstream("[0:0:0:0:0:0:0:1]:8080"));
        assert!(store.is_route_upstream("0:0:0:0:0:0:0:1:8080"));
        assert!(store.lookup_by_upstream("[::1]:8080").is_some());
        assert!(store.lookup_by_upstream("[0:0:0:0:0:0:0:1]:8080").is_some());
        assert!(store.has_intercept_route("[::1]:8080"));
        assert!(store.has_intercept_route("[0:0:0:0:0:0:0:1]:8080"));
        Ok(())
    }

    #[tokio::test]
    async fn test_load_routes_rejects_malformed_or_unsupported_upstreams() {
        for upstream in [
            "not a url",
            "ftp://api.openai.com",
            "https://",
            "https://api.openai.com:notaport",
        ] {
            let routes = vec![RouteConfig {
                prefix: "bad".to_string(),
                upstream: upstream.to_string(),
                credential_key: None,
                inject_mode: Default::default(),
                inject_header: "Authorization".to_string(),
                credential_format: Some("Bearer {}".to_string()),
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                proxy: None,
                env_var: None,
                endpoint_rules: vec![],
                endpoint_policy: None,
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
                aws_auth: None,
                spiffe: None,
                upgrades: vec![],
            }];

            assert!(
                RouteStore::load(&routes).await.is_err(),
                "route upstream {upstream:?} must fail closed at load time"
            );
        }
    }

    #[test]
    fn test_host_port_matches_wildcard_subdomain_only() {
        assert!(host_port_matches(
            "*.dev.example.net:443",
            "api.admin.dev.example.net:443"
        ));
        assert!(host_port_matches(
            "*.dev.example.net:443",
            "admin.dev.example.net:443"
        ));
        assert!(!host_port_matches(
            "*.dev.example.net:443",
            "dev.example.net:443"
        ));
        assert!(!host_port_matches(
            "*.dev.example.net:443",
            "api.admin.dev.example.net:8443"
        ));
        assert!(!host_port_matches(
            "*.dev.example.net:443",
            "api.admin.other.net:443"
        ));
    }

    #[test]
    fn test_loaded_route_debug() {
        let route = LoadedRoute {
            upstream: "https://api.openai.com".to_string(),
            upstream_host_port: Some("api.openai.com:443".to_string()),
            endpoint_rules: CompiledEndpointRules::compile(&[]).unwrap(),
            endpoint_policy: CompiledEndpointPolicy::compile(None, &[]).unwrap(),
            upgrade_rules: CompiledUpgradeRules::compile(&[]).unwrap(),
            tls_connector: None,
            tls_client_config: None,
            tls_config_key: None,
            requires_intercept: false,
            requires_managed_credential: false,
            managed_auth_mechanism: None,
            managed_injection_mode: None,
            managed_auth: None,
        };
        let debug_output = format!("{:?}", route);
        assert!(debug_output.contains("api.openai.com"));
        assert!(debug_output.contains("has_custom_tls_ca"));
        assert!(debug_output.contains("requires_intercept"));
        assert!(debug_output.contains("requires_managed_credential"));
        assert!(debug_output.contains("managed_auth_mechanism"));
        assert!(debug_output.contains("managed_injection_mode"));
    }

    #[tokio::test]
    async fn test_requires_intercept_credential_only() {
        let routes = vec![RouteConfig {
            prefix: "openai".to_string(),
            upstream: "https://api.openai.com".to_string(),
            credential_key: Some("openai_api_key".to_string()),
            inject_mode: Default::default(),
            inject_header: "Authorization".to_string(),
            credential_format: Some("Bearer {}".to_string()),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: None,
            endpoint_rules: vec![],
            endpoint_policy: None,
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
            oauth2: None,
            aws_auth: None,
            spiffe: None,
            upgrades: vec![],
        }];
        let store = RouteStore::load(&routes).await.unwrap();
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

    #[tokio::test]
    async fn test_requires_intercept_wildcard_credential_upstream() {
        let routes = vec![RouteConfig {
            prefix: "internal_api".to_string(),
            upstream: "https://*.dev.example.net".to_string(),
            credential_key: Some("cmd://internal_api".to_string()),
            inject_mode: Default::default(),
            inject_header: "Authorization".to_string(),
            credential_format: Some("Bearer {}".to_string()),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: Some("INTERNAL_API_TOKEN".to_string()),
            endpoint_rules: vec![],
            endpoint_policy: None,
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
            oauth2: None,
            aws_auth: None,
            spiffe: None,
            upgrades: vec![],
        }];
        let store = RouteStore::load(&routes).await.unwrap();

        assert!(store.is_route_upstream("api.admin.dev.example.net:443"));
        assert!(store.has_intercept_route("api.admin.dev.example.net:443"));
        let hit = store
            .lookup_by_upstream("api.admin.dev.example.net:443")
            .unwrap();
        assert_eq!(hit.0, "internal_api");
        assert!(hit.1.requires_managed_credential);

        let all = store.lookup_all_by_upstream("api.admin.dev.example.net:443");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].0, "internal_api");

        assert!(!store.is_route_upstream("dev.example.net:443"));
        assert!(!store.has_intercept_route("api.admin.dev.example.net:8443"));
    }

    #[tokio::test]
    async fn test_requires_intercept_endpoint_rules_only() {
        // L7-only route (no credential): rules alone are enough to require
        // interception.
        let routes = vec![RouteConfig {
            prefix: "internal".to_string(),
            upstream: "https://internal.example.com".to_string(),
            credential_key: None,
            inject_mode: Default::default(),
            inject_header: "Authorization".to_string(),
            credential_format: Some("Bearer {}".to_string()),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: None,
            endpoint_rules: vec![EndpointRule {
                method: "GET".to_string(),
                path: "/v1/items".to_string(),
            }],
            endpoint_policy: None,
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
            oauth2: None,
            aws_auth: None,
            spiffe: None,
            upgrades: vec![],
        }];
        let store = RouteStore::load(&routes).await.unwrap();
        let hit = store
            .lookup_by_upstream("internal.example.com:443")
            .unwrap();
        assert!(store.has_intercept_route("internal.example.com:443"));
        assert!(!hit.1.requires_managed_credential);
    }

    #[tokio::test]
    async fn test_requires_intercept_declarative_only() {
        // No credential, no rules — purely declarative route. CONNECT to
        // this upstream still gets the existing 403 (not intercepted).
        let routes = vec![RouteConfig {
            prefix: "alias".to_string(),
            upstream: "https://aliased.example.com".to_string(),
            credential_key: None,
            inject_mode: Default::default(),
            inject_header: "Authorization".to_string(),
            credential_format: Some("Bearer {}".to_string()),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: None,
            endpoint_rules: vec![],
            endpoint_policy: None,
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
            oauth2: None,
            aws_auth: None,
            spiffe: None,
            upgrades: vec![],
        }];
        let store = RouteStore::load(&routes).await.unwrap();
        assert!(store.is_route_upstream("aliased.example.com:443"));
        assert!(!store.has_intercept_route("aliased.example.com:443"));
    }

    #[tokio::test]
    async fn test_missing_managed_credential_policy() {
        let managed = LoadedRoute {
            upstream: "https://api.openai.com".to_string(),
            upstream_host_port: Some("api.openai.com:443".to_string()),
            endpoint_rules: CompiledEndpointRules::compile(&[]).unwrap(),
            endpoint_policy: CompiledEndpointPolicy::compile(None, &[]).unwrap(),
            upgrade_rules: CompiledUpgradeRules::compile(&[]).unwrap(),
            tls_connector: None,
            tls_client_config: None,
            tls_config_key: None,
            requires_intercept: true,
            requires_managed_credential: true,
            managed_auth_mechanism: Some(NetworkAuditAuthMechanism::PhantomHeader),
            managed_injection_mode: Some(NetworkAuditInjectionMode::Header),
            managed_auth: None,
        };
        assert!(managed.missing_managed_credential(false, false, false, false));
        assert!(!managed.missing_managed_credential(true, false, false, false));
        assert!(!managed.missing_managed_credential(false, true, false, false));
        assert!(!managed.missing_managed_credential(false, false, true, false));
        assert!(!managed.missing_managed_credential(false, false, false, true));

        let l7_only = LoadedRoute {
            upstream: "https://internal.example.com".to_string(),
            upstream_host_port: Some("internal.example.com:443".to_string()),
            endpoint_rules: CompiledEndpointRules::compile(&[]).unwrap(),
            endpoint_policy: CompiledEndpointPolicy::compile(None, &[]).unwrap(),
            upgrade_rules: CompiledUpgradeRules::compile(&[]).unwrap(),
            tls_connector: None,
            tls_client_config: None,
            tls_config_key: None,
            requires_intercept: true,
            requires_managed_credential: false,
            managed_auth_mechanism: None,
            managed_injection_mode: None,
            managed_auth: None,
        };
        assert!(!l7_only.missing_managed_credential(false, false, false, false));
    }

    #[tokio::test]
    async fn test_lookup_by_upstream_returns_prefix() {
        let routes = vec![RouteConfig {
            prefix: "openai".to_string(),
            upstream: "https://api.openai.com".to_string(),
            credential_key: Some("openai_api_key".to_string()),
            inject_mode: Default::default(),
            inject_header: "Authorization".to_string(),
            credential_format: Some("Bearer {}".to_string()),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: None,
            endpoint_rules: vec![],
            endpoint_policy: None,
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
            oauth2: None,
            aws_auth: None,
            spiffe: None,
            upgrades: vec![],
        }];
        let store = RouteStore::load(&routes).await.unwrap();
        let hit = store.lookup_by_upstream("api.openai.com:443").unwrap();
        assert_eq!(hit.0, "openai");
        assert!(hit.1.requires_intercept);
        assert!(hit.1.requires_managed_credential);
        assert!(store.lookup_by_upstream("api.example.com:443").is_none());
    }

    #[tokio::test]
    async fn test_lookup_all_by_upstream_returns_multiple_routes() {
        let routes = vec![
            RouteConfig {
                prefix: "github_org_a".to_string(),
                upstream: "https://github.com".to_string(),
                credential_key: Some("env://GH_TOKEN_A".to_string()),
                inject_mode: Default::default(),
                inject_header: "Authorization".to_string(),
                credential_format: Some("Bearer {}".to_string()),
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                proxy: None,
                env_var: Some("GH_TOKEN_A".to_string()),
                endpoint_rules: vec![crate::config::EndpointRule {
                    method: "*".to_string(),
                    path: "/org-a/**".to_string(),
                }],
                endpoint_policy: None,
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
                aws_auth: None,
                spiffe: None,
                upgrades: vec![],
            },
            RouteConfig {
                prefix: "github_org_b".to_string(),
                upstream: "https://github.com".to_string(),
                credential_key: Some("env://GH_TOKEN_B".to_string()),
                inject_mode: Default::default(),
                inject_header: "Authorization".to_string(),
                credential_format: Some("Bearer {}".to_string()),
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                proxy: None,
                env_var: Some("GH_TOKEN_B".to_string()),
                endpoint_rules: vec![crate::config::EndpointRule {
                    method: "*".to_string(),
                    path: "/org-b/**".to_string(),
                }],
                endpoint_policy: None,
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
                aws_auth: None,
                spiffe: None,
                upgrades: vec![],
            },
        ];
        let store = RouteStore::load(&routes).await.unwrap();

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

    #[derive(Debug, PartialEq)]
    enum Selection<'a> {
        Route(&'a str),
        Passthrough,
        Ambiguous(Vec<&'a str>),
        EndpointDenied,
    }

    /// Thin adapter over the real `select_route` so tests exercise the shipping
    /// decision rather than a mirror, flattening its outcome to a comparable enum.
    fn select<'a>(
        candidates: &'a [(&'a str, &'a LoadedRoute)],
        method: &str,
        path: &str,
    ) -> Selection<'a> {
        match select_route(candidates, method, path) {
            RouteSelection::EndpointDenied => Selection::EndpointDenied,
            RouteSelection::Ambiguous(names) => Selection::Ambiguous(names),
            RouteSelection::Selected(Some((svc, _))) => Selection::Route(svc),
            RouteSelection::Selected(None) => Selection::Passthrough,
        }
    }

    /// Models a real multi-org GitHub profile. Exercises `select_route`:
    ///   1 match  → inject that route's credential
    ///   0 matches → passthrough (no credential injected)
    ///   2+ matches → ambiguous (hard-deny 403)
    #[tokio::test]
    async fn test_route_selection_multi_org_profile() {
        // Helper to build a route with the given prefix and endpoint path.
        fn gh_route(prefix: &str, env: &str, path: &str) -> RouteConfig {
            RouteConfig {
                prefix: prefix.to_string(),
                upstream: "https://github.com".to_string(),
                credential_key: Some(format!("env://{env}")),
                inject_mode: Default::default(),
                inject_header: "Authorization".to_string(),
                credential_format: Some("Bearer {}".to_string()),
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                proxy: None,
                env_var: Some(env.to_string()),
                endpoint_rules: vec![crate::config::EndpointRule {
                    method: "*".to_string(),
                    path: path.to_string(),
                }],
                endpoint_policy: None,
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
                aws_auth: None,
                spiffe: None,
                upgrades: vec![],
            }
        }

        // --- Profile: two org-scoped routes, no catch-all ---
        let routes = vec![
            gh_route("github_https_org_a", "GH_TOKEN_A", "/org-a/**"),
            gh_route("github_https_org_b", "GH_TOKEN_B", "/org-b/**"),
        ];
        let store = RouteStore::load(&routes).await.unwrap();
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
        // Public repo (e.g. nolabs-ai/nono) → passthrough, no cred
        assert_eq!(
            select(&candidates, "GET", "/nolabs-ai/nono.git/info/refs"),
            Selection::Passthrough
        );
        // POST to public repo → also passthrough
        assert_eq!(
            select(&candidates, "POST", "/nolabs-ai/nono.git/git-upload-pack"),
            Selection::Passthrough
        );

        // --- Adding a /** catch-all would cause ambiguity ---
        let routes_with_catchall = vec![
            gh_route("github_https_org_a", "GH_TOKEN_A", "/org-a/**"),
            gh_route("github_https_org_b", "GH_TOKEN_B", "/org-b/**"),
            gh_route("github_https_all", "GH_TOKEN_A", "/**"),
        ];
        let store2 = RouteStore::load(&routes_with_catchall).await.unwrap();
        let candidates2 = store2.lookup_all_by_upstream("github.com:443");
        assert_eq!(candidates2.len(), 3);

        // org-a request now matches BOTH org_a AND the /** catch-all → ambiguous
        assert_eq!(
            select(&candidates2, "GET", "/org-a/repo.git/info/refs"),
            Selection::Ambiguous(vec!["github_https_all", "github_https_org_a"])
        );
        // Public repo matches only the /** catch-all → 1 match, ok
        assert_eq!(
            select(&candidates2, "GET", "/nolabs-ai/nono.git/info/refs"),
            Selection::Route("github_https_all")
        );
    }

    /// A credential-less `_ep_` authorization route (from `allow_domain` with
    /// endpoints) must not shadow a credential catch-all on a path the `_ep_`
    /// route authorizes — the token has to be injected, not silently dropped.
    #[tokio::test]
    async fn test_route_selection_credential_catchall_not_shadowed() {
        // `_ep_` endpoint-authorization route: no credential, scoped to /org/**.
        let ep_route = RouteConfig {
            prefix: "_ep_github.com".to_string(),
            upstream: "https://github.com".to_string(),
            endpoint_rules: vec![crate::config::EndpointRule {
                method: "*".to_string(),
                path: "/org/**".to_string(),
            }],
            ..Default::default()
        };
        // Credential catch-all: carries a token, no endpoint rules.
        let cred_route = RouteConfig {
            prefix: "github_api".to_string(),
            upstream: "https://github.com".to_string(),
            credential_key: Some("env://GH_TOKEN".to_string()),
            credential_format: Some("Bearer {}".to_string()),
            env_var: Some("GH_TOKEN".to_string()),
            ..Default::default()
        };

        let store = RouteStore::load(&[ep_route, cred_route]).await.unwrap();
        let candidates = store.lookup_all_by_upstream("github.com:443");
        assert_eq!(candidates.len(), 2);

        // Authorized path (matches the _ep_ rule): the credential catch-all must
        // win so the token is injected — not the credential-less _ep_ match.
        assert_eq!(
            select(&candidates, "GET", "/org/repo"),
            Selection::Route("github_api"),
            "credential catch-all must be selected on the _ep_-authorized path"
        );
        // Non-matching path: the _ep_ gate hard-denies before the catch-all is
        // reached, so the catch-all cannot bypass endpoint restrictions.
        assert_eq!(
            select(&candidates, "GET", "/other/repo"),
            Selection::EndpointDenied
        );
    }

    /// Two credential catch-alls for the same upstream are ambiguous: the proxy
    /// must not silently pick one to inject, just as with overlapping endpoint
    /// credential routes.
    #[tokio::test]
    async fn test_route_selection_dual_credential_catchall_is_ambiguous() {
        let cred_a = RouteConfig {
            prefix: "github_a".to_string(),
            upstream: "https://github.com".to_string(),
            credential_key: Some("env://GH_TOKEN_A".to_string()),
            credential_format: Some("Bearer {}".to_string()),
            env_var: Some("GH_TOKEN_A".to_string()),
            ..Default::default()
        };
        let cred_b = RouteConfig {
            prefix: "github_b".to_string(),
            upstream: "https://github.com".to_string(),
            credential_key: Some("env://GH_TOKEN_B".to_string()),
            credential_format: Some("Bearer {}".to_string()),
            env_var: Some("GH_TOKEN_B".to_string()),
            ..Default::default()
        };

        let store = RouteStore::load(&[cred_a, cred_b]).await.unwrap();
        let candidates = store.lookup_all_by_upstream("github.com:443");
        assert_eq!(candidates.len(), 2);

        // Both credential catch-alls cover every path → ambiguous, not a silent pick.
        assert_eq!(
            select(&candidates, "GET", "/any/path"),
            Selection::Ambiguous(vec!["github_a", "github_b"])
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

    #[tokio::test]
    async fn test_route_store_loads_mtls_route() {
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
            credential_format: Some("Bearer {}".to_string()),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: None,
            endpoint_rules: vec![],
            endpoint_policy: None,
            tls_ca: None,
            tls_client_cert: Some(cert_path.to_str().unwrap().to_string()),
            tls_client_key: Some(key_path.to_str().unwrap().to_string()),
            oauth2: None,
            aws_auth: None,
            spiffe: None,
            upgrades: vec![],
        }];

        let store = RouteStore::load(&routes)
            .await
            .expect("should load mTLS route");
        let route = store.get("k8s").unwrap();
        assert!(
            route.tls_connector.is_some(),
            "connector must be built when tls_client_cert/key are set"
        );
    }

    #[tokio::test]
    async fn websocket_rule_alone_requires_interception() {
        let route: RouteConfig = serde_json::from_str(
            r#"{
                "prefix": "chat",
                "upstream": "https://chat.example",
                "upgrades": [{"path": "/socket"}]
            }"#,
        )
        .unwrap();
        let store = RouteStore::load(&[route]).await.unwrap();
        assert!(store.get("chat").unwrap().requires_intercept);
    }
}
