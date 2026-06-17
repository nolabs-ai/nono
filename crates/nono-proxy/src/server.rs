//! Proxy server: TCP listener, connection dispatch, and lifecycle.
//!
//! The server binds to `127.0.0.1:0` (OS-assigned port), accepts TCP
//! connections, reads the first HTTP line to determine the mode, and
//! dispatches to the appropriate handler.
//!
//! CONNECT method -> [`connect`] or [`external`] handler
//! Other methods  -> [`reverse`] handler (credential injection)

use crate::audit;
use crate::config::ProxyConfig;
use crate::connect;
use crate::credential::CredentialStore;
use crate::error::{ProxyError, Result};
use crate::external;
use crate::filter::{ProxyFilter, RuntimeProxyFilter};
use crate::reverse;
use crate::route::RouteStore;
use crate::tls_intercept::{self, CertCache, EphemeralCa};
use crate::token;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{debug, info, warn};
use url::Url;
use zeroize::Zeroizing;

/// Maximum total size of HTTP headers (64 KiB). Prevents OOM from
/// malicious clients sending unbounded header data.
const MAX_HEADER_SIZE: usize = 64 * 1024;

/// Parse host and port from a non-CONNECT proxy request line.
///
/// Example: `GET http://google.com/ HTTP/1.1` -> ("google.com", 80)
///          `GET http://google.com:8080/path HTTP/1.1` -> ("google.com", 8080)
fn parse_non_connect_target(line: &str) -> Result<(String, u16)> {
    let mut parts = line.split_whitespace();
    let _method = parts.next();
    let url = parts
        .next()
        .ok_or_else(|| ProxyError::HttpParse(format!("malformed request line: {}", line)))?;
    let parsed = Url::parse(url)
        .map_err(|e| ProxyError::HttpParse(format!("invalid URL in request: {}: {}", url, e)))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| ProxyError::HttpParse(format!("no host in URL: {}", url)))?
        .to_string();
    let port = parsed.port_or_known_default().unwrap_or(80);
    Ok((host, port))
}

/// Handle returned when the proxy server starts.
///
/// Contains the assigned port, session token, and a shutdown channel.
/// Drop the handle or send to `shutdown_tx` to stop the proxy.
pub struct ProxyHandle {
    /// The actual port the proxy is listening on
    pub port: u16,
    /// Session token for client authentication
    pub token: Zeroizing<String>,
    /// Shared in-memory network audit log
    audit_log: audit::SharedAuditLog,
    /// Send `true` to trigger graceful shutdown
    shutdown_tx: watch::Sender<bool>,
    /// Route prefixes that have credentials actually loaded.
    /// Routes whose credentials were unavailable are excluded so we
    /// don't inject phantom tokens that shadow valid external credentials.
    loaded_routes: std::collections::HashSet<String>,
    /// Non-credential allowed hosts that should bypass the proxy (NO_PROXY).
    /// Computed at startup: `allowed_hosts` minus credential upstream hosts.
    no_proxy_hosts: Vec<String>,
    /// Path to the TLS-intercept trust bundle written at startup, when
    /// interception is active. The CLI passes this path to the sandboxed
    /// child via env vars (`SSL_CERT_FILE` etc.) and grants a Landlock /
    /// Seatbelt read capability on it. `None` when interception is not
    /// configured (no `intercept_ca_dir`) or no route requires L7 visibility.
    intercept_ca_path: Option<PathBuf>,
}

impl ProxyHandle {
    /// Signal the proxy to shut down gracefully.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    /// Drain and return collected network audit events.
    #[must_use]
    pub fn drain_audit_events(&self) -> Vec<nono::undo::NetworkAuditEvent> {
        audit::drain_audit_events(&self.audit_log)
    }

    /// Path to the TLS-intercept trust bundle, when interception is active.
    ///
    /// The CLI uses this to:
    /// * point `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` / `NODE_EXTRA_CA_CERTS`
    ///   / `CURL_CA_BUNDLE` at the file in the child env;
    /// * grant the sandboxed child a Landlock / Seatbelt read capability
    ///   on the file before applying the sandbox.
    ///
    /// `None` when interception is not configured (no `intercept_ca_dir`
    /// in `ProxyConfig`) or when no configured route requires L7 visibility.
    #[must_use]
    pub fn intercept_ca_path(&self) -> Option<&std::path::Path> {
        self.intercept_ca_path.as_deref()
    }

    /// One-line-per-route diagnostic summary suitable for surfacing at
    /// session start. Returns `(prefix, summary)` pairs.
    ///
    /// Each summary names: upstream URL, credential resolution status
    /// (✓ / ✗ + source label), TLS-intercept on/off, and `endpoint_rules`
    /// count. Designed to make silent credential-resolution failures
    /// noisy by default, addressing the common "I created the keychain
    /// entry but the warn at debug level got missed" footgun.
    ///
    /// `config` is the same `ProxyConfig` that was passed to `start()`;
    /// the handle doesn't keep a copy, so the CLI passes it back in.
    #[must_use]
    pub fn route_diagnostics(&self, config: &ProxyConfig) -> Vec<(String, String)> {
        let mut rows = Vec::with_capacity(config.routes.len());
        for route in &config.routes {
            let prefix = route.prefix.trim_matches('/').to_string();
            let cred_summary = if let Some(ref key) = route.credential_key {
                let resolved = self.loaded_routes.contains(&prefix);
                if resolved {
                    format!("creds: {} ✓", key)
                } else {
                    format!("creds: {} ✗ (not found)", key)
                }
            } else if route.oauth2.is_some() {
                let resolved = self.loaded_routes.contains(&prefix);
                if resolved {
                    "creds: oauth2 ✓".to_string()
                } else {
                    "creds: oauth2 ✗ (token exchange failed)".to_string()
                }
            } else {
                "creds: none".to_string()
            };

            let intercept_summary = if self.intercept_ca_path.is_some()
                && (route.credential_key.is_some()
                    || route.oauth2.is_some()
                    || !route.endpoint_rules.is_empty())
            {
                "intercept: on"
            } else {
                "intercept: off"
            };

            let rules_summary = format!("endpoint_rules: {}", route.endpoint_rules.len());
            let summary = format!(
                "→ {} | {} | {} | {}",
                route.upstream, cred_summary, intercept_summary, rules_summary
            );
            rows.push((prefix, summary));
        }
        rows
    }

    /// Environment variables to inject into the child process.
    ///
    /// The proxy URL includes `nono:<token>@` userinfo so that standard HTTP
    /// clients (curl, Python requests, etc.) automatically send
    /// `Proxy-Authorization: Basic ...` on every request. The raw token is
    /// also provided via `NONO_PROXY_TOKEN` for nono-aware clients that
    /// prefer Bearer auth.
    ///
    /// When TLS interception is active (`intercept_ca_path()` is `Some`),
    /// the standard runtime CA-trust env vars are also set so the agent
    /// trusts the proxy's ephemeral CA when minted leaf certs are
    /// presented during interception.
    #[must_use]
    pub fn env_vars(&self) -> Vec<(String, String)> {
        let proxy_url = format!("http://nono:{}@127.0.0.1:{}", &*self.token, self.port);

        // Build NO_PROXY: always include loopback, plus non-credential
        // allowed hosts. Credential upstreams are excluded so their traffic
        // goes through the reverse proxy for L7 filtering + injection.
        let mut no_proxy_parts = vec!["localhost".to_string(), "127.0.0.1".to_string()];
        for host in &self.no_proxy_hosts {
            // Strip port for NO_PROXY (most HTTP clients match on hostname).
            // Handle IPv6 brackets: "[::1]:443" → "[::1]", "host:443" → "host"
            let hostname = if host.contains("]:") {
                // IPv6 with port: split at "]:port"
                host.rsplit_once("]:")
                    .map(|(h, _)| format!("{}]", h))
                    .unwrap_or_else(|| host.clone())
            } else {
                host.rsplit_once(':')
                    .and_then(|(h, p)| p.parse::<u16>().ok().map(|_| h.to_string()))
                    .unwrap_or_else(|| host.clone())
            };
            if !no_proxy_parts.contains(&hostname.to_string()) {
                no_proxy_parts.push(hostname.to_string());
            }
        }
        let no_proxy = no_proxy_parts.join(",");

        let mut vars = vec![
            ("HTTP_PROXY".to_string(), proxy_url.clone()),
            ("HTTPS_PROXY".to_string(), proxy_url.clone()),
            ("NO_PROXY".to_string(), no_proxy.clone()),
            ("NONO_PROXY_TOKEN".to_string(), self.token.to_string()),
        ];

        // Lowercase variants for compatibility
        vars.push(("http_proxy".to_string(), proxy_url.clone()));
        vars.push(("https_proxy".to_string(), proxy_url));
        vars.push(("no_proxy".to_string(), no_proxy));

        // Node.js 20.6+ needs an explicit hint to use HTTPS_PROXY for built-in
        // fetch(). Without it, Node-based clients can bypass the proxy and hit
        // the sandboxed network directly.
        // NODE_USE_ENV_PROXY tells Node's built-in fetch() to read HTTPS_PROXY
        // from the environment.
        // Harmless to non-Node runtimes — they ignore unknown env vars.
        vars.push(("NODE_USE_ENV_PROXY".to_string(), "1".to_string()));

        // TLS-intercept trust injection. The bundle file at this path
        // contains the parent's `SSL_CERT_FILE` (if any) + the host's
        // system trust store + the ephemeral session CA, so standard
        // runtimes see a superset of the trust they had before nono.
        //
        // Replacement semantics (swap out the default store entirely):
        //   SSL_CERT_FILE, REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE, GIT_SSL_CAINFO
        // Additive semantics (default + this file):
        //   NODE_EXTRA_CA_CERTS
        //
        // Pointing all five at the same bundle is safe: Node sees system
        // roots twice (harmless), and all other runtimes get the union of
        // trust they need.
        if let Some(path) = self.intercept_ca_path.as_deref() {
            let path_str = path.to_string_lossy().to_string();
            vars.push(("SSL_CERT_FILE".to_string(), path_str.clone()));
            vars.push(("REQUESTS_CA_BUNDLE".to_string(), path_str.clone()));
            vars.push(("NODE_EXTRA_CA_CERTS".to_string(), path_str.clone()));
            vars.push(("CURL_CA_BUNDLE".to_string(), path_str.clone()));
            vars.push(("GIT_SSL_CAINFO".to_string(), path_str));
        }

        vars
    }

    /// Environment variables for reverse proxy credential routes.
    ///
    /// Returns two types of env vars per route:
    /// 1. SDK base URL overrides (e.g., `OPENAI_BASE_URL=http://127.0.0.1:PORT/openai`)
    /// 2. SDK API key vars set to the session token (e.g., `OPENAI_API_KEY=<token>`)
    ///
    /// The SDK sends the session token as its "API key" (phantom token pattern).
    /// The proxy validates this token and swaps it for the real credential.
    #[must_use]
    pub fn credential_env_vars(&self, config: &ProxyConfig) -> Vec<(String, String)> {
        let mut vars = Vec::new();
        for route in &config.routes {
            // Strip any leading or trailing '/' from the prefix — prefix should
            // be a bare service name (e.g., "anthropic"), not a URL path.
            // Defensively handle both forms to prevent malformed env var names
            // and double-slashed URLs.
            let prefix = route.prefix.trim_matches('/');

            // Base URL override (e.g., OPENAI_BASE_URL)
            let base_url_name = format!("{}_BASE_URL", prefix.to_uppercase());
            let url = format!("http://127.0.0.1:{}/{}", self.port, prefix);
            vars.push((base_url_name, url));

            // Only inject phantom token env vars for routes whose credentials
            // were actually loaded. If a credential was unavailable (e.g.,
            // GITHUB_TOKEN env var not set), injecting a phantom token would
            // shadow valid credentials from other sources (keyring, gh auth).
            if !self.loaded_routes.contains(prefix) {
                continue;
            }

            // API key set to session token (phantom token pattern).
            // Use explicit env_var if set (required for URI manager refs), otherwise
            // fall back to uppercasing the credential_key (e.g., "openai_api_key" -> "OPENAI_API_KEY").
            if let Some(ref env_var) = route.env_var {
                vars.push((env_var.clone(), self.token.to_string()));
            } else if let Some(ref cred_key) = route.credential_key {
                // Skip URI-format keys (e.g. env://, op://, apple-password://) —
                // uppercasing a URI produces a nonsensical env var name. These
                // routes must declare an explicit env_var to get phantom token injection.
                if !cred_key.contains("://") {
                    let api_key_name = cred_key.to_uppercase();
                    vars.push((api_key_name, self.token.to_string()));
                }
            }
        }
        vars
    }
}

impl Drop for ProxyHandle {
    /// Best-effort cleanup of the TLS-intercept trust bundle on shutdown.
    ///
    /// The CA private key was never persisted to disk (it lives only in a
    /// `Zeroizing<Vec<u8>>` inside the running proxy task and is zeroized
    /// when that task drops). Here we remove the public certificate file
    /// so the next session doesn't inherit a stale bundle path.
    ///
    /// Errors are intentionally swallowed — `Drop` has no good way to
    /// surface them, and the file may already be gone if the user invoked
    /// `shutdown()` from another path.
    fn drop(&mut self) {
        if let Some(path) = self.intercept_ca_path.take() {
            let _ = std::fs::remove_file(&path);
            // If the parent dir is now empty (we may have been the only
            // tenant in `~/.nono/sessions/<id>/`), tidy up. A non-empty
            // dir simply fails the rmdir and leaves unrelated contents
            // in place — exactly what we want.
            if let Some(parent) = path.parent() {
                let _ = std::fs::remove_dir(parent);
            }
        }
    }
}

/// Shared state for the proxy server.
struct ProxyState {
    filter: ProxyFilter,
    runtime_filter: Option<RuntimeProxyFilter>,
    approval_tx: Option<tokio::sync::mpsc::Sender<connect::ApprovalChannelRequest>>,
    approval_timeout: Duration,
    session_token: Zeroizing<String>,
    /// Route-level configuration (upstream, L7 filtering, custom TLS CA) for all routes.
    route_store: RouteStore,
    /// Credential-specific configuration (inject mode, headers, secrets) for routes with credentials.
    credential_store: CredentialStore,
    config: ProxyConfig,
    /// Shared TLS connector for upstream connections (reverse proxy mode).
    /// Created once at startup to avoid rebuilding the root cert store per request.
    tls_connector: tokio_rustls::TlsConnector,
    /// Active connection count for connection limiting.
    active_connections: AtomicUsize,
    /// Shared network audit log for this proxy session.
    audit_log: audit::SharedAuditLog,
    /// Matcher for hosts that bypass the external proxy and route direct.
    /// Built once at startup from `ExternalProxyConfig.bypass_hosts`.
    bypass_matcher: external::BypassMatcher,
    /// Per-hostname leaf-certificate cache backed by the session ephemeral
    /// CA, when TLS interception is active. `None` disables the intercept
    /// CONNECT branch (CONNECTs fall through to the existing 403/tunnel
    /// dispatch even for routes that would otherwise require L7).
    cert_cache: Option<Arc<CertCache>>,
    /// PID of the sandboxed child process (for approval requests).
    child_pid: u32,
    /// Session ID for correlating approval requests.
    session_id: String,
}

/// Start the proxy server.
///
/// Binds to `config.bind_addr:config.bind_port` (port 0 = OS-assigned),
/// generates a session token, and begins accepting connections.
///
/// Returns a `ProxyHandle` with the assigned port and session token.
/// The server runs until the handle is dropped or `shutdown()` is called.
pub async fn start(config: ProxyConfig) -> Result<ProxyHandle> {
    start_with_approval(config, None, None, 0, "", Duration::from_secs(60)).await
}

/// Start the proxy server with optional network approval support.
///
/// When `runtime_filter` and `approval_tx` are provided, the proxy
/// will request user approval for blocked hosts instead of immediately
/// returning 403.
pub async fn start_with_approval(
    config: ProxyConfig,
    runtime_filter: Option<RuntimeProxyFilter>,
    approval_tx: Option<tokio::sync::mpsc::Sender<connect::ApprovalChannelRequest>>,
    child_pid: u32,
    session_id: &str,
    approval_timeout: Duration,
) -> Result<ProxyHandle> {
    // Generate session token
    let session_token = token::generate_session_token()?;

    // Bind listener
    let bind_addr = SocketAddr::new(config.bind_addr, config.bind_port);
    let listener = TcpListener::bind(bind_addr)
        .await
        .map_err(|e| ProxyError::Bind {
            addr: bind_addr.to_string(),
            source: e,
        })?;

    let local_addr = listener.local_addr().map_err(|e| ProxyError::Bind {
        addr: bind_addr.to_string(),
        source: e,
    })?;
    let port = local_addr.port();

    info!("Proxy server listening on {}", local_addr);

    // Load route-level configuration (upstream, L7 filtering, custom TLS CA)
    // for ALL routes, regardless of credential presence.
    let route_store = if config.routes.is_empty() {
        RouteStore::empty()
    } else {
        RouteStore::load(&config.routes)?
    };

    // Build shared TLS connector (root cert store is expensive to construct).
    // Use the ring provider explicitly to avoid ambiguity when multiple
    // crypto providers are in the dependency tree.
    // Must be created before CredentialStore::load() because OAuth2 token
    // exchange needs TLS.
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let native = rustls_native_certs::load_native_certs();
    if !native.errors.is_empty() {
        debug!(
            "failed to load {} native cert(s); continuing with webpki roots + any that succeeded",
            native.errors.len()
        );
    }
    let native_count = native.certs.len();
    for cert in native.certs {
        if let Err(e) = root_store.add(cert) {
            debug!("skipping unparseable native cert: {e}");
        }
    }
    if native_count > 0 {
        debug!("added {native_count} native system CA(s) to upstream trust store");
    }
    let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| ProxyError::Config(format!("TLS config error: {}", e)))?
    .with_root_certificates(root_store)
    .with_no_client_auth();
    let tls_connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));

    // Load credentials for reverse proxy routes (static keystore + OAuth2)
    let credential_store = if config.routes.is_empty() {
        CredentialStore::empty()
    } else {
        CredentialStore::load(&config.routes, &tls_connector)?
    };
    let loaded_routes = credential_store.loaded_prefixes();

    // Build filter. Strict mode treats an empty allowlist as deny-all.
    let filter = if config.strict_filter {
        ProxyFilter::new_strict(&config.allowed_hosts)
    } else if config.allowed_hosts.is_empty() && config.rejected_hosts.is_empty() {
        ProxyFilter::allow_all()
    } else {
        ProxyFilter::new_with_reject(&config.allowed_hosts, &config.rejected_hosts)
    };

    // Build bypass matcher from external proxy config (once, not per-request)
    let bypass_matcher = config
        .external_proxy
        .as_ref()
        .map(|ext| external::BypassMatcher::new(&ext.bypass_hosts))
        .unwrap_or_else(|| external::BypassMatcher::new(&[]));

    // Shutdown channel
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let audit_log = audit::new_audit_log();

    // Compute NO_PROXY hosts: allowed_hosts that can be reached via
    // direct TCP connections (i.e. their port is in direct_connect_ports).
    // Hosts without a direct TCP grant MUST go through the proxy —
    // adding them to NO_PROXY would cause clients to attempt direct
    // connections that the sandbox (Landlock / Seatbelt) denies.
    //
    // Route upstreams are always excluded so their traffic goes through
    // the proxy for L7 path filtering and/or credential injection.
    //
    // On macOS this MUST be empty regardless: Seatbelt's ProxyOnly mode
    // blocks ALL direct outbound. See #580.
    let no_proxy_hosts: Vec<String> = if cfg!(target_os = "macos") {
        Vec::new()
    } else {
        let route_hosts = route_store.route_upstream_hosts();
        config
            .allowed_hosts
            .iter()
            .filter(|host| {
                let normalised = {
                    let h = host.to_lowercase();
                    if h.starts_with('[') {
                        // IPv6 literal: "[::1]:443" has port, "[::1]" needs default
                        if h.contains("]:") {
                            h
                        } else {
                            format!("{}:443", h)
                        }
                    } else if h.contains(':') {
                        h
                    } else {
                        format!("{}:443", h)
                    }
                };
                if route_hosts.contains(&normalised) {
                    return false;
                }
                // Only bypass the proxy if the sandbox grants direct
                // TCP on this host's port (via --allow-connect-port).
                let port = normalised
                    .rsplit_once(':')
                    .and_then(|(_, p)| p.parse::<u16>().ok())
                    .unwrap_or(443);
                config.direct_connect_ports.contains(&port)
            })
            .cloned()
            .collect()
    };

    if !no_proxy_hosts.is_empty() {
        debug!("Smart NO_PROXY bypass hosts: {:?}", no_proxy_hosts);
    }

    // Initialise TLS interception if a directory was supplied AND at least
    // one configured route actually requires L7 visibility. Routes are
    // checked here (rather than relying solely on the CLI's decision) so a
    // misconfigured `intercept_ca_dir` without intercept-bearing routes
    // doesn't generate a useless CA on disk.
    let any_intercept_route = route_store
        .route_upstream_hosts()
        .iter()
        .any(|hp| route_store.has_intercept_route(hp));
    let (cert_cache, intercept_ca_path) = match (&config.intercept_ca_dir, any_intercept_route) {
        (Some(dir), true) => {
            let intercept_route_count = route_store
                .route_upstream_hosts()
                .iter()
                .filter(|hp| route_store.has_intercept_route(hp))
                .count();
            let ca_result = if let Some(ref preloaded) = config.preloaded_ca {
                EphemeralCa::from_existing(&preloaded.key_der, &preloaded.cert_pem)
            } else {
                let validity = config
                    .ca_validity
                    .unwrap_or(crate::tls_intercept::ca::CA_VALIDITY_DEFAULT);
                EphemeralCa::generate_with_cn("nono-session-ca", validity)
            };
            match ca_result.and_then(|ca| {
                let ca = Arc::new(ca);
                let cache = Arc::new(CertCache::new(Arc::clone(&ca)));
                let path = tls_intercept::write_bundle(tls_intercept::BundleInputs {
                    dir,
                    filename: "intercept-ca.pem",
                    parent_ssl_cert_file: config.intercept_parent_ca_pems.as_deref(),
                    ephemeral_ca_pem: ca.cert_pem(),
                })?;
                Ok((cache, path))
            }) {
                Ok((cache, path)) => {
                    info!(
                        "TLS interception active for {} route(s); trust bundle at {}",
                        intercept_route_count,
                        path.display()
                    );
                    (Some(cache), Some(path))
                }
                Err(e) => {
                    warn!(
                        "TLS interception setup failed for {} route(s): {}. \
                         Continuing with interception disabled; reverse-proxy routes remain available.",
                        intercept_route_count, e
                    );
                    (None, None)
                }
            }
        }
        (Some(_), false) => {
            debug!(
                "TLS interception requested but no configured route requires L7 visibility; \
                 skipping CA generation"
            );
            (None, None)
        }
        (None, _) => (None, None),
    };

    let state = Arc::new(ProxyState {
        filter,
        runtime_filter,
        approval_tx,
        approval_timeout,
        session_token: session_token.clone(),
        route_store,
        credential_store,
        config,
        tls_connector,
        active_connections: AtomicUsize::new(0),
        audit_log: Arc::clone(&audit_log),
        bypass_matcher,
        cert_cache,
        child_pid,
        session_id: session_id.to_string(),
    });

    // Spawn accept loop as a task within the current runtime.
    // The caller MUST ensure this runtime is being driven (e.g., via
    // a dedicated thread calling block_on or a multi-thread runtime).
    tokio::spawn(accept_loop(listener, state, shutdown_rx));

    Ok(ProxyHandle {
        port,
        token: session_token,
        audit_log,
        shutdown_tx,
        loaded_routes,
        no_proxy_hosts,
        intercept_ca_path,
    })
}

/// Accept loop: listen for connections until shutdown.
async fn accept_loop(
    listener: TcpListener,
    state: Arc<ProxyState>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, addr)) => {
                        // Connection limit enforcement
                        let max = state.config.max_connections;
                        if max > 0 {
                            let current = state.active_connections.load(Ordering::Relaxed);
                            if current >= max {
                                warn!("Connection limit reached ({}/{}), rejecting {}", current, max, addr);
                                // Drop the stream (connection refused)
                                drop(stream);
                                continue;
                            }
                        }
                        state.active_connections.fetch_add(1, Ordering::Relaxed);

                        debug!("Accepted connection from {}", addr);
                        let state = Arc::clone(&state);
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, &state).await {
                                debug!("Connection handler error: {}", e);
                            }
                            state.active_connections.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                    Err(e) => {
                        warn!("Accept error: {}", e);
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!("Proxy server shutting down");
                    return;
                }
            }
        }
    }
}

/// Normalise a CONNECT authority to lowercase `host:port`, defaulting the port
/// to 443 when absent. Handles IPv6 brackets: `[::1]:443` already has a port,
/// `[::1]` needs the default, `host:443` has a port.
fn normalize_authority(authority: &str) -> String {
    if authority.starts_with('[') {
        if authority.contains("]:") {
            authority.to_lowercase()
        } else {
            format!("{}:443", authority.to_lowercase())
        }
    } else if authority.contains(':') {
        authority.to_lowercase()
    } else {
        format!("{}:443", authority.to_lowercase())
    }
}

/// Handle a single client connection.
///
/// Reads the first HTTP line to determine the proxy mode:
/// - CONNECT method -> tunnel (Mode 1 or 3)
/// - Other methods  -> reverse proxy (Mode 2)
async fn handle_connection(mut stream: tokio::net::TcpStream, state: &ProxyState) -> Result<()> {
    // Read the first line and headers through a BufReader.
    // We keep the BufReader alive until we've consumed the full header
    // to prevent data loss (BufReader may read ahead into the body).
    let mut buf_reader = BufReader::new(&mut stream);
    let mut first_line = String::new();
    buf_reader.read_line(&mut first_line).await?;

    if first_line.is_empty() {
        return Ok(()); // Client disconnected
    }

    // Read remaining headers (up to empty line), with size limit to prevent OOM.
    let mut header_bytes = Vec::new();
    loop {
        let mut line = String::new();
        let n = buf_reader.read_line(&mut line).await?;
        if n == 0 || line.trim().is_empty() {
            break;
        }
        header_bytes.extend_from_slice(line.as_bytes());
        if header_bytes.len() > MAX_HEADER_SIZE {
            drop(buf_reader);
            let response = "HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n";
            stream.write_all(response.as_bytes()).await?;
            return Ok(());
        }
    }

    // Extract any data buffered beyond headers before dropping BufReader.
    // BufReader may have read ahead into the request body. We capture
    // those bytes and pass them to the reverse proxy handler so no body
    // data is lost. For CONNECT requests this is always empty (no body).
    let buffered = buf_reader.buffer().to_vec();
    drop(buf_reader);

    let first_line = first_line.trim_end();

    // Dispatch by method
    if first_line.starts_with("CONNECT ") {
        // CONNECT requests targeting a configured route's upstream get
        // special handling. There are three sub-cases:
        //
        // 1. Route requires L7 visibility (`endpoint_rules`, `credential_key`,
        //    or `oauth2`) AND TLS interception is configured: terminate TLS
        //    locally so credential injection / endpoint filtering can run.
        // 2. Route requires L7 visibility but interception is *not* configured:
        //    fall back to the existing 403 — the agent must use the reverse
        //    proxy path. Without interception we can't enforce L7 over CONNECT.
        // 3. Route exists but is purely declarative (no L7 requirements):
        //    keep the existing 403 — the route exists to provide a `*_BASE_URL`
        //    env var, and CONNECT would bypass that intent.
        //
        // Anything else (host not matching any route) falls through to the
        // existing transparent-tunnel / external-proxy paths.
        if !state.route_store.is_empty()
            && let Some(authority) = first_line.split_whitespace().nth(1)
        {
            let host_port = normalize_authority(authority);

            if state.route_store.is_route_upstream(&host_port) {
                let route_id = state
                    .route_store
                    .lookup_by_upstream(&host_port)
                    .map(|(prefix, _)| prefix);
                let (host, port) = host_port
                    .rsplit_once(':')
                    .map(|(h, p)| (h.to_string(), p.parse::<u16>().unwrap_or(443)))
                    .unwrap_or_else(|| (host_port.clone(), 443));

                let intercept_eligible = state.route_store.has_intercept_route(&host_port);

                match (intercept_eligible, state.cert_cache.as_ref()) {
                    // Case 1: intercept-eligible route + cert cache available.
                    (true, Some(cache)) => {
                        // Strict OUTER auth: intercept is a privileged op
                        // (we mint a leaf cert and decrypt traffic), so
                        // unlike the lenient transparent-tunnel path we
                        // require Proxy-Authorization here.
                        // Reactive proxy auth (RFC 7235 / RFC 9110 §15.5.8): a
                        // client may send the first CONNECT without credentials,
                        // receive the 407 challenge, then retry the CONNECT with
                        // Proxy-Authorization on the SAME connection. Keep the
                        // connection open across the 407 and re-read the retried
                        // request head rather than dropping the socket — closing
                        // it breaks reactive clients (Apache HttpClient, Java's
                        // HttpClient, Maven's native resolver).
                        let mut current_headers = header_bytes;
                        loop {
                            match token::validate_proxy_auth(&current_headers, &state.session_token)
                            {
                                Ok(()) => break,
                                Err(e) => {
                                    debug!(
                                        "tls_intercept: CONNECT to {}:{} missing/invalid proxy auth — {}",
                                        host, port, e
                                    );
                                    audit::log_denied(
                                        Some(&state.audit_log),
                                        audit::ProxyMode::ConnectIntercept,
                                        &audit::EventContext {
                                            route_id,
                                            auth_mechanism: Some(
                                                nono::undo::NetworkAuditAuthMechanism::ProxyAuthorization,
                                            ),
                                            auth_outcome: Some(
                                                nono::undo::NetworkAuditAuthOutcome::Failed,
                                            ),
                                            denial_category: Some(
                                                nono::undo::NetworkAuditDenialCategory::AuthenticationFailed,
                                            ),
                                            ..audit::EventContext::default()
                                        },
                                        &host,
                                        port,
                                        "proxy auth missing or invalid",
                                    );
                                    let response = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"nono\"\r\nContent-Length: 0\r\n\r\n";
                                    stream.write_all(response.as_bytes()).await?;

                                    // Read the client's retried request head on
                                    // the same connection.
                                    let mut buf_reader = BufReader::new(&mut stream);
                                    let mut retry_line = String::new();
                                    buf_reader.read_line(&mut retry_line).await?;
                                    if retry_line.is_empty() {
                                        return Ok(()); // client disconnected
                                    }
                                    let mut retry_headers = Vec::new();
                                    loop {
                                        let mut line = String::new();
                                        let n = buf_reader.read_line(&mut line).await?;
                                        if n == 0 || line.trim().is_empty() {
                                            break;
                                        }
                                        retry_headers.extend_from_slice(line.as_bytes());
                                        if retry_headers.len() > MAX_HEADER_SIZE {
                                            drop(buf_reader);
                                            let too_large = "HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n";
                                            stream.write_all(too_large.as_bytes()).await?;
                                            return Ok(());
                                        }
                                    }
                                    drop(buf_reader);

                                    // host/port/route are reused from the first
                                    // CONNECT, so the retry must target the same
                                    // authority; anything else (or a non-CONNECT
                                    // request) would desync routing.
                                    let same_authority = retry_line
                                        .trim_end()
                                        .strip_prefix("CONNECT ")
                                        .and_then(|rest| rest.split_whitespace().next())
                                        .map(normalize_authority)
                                        .as_deref()
                                        == Some(host_port.as_str());
                                    if !same_authority {
                                        return Ok(());
                                    }
                                    current_headers = retry_headers;
                                }
                            }
                        }

                        // Decide whether the upstream leg should chain through
                        // the corporate proxy. Mirrors the bypass logic used for
                        // transparent CONNECT below.
                        let upstream_proxy =
                            if let Some(ref ext_config) = state.config.external_proxy {
                                let bypassed = !state.bypass_matcher.is_empty()
                                    && state.bypass_matcher.matches(&host);
                                if bypassed {
                                    debug!("tls_intercept: bypassing upstream proxy for {}", host);
                                    None
                                } else if ext_config.auth.is_some() {
                                    // Auth is configured but not yet implemented.
                                    // Fail loudly rather than silently connecting
                                    // without auth — the corporate proxy would
                                    // reject anyway.
                                    let msg = "external proxy authentication is configured \
                                         but not yet implemented; remove the auth \
                                         section from the external proxy config or \
                                         wait for a future release";
                                    audit::log_denied(
                                        Some(&state.audit_log),
                                        audit::ProxyMode::ConnectIntercept,
                                        &audit::EventContext {
                                            route_id,
                                            ..audit::EventContext::default()
                                        },
                                        &host,
                                        port,
                                        msg,
                                    );
                                    let response =
                                        "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
                                    stream.write_all(response.as_bytes()).await?;
                                    return Err(ProxyError::ExternalProxy(msg.to_string()));
                                } else {
                                    Some(tls_intercept::InterceptUpstreamProxy {
                                        proxy_addr: &ext_config.address,
                                        proxy_auth_header: None,
                                    })
                                }
                            } else {
                                None
                            };

                        let ctx = tls_intercept::InterceptCtx {
                            route_id,
                            host: &host,
                            port,
                            route_store: &state.route_store,
                            credential_store: &state.credential_store,
                            session_token: &state.session_token,
                            cert_cache: Arc::clone(cache),
                            tls_connector: &state.tls_connector,
                            filter: &state.filter,
                            audit_log: Some(&state.audit_log),
                            upstream_proxy,
                        };
                        return tls_intercept::handle_intercept_connect(&mut stream, ctx).await;
                    }
                    // Case 2 & 3: route exists but interception is unavailable
                    // or the route is purely declarative — keep the existing
                    // 403 to force SDK cooperation with the reverse-proxy path.
                    _ => {
                        debug!(
                            "Blocked CONNECT to route upstream {} — use reverse proxy path instead",
                            authority
                        );
                        audit::log_denied(
                            Some(&state.audit_log),
                            audit::ProxyMode::Connect,
                            &audit::EventContext {
                                route_id,
                                denial_category: Some(
                                    nono::undo::NetworkAuditDenialCategory::ConnectBypassesL7,
                                ),
                                ..audit::EventContext::default()
                            },
                            &host,
                            port,
                            "route upstream: CONNECT bypasses L7 filtering",
                        );
                        let response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
                        stream.write_all(response.as_bytes()).await?;
                        return Ok(());
                    }
                }
            }
        }

        // Check if external proxy is configured and host is not bypassed
        let use_external = if let Some(ref ext_config) = state.config.external_proxy {
            if state.bypass_matcher.is_empty() {
                Some(ext_config)
            } else {
                // Parse host from CONNECT line to check bypass
                let host = first_line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|authority| {
                        authority
                            .rsplit_once(':')
                            .map(|(h, _)| h)
                            .or(Some(authority))
                    })
                    .unwrap_or("");
                if state.bypass_matcher.matches(host) {
                    debug!("Bypassing external proxy for {}", host);
                    None
                } else {
                    Some(ext_config)
                }
            }
        } else {
            None
        };

        if let Some(ext_config) = use_external {
            if let (Some(rf), Some(tx)) =
                (state.runtime_filter.as_ref(), state.approval_tx.as_ref())
            {
                let approval_ctx = connect::ApprovalContext {
                    primary_filter: &state.filter,
                    runtime_filter: rf,
                    session_token: &state.session_token,
                    audit_log: Some(&state.audit_log),
                    approval_tx: tx,
                    child_pid: state.child_pid,
                    session_id: &state.session_id,
                    approval_timeout: state.approval_timeout,
                };
                connect::handle_connect_with_approval(
                    first_line,
                    &mut stream,
                    &header_bytes,
                    &approval_ctx,
                )
                .await
            } else {
                external::handle_external_proxy(
                    first_line,
                    &mut stream,
                    &header_bytes,
                    &state.filter,
                    &state.session_token,
                    ext_config,
                    Some(&state.audit_log),
                )
                .await
            }
        } else if state.config.external_proxy.is_some() {
            token::validate_proxy_auth(&header_bytes, &state.session_token)?;

            if let (Some(rf), Some(tx)) =
                (state.runtime_filter.as_ref(), state.approval_tx.as_ref())
            {
                let approval_ctx = connect::ApprovalContext {
                    primary_filter: &state.filter,
                    runtime_filter: rf,
                    session_token: &state.session_token,
                    audit_log: Some(&state.audit_log),
                    approval_tx: tx,
                    child_pid: state.child_pid,
                    session_id: &state.session_id,
                    approval_timeout: state.approval_timeout,
                };
                connect::handle_connect_with_approval(
                    first_line,
                    &mut stream,
                    &header_bytes,
                    &approval_ctx,
                )
                .await
            } else {
                connect::handle_connect(
                    first_line,
                    &mut stream,
                    &state.filter,
                    &state.session_token,
                    &header_bytes,
                    Some(&state.audit_log),
                )
                .await
            }
        } else if let (Some(rf), Some(tx)) =
            (state.runtime_filter.as_ref(), state.approval_tx.as_ref())
        {
            let approval_ctx = connect::ApprovalContext {
                primary_filter: &state.filter,
                runtime_filter: rf,
                session_token: &state.session_token,
                audit_log: Some(&state.audit_log),
                approval_tx: tx,
                child_pid: state.child_pid,
                session_id: &state.session_id,
                approval_timeout: state.approval_timeout,
            };
            connect::handle_connect_with_approval(
                first_line,
                &mut stream,
                &header_bytes,
                &approval_ctx,
            )
            .await
        } else {
            connect::handle_connect(
                first_line,
                &mut stream,
                &state.filter,
                &state.session_token,
                &header_bytes,
                Some(&state.audit_log),
            )
            .await
        }
    } else if !state.route_store.is_empty() {
        // Non-CONNECT request with routes configured -> reverse proxy
        let ctx = reverse::ReverseProxyCtx {
            route_store: &state.route_store,
            credential_store: &state.credential_store,
            session_token: &state.session_token,
            filter: &state.filter,
            tls_connector: &state.tls_connector,
            audit_log: Some(&state.audit_log),
        };
        reverse::handle_reverse_proxy(first_line, &mut stream, &header_bytes, &ctx, &buffered).await
    } else {
        // No routes configured: filter, audit, and respond inline.
        let (host, port) = parse_non_connect_target(first_line)?;
        let check = state.filter.check_host(&host, port).await?;
        if !check.result.is_allowed() {
            let reason = check.result.reason();
            audit::log_denied(
                Some(&state.audit_log),
                audit::ProxyMode::Connect,
                &audit::EventContext {
                    denial_category: Some(nono::undo::NetworkAuditDenialCategory::HostDenied),
                    ..audit::EventContext::default()
                },
                &host,
                port,
                &reason,
            );
            let sanitised = reason.replace(['\r', '\n'], " ");
            let response = format!("HTTP/1.1 403 Forbidden: {}\r\n\r\n", sanitised);
            stream.write_all(response.as_bytes()).await?;
        } else {
            stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn normalize_authority_normalises_case_and_default_port() {
        assert_eq!(normalize_authority("API.OpenAI.com"), "api.openai.com:443");
        assert_eq!(
            normalize_authority("api.openai.com:443"),
            "api.openai.com:443"
        );
        assert_eq!(
            normalize_authority("api.openai.com:8443"),
            "api.openai.com:8443"
        );
        assert_eq!(normalize_authority("[::1]"), "[::1]:443");
        assert_eq!(normalize_authority("[::1]:8443"), "[::1]:8443");
        // case- and port-insensitive equality is the point of the retry guard
        assert_eq!(
            normalize_authority("API.OPENAI.COM:443"),
            normalize_authority("api.openai.com")
        );
    }

    #[tokio::test]
    async fn test_proxy_starts_and_binds() {
        let config = ProxyConfig::default();
        let handle = start(config).await.unwrap();

        // Port should be non-zero (OS-assigned)
        assert!(handle.port > 0);
        // Token should be 64 hex chars
        assert_eq!(handle.token.len(), 64);

        // Shutdown
        handle.shutdown();
    }

    /// End-to-end smoke test: when `intercept_ca_dir` is set AND a route
    /// requires L7 visibility, the proxy:
    /// 1. generates an ephemeral CA;
    /// 2. writes a trust bundle file with at least the ephemeral cert + system roots;
    /// 3. exposes the path via `intercept_ca_path()`;
    /// 4. emits trust env vars (`SSL_CERT_FILE` etc.) pointing at it;
    /// 5. cleans the file on `Drop`.
    #[tokio::test]
    async fn test_intercept_lifecycle_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let ca_path_clone;

        {
            let config = ProxyConfig {
                routes: vec![crate::config::RouteConfig {
                    prefix: "openai".to_string(),
                    upstream: "https://api.openai.com".to_string(),
                    credential_key: Some("env://NONO_TEST_TOTALLY_MISSING".to_string()),
                    inject_mode: Default::default(),
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
                }],
                intercept_ca_dir: Some(dir.path().to_path_buf()),
                ..Default::default()
            };
            let handle = start(config).await.unwrap();
            assert!(
                handle.intercept_ca_path().is_some(),
                "intercept-eligible route + intercept_ca_dir → bundle path should be Some"
            );
            ca_path_clone = handle.intercept_ca_path().unwrap().to_path_buf();
            assert!(
                ca_path_clone.exists(),
                "bundle file should have been written"
            );

            let contents = std::fs::read_to_string(&ca_path_clone).unwrap();
            assert!(
                contents.contains("BEGIN CERTIFICATE"),
                "bundle should contain at least one PEM block"
            );

            // Trust env vars should reference the bundle.
            let vars = handle.env_vars();
            let ssl = vars
                .iter()
                .find(|(k, _)| k == "SSL_CERT_FILE")
                .expect("SSL_CERT_FILE should be set when intercept active");
            assert_eq!(std::path::Path::new(&ssl.1), ca_path_clone);
            assert!(vars.iter().any(|(k, _)| k == "REQUESTS_CA_BUNDLE"));
            assert!(vars.iter().any(|(k, _)| k == "NODE_EXTRA_CA_CERTS"));
            assert!(vars.iter().any(|(k, _)| k == "CURL_CA_BUNDLE"));

            handle.shutdown();
        }
        // After `handle` is dropped, the bundle file should be gone.
        assert!(
            !ca_path_clone.exists(),
            "bundle should be removed when ProxyHandle drops"
        );
    }

    /// When `intercept_ca_dir` is set but no route requires L7 visibility,
    /// the proxy should NOT generate a CA (it would just be wasted material).
    #[tokio::test]
    async fn test_intercept_skipped_for_purely_declarative_routes() {
        let dir = tempfile::tempdir().unwrap();
        let config = ProxyConfig {
            routes: vec![crate::config::RouteConfig {
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
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
                aws_auth: None,
            }],
            intercept_ca_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let handle = start(config).await.unwrap();
        assert!(
            handle.intercept_ca_path().is_none(),
            "no L7-bearing route → no CA should be generated"
        );
        let vars = handle.env_vars();
        assert!(
            vars.iter().all(|(k, _)| k != "SSL_CERT_FILE"),
            "trust env vars must not be set when intercept inactive"
        );
        handle.shutdown();
    }

    /// Intercept setup failures must not abort proxy startup for reverse-proxy
    /// routes. We degrade to "intercept off" so credential routes still work,
    /// while CONNECT interception remains unavailable and will keep its
    /// existing deny behaviour.
    #[tokio::test]
    async fn test_intercept_setup_failure_degrades_without_aborting_proxy() {
        let missing_dir = tempfile::tempdir()
            .unwrap()
            .path()
            .join("missing")
            .join("intercept");
        let config = ProxyConfig {
            routes: vec![crate::config::RouteConfig {
                prefix: "openai".to_string(),
                upstream: "https://api.openai.com".to_string(),
                credential_key: Some("env://NONO_TEST_TOTALLY_MISSING".to_string()),
                inject_mode: Default::default(),
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
            }],
            intercept_ca_dir: Some(missing_dir),
            ..Default::default()
        };
        let handle = start(config.clone()).await.unwrap();
        assert!(
            handle.intercept_ca_path().is_none(),
            "intercept setup failure should disable interception instead of aborting startup"
        );
        let vars = handle.env_vars();
        assert!(
            vars.iter().all(|(k, _)| k != "SSL_CERT_FILE"),
            "trust env vars must not be set when interception setup fails"
        );
        let route_vars = handle.credential_env_vars(&config);
        assert!(
            route_vars.iter().any(|(k, _)| k == "OPENAI_BASE_URL"),
            "reverse-proxy route env vars should still be emitted"
        );
        handle.shutdown();
    }

    /// `route_diagnostics()` returns one row per route summarising
    /// upstream, credential resolution, intercept on/off, and rule count.
    #[tokio::test]
    async fn test_route_diagnostics_summarises_each_route() {
        let dir = tempfile::tempdir().unwrap();
        let config = ProxyConfig {
            routes: vec![
                crate::config::RouteConfig {
                    prefix: "openai".to_string(),
                    upstream: "https://api.openai.com".to_string(),
                    credential_key: Some("env://NONO_TEST_MISSING".to_string()),
                    inject_mode: Default::default(),
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
                },
                crate::config::RouteConfig {
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
                    tls_ca: None,
                    tls_client_cert: None,
                    tls_client_key: None,
                    oauth2: None,
                    aws_auth: None,
                },
            ],
            intercept_ca_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let handle = start(config.clone()).await.unwrap();
        let rows = handle.route_diagnostics(&config);
        assert_eq!(rows.len(), 2);

        let openai = rows.iter().find(|(p, _)| p == "openai").unwrap();
        assert!(openai.1.contains("api.openai.com"));
        assert!(openai.1.contains("intercept: on"));
        assert!(
            openai.1.contains("✗") || openai.1.contains("not found"),
            "missing credential should show ✗, got: {}",
            openai.1
        );

        let alias = rows.iter().find(|(p, _)| p == "alias").unwrap();
        assert!(alias.1.contains("creds: none"));
        assert!(alias.1.contains("intercept: off"));

        handle.shutdown();
    }

    #[tokio::test]
    async fn test_proxy_env_vars() {
        let config = ProxyConfig::default();
        let handle = start(config).await.unwrap();

        let vars = handle.env_vars();
        let http_proxy = vars.iter().find(|(k, _)| k == "HTTP_PROXY");
        assert!(http_proxy.is_some());
        assert!(http_proxy.unwrap().1.starts_with("http://nono:"));

        let token_var = vars.iter().find(|(k, _)| k == "NONO_PROXY_TOKEN");
        assert!(token_var.is_some());
        assert_eq!(token_var.unwrap().1.len(), 64);

        let node_proxy_flag = vars.iter().find(|(k, _)| k == "NODE_USE_ENV_PROXY");
        assert!(
            node_proxy_flag.is_some(),
            "proxy env must set NODE_USE_ENV_PROXY for Node 20.6+ (undici 5.22+) built-in fetch()"
        );
        assert_eq!(
            node_proxy_flag.unwrap().1,
            "1",
            "NODE_USE_ENV_PROXY must be '1'"
        );

        handle.shutdown();
    }

    #[tokio::test]
    async fn test_proxy_credential_env_vars() {
        let config = ProxyConfig {
            routes: vec![crate::config::RouteConfig {
                prefix: "openai".to_string(),
                upstream: "https://api.openai.com".to_string(),
                credential_key: None,
                inject_mode: crate::config::InjectMode::Header,
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
            }],
            ..Default::default()
        };
        let handle = start(config.clone()).await.unwrap();

        let vars = handle.credential_env_vars(&config);
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].0, "OPENAI_BASE_URL");
        assert!(vars[0].1.contains("/openai"));

        handle.shutdown();
    }

    #[test]
    fn test_proxy_credential_env_vars_fallback_to_uppercase_key() {
        // When env_var is None and credential_key is set, the env var name
        // should be derived from uppercasing credential_key. This is the
        // backward-compatible path for keyring-backed credentials.
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        let handle = ProxyHandle {
            port: 12345,
            token: Zeroizing::new("test_token".to_string()),
            audit_log: audit::new_audit_log(),
            shutdown_tx,
            loaded_routes: ["openai".to_string()].into_iter().collect(),
            no_proxy_hosts: Vec::new(),
            intercept_ca_path: None,
        };
        let config = ProxyConfig {
            routes: vec![crate::config::RouteConfig {
                prefix: "openai".to_string(),
                upstream: "https://api.openai.com".to_string(),
                credential_key: Some("openai_api_key".to_string()),
                inject_mode: crate::config::InjectMode::Header,
                inject_header: "Authorization".to_string(),
                credential_format: Some("Bearer {}".to_string()),
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                proxy: None,
                env_var: None, // No explicit env_var — should fall back to uppercase
                endpoint_rules: vec![],
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
                aws_auth: None,
            }],
            ..Default::default()
        };

        let vars = handle.credential_env_vars(&config);
        assert_eq!(vars.len(), 2); // BASE_URL + API_KEY

        // Should derive OPENAI_API_KEY from uppercasing "openai_api_key"
        let api_key_var = vars.iter().find(|(k, _)| k == "OPENAI_API_KEY");
        assert!(
            api_key_var.is_some(),
            "Should derive env var name from credential_key.to_uppercase()"
        );

        let (_, val) = api_key_var.expect("OPENAI_API_KEY should exist");
        assert_eq!(val, "test_token");
    }

    #[test]
    fn test_proxy_credential_env_vars_with_explicit_env_var() {
        // When env_var is set on a route, it should be used instead of
        // deriving from credential_key. This is essential for URI manager
        // credential refs (e.g., op://, apple-password://)
        // where uppercasing produces nonsensical env var names.
        //
        // We construct a ProxyHandle directly to test env var generation
        // without starting a real proxy (which would try to load credentials).
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        let handle = ProxyHandle {
            port: 12345,
            token: Zeroizing::new("test_token".to_string()),
            audit_log: audit::new_audit_log(),
            shutdown_tx,
            loaded_routes: ["openai".to_string()].into_iter().collect(),
            no_proxy_hosts: Vec::new(),
            intercept_ca_path: None,
        };
        let config = ProxyConfig {
            routes: vec![crate::config::RouteConfig {
                prefix: "openai".to_string(),
                upstream: "https://api.openai.com".to_string(),
                credential_key: Some("op://Development/OpenAI/credential".to_string()),
                inject_mode: crate::config::InjectMode::Header,
                inject_header: "Authorization".to_string(),
                credential_format: Some("Bearer {}".to_string()),
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                proxy: None,
                env_var: Some("OPENAI_API_KEY".to_string()),
                endpoint_rules: vec![],
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
                aws_auth: None,
            }],
            ..Default::default()
        };

        let vars = handle.credential_env_vars(&config);
        assert_eq!(vars.len(), 2); // BASE_URL + API_KEY

        let api_key_var = vars.iter().find(|(k, _)| k == "OPENAI_API_KEY");
        assert!(
            api_key_var.is_some(),
            "Should use explicit env_var name, not derive from credential_key"
        );

        // Verify the value is the phantom token, not the real credential
        let (_, val) = api_key_var.expect("OPENAI_API_KEY var should exist");
        assert_eq!(val, "test_token");

        // Verify no nonsensical OP:// env var was generated
        let bad_var = vars.iter().find(|(k, _)| k.starts_with("OP://"));
        assert!(
            bad_var.is_none(),
            "Should not generate env var from op:// URI uppercase"
        );
    }

    #[test]
    fn test_proxy_credential_env_vars_skips_unloaded_routes() {
        // When a credential is unavailable (e.g., GITHUB_TOKEN not set),
        // the route should NOT inject a phantom token env var. Otherwise
        // the phantom token shadows valid credentials from other sources
        // like the system keyring. See: #234
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        let handle = ProxyHandle {
            port: 12345,
            token: Zeroizing::new("test_token".to_string()),
            audit_log: audit::new_audit_log(),
            shutdown_tx,
            // Only "openai" was loaded; "github" credential was unavailable
            loaded_routes: ["openai".to_string()].into_iter().collect(),
            no_proxy_hosts: Vec::new(),
            intercept_ca_path: None,
        };
        let config = ProxyConfig {
            routes: vec![
                crate::config::RouteConfig {
                    prefix: "openai".to_string(),
                    upstream: "https://api.openai.com".to_string(),
                    credential_key: Some("openai_api_key".to_string()),
                    inject_mode: crate::config::InjectMode::Header,
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
                },
                crate::config::RouteConfig {
                    prefix: "github".to_string(),
                    upstream: "https://api.github.com".to_string(),
                    credential_key: Some("env://GITHUB_TOKEN".to_string()),
                    inject_mode: crate::config::InjectMode::Header,
                    inject_header: "Authorization".to_string(),
                    credential_format: Some("token {}".to_string()),
                    path_pattern: None,
                    path_replacement: None,
                    query_param_name: None,
                    proxy: None,
                    env_var: Some("GITHUB_TOKEN".to_string()),
                    endpoint_rules: vec![],
                    tls_ca: None,
                    tls_client_cert: None,
                    tls_client_key: None,
                    oauth2: None,
                    aws_auth: None,
                },
            ],
            ..Default::default()
        };

        let vars = handle.credential_env_vars(&config);

        // openai should have BASE_URL + API_KEY (credential loaded)
        let openai_base = vars.iter().find(|(k, _)| k == "OPENAI_BASE_URL");
        assert!(openai_base.is_some(), "loaded route should have BASE_URL");
        let openai_key = vars.iter().find(|(k, _)| k == "OPENAI_API_KEY");
        assert!(openai_key.is_some(), "loaded route should have API key");

        // github should have BASE_URL (always set for declared routes) but
        // must NOT have GITHUB_TOKEN (credential was not loaded)
        let github_base = vars.iter().find(|(k, _)| k == "GITHUB_BASE_URL");
        assert!(
            github_base.is_some(),
            "declared route should still have BASE_URL"
        );
        let github_token = vars.iter().find(|(k, _)| k == "GITHUB_TOKEN");
        assert!(
            github_token.is_none(),
            "unloaded route must not inject phantom GITHUB_TOKEN"
        );
    }

    #[test]
    fn test_proxy_credential_env_vars_strips_slashes() {
        // When prefix includes leading/trailing slashes, the env var name
        // must not contain slashes and the URL must not double-slash.
        // Regression test for user-reported bug where "/anthropic" produced
        // "/ANTHROPIC_BASE_URL=http://127.0.0.1:PORT//anthropic".
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        let handle = ProxyHandle {
            port: 58406,
            token: Zeroizing::new("test_token".to_string()),
            audit_log: audit::new_audit_log(),
            shutdown_tx,
            loaded_routes: std::collections::HashSet::new(),
            no_proxy_hosts: Vec::new(),
            intercept_ca_path: None,
        };

        // Test leading slash
        let config = ProxyConfig {
            routes: vec![crate::config::RouteConfig {
                prefix: "/anthropic".to_string(),
                upstream: "https://api.anthropic.com".to_string(),
                credential_key: None,
                inject_mode: crate::config::InjectMode::Header,
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
            }],
            ..Default::default()
        };

        let vars = handle.credential_env_vars(&config);
        assert_eq!(vars.len(), 1);
        assert_eq!(
            vars[0].0, "ANTHROPIC_BASE_URL",
            "env var name must not have leading slash"
        );
        assert_eq!(
            vars[0].1, "http://127.0.0.1:58406/anthropic",
            "URL must not have double slash"
        );

        // Test trailing slash
        let config = ProxyConfig {
            routes: vec![crate::config::RouteConfig {
                prefix: "openai/".to_string(),
                upstream: "https://api.openai.com".to_string(),
                credential_key: None,
                inject_mode: crate::config::InjectMode::Header,
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
            }],
            ..Default::default()
        };

        let vars = handle.credential_env_vars(&config);
        assert_eq!(
            vars[0].0, "OPENAI_BASE_URL",
            "env var name must not have trailing slash"
        );
        assert_eq!(
            vars[0].1, "http://127.0.0.1:58406/openai",
            "URL must not have trailing slash in path"
        );
    }

    #[test]
    fn test_anthropic_credential_phantom_token_regression() {
        // Regression test for issue #624: the built-in anthropic credential
        // entry had no env_var or credential_key, so ANTHROPIC_API_KEY was
        // never set to the phantom token. Only ANTHROPIC_BASE_URL was injected,
        // leaving the sandbox to send the host's real key directly.
        //
        // Pre-fix state: route in loaded_routes but no env_var / credential_key
        // => ANTHROPIC_API_KEY must NOT appear (demonstrates the bug).
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        let handle_no_env_var = ProxyHandle {
            port: 12345,
            token: Zeroizing::new("phantom".to_string()),
            audit_log: audit::new_audit_log(),
            shutdown_tx: shutdown_tx.clone(),
            loaded_routes: ["anthropic".to_string()].into_iter().collect(),
            no_proxy_hosts: Vec::new(),
            intercept_ca_path: None,
        };
        let config_no_env_var = ProxyConfig {
            routes: vec![crate::config::RouteConfig {
                prefix: "anthropic".to_string(),
                upstream: "https://api.anthropic.com".to_string(),
                credential_key: None,
                inject_mode: crate::config::InjectMode::Header,
                inject_header: "x-api-key".to_string(),
                credential_format: Some("{}".to_string()),
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
            }],
            ..Default::default()
        };
        let vars_no_env_var = handle_no_env_var.credential_env_vars(&config_no_env_var);
        assert!(
            vars_no_env_var
                .iter()
                .all(|(k, _)| k != "ANTHROPIC_API_KEY"),
            "pre-fix: ANTHROPIC_API_KEY must not be set when neither env_var nor credential_key is defined (bug reproduced)"
        );

        // Post-fix state: route has env_var = "ANTHROPIC_API_KEY"
        // => ANTHROPIC_API_KEY must be set to the phantom token.
        let (shutdown_tx2, _) = tokio::sync::watch::channel(false);
        let handle_fixed = ProxyHandle {
            port: 12345,
            token: Zeroizing::new("phantom".to_string()),
            audit_log: audit::new_audit_log(),
            shutdown_tx: shutdown_tx2,
            loaded_routes: ["anthropic".to_string()].into_iter().collect(),
            no_proxy_hosts: Vec::new(),
            intercept_ca_path: None,
        };
        let config_fixed = ProxyConfig {
            routes: vec![crate::config::RouteConfig {
                prefix: "anthropic".to_string(),
                upstream: "https://api.anthropic.com".to_string(),
                credential_key: Some("ANTHROPIC_API_KEY".to_string()),
                inject_mode: crate::config::InjectMode::Header,
                inject_header: "x-api-key".to_string(),
                credential_format: Some("{}".to_string()),
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                proxy: None,
                env_var: Some("ANTHROPIC_API_KEY".to_string()),
                endpoint_rules: vec![],
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
                aws_auth: None,
            }],
            ..Default::default()
        };
        let vars_fixed = handle_fixed.credential_env_vars(&config_fixed);
        let api_key_var = vars_fixed.iter().find(|(k, _)| k == "ANTHROPIC_API_KEY");
        assert!(
            api_key_var.is_some(),
            "post-fix: ANTHROPIC_API_KEY must be set to the phantom token"
        );
        assert_eq!(api_key_var.unwrap().1, "phantom");
    }

    #[test]
    fn test_no_proxy_excludes_credential_upstreams() {
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        let handle = ProxyHandle {
            port: 12345,
            token: Zeroizing::new("test_token".to_string()),
            audit_log: audit::new_audit_log(),
            shutdown_tx,
            loaded_routes: std::collections::HashSet::new(),
            no_proxy_hosts: vec![
                "nats.internal:4222".to_string(),
                "opencode.internal:4096".to_string(),
            ],
            intercept_ca_path: None,
        };

        let vars = handle.env_vars();
        let no_proxy = vars.iter().find(|(k, _)| k == "NO_PROXY").unwrap();
        assert!(
            no_proxy.1.contains("nats.internal"),
            "non-credential host should be in NO_PROXY"
        );
        assert!(
            no_proxy.1.contains("opencode.internal"),
            "non-credential host should be in NO_PROXY"
        );
        assert!(
            no_proxy.1.contains("localhost"),
            "localhost should always be in NO_PROXY"
        );
    }

    #[test]
    fn test_no_proxy_empty_when_no_non_credential_hosts() {
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        let handle = ProxyHandle {
            port: 12345,
            token: Zeroizing::new("test_token".to_string()),
            audit_log: audit::new_audit_log(),
            shutdown_tx,
            loaded_routes: std::collections::HashSet::new(),
            no_proxy_hosts: Vec::new(),
            intercept_ca_path: None,
        };

        let vars = handle.env_vars();
        let no_proxy = vars.iter().find(|(k, _)| k == "NO_PROXY").unwrap();
        assert_eq!(
            no_proxy.1, "localhost,127.0.0.1",
            "NO_PROXY should only contain loopback when no bypass hosts"
        );
    }

    #[tokio::test]
    async fn test_no_proxy_empty_without_direct_connect_ports() {
        // When direct_connect_ports is empty (no --allow-connect-port),
        // allowed_hosts should NOT appear in NO_PROXY because the sandbox
        // blocks direct TCP and clients would fail to connect. See #760.
        let config = ProxyConfig {
            allowed_hosts: vec!["github.com".to_string()],
            ..Default::default()
        };
        let handle = start(config).await.unwrap();

        let vars = handle.env_vars();
        let no_proxy = vars.iter().find(|(k, _)| k == "NO_PROXY").unwrap();
        assert_eq!(
            no_proxy.1, "localhost,127.0.0.1",
            "allowed_hosts must not appear in NO_PROXY without direct_connect_ports"
        );

        handle.shutdown();
    }

    #[cfg(not(target_os = "macos"))]
    #[tokio::test]
    async fn test_no_proxy_includes_hosts_with_matching_connect_port() {
        // When direct_connect_ports includes port 443, allowed_hosts on
        // that port SHOULD appear in NO_PROXY (direct TCP is permitted).
        // macOS always returns empty NO_PROXY (Seatbelt blocks all direct outbound).
        let config = ProxyConfig {
            allowed_hosts: vec!["github.com".to_string(), "server.internal:4222".to_string()],
            direct_connect_ports: vec![443],
            ..Default::default()
        };
        let handle = start(config).await.unwrap();

        let vars = handle.env_vars();
        let no_proxy = vars.iter().find(|(k, _)| k == "NO_PROXY").unwrap();
        assert!(
            no_proxy.1.contains("github.com"),
            "host on port 443 should be in NO_PROXY when 443 is in direct_connect_ports"
        );
        assert!(
            !no_proxy.1.contains("server.internal"),
            "host on port 4222 should NOT be in NO_PROXY when only 443 is allowed"
        );

        handle.shutdown();
    }

    /// Regression test: when `strict_filter` is true and `allowed_hosts` is
    /// empty, the proxy must deny CONNECT instead of falling back to allow-all.
    #[tokio::test]
    async fn test_strict_filter_with_empty_allowlist_denies_connect() {
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpStream;

        let config = ProxyConfig {
            strict_filter: true,
            allowed_hosts: Vec::new(),
            ..ProxyConfig::default()
        };
        let handle = start(config).await.unwrap();
        let addr = format!("127.0.0.1:{}", handle.port);

        let mut stream = TcpStream::connect(&addr).await.unwrap();
        let request = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        tokio::io::AsyncWriteExt::write_all(&mut stream, request)
            .await
            .unwrap();

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let response_str = String::from_utf8_lossy(&response);
        assert!(
            response_str.starts_with("HTTP/1.1 403"),
            "strict filter with empty allowlist must deny CONNECT, got: {}",
            response_str
        );

        let events = handle.drain_audit_events();
        assert!(
            events
                .iter()
                .any(|e| e.decision == nono::undo::NetworkAuditDecision::Deny
                    && e.target == "example.com"),
            "expected a Deny audit event for example.com, got: {:?}",
            events
        );

        handle.shutdown();
    }

    /// Regression test for reactive proxy auth on the intercept CONNECT path.
    /// After a 407 the proxy must keep the connection open and answer the
    /// client's credentialed retry on the same socket, rather than closing it
    /// (which breaks reactive clients such as Apache HttpClient / Maven's
    /// native resolver).
    #[tokio::test]
    async fn reactive_proxy_auth_retry_answered_after_407() {
        use base64::Engine;
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let dir = tempfile::tempdir().unwrap();
        let config = ProxyConfig {
            routes: vec![crate::config::RouteConfig {
                prefix: "openai".to_string(),
                upstream: "https://api.openai.com".to_string(),
                credential_key: Some("env://NONO_TEST_TOTALLY_MISSING".to_string()),
                inject_mode: Default::default(),
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
            }],
            intercept_ca_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let handle = start(config).await.unwrap();
        assert!(
            handle.intercept_ca_path().is_some(),
            "precondition: interception must be active so the 407 path is reached"
        );
        let port = handle.port;
        let token = handle.token.to_string();

        let mut sock = TcpStream::connect(("127.0.0.1", port)).await.unwrap();

        // 1) Unauthenticated CONNECT -> expect a 407 challenge.
        sock.write_all(b"CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\n\r\n")
            .await
            .unwrap();
        sock.flush().await.unwrap();

        let mut buf = [0u8; 4096];
        let n = sock.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(
            response.starts_with("HTTP/1.1 407 "),
            "expected 407 challenge, got: {:?}",
            response
        );

        // 2) Reactive retry WITH valid credentials on the SAME socket.
        let creds = base64::engine::general_purpose::STANDARD.encode(format!("nono:{}", token));
        let retry = format!(
            "CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\nProxy-Authorization: Basic {}\r\n\r\n",
            creds
        );
        sock.write_all(retry.as_bytes()).await.unwrap();
        sock.flush().await.unwrap();

        // 3) The proxy must answer the retried CONNECT on the same socket
        //    instead of returning EOF. (The upstream connect to api.openai.com
        //    may fail in the test env, so we require a response, not a 200.)
        let mut retry_buf = [0u8; 4096];
        let read_result =
            tokio::time::timeout(Duration::from_secs(5), sock.read(&mut retry_buf)).await;
        match read_result {
            Ok(Ok(0)) => panic!(
                "regression: proxy closed the socket after the 407 instead of \
                 answering the reactive retry"
            ),
            Ok(Ok(_)) => {} // answered -> reactive auth handled
            Ok(Err(e)) => panic!("retry read errored: {e}"),
            Err(_) => panic!("retry read timed out — proxy did not answer the retry"),
        }

        handle.shutdown();
    }

    #[test]
    fn test_parse_non_connect_target_default_port_80() {
        let (host, port) = parse_non_connect_target("GET http://google.com/ HTTP/1.1").unwrap();
        assert_eq!(host, "google.com");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_parse_non_connect_target_parses_url_with_port() {
        let (host, port) =
            parse_non_connect_target("GET http://google.com:8080/path HTTP/1.1").unwrap();
        assert_eq!(host, "google.com");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_non_connect_target_rejects_malformed_line() {
        let err = parse_non_connect_target("garbage").unwrap_err();
        assert!(err.to_string().contains("malformed request line"));
    }

    /// Regression for #1062: a denied non-CONNECT request must return 403
    /// (not 400) and produce a `http` audit deny event.
    #[tokio::test]
    async fn test_denied_non_connect_returns_403_and_audits() {
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpStream;

        // allowed_hosts = ["example.com"] -> google.com is denied
        let config = ProxyConfig {
            allowed_hosts: vec!["example.com".to_string()],
            ..ProxyConfig::default()
        };
        let handle = start(config).await.unwrap();
        let addr = format!("127.0.0.1:{}", handle.port);

        let mut stream = TcpStream::connect(&addr).await.unwrap();
        let request = b"GET http://google.com/ HTTP/1.1\r\nHost: google.com\r\n\r\n";
        tokio::io::AsyncWriteExt::write_all(&mut stream, request)
            .await
            .unwrap();

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let response_str = String::from_utf8_lossy(&response);
        assert!(
            response_str.starts_with("HTTP/1.1 403"),
            "expected 403 status, got: {}",
            response_str
        );

        let events = handle.drain_audit_events();
        assert_eq!(events.len(), 1, "expected one audit event");
        let event = &events[0];
        assert_eq!(event.mode, nono::undo::NetworkAuditMode::Connect);
        assert_eq!(event.decision, nono::undo::NetworkAuditDecision::Deny);
        assert_eq!(event.target, "google.com");
        assert_eq!(event.port, Some(80));

        handle.shutdown();
    }
}
