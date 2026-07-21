//! Proxy server: TCP listener, connection dispatch, and lifecycle.
//!
//! The server binds to `127.0.0.1:0` (OS-assigned port), accepts TCP
//! connections, reads the first HTTP line to determine the mode, and
//! dispatches to the appropriate handler.
//!
//! CONNECT method -> [`connect`] or [`external`] handler
//! Other methods  -> [`reverse`] handler (credential injection)

use crate::audit;
use crate::capture::CredentialCaptureBackend;
use crate::config::ProxyConfig;
use crate::connect;
use crate::credential::CredentialStore;
use crate::error::{ProxyError, Result};
use crate::external;
use crate::filter::ProxyFilter;
use crate::forward::{self, AuditCtx, UpstreamScheme, UpstreamSpec, UpstreamStrategy};
use crate::oauth_capture::OAuthCaptureStore;
use crate::pool::UpstreamPool;
use crate::reverse;
use crate::route::RouteStore;
use crate::tls_intercept::{self, CertCache, EphemeralCa, UpstreamH2Cache};
use crate::token;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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

/// Request-target form of a non-CONNECT proxy request line, used to
/// discriminate forward-proxy (absolute-form) requests from reverse-proxy
/// (origin-form) ones.
///
/// A forward-proxy client (one honoring `HTTP_PROXY`) sends the *absolute*
/// URL in the request line: `GET http://example.com/path HTTP/1.1`. A
/// reverse-proxy client sends *origin-form*: `GET /service/path HTTP/1.1`.
/// Discriminating on the target's form (not the method) is what lets nono
/// act as a drop-in `HTTP_PROXY` target without disturbing the existing
/// origin-form reverse-proxy routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestTargetForm {
    /// Absolute-form `http://…` — plain HTTP forward proxy.
    AbsoluteHttp,
    /// Absolute-form `https://…` — must be tunneled via CONNECT, not forwarded.
    AbsoluteHttps,
    /// Origin-form (`/path`) or anything else — reverse-proxy / inline path.
    Origin,
}

/// Classify the request-target of a non-CONNECT request line.
///
/// Only the scheme prefix of the request target is inspected. The check is
/// ASCII-case-insensitive per RFC 3986 (schemes are case-insensitive) and
/// deliberately conservative: anything that is not an `http://` or `https://`
/// absolute URL is treated as origin-form so existing reverse-proxy and
/// inline flows are completely unaffected.
fn classify_request_target(line: &str) -> RequestTargetForm {
    // Request line: METHOD SP request-target SP HTTP-version
    let Some(target) = line.split_whitespace().nth(1) else {
        return RequestTargetForm::Origin;
    };
    // Case-insensitive scheme match without allocating a lowercase copy of
    // the whole (possibly long) URL.
    let lower_starts_with = |s: &str, prefix: &str| {
        s.len() >= prefix.len()
            && s.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
    };
    if lower_starts_with(target, "http://") {
        RequestTargetForm::AbsoluteHttp
    } else if lower_starts_with(target, "https://") {
        RequestTargetForm::AbsoluteHttps
    } else {
        RequestTargetForm::Origin
    }
}

/// Rewrite an absolute-form request line into origin-form for forwarding.
///
/// `GET http://host/p?q HTTP/1.1` -> `GET /p?q HTTP/1.1`
/// `GET http://host HTTP/1.1`     -> `GET /`      (empty path becomes `/`)
///
/// The method and HTTP-version tokens are preserved verbatim. Returns the
/// rewritten first line (with trailing CRLF) so it can be prepended to the
/// forwarded header block.
fn rewrite_absolute_to_origin_form(line: &str) -> Result<String> {
    let mut parts = line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| ProxyError::HttpParse(format!("malformed request line: {}", line)))?;
    let target = parts
        .next()
        .ok_or_else(|| ProxyError::HttpParse(format!("malformed request line: {}", line)))?;
    // Preserve the version if present; default to HTTP/1.1 otherwise.
    let version = parts.next().unwrap_or("HTTP/1.1");

    let parsed = Url::parse(target)
        .map_err(|e| ProxyError::HttpParse(format!("invalid URL in request: {}: {}", target, e)))?;

    let mut origin = parsed.path().to_string();
    if origin.is_empty() {
        origin.push('/');
    }
    if let Some(query) = parsed.query() {
        origin.push('?');
        origin.push_str(query);
    }

    // Defence in depth: the method/version tokens come from the client's
    // request line and are echoed into the forwarded request line, which is
    // itself a protocol-formatting boundary. `Url` already rejects control
    // characters in the target, but strip CR/LF from the surrounding tokens
    // so a crafted method/version can never split the forwarded request.
    let sanitise = |s: &str| s.replace(['\r', '\n'], "");
    Ok(format!(
        "{} {} {}\r\n",
        sanitise(method),
        origin,
        sanitise(version)
    ))
}

/// Strip hop-by-hop proxy headers (`Proxy-Connection`, `Proxy-Authorization`)
/// from a raw header block before forwarding upstream.
///
/// These headers are meaningful only on the client<->proxy hop and must never
/// be forwarded: `Proxy-Authorization` carries the session token, and
/// `Proxy-Connection` is a non-standard hop-by-hop hint. Other headers
/// (including `Host`) are preserved verbatim so the forwarded request matches
/// what the client sent.
fn strip_proxy_headers(header_bytes: &[u8]) -> Vec<u8> {
    let header_str = match std::str::from_utf8(header_bytes) {
        Ok(s) => s,
        // Non-UTF-8 headers: forward unchanged rather than corrupt the block.
        // The upstream will reject malformed headers itself.
        Err(_) => return header_bytes.to_vec(),
    };
    let mut out = Vec::with_capacity(header_bytes.len());
    for line in header_str.split_inclusive("\r\n") {
        let name = line.split(':').next().unwrap_or("").trim();
        if name.eq_ignore_ascii_case("proxy-connection")
            || name.eq_ignore_ascii_case("proxy-authorization")
        {
            continue;
        }
        out.extend_from_slice(line.as_bytes());
    }
    out
}

#[must_use]
fn proxy_diagnostic_code_label(code: crate::diagnostic::ProxyDiagnosticCode) -> &'static str {
    code.as_str()
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
    /// Client-side proxy bypass entries appended after loopback defaults.
    /// Computed at startup from direct-connect bypasses and profile-declared
    /// `network.no_proxy` entries, excluding route upstreams.
    no_proxy_hosts: Vec<String>,
    /// When true, loopback must not appear in `NO_PROXY` because a managed
    /// credential route targets a loopback upstream host.
    managed_loopback_upstream: bool,
    /// Canonical nono-owned bypass patterns for wrappers/SDKs that need to
    /// translate profile intent to non-env proxy surfaces such as Java
    /// `http.nonProxyHosts`.
    canonical_no_proxy_hosts: Vec<String>,
    /// Path to the TLS-intercept trust bundle written at startup, when
    /// interception is active. The CLI passes this path to the sandboxed
    /// child via env vars (`SSL_CERT_FILE` etc.) and grants a Landlock /
    /// Seatbelt read capability on it. `None` when interception is not
    /// configured (no `intercept_ca_dir`) or no route requires L7 visibility.
    intercept_ca_path: Option<PathBuf>,
    /// Environment variables that should point at `intercept_ca_path`.
    intercept_ca_env_vars: Vec<String>,
    /// Credential load warnings collected at startup.
    diagnostics: Vec<crate::diagnostic::ProxyDiagnostic>,
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

    /// Startup diagnostics from credential loading.
    #[must_use]
    pub fn diagnostics(&self) -> &[crate::diagnostic::ProxyDiagnostic] {
        &self.diagnostics
    }

    /// Serialize startup diagnostics to JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if JSON serialization fails.
    pub fn diagnostics_json(&self) -> crate::Result<String> {
        serde_json::to_string(&self.diagnostics)
            .map_err(|e| ProxyError::Config(format!("proxy diagnostics JSON error: {e}")))
    }

    /// One-line-per-upstream diagnostic summary suitable for surfacing at
    /// session start. Returns one summary string per upstream.
    ///
    /// Each summary names: upstream URL, credential resolution status
    /// (✓ / ✗ + source label), TLS-intercept on/off, and `endpoint_rules`
    /// count. Designed to make silent credential-resolution failures
    /// noisy by default, addressing the common "I created the keychain
    /// entry but the warn at debug level got missed" footgun.
    ///
    /// Routes are grouped by upstream so that the credential route and the
    /// synthetic endpoint-authorization route (`_ep_<host>`) the CLI emits for
    /// the same host collapse into one row. These are distinct internal routes
    /// — credential injection is decoupled from L7 endpoint filtering (see
    /// `route.rs`) — but at request time they are evaluated together against a
    /// single upstream (the `_ep_` route gates, the credential catch-all
    /// injects). A combined row therefore reflects the effective behaviour
    /// instead of exposing the internal split as a confusing credential-less
    /// duplicate. The internal route prefixes are intentionally not surfaced;
    /// the upstream URL is the user-meaningful identity.
    ///
    /// `config` is the same `ProxyConfig` that was passed to `start()`;
    /// the handle doesn't keep a copy, so the CLI passes it back in.
    #[must_use]
    pub fn route_diagnostics(&self, config: &ProxyConfig) -> Vec<String> {
        // Reconstruct the same host filter the server applies (see `start`).
        // A credential/endpoint route only injects or filters; traffic still
        // has to clear the allowlist to reach the upstream at all. A route
        // whose upstream is not allow-listed is dead config (the proxy 403s
        // it), so skip it here rather than advertise an unreachable route.
        let filter = if config.strict_filter {
            crate::filter::ProxyFilter::new_strict(&config.allowed_hosts)
        } else if config.allowed_hosts.is_empty() {
            crate::filter::ProxyFilter::allow_all()
        } else {
            crate::filter::ProxyFilter::new(&config.allowed_hosts)
        }
        .with_denied_hosts(&config.denied_hosts);
        // Hostname-only reachability: pass no resolved IPs so the link-local
        // SSRF check is skipped (that is a runtime DNS concern, not a config
        // one) and only the deny-list / allowlist hostname rules apply.
        let upstream_reachable = |upstream: &str| -> bool {
            match crate::route::extract_host_port(upstream) {
                Ok(host_port) => {
                    let host = host_port
                        .rsplit_once(':')
                        .map(|(h, _)| h)
                        .unwrap_or(&host_port);
                    filter.check_host_with_ips(host, &[]).is_allowed()
                }
                // Unparseable upstream can't be matched against the allowlist;
                // keep it visible rather than silently hiding a misconfig.
                Err(_) => true,
            }
        };

        // Group routes by upstream, preserving first-seen order. Route counts
        // are small (a handful), so the linear scan per route is cheap.
        let mut groups: Vec<(&str, Vec<&crate::config::RouteConfig>)> = Vec::new();
        for route in &config.routes {
            if !upstream_reachable(&route.upstream) {
                continue;
            }
            if let Some(group) = groups
                .iter_mut()
                .find(|(u, _)| *u == route.upstream.as_str())
            {
                group.1.push(route);
            } else {
                groups.push((route.upstream.as_str(), vec![route]));
            }
        }

        let mut rows = Vec::with_capacity(groups.len());
        for (upstream, group) in &groups {
            // Credential summary comes from the credential-bearing route in the
            // group (if any); the `_ep_` route never carries one.
            //
            // A group may still be covered by a credential route on *another*
            // upstream: a wildcard credential route (e.g. `*.githubusercontent.com`)
            // matches concrete `_ep_` hosts (`raw.githubusercontent.com`) at
            // request time via `host_port_matches`. Reporting that covering
            // credential keeps the display honest — the token really is injected.
            let own_cred = group
                .iter()
                .find(|r| r.credential_key.is_some() || r.oauth2.is_some() || r.aws_auth.is_some());
            let covering_cred = own_cred.copied().or_else(|| {
                let host_port = crate::route::extract_host_port(upstream).ok()?;
                config.routes.iter().find(|r| {
                    (r.credential_key.is_some() || r.oauth2.is_some() || r.aws_auth.is_some())
                        && crate::route::extract_host_port(&r.upstream)
                            .is_ok_and(|hp| crate::route::host_port_matches(&hp, &host_port))
                })
            });
            let cred_route = covering_cred.unwrap_or(group[0]);
            let cred_prefix = cred_route.prefix.trim_matches('/');
            let cred_summary = self.credential_status_summary(cred_prefix, cred_route);

            let intercept_summary = if self.intercept_ca_path.is_some()
                && group.iter().any(|r| {
                    r.credential_key.is_some()
                        || r.oauth2.is_some()
                        || r.spiffe.is_some()
                        || !r.endpoint_rules.is_empty()
                        || r.endpoint_policy.is_some()
                }) {
                "intercept: on"
            } else {
                "intercept: off"
            };

            let rules_summary = if group.iter().any(|r| r.endpoint_policy.is_some()) {
                "endpoint_policy: on".to_string()
            } else {
                let total: usize = group.iter().map(|r| r.endpoint_rules.len()).sum();
                format!("endpoint_rules: {}", total)
            };
            rows.push(format!(
                "{} | {} | {} | {}",
                upstream, cred_summary, intercept_summary, rules_summary
            ));
        }
        rows
    }

    fn credential_status_summary(
        &self,
        prefix: &str,
        route: &crate::config::RouteConfig,
    ) -> String {
        if let Some(diagnostic) = self
            .diagnostics
            .iter()
            .find(|entry| entry.route_prefix == prefix)
        {
            let code = proxy_diagnostic_code_label(diagnostic.code);
            let cred_ref = diagnostic.credential_ref.as_deref().unwrap_or("credential");
            return format!("creds: {cred_ref} ✗ ({code})");
        }

        if let Some(ref key) = route.credential_key {
            let resolved = self.loaded_routes.contains(prefix);
            if resolved {
                format!("creds: {} ✓", key)
            } else {
                format!("creds: {} ✗ (not found)", key)
            }
        } else if route.oauth2.is_some() {
            let resolved = self.loaded_routes.contains(prefix);
            if resolved {
                "creds: oauth2 ✓".to_string()
            } else {
                "creds: oauth2 ✗ (token exchange failed)".to_string()
            }
        } else if route.spiffe.is_some() {
            let resolved = self.loaded_routes.contains(prefix);
            if resolved {
                "creds: spiffe ✓".to_string()
            } else {
                "creds: spiffe ✗ (Workload API unavailable)".to_string()
            }
        } else {
            "creds: none".to_string()
        }
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
        let proxy_url = format!("http://nono:{}@127.0.0.1:{}", *self.token, self.port);

        // Build NO_PROXY: include loopback unless a managed credential route
        // targets a loopback upstream (those must traverse the proxy). Add
        // startup-filtered bypass entries. Parent-shell NO_PROXY/no_proxy is
        // intentionally not read here; proxy mode owns the child proxy env.
        let mut no_proxy_parts = Vec::new();
        let mut canonical_no_proxy_parts = Vec::new();
        push_no_proxy_entry(&mut no_proxy_parts, "localhost");
        push_no_proxy_entry(&mut no_proxy_parts, "127.0.0.1");
        push_canonical_no_proxy_entry(&mut canonical_no_proxy_parts, "localhost");
        push_canonical_no_proxy_entry(&mut canonical_no_proxy_parts, "127.0.0.1");
        if self.managed_loopback_upstream {
            no_proxy_parts.clear();
            canonical_no_proxy_parts.clear();
        }
        for host in &self.no_proxy_hosts {
            push_no_proxy_entry(&mut no_proxy_parts, host);
        }
        for host in &self.canonical_no_proxy_hosts {
            push_canonical_no_proxy_entry(&mut canonical_no_proxy_parts, host);
        }
        let no_proxy = no_proxy_parts.join(",");
        let nono_no_proxy = canonical_no_proxy_parts.join(",");

        let mut vars = vec![
            ("HTTP_PROXY".to_string(), proxy_url.clone()),
            ("HTTPS_PROXY".to_string(), proxy_url.clone()),
            ("NO_PROXY".to_string(), no_proxy.clone()),
            ("NONO_NO_PROXY".to_string(), nono_no_proxy),
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
        if let Some(path) = self.intercept_ca_path.as_deref() {
            let path_str = path.to_string_lossy().to_string();
            for name in &self.intercept_ca_env_vars {
                vars.push((name.clone(), path_str.clone()));
            }
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
            } else if route.spiffe.is_some() {
                // SPIFFE routes use the same phantom token pattern for SDK-style
                // `*_BASE_URL` clients even though upstream auth is SPIFFE.
                let api_key_name = format!("{}_API_KEY", prefix.to_uppercase());
                vars.push((api_key_name, self.token.to_string()));
            } else if route
                .oauth2
                .as_ref()
                .and_then(|o| o.client_assertion.as_ref())
                .is_some()
            {
                // OAuth2 jwt-bearer assertion routes need the same phantom token
                // pattern — the proxy validates session integrity before injecting
                // the exchanged access token, so the child process must present it.
                let api_key_name = format!("{}_API_KEY", prefix.to_uppercase());
                vars.push((api_key_name, self.token.to_string()));
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
        let _ = self.shutdown_tx.send(true);
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

fn merge_no_proxy_hosts(
    smart_no_proxy_hosts: &[String],
    profile_no_proxy: &[String],
    route_hosts: &std::collections::HashSet<String>,
) -> Vec<String> {
    let mut merged = Vec::new();
    for entry in smart_no_proxy_hosts {
        if no_proxy_entry_matches_any_route(entry, route_hosts) {
            debug!(
                "Skipping smart no_proxy entry {:?}: it matches a proxy route upstream",
                entry
            );
            continue;
        }
        push_no_proxy_entry(&mut merged, entry);
    }

    for entry in profile_no_proxy {
        if no_proxy_entry_matches_any_route(entry, route_hosts) {
            debug!(
                "Skipping no_proxy entry {:?}: it matches a proxy route upstream",
                entry
            );
            continue;
        }
        push_no_proxy_entry(&mut merged, entry);
    }

    merged
}

fn merge_canonical_no_proxy_hosts(
    smart_no_proxy_hosts: &[String],
    profile_no_proxy: &[String],
    route_hosts: &std::collections::HashSet<String>,
) -> Vec<String> {
    let mut merged = Vec::new();
    for entry in smart_no_proxy_hosts {
        if no_proxy_entry_matches_any_route(entry, route_hosts) {
            continue;
        }
        push_canonical_no_proxy_entry(&mut merged, entry);
    }

    for entry in profile_no_proxy {
        if no_proxy_entry_matches_any_route(entry, route_hosts) {
            continue;
        }
        push_canonical_no_proxy_entry(&mut merged, entry);
    }

    merged
}

#[must_use = "no_proxy proxy config validation result must be handled"]
fn validate_no_proxy_config(config: &ProxyConfig) -> Result<()> {
    for entry in &config.no_proxy {
        crate::config::validate_no_proxy_entry(entry).map_err(|err| match err {
            ProxyError::Config(message) => {
                ProxyError::Config(format!("invalid no_proxy entry '{entry}': {message}"))
            }
            other => other,
        })?;
    }
    validate_no_proxy_allowed_host_conflicts(&config.no_proxy, &config.allowed_hosts)
}

#[must_use = "no_proxy route conflict validation result must be handled"]
fn validate_no_proxy_route_conflicts(
    no_proxy: &[String],
    route_hosts: &std::collections::HashSet<String>,
) -> Result<()> {
    for no_proxy_entry in no_proxy {
        for route_host in route_hosts {
            if no_proxy_entry_matches_route(no_proxy_entry, route_host) {
                return Err(ProxyError::Config(format!(
                    "no_proxy entry '{no_proxy_entry}' conflicts with route upstream '{route_host}': configured route traffic must go through the proxy, not bypass it"
                )));
            }
        }
    }
    Ok(())
}

#[must_use = "no_proxy allowed_host conflict validation result must be handled"]
fn validate_no_proxy_allowed_host_conflicts(
    no_proxy: &[String],
    allowed_hosts: &[String],
) -> Result<()> {
    for no_proxy_entry in no_proxy {
        for allowed_host in allowed_hosts {
            if crate::config::no_proxy_entry_overlaps_host_pattern(no_proxy_entry, allowed_host) {
                return Err(ProxyError::Config(format!(
                    "no_proxy entry '{no_proxy_entry}' conflicts with allowed_host '{allowed_host}': proxy-allowed traffic must go through the proxy filter, not bypass it"
                )));
            }
        }
    }
    Ok(())
}

fn push_no_proxy_entry(entries: &mut Vec<String>, entry: &str) {
    let env_entry = crate::config::normalise_no_proxy_env_entry(entry);
    let normalised = crate::config::normalise_no_proxy_host_pattern(&env_entry);
    if !entries
        .iter()
        .any(|existing| crate::config::normalise_no_proxy_host_pattern(existing) == normalised)
    {
        entries.push(env_entry);
    }
}

fn push_canonical_no_proxy_entry(entries: &mut Vec<String>, entry: &str) {
    let canonical = canonical_no_proxy_entry(entry);
    let normalised = crate::config::normalise_no_proxy_host_pattern(&canonical);
    if !entries
        .iter()
        .any(|existing| crate::config::normalise_no_proxy_host_pattern(existing) == normalised)
    {
        entries.push(canonical);
    }
}

fn canonical_no_proxy_entry(entry: &str) -> String {
    let host = crate::config::strip_no_proxy_port(entry);
    let normalised = host.trim().to_ascii_lowercase();
    if let Some(suffix) = normalised.strip_prefix("*.") {
        format!("*.{suffix}")
    } else {
        crate::config::normalise_no_proxy_env_entry(&normalised)
    }
}

fn smart_no_proxy_entry(host: &str) -> Option<String> {
    let entry = crate::config::strip_no_proxy_port(host);
    if entry.trim().to_ascii_lowercase().starts_with("*.") {
        debug!(
            "Skipping smart no_proxy entry {:?}: wildcard allowlist entries cannot be emitted without broadening to a bare-domain NO_PROXY bypass",
            host
        );
        return None;
    }
    if crate::config::validate_no_proxy_entry(&entry).is_ok() {
        Some(crate::config::normalise_no_proxy_env_entry(&entry))
    } else {
        debug!(
            "Skipping smart no_proxy entry {:?}: unsafe or ambiguous NO_PROXY bypass semantics",
            host
        );
        None
    }
}

fn no_proxy_entry_matches_any_route(
    entry: &str,
    route_hosts: &std::collections::HashSet<String>,
) -> bool {
    route_hosts
        .iter()
        .any(|route_host| no_proxy_entry_matches_route(entry, route_host))
}

fn no_proxy_entry_matches_route(entry: &str, route_host_port: &str) -> bool {
    let Some(route_host) = route_host_from_host_port(route_host_port) else {
        return true;
    };
    crate::config::no_proxy_entry_overlaps_host_pattern(entry, route_host)
}

fn route_host_from_host_port(route_host_port: &str) -> Option<&str> {
    if let Some(rest) = route_host_port.strip_prefix('[') {
        let end = rest.find(']')?;
        let host_end = end.checked_add(2)?;
        let port = route_host_port[host_end..].strip_prefix(':')?;
        if port.parse::<u16>().is_err() {
            return None;
        }
        return Some(&route_host_port[..host_end]);
    }

    let (host, port) = route_host_port.rsplit_once(':')?;
    if host.is_empty() || host.contains(':') || port.parse::<u16>().is_err() {
        return None;
    }
    Some(host)
}

#[must_use]
fn connect_target_from_normalized_authority(host_port: &str) -> Option<(String, u16)> {
    if let Some(rest) = host_port.strip_prefix('[') {
        let (host, remainder) = rest.split_once(']')?;
        let port = remainder.strip_prefix(':')?.parse::<u16>().ok()?;
        return Some((host.to_string(), port));
    }

    let (host, port) = host_port.rsplit_once(':')?;
    if host.is_empty() || host.contains(':') {
        return None;
    }
    Some((host.to_string(), port.parse::<u16>().ok()?))
}

/// Shared state for the proxy server.
struct ProxyState {
    filter: ProxyFilter,
    session_token: Zeroizing<String>,
    /// Route-level configuration (upstream, L7 filtering, custom TLS CA) for all routes.
    route_store: Arc<RouteStore>,
    /// Credential-specific configuration (inject mode, headers, secrets) for routes with credentials.
    credential_store: Arc<CredentialStore>,
    /// OAuth token endpoint capture and phantom-token store.
    oauth_capture_store: Arc<OAuthCaptureStore>,
    config: ProxyConfig,
    /// Shared TLS connector for upstream connections (reverse proxy mode).
    /// Created once at startup to avoid rebuilding the root cert store per request.
    tls_connector: tokio_rustls::TlsConnector,
    /// Default TLS client config (system roots). Used as the pool key for
    /// routes without a custom CA.
    default_tls_config: Arc<rustls::ClientConfig>,
    /// Upstream connection pool (HTTP/1.1 keep-alive + HTTP/2 multiplexing).
    upstream_pool: Arc<UpstreamPool>,
    /// TLS connector with h2 ALPN for upstream HTTP/2 connections (gRPC).
    tls_connector_h2: tokio_rustls::TlsConnector,
    /// Active connection count for connection limiting.
    active_connections: AtomicUsize,
    /// Shared network audit log for this proxy session.
    audit_log: audit::SharedAuditLog,
    /// Optional approval backend registry for L7 endpoint-policy approve routes.
    approval_backends: Option<crate::approval::ApprovalBackendRegistry>,
    /// Optional supervisor-backed capture backend for command-backed credentials.
    credential_capture_backend: Option<Arc<dyn CredentialCaptureBackend>>,
    /// Optional resolver for tool-sandbox broker nonces found in request headers.
    /// Resolves `nono_<hex>` values in `Authorization` and similar headers before
    /// forwarding upstream. Consumer IDs use the form `"proxy.<route_id>"`.
    nonce_resolver: Option<Arc<dyn crate::token::NonceResolver>>,
    /// Matcher for hosts that bypass the external proxy and route direct.
    /// Built once at startup from `ExternalProxyConfig.bypass_hosts`.
    bypass_matcher: external::BypassMatcher,
    /// Per-hostname leaf-certificate cache backed by the session ephemeral
    /// CA, when TLS interception is active. `None` disables the intercept
    /// CONNECT branch (CONNECTs fall through to the existing 403/tunnel
    /// dispatch even for routes that would otherwise require L7).
    cert_cache: Option<Arc<CertCache>>,
    /// Whether HTTP/2 is enabled for upstream connections and intercept ALPN.
    enable_h2: bool,
    /// Per-host HTTP/2 capability cache. Populated by pre-flight probes so
    /// the inbound acceptor only advertises h2 when the upstream supports it.
    h2_cache: Arc<UpstreamH2Cache>,
    /// Actual bound port (OS-assigned when config.bind_port is 0).
    /// Used by `handle_forward_http` to detect requests targeting the proxy
    /// itself (absolute-form `http://127.0.0.1:{bound_port}/…`) and re-route
    /// them to the reverse-proxy credential-injection path.
    bound_port: u16,
}

struct CompositeNonceResolver {
    external: Option<Arc<dyn crate::token::NonceResolver>>,
    oauth: Arc<OAuthCaptureStore>,
}

impl crate::token::NonceResolver for CompositeNonceResolver {
    fn resolve(&self, nonce: &str, consumer: &str) -> Option<Zeroizing<Vec<u8>>> {
        self.external
            .as_ref()
            .and_then(|resolver| resolver.resolve(nonce, consumer))
            .or_else(|| self.oauth.resolve(nonce, consumer))
    }

    fn resolve_for_credentials(
        &self,
        nonce: &str,
        allowed_credentials: &[String],
    ) -> Option<Zeroizing<Vec<u8>>> {
        // Only the broker tracks credential names; OAuth-capture has none.
        self.external
            .as_ref()
            .and_then(|resolver| resolver.resolve_for_credentials(nonce, allowed_credentials))
    }
}

/// Start the proxy server.
///
/// Binds to `config.bind_addr:config.bind_port` (port 0 = OS-assigned),
/// generates a session token, and begins accepting connections.
///
/// Returns a `ProxyHandle` with the assigned port and session token.
/// The server runs until the handle is dropped or `shutdown()` is called.
pub async fn start(config: ProxyConfig) -> Result<ProxyHandle> {
    start_with_approval(config, None).await
}

/// Start the proxy server with an optional approval backend for L7
/// endpoint-policy `approve` decisions.
pub async fn start_with_approval(
    config: ProxyConfig,
    approval_backend: Option<Arc<dyn nono::ApprovalBackend>>,
) -> Result<ProxyHandle> {
    let approval_backends =
        approval_backend.map(crate::approval::ApprovalBackendRegistry::singleton);
    start_with_approval_registry(config, approval_backends).await
}

/// Start the proxy server with an optional named approval backend registry for
/// L7 endpoint-policy `approve` decisions.
pub async fn start_with_approval_registry(
    config: ProxyConfig,
    approval_backends: Option<crate::approval::ApprovalBackendRegistry>,
) -> Result<ProxyHandle> {
    start_with_approval_and_capture_registry(config, approval_backends, None).await
}

/// Start the proxy server with optional named approval and credential capture
/// backend registries, and an optional nonce resolver for L7 header injection.
pub async fn start_with_approval_and_capture_registry(
    config: ProxyConfig,
    approval_backends: Option<crate::approval::ApprovalBackendRegistry>,
    credential_capture_backend: Option<Arc<dyn CredentialCaptureBackend>>,
) -> Result<ProxyHandle> {
    start_with_nonce_resolver(config, approval_backends, credential_capture_backend, None).await
}

/// Start the proxy server with all optional backends including a nonce resolver.
pub async fn start_with_nonce_resolver(
    config: ProxyConfig,
    approval_backends: Option<crate::approval::ApprovalBackendRegistry>,
    credential_capture_backend: Option<Arc<dyn CredentialCaptureBackend>>,
    nonce_resolver: Option<Arc<dyn crate::token::NonceResolver>>,
) -> Result<ProxyHandle> {
    validate_no_proxy_config(&config)?;

    // Load route-level configuration (upstream, L7 filtering, custom TLS CA)
    // for ALL routes, regardless of credential presence. This happens before
    // binding so route/no_proxy conflicts fail configuration instead of being
    // silently omitted from the generated environment.
    let route_store = if config.routes.is_empty() {
        RouteStore::empty()
    } else {
        RouteStore::load(&config.routes).await?
    };
    let route_hosts = route_store.route_upstream_hosts();
    validate_no_proxy_route_conflicts(&config.no_proxy, &route_hosts)?;

    // Use the caller-supplied password if one was provided (the standalone
    // `nono proxy --pass` case), otherwise mint a fresh random session token.
    // An empty override is treated as "not supplied" so a blank `--pass`
    // can't silently produce an unguessable-but-empty credential.
    let session_token = match config.session_token {
        Some(ref token) if !token.is_empty() => token.clone(),
        _ => token::generate_session_token()?,
    };

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

    let oauth_capture_store = OAuthCaptureStore::load_with_persistence(
        &config.oauth_capture,
        config.oauth_capture_store_path.clone(),
    )?;
    let oauth_capture_store = Arc::new(oauth_capture_store);
    let effective_nonce_resolver: Option<Arc<dyn crate::token::NonceResolver>> =
        if oauth_capture_store.is_empty() {
            nonce_resolver
        } else {
            Some(Arc::new(CompositeNonceResolver {
                external: nonce_resolver,
                oauth: Arc::clone(&oauth_capture_store),
            }))
        };
    // Build shared TLS connector (root cert store is expensive to construct).
    // Use the ring provider explicitly to avoid ambiguity when multiple
    // crypto providers are in the dependency tree.
    // Must be created before CredentialStore::load_with_diagnostics() because OAuth2 token
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
    let tls_config_arc = Arc::new(tls_config.clone());
    let tls_connector = tokio_rustls::TlsConnector::from(Arc::clone(&tls_config_arc));
    let upstream_pool = Arc::new(UpstreamPool::new(
        Arc::clone(&tls_config_arc),
        config.enable_h2,
    ));

    let mut tls_config_h2 = tls_config;
    tls_config_h2.alpn_protocols = vec![b"h2".to_vec()];
    let tls_connector_h2 = tokio_rustls::TlsConnector::from(Arc::new(tls_config_h2));

    // Load credentials for reverse proxy routes (static keystore + OAuth2)
    let (credential_store, proxy_diagnostics) = if config.routes.is_empty() {
        (CredentialStore::empty(), Vec::new())
    } else {
        let outcome =
            CredentialStore::load_with_diagnostics(&config.routes, &tls_connector).await?;
        (outcome.store, outcome.diagnostics)
    };
    let mut loaded_routes = credential_store.loaded_prefixes();
    loaded_routes.extend(route_store.spiffe_loaded_prefixes());
    let config_loopback_upstream = crate::route::config_has_loopback_proxy_route(&config.routes);
    let managed_loopback_upstream =
        route_store.has_managed_loopback_upstream() || config_loopback_upstream;
    if config_loopback_upstream && !route_store.has_managed_loopback_upstream() {
        debug!(
            "NO_PROXY: clearing loopback via config route match ({} route(s))",
            config.routes.len()
        );
    }

    // Build filter. Strict mode treats an empty allowlist as deny-all.
    let filter = if config.strict_filter {
        ProxyFilter::new_strict(&config.allowed_hosts)
    } else if config.allowed_hosts.is_empty() {
        ProxyFilter::allow_all()
    } else {
        ProxyFilter::new(&config.allowed_hosts)
    }
    .with_denied_hosts(&config.denied_hosts);

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
    // Route upstreams are always kept on the proxy path: explicit profile
    // conflicts fail startup above, while smart-derived entries are filtered
    // here because they are implementation details, not user-declared bypasses.
    //
    // On macOS the derived smart list MUST be empty: Seatbelt's ProxyOnly mode
    // cannot infer arbitrary direct outbound bypasses. Explicit profile
    // `network.no_proxy` entries are still merged below. They do not expand
    // kernel permissions; direct attempts still fail closed unless the sandbox
    // grants that destination (for example a loopback alias with an open port).
    let smart_no_proxy_hosts: Vec<String> = if cfg!(target_os = "macos") {
        Vec::new()
    } else {
        config
            .allowed_hosts
            .iter()
            .filter_map(|host| {
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
                if no_proxy_entry_matches_any_route(&normalised, &route_hosts) {
                    return None;
                }
                // Only bypass the proxy if the sandbox grants direct
                // TCP on this host's port (via --allow-connect-port).
                let port = normalised
                    .rsplit_once(':')
                    .and_then(|(_, p)| p.parse::<u16>().ok())
                    .unwrap_or(443);
                if config.direct_connect_ports.contains(&port) {
                    smart_no_proxy_entry(host)
                } else {
                    None
                }
            })
            .collect()
    };

    let profile_no_proxy_hosts = config.no_proxy.as_slice();
    let no_proxy_hosts =
        merge_no_proxy_hosts(&smart_no_proxy_hosts, profile_no_proxy_hosts, &route_hosts);
    let canonical_no_proxy_hosts =
        merge_canonical_no_proxy_hosts(&smart_no_proxy_hosts, profile_no_proxy_hosts, &route_hosts);

    if !no_proxy_hosts.is_empty() {
        debug!("NO_PROXY bypass hosts: {:?}", no_proxy_hosts);
    }

    // Initialise TLS interception if a directory was supplied AND at least
    // one configured route actually requires L7 visibility. Routes are
    // checked here (rather than relying solely on the CLI's decision) so a
    // misconfigured `intercept_ca_dir` without intercept-bearing routes
    // doesn't generate a useless CA on disk.
    let any_route_intercept = route_store
        .route_upstream_hosts()
        .iter()
        .any(|hp| route_store.has_intercept_route(hp));
    let any_intercept_route = any_route_intercept || !oauth_capture_store.is_empty();
    let (cert_cache, intercept_ca_path) = match (&config.intercept_ca_dir, any_intercept_route) {
        (Some(dir), true) => {
            let intercept_route_count = route_store
                .route_upstream_hosts()
                .iter()
                .filter(|hp| route_store.has_intercept_route(hp))
                .count()
                + oauth_capture_store.host_ports().len();
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
                let cache = Arc::new(CertCache::new_with_leaf_validity(
                    Arc::clone(&ca),
                    config.leaf_validity,
                ));
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

    let enable_h2 = config.enable_h2;
    let intercept_ca_env_vars = config.intercept_ca_env_vars.clone();
    let state = Arc::new(ProxyState {
        filter,
        session_token: session_token.clone(),
        route_store: Arc::new(route_store),
        credential_store: Arc::new(credential_store),
        oauth_capture_store,
        config,
        tls_connector,
        default_tls_config: tls_config_arc,
        upstream_pool,
        tls_connector_h2,
        active_connections: AtomicUsize::new(0),
        audit_log: Arc::clone(&audit_log),
        approval_backends,
        credential_capture_backend,
        nonce_resolver: effective_nonce_resolver,
        bypass_matcher,
        cert_cache,
        enable_h2,
        h2_cache: UpstreamH2Cache::new(),
        bound_port: port,
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
        managed_loopback_upstream,
        canonical_no_proxy_hosts,
        intercept_ca_path,
        intercept_ca_env_vars,
        diagnostics: proxy_diagnostics,
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
    if let Some(rest) = authority.strip_prefix('[') {
        if let Some((host, remainder)) = rest.split_once(']') {
            if remainder.is_empty() {
                return crate::route::format_host_port(host, 443);
            }
            if let Some(port) = remainder.strip_prefix(':')
                && let Ok(port) = port.parse::<u16>()
            {
                return crate::route::format_host_port(host, port);
            }
        }
        authority.to_lowercase()
    } else {
        if let Some((host, port)) = authority.rsplit_once(':')
            && let Ok(port) = port.parse::<u16>()
        {
            if host.parse::<std::net::Ipv6Addr>().is_ok() {
                return crate::route::format_host_port(host, port);
            }
            if !host.contains(':') {
                return crate::route::format_host_port(host, port);
            }
        }
        if authority.parse::<std::net::Ipv6Addr>().is_ok() {
            crate::route::format_host_port(authority, 443)
        } else if authority.contains(':') {
            authority.to_lowercase()
        } else {
            crate::route::format_host_port(authority, 443)
        }
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
        // Resolve how the transparent CONNECT path treats Proxy-Authorization.
        // Strict (407 on failure) only for standalone `nono proxy` with auth
        // on; lenient (validate-but-tunnel) for the sandboxed paths; disabled
        // under `--no-auth`. See [`connect::ConnectAuthMode`].
        let connect_auth_mode = if !state.config.require_auth {
            connect::ConnectAuthMode::Disabled
        } else if state.config.strict_connect_auth {
            connect::ConnectAuthMode::Strict
        } else {
            connect::ConnectAuthMode::Lenient
        };

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
        if (!state.route_store.is_empty() || !state.oauth_capture_store.is_empty())
            && let Some(authority) = first_line.split_whitespace().nth(1)
        {
            let host_port = normalize_authority(authority);
            let oauth_host_policy = state.oauth_capture_store.host_policy(&host_port);

            if state.route_store.is_route_upstream(&host_port) || oauth_host_policy.is_some() {
                let route_id = state
                    .route_store
                    .lookup_by_upstream(&host_port)
                    .map(|(prefix, _)| prefix)
                    .or_else(|| {
                        oauth_host_policy
                            .as_ref()
                            .map(|policy| policy.route_id.as_str())
                    });
                let (host, port) = connect_target_from_normalized_authority(&host_port)
                    .unwrap_or_else(|| (host_port.clone(), 443));

                let intercept_eligible = state.route_store.has_intercept_route(&host_port)
                    || oauth_host_policy.is_some();

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
                        //
                        // When auth is disabled (standalone `nono proxy
                        // --no-auth`), `enforce_proxy_auth` returns `Ok(())` on
                        // the first pass and the loop exits without challenging.
                        let mut current_headers = header_bytes;
                        loop {
                            match token::enforce_proxy_auth(
                                state.config.require_auth,
                                &current_headers,
                                &state.session_token,
                            ) {
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

                        let mut h2_enabled_for_target = state.enable_h2
                            && !oauth_host_policy
                                .as_ref()
                                .is_some_and(|policy| policy.force_http1);
                        let (tls_connector_h2, h2_connector_cache_key) = if state.enable_h2 {
                            match tls_intercept::handle::select_h2_tls_connector_for_target(
                                &state.route_store,
                                &host,
                                port,
                                &state.tls_connector_h2,
                            ) {
                                Ok(selected) => selected,
                                Err(err) => {
                                    warn!(
                                        "tls_intercept: disabling h2 for {}:{}: {}",
                                        host, port, err
                                    );
                                    h2_enabled_for_target = false;
                                    (
                                        state.tls_connector_h2.clone(),
                                        "disabled-route-tls".to_string(),
                                    )
                                }
                            }
                        } else {
                            (state.tls_connector_h2.clone(), "disabled".to_string())
                        };

                        // Pre-flight h2 probe: only advertise h2 to the agent
                        // when the upstream actually negotiates it, avoiding
                        // NoApplicationProtocol against h1-only upstreams.
                        let upstream_h2 = if h2_enabled_for_target {
                            state
                                .h2_cache
                                .get_or_probe(
                                    &host,
                                    port,
                                    &state.filter,
                                    &tls_connector_h2,
                                    upstream_proxy.as_ref(),
                                    &h2_connector_cache_key,
                                )
                                .await
                        } else {
                            false
                        };
                        let ctx = tls_intercept::InterceptCtx {
                            route_id,
                            host: &host,
                            port,
                            route_store: Arc::clone(&state.route_store),
                            credential_store: Arc::clone(&state.credential_store),
                            oauth_capture_store: Arc::clone(&state.oauth_capture_store),
                            session_token: &state.session_token,
                            cert_cache: Arc::clone(cache),
                            tls_connector: &state.tls_connector,
                            tls_connector_h2: &tls_connector_h2,
                            filter: &state.filter,
                            audit_log: Some(&state.audit_log),
                            upstream_proxy,
                            approval_backends: state.approval_backends.clone(),
                            credential_capture_backend: state.credential_capture_backend.clone(),
                            nonce_resolver: state.nonce_resolver.clone(),
                            enable_h2: upstream_h2,
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
            external::handle_external_proxy(
                first_line,
                &mut stream,
                &header_bytes,
                &state.filter,
                &state.session_token,
                state.config.require_auth,
                ext_config,
                Some(&state.audit_log),
            )
            .await
        } else if state.config.external_proxy.is_some() {
            // Bypass route: enforce strict session token validation before
            // routing direct. Without this, bypassed hosts would inherit
            // connect::handle_connect()'s lenient auth (which tolerates
            // missing Proxy-Authorization for Node.js undici compat).
            token::enforce_proxy_auth(
                state.config.require_auth,
                &header_bytes,
                &state.session_token,
            )?;
            connect::handle_connect(
                first_line,
                &mut stream,
                &state.filter,
                &state.session_token,
                &header_bytes,
                connect_auth_mode,
                Some(&state.audit_log),
            )
            .await
        } else {
            connect::handle_connect(
                first_line,
                &mut stream,
                &state.filter,
                &state.session_token,
                &header_bytes,
                connect_auth_mode,
                Some(&state.audit_log),
            )
            .await
        }
    } else if classify_request_target(first_line) == RequestTargetForm::AbsoluteHttp {
        // Absolute-form `http://…` request from an HTTP_PROXY-honoring client.
        // Forward it as a plain-HTTP forward proxy (see handle_forward_http).
        // This branch is checked BEFORE the origin-form reverse-proxy path so
        // that absolute-form URLs never reach parse_service_prefix (which
        // would misread the scheme as a service name — see issue #1334).
        handle_forward_http(first_line, &mut stream, &header_bytes, &buffered, state).await
    } else if classify_request_target(first_line) == RequestTargetForm::AbsoluteHttps {
        // Absolute-form `https://…` cannot be forwarded as cleartext: the
        // proxy would have to originate TLS to the upstream on the client's
        // behalf, which no standard HTTP_PROXY client expects. Such clients
        // use CONNECT for HTTPS. Reject with explicit guidance rather than a
        // confusing 502.
        let response = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: 62\r\n\r\nhttps forward-proxying is not supported; use CONNECT for https";
        stream.write_all(response.as_bytes()).await?;
        Ok(())
    } else if !state.route_store.is_empty() {
        // Non-CONNECT request with routes configured -> reverse proxy
        let ctx = reverse::ReverseProxyCtx {
            route_store: &state.route_store,
            credential_store: &state.credential_store,
            session_token: &state.session_token,
            require_auth: state.config.require_auth,
            filter: &state.filter,
            tls_connector: &state.tls_connector,
            default_tls_config: &state.default_tls_config,
            upstream_pool: &state.upstream_pool,
            audit_log: Some(&state.audit_log),
            approval_backends: state.approval_backends.clone(),
            credential_capture_backend: state.credential_capture_backend.clone(),
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

/// Handle an absolute-form `http://` forward-proxy request.
///
/// This is the plain-HTTP counterpart to the CONNECT tunnel: a client that
/// honors `HTTP_PROXY` sends `GET http://host/path HTTP/1.1` for cleartext
/// HTTP, and nono forwards it after applying the same trust boundary the
/// tunnel path uses (session-token auth + host filter).
///
/// Steps:
/// 1. Enforce `Proxy-Authorization` (same session-token gate as CONNECT /
///    reverse). On failure: 407 + audit denial, matching the reverse path's
///    no-credential branch.
/// 2. Parse host+port from the absolute URL and run the host filter. On deny:
///    403 + `HostDenied` audit event, mirroring the no-routes inline `else`.
/// 3. Rewrite the request line to origin-form and strip hop-by-hop proxy
///    headers, then forward via the shared L7 pipeline using the
///    DNS-rebinding-safe resolved addresses (or the external proxy chain).
///
/// SAFETY / SECURITY: this path intentionally does NOT call
/// `reverse::validate_http_upstream_target`. That check enforces
/// loopback-only for `http` upstreams, which is correct for the *reverse*
/// proxy (whose upstreams are operator-configured and where plain HTTP to a
/// non-local host would be an accidental credential-leak footgun). A general
/// forward proxy, by contrast, exists precisely to reach arbitrary allowed
/// `http://` hosts on behalf of the agent. Here the host filter
/// (`check_host`) is the sufficient and authoritative trust boundary: it
/// applies the allowlist and the cloud-metadata / link-local SSRF guards, and
/// returns the exact resolved addresses we then connect to. Do NOT assume
/// "http upstream => loopback" holds on this path.
async fn handle_forward_http(
    first_line: &str,
    stream: &mut tokio::net::TcpStream,
    header_bytes: &[u8],
    buffered: &[u8],
    state: &ProxyState,
) -> Result<()> {
    // 1. Proxy-Authorization gate — identical to the reverse-proxy
    //    no-credential branch: 407 on missing/invalid auth, with an audit
    //    denial recording the authentication failure. No auth bypass.
    if let Err(e) = token::validate_proxy_auth(header_bytes, &state.session_token) {
        // Parse the target host for the audit record where possible; fall
        // back to a placeholder so a malformed line still audits.
        let (host, port) =
            parse_non_connect_target(first_line).unwrap_or_else(|_| ("unknown".to_string(), 0));
        audit::log_denied(
            Some(&state.audit_log),
            audit::ProxyMode::Reverse,
            &audit::EventContext {
                auth_mechanism: Some(nono::undo::NetworkAuditAuthMechanism::ProxyAuthorization),
                auth_outcome: Some(nono::undo::NetworkAuditAuthOutcome::Failed),
                denial_category: Some(nono::undo::NetworkAuditDenialCategory::AuthenticationFailed),
                ..audit::EventContext::default()
            },
            &host,
            port,
            &e.to_string(),
        );
        let response = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"nono\"\r\nContent-Length: 0\r\n\r\n";
        stream.write_all(response.as_bytes()).await?;
        return Ok(());
    }

    // 2. Parse host+port and run the host filter (DNS resolution + SSRF guard).
    let (host, port) = parse_non_connect_target(first_line)?;

    // Self-request: the absolute URL targets the proxy's own address.
    //
    // When `MOCKAPI_BASE_URL = http://127.0.0.1:{proxy_port}/mockapi` and
    // loopback is absent from NO_PROXY (because a managed-credential route
    // has a loopback upstream), HTTP_PROXY-aware clients such as curl send
    // the request in absolute-form to the proxy.  Without this check the
    // request would enter the transparent forward path and try to connect to
    // the proxy itself (a self-loop), bypassing credential injection.
    //
    // Detect the pattern and delegate to `handle_reverse_proxy`, which
    // already strips the scheme+authority from absolute-form URLs before
    // routing by path prefix, so credential injection (including SPIFFE JWT)
    // works correctly.
    if port == state.bound_port
        && (host == "127.0.0.1" || host == "localhost" || host == "[::1]" || host == "::1")
    {
        let ctx = reverse::ReverseProxyCtx {
            route_store: &state.route_store,
            credential_store: &state.credential_store,
            session_token: &state.session_token,
            require_auth: state.config.require_auth,
            filter: &state.filter,
            tls_connector: &state.tls_connector,
            default_tls_config: &state.default_tls_config,
            upstream_pool: &state.upstream_pool,
            audit_log: Some(&state.audit_log),
            approval_backends: state.approval_backends.clone(),
            credential_capture_backend: state.credential_capture_backend.clone(),
        };
        return reverse::handle_reverse_proxy(first_line, stream, header_bytes, &ctx, buffered)
            .await;
    }

    let check = state.filter.check_host(&host, port).await?;
    if !check.result.is_allowed() {
        let reason = check.result.reason();
        audit::log_denied(
            Some(&state.audit_log),
            audit::ProxyMode::Reverse,
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
        return Ok(());
    }

    // 3. Build the origin-form request bytes: rewritten request line +
    //    proxy-header-stripped header block + terminating CRLF.
    let origin_line = rewrite_absolute_to_origin_form(first_line)?;
    let inbound_path = origin_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_string();
    let method = first_line
        .split_whitespace()
        .next()
        .unwrap_or("GET")
        .to_string();

    let filtered_headers = strip_proxy_headers(header_bytes);
    let mut request_bytes = Vec::with_capacity(origin_line.len() + filtered_headers.len() + 2);
    request_bytes.extend_from_slice(origin_line.as_bytes());
    request_bytes.extend_from_slice(&filtered_headers);
    request_bytes.extend_from_slice(b"\r\n");

    // Read the request body honoring Content-Length. `buffered` holds any
    // bytes the BufReader already read past the header terminator.
    let content_length = reverse::extract_content_length(header_bytes);
    let body = match reverse::read_request_body(stream, content_length, buffered).await? {
        Some(body) => body,
        None => return Ok(()), // send_error already written (e.g. 413)
    };

    // 4. Choose the upstream strategy: chain through the external/enterprise
    //    proxy when configured (unless the host is a bypass host), else
    //    connect directly to the resolved addresses (DNS-rebinding-safe).
    let ext_proxy_addr = match state.config.external_proxy.as_ref() {
        Some(ext) if !(state.bypass_matcher.matches(&host)) => {
            // Mirror the CONNECT/intercept paths: external proxy auth is
            // configured-but-unimplemented, so fail loudly rather than
            // silently connecting unauthenticated.
            if ext.auth.is_some() {
                let msg = "external proxy authentication is configured but not yet \
                     implemented; remove the auth section from the external proxy \
                     config or wait for a future release";
                audit::log_denied(
                    Some(&state.audit_log),
                    audit::ProxyMode::Reverse,
                    &audit::EventContext {
                        denial_category: Some(
                            nono::undo::NetworkAuditDenialCategory::UpstreamConnectFailed,
                        ),
                        ..audit::EventContext::default()
                    },
                    &host,
                    port,
                    msg,
                );
                let response = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
                stream.write_all(response.as_bytes()).await?;
                return Err(ProxyError::ExternalProxy(msg.to_string()));
            }
            Some(ext.address.clone())
        }
        _ => None,
    };

    let strategy = match ext_proxy_addr.as_deref() {
        Some(addr) => UpstreamStrategy::ExternalProxy {
            proxy_addr: addr,
            proxy_auth_header: None,
        },
        None => UpstreamStrategy::Direct {
            resolved_addrs: &check.resolved_addrs,
        },
    };

    let upstream = UpstreamSpec {
        scheme: UpstreamScheme::Http,
        host: &host,
        port,
        strategy,
        // Unused for the Http scheme (no TLS to the upstream), but the shared
        // pipeline requires a connector value. Reuse the shared default.
        tls_connector: &state.tls_connector,
    };

    let audit_ctx = AuditCtx {
        log: Some(&state.audit_log),
        mode: audit::ProxyMode::Reverse,
        event_ctx: audit::EventContext {
            auth_mechanism: Some(nono::undo::NetworkAuditAuthMechanism::ProxyAuthorization),
            auth_outcome: Some(nono::undo::NetworkAuditAuthOutcome::Succeeded),
            managed_credential_active: Some(false),
            ..audit::EventContext::default()
        },
        target: &host,
        method: &method,
        path: &inbound_path,
    };

    match forward::forward_request(stream, &request_bytes, &body, upstream, audit_ctx).await {
        Ok(_status) => Ok(()),
        Err(e) => {
            warn!("forward-http upstream connection failed: {}", e);
            audit::log_denied(
                Some(&state.audit_log),
                audit::ProxyMode::Reverse,
                &audit::EventContext {
                    denial_category: Some(
                        nono::undo::NetworkAuditDenialCategory::UpstreamConnectFailed,
                    ),
                    ..audit::EventContext::default()
                },
                &host,
                port,
                &e.to_string(),
            );
            // The upstream connect failed before any response bytes were
            // streamed, so it is safe to emit a 502 to the client here.
            let response = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
            stream.write_all(response.as_bytes()).await?;
            Ok(())
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    fn env_value<'a>(vars: &'a [(String, String)], key: &str) -> Result<&'a str> {
        vars.iter()
            .find(|(candidate, _)| candidate == key)
            .map(|(_, value)| value.as_str())
            .ok_or_else(|| ProxyError::Config(format!("{key} should be emitted")))
    }

    async fn start_config_error(config: ProxyConfig) -> Result<String> {
        match start(config).await {
            Err(ProxyError::Config(message)) => Ok(message),
            Err(err) => Err(err),
            Ok(handle) => {
                handle.shutdown();
                Err(ProxyError::Config(
                    "proxy startup should have rejected config".to_string(),
                ))
            }
        }
    }

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
        assert_eq!(normalize_authority("::1"), "[::1]:443");
        assert_eq!(normalize_authority("::1:8080"), "[::1]:8080");
        assert_eq!(normalize_authority("[0:0:0:0:0:0:0:1]:8080"), "[::1]:8080");
        assert_eq!(normalize_authority("0:0:0:0:0:0:0:1:8080"), "[::1]:8080");
        // case- and port-insensitive equality is the point of the retry guard
        assert_eq!(
            normalize_authority("API.OPENAI.COM:443"),
            normalize_authority("api.openai.com")
        );
    }

    #[tokio::test]
    async fn normalize_authority_matches_ipv6_route_upstreams() -> Result<()> {
        let routes = vec![crate::config::RouteConfig {
            redeem_phantoms: Vec::new(),
            prefix: "local".to_string(),
            upstream: "http://[::1]:8080/v1".to_string(),
            credential_key: Some("local".to_string()),
            inject_mode: crate::config::InjectMode::Header,
            inject_header: "Authorization".to_string(),
            credential_format: None,
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: None,
            endpoint_rules: Vec::new(),
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
        let host_port = normalize_authority("::1:8080");

        assert_eq!(host_port, "[::1]:8080");
        assert!(store.is_route_upstream(&host_port));
        assert!(store.has_intercept_route(&host_port));
        Ok(())
    }

    #[test]
    fn connect_target_from_normalized_authority_unbrackets_ipv6() {
        let host_port = normalize_authority("::1:8080");

        assert_eq!(host_port, "[::1]:8080");
        assert_eq!(
            connect_target_from_normalized_authority(&host_port),
            Some(("::1".to_string(), 8080))
        );
        assert_eq!(
            connect_target_from_normalized_authority("api.openai.com:443"),
            Some(("api.openai.com".to_string(), 443))
        );
    }

    #[tokio::test]
    async fn test_proxy_uses_supplied_session_token() {
        // A caller-supplied password (the `nono proxy --pass` case) must be
        // used verbatim as the proxy credential instead of a random token.
        let config = ProxyConfig {
            session_token: Some(Zeroizing::new("my-fixed-password".to_string())),
            ..Default::default()
        };
        let handle = start(config).await.unwrap();
        assert_eq!(*handle.token, "my-fixed-password");
        handle.shutdown();
    }

    #[tokio::test]
    async fn test_proxy_ignores_empty_session_token() {
        // An empty override must fall back to a random token, never an
        // effectively-absent credential.
        let config = ProxyConfig {
            session_token: Some(Zeroizing::new(String::new())),
            ..Default::default()
        };
        let handle = start(config).await.unwrap();
        assert_eq!(
            handle.token.len(),
            64,
            "empty --pass must fall back to a random token"
        );
        handle.shutdown();
    }

    /// Spawn a one-shot loopback HTTP server that accepts a single connection,
    /// drains the request, and replies `200 OK`. Returns its `host:port`.
    /// Used as a reverse-proxy upstream so the auth decision can be observed
    /// end-to-end without reaching the network.
    async fn spawn_mock_upstream() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                // Read until the end of the request head, then reply.
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await;
            }
        });
        format!("127.0.0.1:{}", addr.port())
    }

    /// A declarative (credential-less) reverse-proxy route whose upstream is a
    /// loopback `http://` server. With no credential, the auth path falls to
    /// the session-token fallback branch — the branch the `require_auth` fix
    /// moved back inside the guard.
    fn declarative_route(upstream: &str) -> crate::config::RouteConfig {
        crate::config::RouteConfig {
            redeem_phantoms: Vec::new(),
            prefix: "svc".to_string(),
            upstream: upstream.to_string(),
            credential_key: None,
            inject_mode: Default::default(),
            inject_header: "Authorization".to_string(),
            credential_format: None,
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
        }
    }

    /// Send `GET /svc/` through the proxy at `port` with no `Proxy-Authorization`
    /// header and return the upstream status line the proxy wrote back.
    async fn unauthenticated_reverse_request(port: u16) -> String {
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        client
            .write_all(b"GET /svc/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .unwrap();
        let mut resp = Vec::new();
        // Read the response head; the upstream is tiny so a single read suffices.
        let mut buf = [0u8; 1024];
        if let Ok(n) = client.read(&mut buf).await {
            resp.extend_from_slice(&buf[..n]);
        }
        String::from_utf8_lossy(&resp)
            .lines()
            .next()
            .unwrap_or("")
            .to_string()
    }

    #[tokio::test]
    async fn test_no_auth_skips_reverse_proxy_authentication() {
        // Regression: `nono proxy --no-auth` (require_auth == false) must skip
        // session-token enforcement on reverse-proxy routes. A previous
        // restructure chained the auth branches as `else if` alternatives to
        // `if ctx.require_auth`, so disabling auth still rejected requests.
        let upstream = spawn_mock_upstream().await;
        let config = ProxyConfig {
            routes: vec![declarative_route(&format!("http://{upstream}"))],
            allowed_hosts: vec!["127.0.0.1".to_string()],
            require_auth: false,
            ..Default::default()
        };
        let handle = start(config).await.unwrap();
        let status = unauthenticated_reverse_request(handle.port).await;
        assert!(
            status.contains("200"),
            "with --no-auth an unauthenticated reverse request must reach the upstream, got: {status:?}"
        );
        assert!(
            !status.contains("407") && !status.contains("401"),
            "auth must not be enforced when disabled, got: {status:?}"
        );
        handle.shutdown();
    }

    #[tokio::test]
    async fn test_reverse_proxy_enforces_auth_when_required() {
        // Companion to the --no-auth case: with auth required, an
        // unauthenticated reverse request must still be challenged (407),
        // locking the toggle in both directions.
        let upstream = spawn_mock_upstream().await;
        let config = ProxyConfig {
            routes: vec![declarative_route(&format!("http://{upstream}"))],
            allowed_hosts: vec!["127.0.0.1".to_string()],
            require_auth: true,
            ..Default::default()
        };
        let handle = start(config).await.unwrap();
        let status = unauthenticated_reverse_request(handle.port).await;
        assert!(
            status.contains("407"),
            "with auth required an unauthenticated reverse request must be challenged, got: {status:?}"
        );
        handle.shutdown();
    }

    /// Send a raw request through the proxy at `port` and return everything
    /// the proxy wrote back (status line, headers, body).
    async fn send_raw_request(port: u16, request: &[u8]) -> String {
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        client.write_all(request).await.unwrap();
        let mut resp = Vec::new();
        let mut buf = [0u8; 4096];
        if let Ok(n) = client.read(&mut buf).await {
            resp.extend_from_slice(&buf[..n]);
        }
        String::from_utf8_lossy(&resp).to_string()
    }

    #[tokio::test]
    async fn test_websocket_upgrade_returns_501_without_reaching_upstream() {
        // A structurally valid WebSocket handshake must be rejected
        // immediately with 501 rather than forwarded to the upstream (which
        // would otherwise hang waiting for a 101 response that never comes).
        let upstream = spawn_mock_upstream().await;
        let config = ProxyConfig {
            routes: vec![declarative_route(&format!("http://{upstream}"))],
            allowed_hosts: vec!["127.0.0.1".to_string()],
            require_auth: false,
            ..Default::default()
        };
        let handle = start(config).await.unwrap();
        let response = send_raw_request(
            handle.port,
            b"GET /svc/ HTTP/1.1\r\n\
              Host: 127.0.0.1\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              Sec-WebSocket-Version: 13\r\n\r\n",
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 501"),
            "valid websocket handshake must get 501, got: {response:?}"
        );
        assert!(
            response.to_lowercase().contains("connection: close"),
            "501 upgrade response must close the connection, got: {response:?}"
        );

        let events = handle.drain_audit_events();
        assert!(
            events.iter().any(|e| {
                e.denial_category
                    == Some(nono::undo::NetworkAuditDenialCategory::UnsupportedUpgrade)
            }),
            "expected an UnsupportedUpgrade audit event, got: {events:?}"
        );

        handle.shutdown();
    }

    #[tokio::test]
    async fn test_websocket_upgrade_malformed_returns_400() {
        // A request that claims to be an upgrade but is missing required
        // handshake headers must be rejected as malformed, not forwarded.
        let upstream = spawn_mock_upstream().await;
        let config = ProxyConfig {
            routes: vec![declarative_route(&format!("http://{upstream}"))],
            allowed_hosts: vec!["127.0.0.1".to_string()],
            require_auth: false,
            ..Default::default()
        };
        let handle = start(config).await.unwrap();
        let response = send_raw_request(
            handle.port,
            b"GET /svc/ HTTP/1.1\r\n\
              Host: 127.0.0.1\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\r\n",
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 400"),
            "malformed websocket handshake must get 400, got: {response:?}"
        );
        assert!(
            response.to_lowercase().contains("connection: close"),
            "400 upgrade response must close the connection, got: {response:?}"
        );
        handle.shutdown();
    }

    #[tokio::test]
    async fn test_ordinary_request_unaffected_by_upgrade_detection() {
        // Regression guard: a plain (non-upgrade) request through a
        // configured route must still be proxied normally.
        let upstream = spawn_mock_upstream().await;
        let config = ProxyConfig {
            routes: vec![declarative_route(&format!("http://{upstream}"))],
            allowed_hosts: vec!["127.0.0.1".to_string()],
            require_auth: false,
            ..Default::default()
        };
        let handle = start(config).await.unwrap();
        let status = unauthenticated_reverse_request(handle.port).await;
        assert!(
            status.contains("200"),
            "ordinary requests must be unaffected by upgrade detection, got: {status:?}"
        );
        handle.shutdown();
    }

    /// Send an unauthenticated `CONNECT host:443` through the proxy at `port`
    /// and return the status line the proxy wrote back.
    async fn unauthenticated_connect_request(port: u16, host: &str) -> String {
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        client
            .write_all(
                format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
        let mut buf = [0u8; 1024];
        let n = client.read(&mut buf).await.unwrap_or(0);
        String::from_utf8_lossy(&buf[..n])
            .lines()
            .next()
            .unwrap_or("")
            .to_string()
    }

    #[tokio::test]
    async fn test_strict_connect_auth_rejects_unauthenticated_connect() {
        // Standalone `nono proxy` sets strict_connect_auth: an unauthenticated
        // CONNECT must be answered with 407 *before* any DNS/filter/upstream
        // handling, rather than tunnelled (which would otherwise surface as a
        // 502 once the upstream connect fails).
        let config = ProxyConfig {
            allowed_hosts: vec!["nonexistent.invalid".to_string()],
            require_auth: true,
            strict_connect_auth: true,
            ..Default::default()
        };
        let handle = start(config).await.unwrap();
        let status = unauthenticated_connect_request(handle.port, "nonexistent.invalid").await;
        assert!(
            status.contains("407"),
            "strict CONNECT auth must challenge an unauthenticated CONNECT, got: {status:?}"
        );
        handle.shutdown();
    }

    #[tokio::test]
    async fn test_lenient_connect_auth_tunnels_unauthenticated_connect() {
        // Sandboxed run/shell/wrap path (strict_connect_auth == false): an
        // unauthenticated CONNECT is *not* rejected with 407 — it proceeds to
        // host filtering / upstream connect (undici compat). The unresolvable
        // host then yields a 502, proving the request was never short-circuited
        // at the auth gate.
        let config = ProxyConfig {
            allowed_hosts: vec!["nonexistent.invalid".to_string()],
            require_auth: true,
            strict_connect_auth: false,
            ..Default::default()
        };
        let handle = start(config).await.unwrap();
        let status = unauthenticated_connect_request(handle.port, "nonexistent.invalid").await;
        assert!(
            !status.contains("407"),
            "lenient CONNECT auth must not challenge with 407, got: {status:?}"
        );
        handle.shutdown();
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

    #[test]
    fn test_proxy_handle_drop_signals_shutdown() {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        {
            let _handle = ProxyHandle {
                port: 12345,
                token: Zeroizing::new("test_token".to_string()),
                audit_log: audit::new_audit_log(),
                shutdown_tx,
                loaded_routes: std::collections::HashSet::new(),
                no_proxy_hosts: Vec::new(),
                managed_loopback_upstream: false,
                canonical_no_proxy_hosts: Vec::new(),
                intercept_ca_path: None,
                intercept_ca_env_vars: crate::config::default_intercept_ca_env_vars(),
                diagnostics: vec![],
            };
        }

        assert!(*shutdown_rx.borrow());
    }

    /// End-to-end smoke test: when `intercept_ca_dir` is set AND a route
    /// requires L7 visibility, the proxy:
    /// 1. generates an ephemeral CA;
    /// 2. writes a trust bundle file with at least the ephemeral cert + system roots;
    /// 3. exposes the path via `intercept_ca_path()`;
    /// 4. emits configured trust env vars (`SSL_CERT_FILE` etc.) pointing at it;
    /// 5. cleans the file on `Drop`.
    #[tokio::test]
    async fn test_intercept_lifecycle_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let ca_path_clone;

        {
            let config = ProxyConfig {
                routes: vec![crate::config::RouteConfig {
                    redeem_phantoms: Vec::new(),
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
                    endpoint_policy: None,
                    tls_ca: None,
                    tls_client_cert: None,
                    tls_client_key: None,
                    oauth2: None,
                    aws_auth: None,
                    spiffe: None,
                    upgrades: vec![],
                }],
                intercept_ca_dir: Some(dir.path().to_path_buf()),
                intercept_ca_env_vars: {
                    let mut vars = crate::config::default_intercept_ca_env_vars();
                    vars.push("CODEX_CA_CERTIFICATE".to_string());
                    vars
                },
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
            let codex_ca = vars
                .iter()
                .find(|(k, _)| k == "CODEX_CA_CERTIFICATE")
                .expect("CODEX_CA_CERTIFICATE should be set when intercept active");
            assert_eq!(std::path::Path::new(&codex_ca.1), ca_path_clone);
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
                redeem_phantoms: Vec::new(),
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

    #[tokio::test]
    async fn test_oauth_capture_routes_activate_intercept() {
        let dir = tempfile::tempdir().unwrap();
        let config = ProxyConfig {
            oauth_capture: vec![crate::config::OAuthCaptureConfig {
                provider: "codex".to_string(),
                token_endpoints: vec![crate::config::OAuthTokenEndpointConfig {
                    host: "https://auth.openai.com".to_string(),
                    path: "/oauth/token".to_string(),
                    response_fields: vec![
                        crate::config::OAuthTokenResponseFieldConfig {
                            path: "access_token".to_string(),
                            kind: crate::config::OAuthTokenResponseFieldKind::Opaque,
                        },
                        crate::config::OAuthTokenResponseFieldConfig {
                            path: "refresh_token".to_string(),
                            kind: crate::config::OAuthTokenResponseFieldKind::Opaque,
                        },
                    ],
                    request_body: crate::config::OAuthTokenRequestBodyFormat::Auto,
                    request_nonce_fields: vec!["refresh_token".to_string()],
                }],
                admitted_consumers: vec!["proxy.openai_oauth".to_string()],
            }],
            intercept_ca_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let handle = start(config).await.unwrap();
        assert!(
            handle.intercept_ca_path().is_some(),
            "oauth_capture token endpoints must activate TLS interception"
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
                redeem_phantoms: Vec::new(),
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
                endpoint_policy: None,
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
                aws_auth: None,
                spiffe: None,
                upgrades: vec![],
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
                    redeem_phantoms: Vec::new(),
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
                    endpoint_policy: None,
                    tls_ca: None,
                    tls_client_cert: None,
                    tls_client_key: None,
                    oauth2: None,
                    aws_auth: None,
                    spiffe: None,
                    upgrades: vec![],
                },
                crate::config::RouteConfig {
                    redeem_phantoms: Vec::new(),
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
                },
            ],
            intercept_ca_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let handle = start(config.clone()).await.unwrap();
        let rows = handle.route_diagnostics(&config);
        assert_eq!(rows.len(), 2);

        let openai = rows.iter().find(|s| s.contains("api.openai.com")).unwrap();
        assert!(openai.contains("intercept: on"));
        assert!(
            openai.contains("✗") || openai.contains("credential_not_found"),
            "missing credential should show structured code, got: {}",
            openai
        );

        let alias = rows
            .iter()
            .find(|s| s.contains("aliased.example.com"))
            .unwrap();
        assert!(alias.contains("creds: none"));
        assert!(alias.contains("intercept: off"));

        handle.shutdown();
    }

    /// A credential route and the synthetic `_ep_<host>` endpoint-authorization
    /// route for the same upstream collapse into a single diagnostic row that
    /// carries the credential and the summed endpoint-rule count, rather than
    /// surfacing the internal split as a credential-less duplicate.
    #[tokio::test]
    async fn test_route_diagnostics_groups_credential_and_endpoint_routes() {
        let dir = tempfile::tempdir().unwrap();
        let endpoint_rule = crate::config::EndpointRule {
            method: "GET".to_string(),
            path: "/repos/*".to_string(),
        };
        let config = ProxyConfig {
            routes: vec![
                // Credential catch-all route (no endpoint rules).
                crate::config::RouteConfig {
                    redeem_phantoms: Vec::new(),
                    prefix: "github_api".to_string(),
                    upstream: "https://api.github.com".to_string(),
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
                    endpoint_policy: None,
                    tls_ca: None,
                    tls_client_cert: None,
                    tls_client_key: None,
                    oauth2: None,
                    aws_auth: None,
                    spiffe: None,
                    upgrades: vec![],
                },
                // Synthetic endpoint-authorization route for the same upstream.
                crate::config::RouteConfig {
                    redeem_phantoms: Vec::new(),
                    prefix: "_ep_api.github.com".to_string(),
                    upstream: "https://api.github.com".to_string(),
                    credential_key: None,
                    inject_mode: Default::default(),
                    inject_header: "Authorization".to_string(),
                    credential_format: None,
                    path_pattern: None,
                    path_replacement: None,
                    query_param_name: None,
                    proxy: None,
                    env_var: None,
                    endpoint_rules: vec![endpoint_rule.clone(), endpoint_rule],
                    endpoint_policy: None,
                    tls_ca: None,
                    tls_client_cert: None,
                    tls_client_key: None,
                    oauth2: None,
                    aws_auth: None,
                    spiffe: None,
                    upgrades: vec![],
                },
            ],
            intercept_ca_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let handle = start(config.clone()).await.unwrap();
        let rows = handle.route_diagnostics(&config);

        // Two routes, one upstream → a single grouped row.
        assert_eq!(rows.len(), 1, "routes sharing an upstream should collapse");
        let summary = &rows[0];
        assert!(summary.contains("api.github.com"));
        // Credential status comes from the credential-bearing route, not `none`.
        assert!(
            !summary.contains("creds: none"),
            "grouped row must carry the credential, got: {summary}"
        );
        // Endpoint rules from the `_ep_` route are summed onto the row.
        assert!(
            summary.contains("endpoint_rules: 2"),
            "grouped row must sum endpoint rules, got: {summary}"
        );
        assert!(summary.contains("intercept: on"));

        handle.shutdown();
    }

    /// An `_ep_` route on a concrete subdomain (`raw.githubusercontent.com`)
    /// stays its own row but reports the credential from the covering wildcard
    /// route (`*.githubusercontent.com`) rather than `creds: none`, because the
    /// wildcard route injects that credential for the subdomain at request time.
    #[tokio::test]
    async fn test_route_diagnostics_reports_covering_wildcard_credential() {
        let dir = tempfile::tempdir().unwrap();
        let endpoint_rule = crate::config::EndpointRule {
            method: "GET".to_string(),
            path: "/**".to_string(),
        };
        let config = ProxyConfig {
            routes: vec![
                // Wildcard credential route.
                crate::config::RouteConfig {
                    redeem_phantoms: Vec::new(),
                    prefix: "github_raw".to_string(),
                    upstream: "https://*.githubusercontent.com".to_string(),
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
                    endpoint_policy: None,
                    tls_ca: None,
                    tls_client_cert: None,
                    tls_client_key: None,
                    oauth2: None,
                    aws_auth: None,
                    spiffe: None,
                    upgrades: vec![],
                },
                // `_ep_` route on a concrete subdomain covered by the wildcard.
                crate::config::RouteConfig {
                    redeem_phantoms: Vec::new(),
                    prefix: "_ep_raw.githubusercontent.com".to_string(),
                    upstream: "https://raw.githubusercontent.com".to_string(),
                    credential_key: None,
                    inject_mode: Default::default(),
                    inject_header: "Authorization".to_string(),
                    credential_format: None,
                    path_pattern: None,
                    path_replacement: None,
                    query_param_name: None,
                    proxy: None,
                    env_var: None,
                    endpoint_rules: vec![endpoint_rule],
                    endpoint_policy: None,
                    tls_ca: None,
                    tls_client_cert: None,
                    tls_client_key: None,
                    oauth2: None,
                    aws_auth: None,
                    spiffe: None,
                    upgrades: vec![],
                },
            ],
            intercept_ca_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let handle = start(config.clone()).await.unwrap();
        let rows = handle.route_diagnostics(&config);

        // Distinct upstreams → two rows (no merge across different hosts).
        assert_eq!(rows.len(), 2, "distinct upstreams must not merge");
        let ep_row = rows
            .iter()
            .find(|s| s.contains("raw.githubusercontent.com") && !s.contains('*'))
            .expect("subdomain row present");
        // The covering wildcard credential is reported, not `none`.
        assert!(
            !ep_row.contains("creds: none"),
            "covered subdomain must report the wildcard credential, got: {}",
            ep_row
        );
        assert!(ep_row.contains("endpoint_rules: 1"));

        handle.shutdown();
    }

    /// A credential route whose upstream is not in the host allowlist is dead
    /// config — traffic to it would be denied by the filter regardless of the
    /// injected credential — so it is omitted from the diagnostics entirely.
    #[tokio::test]
    async fn test_route_diagnostics_omits_unreachable_upstream() {
        let dir = tempfile::tempdir().unwrap();
        let route = |prefix: &str, upstream: &str| crate::config::RouteConfig {
            redeem_phantoms: Vec::new(),
            prefix: prefix.to_string(),
            upstream: upstream.to_string(),
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
            endpoint_policy: None,
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
            oauth2: None,
            aws_auth: None,
            spiffe: None,
            upgrades: vec![],
        };
        let config = ProxyConfig {
            routes: vec![
                route("github_api", "https://api.github.com"),
                route("datadog", "https://api.datadoghq.com"),
            ],
            // Only github is allow-listed; datadog's upstream is unreachable.
            allowed_hosts: vec!["api.github.com".to_string()],
            intercept_ca_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let handle = start(config.clone()).await.unwrap();
        let rows = handle.route_diagnostics(&config);

        assert_eq!(rows.len(), 1, "unreachable upstream must be omitted");
        assert!(rows[0].contains("api.github.com"));
        assert!(
            !rows.iter().any(|s| s.contains("datadoghq.com")),
            "non-allow-listed upstream must not be listed, got: {rows:?}"
        );

        handle.shutdown();
    }

    /// Strict mode with a non-empty allowlist behaves the same: a route to a
    /// non-allow-listed upstream is omitted, an allow-listed one is shown.
    #[tokio::test]
    async fn test_route_diagnostics_respects_wildcard_allowlist() {
        let dir = tempfile::tempdir().unwrap();
        let route = |prefix: &str, upstream: &str| crate::config::RouteConfig {
            redeem_phantoms: Vec::new(),
            prefix: prefix.to_string(),
            upstream: upstream.to_string(),
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
            endpoint_policy: None,
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
            oauth2: None,
            aws_auth: None,
            spiffe: None,
            upgrades: vec![],
        };
        let config = ProxyConfig {
            routes: vec![
                route("github_raw", "https://raw.githubusercontent.com"),
                route("evil", "https://evil.example.com"),
            ],
            // Wildcard covers the githubusercontent subdomain but not evil.
            allowed_hosts: vec!["*.githubusercontent.com".to_string()],
            strict_filter: true,
            intercept_ca_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let handle = start(config.clone()).await.unwrap();
        let rows = handle.route_diagnostics(&config);

        assert_eq!(rows.len(), 1, "only the wildcard-covered upstream remains");
        assert!(rows[0].contains("raw.githubusercontent.com"));
        assert!(
            !rows.iter().any(|s| s.contains("evil.example.com")),
            "upstream outside the wildcard must be omitted, got: {rows:?}"
        );

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

    #[test]
    fn test_proxy_env_vars_include_canonical_nono_no_proxy() -> Result<()> {
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);
        let handle = ProxyHandle {
            port: 12345,
            token: Zeroizing::new("a".repeat(64)),
            audit_log: audit::new_audit_log(),
            shutdown_tx,
            loaded_routes: std::collections::HashSet::new(),
            no_proxy_hosts: vec![
                "redis".to_string(),
                ".internal.example".to_string(),
                "::1".to_string(),
            ],
            managed_loopback_upstream: false,
            canonical_no_proxy_hosts: vec![
                "redis".to_string(),
                "*.internal.example".to_string(),
                "::1".to_string(),
            ],
            intercept_ca_env_vars: crate::config::default_intercept_ca_env_vars(),
            intercept_ca_path: None,
            diagnostics: Vec::new(),
        };

        let vars = handle.env_vars();

        assert_eq!(
            env_value(&vars, "NO_PROXY")?,
            "localhost,127.0.0.1,redis,.internal.example,::1"
        );
        assert_eq!(
            env_value(&vars, "NONO_NO_PROXY")?,
            "localhost,127.0.0.1,redis,*.internal.example,::1"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_proxy_credential_env_vars() {
        let config = ProxyConfig {
            routes: vec![crate::config::RouteConfig {
                redeem_phantoms: Vec::new(),
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
                endpoint_policy: None,
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
                aws_auth: None,
                spiffe: None,
                upgrades: vec![],
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
            managed_loopback_upstream: false,
            canonical_no_proxy_hosts: Vec::new(),
            intercept_ca_path: None,
            intercept_ca_env_vars: crate::config::default_intercept_ca_env_vars(),
            diagnostics: vec![],
        };
        let config = ProxyConfig {
            routes: vec![crate::config::RouteConfig {
                redeem_phantoms: Vec::new(),
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
                endpoint_policy: None,
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
                aws_auth: None,
                spiffe: None,
                upgrades: vec![],
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
            managed_loopback_upstream: false,
            canonical_no_proxy_hosts: Vec::new(),
            intercept_ca_path: None,
            intercept_ca_env_vars: crate::config::default_intercept_ca_env_vars(),
            diagnostics: vec![],
        };
        let config = ProxyConfig {
            routes: vec![crate::config::RouteConfig {
                redeem_phantoms: Vec::new(),
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
                endpoint_policy: None,
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
                aws_auth: None,
                spiffe: None,
                upgrades: vec![],
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
            managed_loopback_upstream: false,
            canonical_no_proxy_hosts: Vec::new(),
            intercept_ca_path: None,
            intercept_ca_env_vars: crate::config::default_intercept_ca_env_vars(),
            diagnostics: vec![],
        };
        let config = ProxyConfig {
            routes: vec![
                crate::config::RouteConfig {
                    redeem_phantoms: Vec::new(),
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
                    endpoint_policy: None,
                    tls_ca: None,
                    tls_client_cert: None,
                    tls_client_key: None,
                    oauth2: None,
                    aws_auth: None,
                    spiffe: None,
                    upgrades: vec![],
                },
                crate::config::RouteConfig {
                    redeem_phantoms: Vec::new(),
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
                    endpoint_policy: None,
                    tls_ca: None,
                    tls_client_cert: None,
                    tls_client_key: None,
                    oauth2: None,
                    aws_auth: None,
                    spiffe: None,
                    upgrades: vec![],
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
    fn test_proxy_credential_env_vars_injects_spiffe_phantom_token() {
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        let handle = ProxyHandle {
            port: 12345,
            token: Zeroizing::new("session_token".to_string()),
            audit_log: audit::new_audit_log(),
            shutdown_tx,
            loaded_routes: ["myapi".to_string()].into_iter().collect(),
            no_proxy_hosts: Vec::new(),
            managed_loopback_upstream: false,
            canonical_no_proxy_hosts: Vec::new(),
            intercept_ca_path: None,
            intercept_ca_env_vars: crate::config::default_intercept_ca_env_vars(),
            diagnostics: vec![],
        };
        let config = ProxyConfig {
            routes: vec![crate::config::RouteConfig {
                redeem_phantoms: Vec::new(),
                prefix: "myapi".to_string(),
                upstream: "https://api.internal.corp".to_string(),
                credential_key: None,
                inject_mode: crate::config::InjectMode::Header,
                inject_header: "Authorization".to_string(),
                credential_format: None,
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
                spiffe: Some(crate::config::SpiffeAuthConfig::Jwt {
                    workload_api_socket: "/tmp/spire.sock".to_string(),
                    audience: vec!["api.internal.corp".to_string()],
                    inject_header: "Authorization".to_string(),
                    credential_format: None,
                    svid_hint: None,
                }),
                upgrades: vec![],
            }],
            ..Default::default()
        };

        let vars = handle.credential_env_vars(&config);
        let api_key = vars.iter().find(|(k, _)| k == "MYAPI_API_KEY");
        assert!(
            api_key.is_some(),
            "SPIFFE route should inject phantom API key"
        );
        assert_eq!(api_key.unwrap().1, "session_token");
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
            managed_loopback_upstream: false,
            canonical_no_proxy_hosts: Vec::new(),
            intercept_ca_path: None,
            intercept_ca_env_vars: crate::config::default_intercept_ca_env_vars(),
            diagnostics: vec![],
        };

        // Test leading slash
        let config = ProxyConfig {
            routes: vec![crate::config::RouteConfig {
                redeem_phantoms: Vec::new(),
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
                endpoint_policy: None,
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
                aws_auth: None,
                spiffe: None,
                upgrades: vec![],
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
                redeem_phantoms: Vec::new(),
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
                endpoint_policy: None,
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
                aws_auth: None,
                spiffe: None,
                upgrades: vec![],
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
            managed_loopback_upstream: false,
            canonical_no_proxy_hosts: Vec::new(),
            intercept_ca_path: None,
            intercept_ca_env_vars: crate::config::default_intercept_ca_env_vars(),
            diagnostics: vec![],
        };
        let config_no_env_var = ProxyConfig {
            routes: vec![crate::config::RouteConfig {
                redeem_phantoms: Vec::new(),
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
                endpoint_policy: None,
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
                aws_auth: None,
                spiffe: None,
                upgrades: vec![],
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
            managed_loopback_upstream: false,
            canonical_no_proxy_hosts: Vec::new(),
            intercept_ca_path: None,
            intercept_ca_env_vars: crate::config::default_intercept_ca_env_vars(),
            diagnostics: vec![],
        };
        let config_fixed = ProxyConfig {
            routes: vec![crate::config::RouteConfig {
                redeem_phantoms: Vec::new(),
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
                endpoint_policy: None,
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
                aws_auth: None,
                spiffe: None,
                upgrades: vec![],
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
            managed_loopback_upstream: false,
            canonical_no_proxy_hosts: vec![
                "nats.internal:4222".to_string(),
                "opencode.internal:4096".to_string(),
            ],
            intercept_ca_path: None,
            intercept_ca_env_vars: crate::config::default_intercept_ca_env_vars(),
            diagnostics: vec![],
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
            managed_loopback_upstream: false,
            canonical_no_proxy_hosts: Vec::new(),
            intercept_ca_path: None,
            intercept_ca_env_vars: crate::config::default_intercept_ca_env_vars(),
            diagnostics: vec![],
        };

        let vars = handle.env_vars();
        let no_proxy = vars.iter().find(|(k, _)| k == "NO_PROXY").unwrap();
        assert_eq!(
            no_proxy.1, "localhost,127.0.0.1",
            "NO_PROXY should only contain loopback when no bypass hosts"
        );
    }

    #[test]
    fn test_no_proxy_omits_loopback_for_managed_loopback_upstream() {
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        let handle = ProxyHandle {
            port: 12345,
            token: Zeroizing::new("test_token".to_string()),
            audit_log: audit::new_audit_log(),
            shutdown_tx,
            loaded_routes: std::collections::HashSet::new(),
            no_proxy_hosts: Vec::new(),
            managed_loopback_upstream: true,
            canonical_no_proxy_hosts: Vec::new(),
            intercept_ca_path: None,
            intercept_ca_env_vars: crate::config::default_intercept_ca_env_vars(),
            diagnostics: vec![],
        };

        let vars = handle.env_vars();
        let no_proxy = vars.iter().find(|(k, _)| k == "NO_PROXY").unwrap();
        assert_eq!(
            no_proxy.1, "",
            "loopback credential upstreams must traverse the proxy"
        );
    }

    #[cfg(not(target_os = "macos"))]
    #[tokio::test]
    async fn test_profile_no_proxy_emits_uppercase_and_lowercase() -> Result<()> {
        let config = ProxyConfig {
            no_proxy: vec![
                "redis".to_string(),
                "*.internal.example".to_string(),
                "REDIS".to_string(),
                "[::1]".to_string(),
            ],
            ..Default::default()
        };
        let handle = start(config).await?;

        let vars = handle.env_vars();
        let upper = env_value(&vars, "NO_PROXY")?;
        let lower = env_value(&vars, "no_proxy")?;
        let canonical = env_value(&vars, "NONO_NO_PROXY")?;

        assert_eq!(upper, "localhost,127.0.0.1,redis,.internal.example,::1");
        assert_eq!(lower, upper);
        assert_eq!(
            canonical,
            "localhost,127.0.0.1,redis,*.internal.example,::1"
        );

        handle.shutdown();
        Ok(())
    }

    #[test]
    fn test_no_proxy_route_matching_strips_direct_connect_ports() {
        assert!(no_proxy_entry_matches_route(
            "api.openai.com:443",
            "api.openai.com:443"
        ));
        assert!(no_proxy_entry_matches_route(
            ".openai.com",
            "api.openai.com:443"
        ));
        assert!(
            no_proxy_entry_matches_route("openai.com", "api.openai.com:443"),
            "bare multi-label NO_PROXY entries are interpreted as suffix bypasses by common clients"
        );
        assert!(!no_proxy_entry_matches_route(
            "api.anthropic.com:443",
            "api.openai.com:443"
        ));
        assert!(no_proxy_entry_matches_route("::1", "[::1]:8080"));
        assert!(no_proxy_entry_matches_route("[::1]", "[::1]:8080"));
        assert!(no_proxy_entry_matches_route("[::1]:8080", "[::1]:8080"));
    }

    #[tokio::test]
    async fn test_profile_no_proxy_rejects_allowed_host_conflicts() -> Result<()> {
        for (allowed_host, no_proxy_entry) in [
            ("api.internal.corp", ".internal.corp"),
            ("*.internal.corp", ".api.internal.corp"),
            ("redis", "redis"),
        ] {
            let config = ProxyConfig {
                allowed_hosts: vec![allowed_host.to_string()],
                no_proxy: vec![no_proxy_entry.to_string()],
                ..Default::default()
            };

            let err = start(config).await.err().ok_or_else(|| {
                ProxyError::Config(format!(
                    "no_proxy entry {no_proxy_entry:?} should conflict with allowed_host {allowed_host:?}"
                ))
            })?;

            assert!(
                err.to_string().contains("conflicts with allowed_host"),
                "expected allowed_host/no_proxy conflict error, got {err}"
            );
        }
        Ok(())
    }

    #[test]
    fn test_no_proxy_route_matching_detects_wildcard_route_overlap() {
        assert!(no_proxy_entry_matches_route(
            "api.admin.dev.example.net",
            "*.dev.example.net:443"
        ));
        assert!(no_proxy_entry_matches_route(
            "admin.dev.example.net",
            "*.dev.example.net:443"
        ));
        assert!(no_proxy_entry_matches_route(
            "dev.example.net",
            "*.dev.example.net:443"
        ));
        assert!(no_proxy_entry_matches_route(
            "example.net",
            "*.dev.example.net:443"
        ));
        assert!(no_proxy_entry_matches_route(
            "*.example.net",
            "*.dev.example.net:443"
        ));
        assert!(no_proxy_entry_matches_route(
            ".admin.dev.example.net",
            "*.dev.example.net:443"
        ));
        assert!(!no_proxy_entry_matches_route(
            "api.other.example.net",
            "*.dev.example.net:443"
        ));
        assert!(!no_proxy_entry_matches_route(
            "evildev.example.net",
            "*.dev.example.net:443"
        ));
    }

    #[test]
    fn test_no_proxy_route_matching_fails_closed_for_unparseable_routes() {
        for route_host in [
            "api.openai.com",
            ":443",
            "api.openai.com:notaport",
            "[::1",
            "[::1]:notaport",
            "*.dev.example.net:notaport",
        ] {
            assert!(
                no_proxy_entry_matches_route("redis", route_host),
                "unparseable route host {route_host:?} must block profile no_proxy bypass"
            );
        }
    }

    #[test]
    fn test_smart_no_proxy_entry_filters_ambiguous_bare_domains() -> Result<()> {
        assert_eq!(smart_no_proxy_entry("github.com"), None);
        assert_eq!(smart_no_proxy_entry("api.github.com:443"), None);
        assert_eq!(smart_no_proxy_entry("redis"), Some("redis".to_string()));
        assert_eq!(
            smart_no_proxy_entry("127.0.0.1"),
            Some("127.0.0.1".to_string())
        );
        assert_eq!(smart_no_proxy_entry("[::1]:443"), Some("::1".to_string()));
        assert_eq!(smart_no_proxy_entry("*.internal.example:443"), None);
        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    #[tokio::test]
    async fn test_smart_no_proxy_excludes_route_upstreams() -> Result<()> {
        let config = ProxyConfig {
            allowed_hosts: vec!["api.openai.com".to_string()],
            direct_connect_ports: vec![443],
            routes: vec![crate::config::RouteConfig {
                redeem_phantoms: Vec::new(),
                prefix: "openai".to_string(),
                upstream: "https://api.openai.com/v1".to_string(),
                credential_key: Some("openai".to_string()),
                inject_mode: crate::config::InjectMode::Header,
                inject_header: "Authorization".to_string(),
                credential_format: None,
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                proxy: None,
                env_var: None,
                endpoint_rules: Vec::new(),
                endpoint_policy: None,
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
                aws_auth: None,
                spiffe: None,
                upgrades: vec![],
            }],
            ..Default::default()
        };
        let handle = start(config).await?;

        let vars = handle.env_vars();
        let no_proxy = env_value(&vars, "NO_PROXY")?;
        let no_proxy_entries: std::collections::HashSet<&str> = no_proxy.split(',').collect();

        assert!(
            !no_proxy_entries.contains("api.openai.com"),
            "derived direct-connect bypass must not bypass credential route upstreams"
        );

        handle.shutdown();
        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    #[tokio::test]
    async fn test_smart_no_proxy_excludes_bare_parent_of_route_upstream() -> Result<()> {
        let config = ProxyConfig {
            allowed_hosts: vec!["openai.com".to_string()],
            direct_connect_ports: vec![443],
            routes: vec![crate::config::RouteConfig {
                redeem_phantoms: Vec::new(),
                prefix: "openai".to_string(),
                upstream: "https://api.openai.com/v1".to_string(),
                credential_key: Some("openai".to_string()),
                inject_mode: crate::config::InjectMode::Header,
                inject_header: "Authorization".to_string(),
                credential_format: None,
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                proxy: None,
                env_var: None,
                endpoint_rules: Vec::new(),
                endpoint_policy: None,
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
                aws_auth: None,
                spiffe: None,
                upgrades: vec![],
            }],
            ..Default::default()
        };
        let handle = start(config).await?;

        let vars = handle.env_vars();
        let no_proxy = env_value(&vars, "NO_PROXY")?;
        let no_proxy_entries: std::collections::HashSet<&str> = no_proxy.split(',').collect();

        assert!(
            !no_proxy_entries.contains("openai.com"),
            "derived direct-connect bypass must not emit a bare parent domain that can bypass api.openai.com routes"
        );

        handle.shutdown();
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_profile_no_proxy_is_emitted_on_macos_proxy_only() -> Result<()> {
        let config = ProxyConfig {
            no_proxy: vec!["redis".to_string()],
            ..Default::default()
        };
        let handle = start(config).await?;

        let vars = handle.env_vars();
        let no_proxy = env_value(&vars, "NO_PROXY")?;

        assert_eq!(
            no_proxy, "localhost,127.0.0.1,redis",
            "explicit profile no_proxy entries should be emitted on macOS; Seatbelt still gates direct access"
        );

        handle.shutdown();
        Ok(())
    }

    #[tokio::test]
    async fn test_profile_no_proxy_rejects_route_upstream_patterns() -> Result<()> {
        let config = ProxyConfig {
            no_proxy: vec![
                "*.openai.com".to_string(),
                ".openai.com".to_string(),
                ".anthropic.com".to_string(),
                "redis".to_string(),
            ],
            routes: vec![crate::config::RouteConfig {
                redeem_phantoms: Vec::new(),
                prefix: "openai".to_string(),
                upstream: "https://api.openai.com/v1".to_string(),
                credential_key: Some("openai".to_string()),
                inject_mode: crate::config::InjectMode::Header,
                inject_header: "Authorization".to_string(),
                credential_format: None,
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                proxy: None,
                env_var: None,
                endpoint_rules: Vec::new(),
                endpoint_policy: None,
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
                aws_auth: None,
                spiffe: None,
                upgrades: vec![],
            }],
            ..Default::default()
        };
        let message = start_config_error(config).await?;

        assert!(message.contains("no_proxy entry '*.openai.com' conflicts with route upstream"));
        assert!(message.contains("api.openai.com:443"));
        Ok(())
    }

    #[tokio::test]
    async fn test_profile_no_proxy_rejects_ipv6_route_upstream_patterns() -> Result<()> {
        let config = ProxyConfig {
            no_proxy: vec![
                "0:0:0:0:0:0:0:1".to_string(),
                "[0:0:0:0:0:0:0:1]".to_string(),
                "redis".to_string(),
            ],
            routes: vec![crate::config::RouteConfig {
                redeem_phantoms: Vec::new(),
                prefix: "local".to_string(),
                upstream: "http://[::1]:8080/v1".to_string(),
                credential_key: Some("local".to_string()),
                inject_mode: crate::config::InjectMode::Header,
                inject_header: "Authorization".to_string(),
                credential_format: None,
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                proxy: None,
                env_var: None,
                endpoint_rules: Vec::new(),
                endpoint_policy: None,
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
                aws_auth: None,
                spiffe: None,
                upgrades: vec![],
            }],
            ..Default::default()
        };
        let message = start_config_error(config).await?;

        assert!(message.contains("no_proxy entry '0:0:0:0:0:0:0:1' conflicts with route upstream"));
        assert!(message.contains("[::1]:8080"));
        Ok(())
    }

    #[tokio::test]
    async fn test_profile_no_proxy_rejects_wildcard_route_upstream_overlap() -> Result<()> {
        let config = ProxyConfig {
            no_proxy: vec![
                "*.example.net".to_string(),
                ".admin.dev.example.net".to_string(),
                ".dev.example.net".to_string(),
                ".example.net".to_string(),
                "redis".to_string(),
            ],
            routes: vec![crate::config::RouteConfig {
                redeem_phantoms: Vec::new(),
                prefix: "internal".to_string(),
                upstream: "https://*.dev.example.net".to_string(),
                credential_key: Some("internal".to_string()),
                inject_mode: crate::config::InjectMode::Header,
                inject_header: "Authorization".to_string(),
                credential_format: None,
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                proxy: None,
                env_var: None,
                endpoint_rules: Vec::new(),
                endpoint_policy: None,
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
                aws_auth: None,
                spiffe: None,
                upgrades: vec![],
            }],
            ..Default::default()
        };
        let message = start_config_error(config).await?;
        assert!(message.contains("no_proxy entry '*.example.net' conflicts with route upstream"));
        assert!(message.contains("*.dev.example.net:443"));
        Ok(())
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
    async fn test_smart_no_proxy_filters_ambiguous_bare_domains() -> Result<()> {
        // Smart-derived NO_PROXY keeps unambiguous single-label/IP direct
        // grants, but must not emit bare multi-label DNS names because common
        // clients interpret them as suffix bypasses.
        let config = ProxyConfig {
            allowed_hosts: vec![
                "github.com".to_string(),
                "API.OPENAI.COM".to_string(),
                "*.googleapis.com".to_string(),
                "redis".to_string(),
                "127.0.0.1".to_string(),
                "[::1]".to_string(),
                "169.254.169.254".to_string(),
                "server.internal:4222".to_string(),
            ],
            direct_connect_ports: vec![443],
            ..Default::default()
        };
        let handle = start(config).await?;

        let vars = handle.env_vars();
        let no_proxy = env_value(&vars, "NO_PROXY")?;
        assert!(
            !no_proxy.contains("github.com"),
            "bare multi-label host must not be emitted as smart NO_PROXY"
        );
        assert!(
            !no_proxy.contains("API.OPENAI.COM") && !no_proxy.contains("api.openai.com"),
            "uppercase bare multi-label host must not bypass smart NO_PROXY filtering"
        );
        assert!(
            !no_proxy.contains(".googleapis.com") && !no_proxy.contains("googleapis.com"),
            "wildcard allowlist entries must not be broadened into suffix NO_PROXY bypasses"
        );
        assert!(
            no_proxy.contains("redis"),
            "single-label alias should remain eligible for smart NO_PROXY"
        );
        assert!(
            no_proxy.contains("127.0.0.1"),
            "IP literals should remain eligible for smart NO_PROXY"
        );
        assert!(
            no_proxy.contains("::1") && !no_proxy.contains("[::1]"),
            "bracketed IPv6 smart NO_PROXY entries should emit portable unbracketed literals"
        );
        assert!(
            !no_proxy.contains("169.254.169.254"),
            "link-local metadata IPs must not be emitted as smart NO_PROXY"
        );
        assert!(
            !no_proxy.contains("server.internal"),
            "host on port 4222 should NOT be in NO_PROXY when only 443 is allowed"
        );

        handle.shutdown();
        Ok(())
    }

    #[tokio::test]
    async fn test_profile_no_proxy_rejects_link_local_and_metadata_bypass_entries() {
        for entry in [
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
        ] {
            let config = ProxyConfig {
                no_proxy: vec![entry.to_string()],
                ..Default::default()
            };

            let result = start(config).await;

            assert!(
                result.is_err(),
                "profile no_proxy entry {entry:?} must not bypass proxy deny invariants"
            );
        }
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
                redeem_phantoms: Vec::new(),
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
                endpoint_policy: None,
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
                aws_auth: None,
                spiffe: None,
                upgrades: vec![],
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

    /// Regression for #1062: a denied absolute-form `http://` request must
    /// return 403 (not 400) and produce a deny audit event.
    ///
    /// Since #1334, absolute-form `http://` requests are handled by the
    /// forward-proxy path (`handle_forward_http`), which audits denials under
    /// `Reverse` mode rather than the old inline `Connect` mode. The 403
    /// status, target, and port are unchanged.
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
        let token = handle.token.to_string();

        let mut stream = TcpStream::connect(&addr).await.unwrap();
        // Include valid proxy auth so the request reaches the host filter
        // (rather than being rejected at the auth gate).
        let creds = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(format!("nono:{}", token))
        };
        let request = format!(
            "GET http://google.com/ HTTP/1.1\r\nHost: google.com\r\nProxy-Authorization: Basic {}\r\n\r\n",
            creds
        );
        tokio::io::AsyncWriteExt::write_all(&mut stream, request.as_bytes())
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
        assert_eq!(event.mode, nono::undo::NetworkAuditMode::Reverse);
        assert_eq!(event.decision, nono::undo::NetworkAuditDecision::Deny);
        assert_eq!(event.target, "google.com");
        assert_eq!(event.port, Some(80));

        handle.shutdown();
    }

    // ========================================================================
    // Forward-proxy (absolute-form http://) tests — issue #1334
    // ========================================================================

    #[test]
    fn classify_request_target_detects_absolute_and_origin_forms() {
        assert_eq!(
            classify_request_target("GET http://example.com/path HTTP/1.1"),
            RequestTargetForm::AbsoluteHttp
        );
        // Scheme match is case-insensitive.
        assert_eq!(
            classify_request_target("GET HTTP://example.com/ HTTP/1.1"),
            RequestTargetForm::AbsoluteHttp
        );
        assert_eq!(
            classify_request_target("CONNECT https://example.com/ HTTP/1.1"),
            RequestTargetForm::AbsoluteHttps
        );
        assert_eq!(
            classify_request_target("GET /openai/v1/chat HTTP/1.1"),
            RequestTargetForm::Origin
        );
        // Malformed / empty lines are treated as origin-form (unaffected).
        assert_eq!(classify_request_target("GET"), RequestTargetForm::Origin);
        assert_eq!(classify_request_target(""), RequestTargetForm::Origin);
    }

    #[test]
    fn rewrite_absolute_to_origin_form_produces_origin_line() {
        assert_eq!(
            rewrite_absolute_to_origin_form("GET http://host.example/p/q?a=1 HTTP/1.1").unwrap(),
            "GET /p/q?a=1 HTTP/1.1\r\n"
        );
        // Bare authority with no path becomes "/".
        assert_eq!(
            rewrite_absolute_to_origin_form("GET http://host.example HTTP/1.1").unwrap(),
            "GET / HTTP/1.1\r\n"
        );
        // Method and version are preserved verbatim.
        assert_eq!(
            rewrite_absolute_to_origin_form("POST http://host.example:8080/x HTTP/1.0").unwrap(),
            "POST /x HTTP/1.0\r\n"
        );
    }

    #[test]
    fn strip_proxy_headers_removes_proxy_hop_by_hop_only() {
        let headers = b"Host: example.com\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic abc\r\nAccept: */*\r\n";
        let stripped = strip_proxy_headers(headers);
        let s = String::from_utf8(stripped).unwrap();
        assert!(s.contains("Host: example.com"));
        assert!(s.contains("Accept: */*"));
        assert!(
            !s.to_lowercase().contains("proxy-connection"),
            "Proxy-Connection must be stripped, got: {s:?}"
        );
        assert!(
            !s.to_lowercase().contains("proxy-authorization"),
            "Proxy-Authorization must be stripped, got: {s:?}"
        );
    }

    /// Spawn a one-shot local HTTP/1.1 origin server that echoes the received
    /// request line back in the body and returns 200. Returns its address and
    /// a receiver that yields the raw request bytes it saw.
    async fn spawn_echo_origin() -> (std::net::SocketAddr, tokio::sync::oneshot::Receiver<String>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let received = String::from_utf8_lossy(&buf[..n]).to_string();
                let body = "ok";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.flush().await;
                let _ = tx.send(received);
            }
        });
        (addr, rx)
    }

    /// Absolute-form http:// to an ALLOWED host is forwarded and returns the
    /// upstream status. Also asserts the upstream saw an origin-form request
    /// line with the proxy headers stripped.
    #[tokio::test]
    async fn forward_http_allowed_host_is_forwarded() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let (origin_addr, origin_rx) = spawn_echo_origin().await;

        let config = ProxyConfig {
            allowed_hosts: vec!["127.0.0.1".to_string()],
            ..ProxyConfig::default()
        };
        let handle = start(config).await.unwrap();
        let token = handle.token.to_string();

        let mut stream = TcpStream::connect(("127.0.0.1", handle.port))
            .await
            .unwrap();
        let creds = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(format!("nono:{}", token))
        };
        let request = format!(
            "GET http://127.0.0.1:{}/hello?x=1 HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic {}\r\nAccept: */*\r\n\r\n",
            origin_addr.port(),
            origin_addr.port(),
            creds
        );
        stream.write_all(request.as_bytes()).await.unwrap();

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let response_str = String::from_utf8_lossy(&response);
        assert!(
            response_str.starts_with("HTTP/1.1 200"),
            "expected upstream 200 status, got: {}",
            response_str
        );

        // The upstream must have seen an origin-form request line with the
        // proxy headers stripped.
        let received = origin_rx.await.unwrap();
        assert!(
            received.starts_with("GET /hello?x=1 HTTP/1.1"),
            "upstream should see origin-form request line, got: {received:?}"
        );
        assert!(
            !received.to_lowercase().contains("proxy-connection"),
            "Proxy-Connection must not reach upstream: {received:?}"
        );
        assert!(
            !received.to_lowercase().contains("proxy-authorization"),
            "Proxy-Authorization must not reach upstream: {received:?}"
        );
        assert!(
            received.contains("Accept: */*"),
            "non-proxy headers must be preserved: {received:?}"
        );

        // An L7 audit event should have been recorded for the allowed request.
        let events = handle.drain_audit_events();
        assert!(
            events
                .iter()
                .any(|e| e.decision == nono::undo::NetworkAuditDecision::Allow
                    && e.target == "127.0.0.1"
                    && e.status == Some(200)),
            "expected an allow L7 audit event, got: {events:?}"
        );

        handle.shutdown();
    }

    /// The forward path is a TRANSPARENT proxy: it must never inject a managed
    /// credential, even when credential-injecting routes are configured.
    /// Credential injection is reserved for the reverse path (HTTPS or
    /// http-loopback upstreams).
    ///
    /// The configured route carries an UNRESOLVABLE credential key. If the
    /// forward path ever attempted injection it would fail credential
    /// resolution and return 503 (the reverse path's missing-credential
    /// behavior) — so a 200 with the client's own Authorization header intact
    /// proves the forward path bypasses routing/injection entirely. We also
    /// assert the audit event reports `managed_credential_active = false`.
    #[tokio::test]
    async fn forward_http_does_not_inject_managed_credential() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let (origin_addr, origin_rx) = spawn_echo_origin().await;

        // A credential-injecting route whose key cannot resolve. The forward
        // path must ignore it entirely rather than fail resolving it.
        let config = ProxyConfig {
            allowed_hosts: vec!["127.0.0.1".to_string()],
            routes: vec![crate::config::RouteConfig {
                redeem_phantoms: Vec::new(),
                prefix: "svc".to_string(),
                upstream: "https://api.example.com".to_string(),
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
                endpoint_policy: None,
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
                aws_auth: None,
                spiffe: None,
                upgrades: vec![],
            }],
            ..ProxyConfig::default()
        };
        let handle = start(config).await.unwrap();
        let token = handle.token.to_string();

        let mut stream = TcpStream::connect(("127.0.0.1", handle.port))
            .await
            .unwrap();
        let creds = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(format!("nono:{}", token))
        };
        // The client sends its own Authorization header. A transparent proxy
        // forwards it unchanged.
        let request = format!(
            "GET http://127.0.0.1:{}/data HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nProxy-Authorization: Basic {}\r\nAuthorization: Bearer client-token\r\n\r\n",
            origin_addr.port(),
            origin_addr.port(),
            creds
        );
        stream.write_all(request.as_bytes()).await.unwrap();

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let response_str = String::from_utf8_lossy(&response);
        // 200 (not 503) proves no credential resolution/injection was attempted.
        assert!(
            response_str.starts_with("HTTP/1.1 200"),
            "expected upstream 200 (no injection attempt), got: {}",
            response_str
        );

        let received = origin_rx.await.unwrap();
        // The client's own credential must survive verbatim, unmodified.
        assert!(
            received.contains("Authorization: Bearer client-token"),
            "client Authorization must be forwarded verbatim: {received:?}"
        );

        // The audit event must record that no managed credential was active.
        let events = handle.drain_audit_events();
        let l7 = events
            .iter()
            .find(|e| e.status == Some(200))
            .expect("expected an L7 audit event for the forwarded request");
        assert_eq!(
            l7.managed_credential_active,
            Some(false),
            "forward path must audit managed_credential_active=false: {l7:?}"
        );

        handle.shutdown();
    }

    /// Absolute-form http:// to a DENIED host returns 403 with an audit denial.
    #[tokio::test]
    async fn forward_http_denied_host_returns_403_and_audits() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        // Allowlist a different host so 127.0.0.1 is denied.
        let config = ProxyConfig {
            allowed_hosts: vec!["example.com".to_string()],
            ..ProxyConfig::default()
        };
        let handle = start(config).await.unwrap();
        let token = handle.token.to_string();

        let mut stream = TcpStream::connect(("127.0.0.1", handle.port))
            .await
            .unwrap();
        let creds = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(format!("nono:{}", token))
        };
        let request = format!(
            "GET http://denied.example.org/secret HTTP/1.1\r\nHost: denied.example.org\r\nProxy-Authorization: Basic {}\r\n\r\n",
            creds
        );
        stream.write_all(request.as_bytes()).await.unwrap();

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let response_str = String::from_utf8_lossy(&response);
        assert!(
            response_str.starts_with("HTTP/1.1 403"),
            "expected 403 for denied host, got: {}",
            response_str
        );

        let events = handle.drain_audit_events();
        assert!(
            events
                .iter()
                .any(|e| e.decision == nono::undo::NetworkAuditDecision::Deny
                    && e.target == "denied.example.org"
                    && e.denial_category
                        == Some(nono::undo::NetworkAuditDenialCategory::HostDenied)),
            "expected a HostDenied audit event, got: {events:?}"
        );

        handle.shutdown();
    }

    /// Absolute-form https:// is rejected with guidance to use CONNECT.
    #[tokio::test]
    async fn forward_https_absolute_form_is_rejected_with_connect_guidance() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let config = ProxyConfig {
            allowed_hosts: vec!["example.com".to_string()],
            ..ProxyConfig::default()
        };
        let handle = start(config).await.unwrap();

        let mut stream = TcpStream::connect(("127.0.0.1", handle.port))
            .await
            .unwrap();
        let request = b"GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
        stream.write_all(request).await.unwrap();

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let response_str = String::from_utf8_lossy(&response);
        assert!(
            response_str.starts_with("HTTP/1.1 400"),
            "expected 400 for absolute-form https, got: {}",
            response_str
        );
        assert!(
            response_str.to_lowercase().contains("connect"),
            "response should direct the client to use CONNECT, got: {}",
            response_str
        );

        handle.shutdown();
    }

    /// Missing/invalid Proxy-Authorization with the strict filter active is
    /// rejected with 407 (matching the reverse-proxy no-credential branch).
    #[tokio::test]
    async fn forward_http_missing_proxy_auth_is_rejected_407() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let config = ProxyConfig {
            allowed_hosts: vec!["127.0.0.1".to_string()],
            ..ProxyConfig::default()
        };
        let handle = start(config).await.unwrap();

        let mut stream = TcpStream::connect(("127.0.0.1", handle.port))
            .await
            .unwrap();
        // No Proxy-Authorization header at all.
        let request = b"GET http://127.0.0.1:9/hello HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n";
        stream.write_all(request).await.unwrap();

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let response_str = String::from_utf8_lossy(&response);
        assert!(
            response_str.starts_with("HTTP/1.1 407"),
            "expected 407 for missing proxy auth, got: {}",
            response_str
        );

        let events = handle.drain_audit_events();
        assert!(
            events
                .iter()
                .any(|e| e.decision == nono::undo::NetworkAuditDecision::Deny
                    && e.denial_category
                        == Some(nono::undo::NetworkAuditDenialCategory::AuthenticationFailed)),
            "expected an AuthenticationFailed audit event, got: {events:?}"
        );

        handle.shutdown();
    }

    /// Regression guard: origin-form requests with routes configured still
    /// route to the reverse proxy (unaffected by the forward-proxy dispatch).
    #[tokio::test]
    async fn origin_form_request_still_routes_to_reverse_proxy() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        // A route whose credential is missing -> reverse proxy returns 503
        // (managed credential unavailable). The point is that it reaches the
        // reverse handler at all, not the forward path.
        let config = ProxyConfig {
            routes: vec![crate::config::RouteConfig {
                redeem_phantoms: Vec::new(),
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
                endpoint_policy: None,
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
                aws_auth: None,
                spiffe: None,
                upgrades: vec![],
            }],
            ..Default::default()
        };
        let handle = start(config).await.unwrap();

        let mut stream = TcpStream::connect(("127.0.0.1", handle.port))
            .await
            .unwrap();
        let request = b"GET /openai/v1/models HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer whatever\r\n\r\n";
        stream.write_all(request).await.unwrap();

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let response_str = String::from_utf8_lossy(&response);
        // The reverse handler answers 503 for a route with a missing managed
        // credential. Any structured HTTP answer (not a dropped socket / 502
        // forward failure) proves the reverse path handled it.
        assert!(
            response_str.starts_with("HTTP/1.1 503"),
            "origin-form request must reach the reverse proxy (503 for missing \
             credential), got: {}",
            response_str
        );

        let events = handle.drain_audit_events();
        assert!(
            events
                .iter()
                .any(|e| e.mode == nono::undo::NetworkAuditMode::Reverse),
            "expected a Reverse-mode audit event, got: {events:?}"
        );

        handle.shutdown();
    }
}
