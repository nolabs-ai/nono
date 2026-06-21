use std::time::Duration;

use crate::cli::SandboxArgs;
use crate::launch_runtime::{
    CredentialProxyIntent, DomainFilterIntent, EndpointFilterIntent, OpenUrlIntent,
    ProxyLaunchOptions, TlsInterceptIntent, UpstreamProxyIntent,
};
use crate::network_approval::{NetworkApprovalBackend, NetworkApprovalMode};
use crate::network_policy;
use crate::sandbox_prepare::{PreparedSandbox, validate_external_proxy_bypass};
#[cfg(not(target_os = "macos"))]
use nono::AccessMode;
use nono::{CapabilitySet, HostFilter, NonoError, Result, RuntimeHostFilter};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

pub(crate) struct ActiveProxyRuntime {
    pub(crate) env_vars: Vec<(String, String)>,
    pub(crate) handle: Option<nono_proxy::server::ProxyHandle>,
    pub(crate) approval_backend: Option<std::sync::Arc<NetworkApprovalBackend>>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct EffectiveProxySettings {
    pub(crate) network_profile: Option<String>,
    pub(crate) allow_domain: Vec<crate::profile::AllowDomainEntry>,
    pub(crate) reject_domain: Vec<String>,
    pub(crate) credentials: Vec<String>,
}

pub(crate) fn prepare_proxy_launch_options(
    args: &SandboxArgs,
    prepared: &PreparedSandbox,
    silent: bool,
) -> Result<ProxyLaunchOptions> {
    validate_external_proxy_bypass(args, prepared)?;

    let effective_proxy = resolve_effective_proxy_settings(args, prepared);
    let network_profile = effective_proxy.network_profile;
    let allow_domain = effective_proxy.allow_domain;
    let reject_domain = effective_proxy.reject_domain;
    let credentials = effective_proxy.credentials;
    let allow_bind_ports = merge_dedup_ports(&prepared.listen_ports, &args.allow_bind);

    let upstream_proxy_addr = if args.allow_net {
        None
    } else {
        args.external_proxy
            .clone()
            .or_else(|| prepared.upstream_proxy.clone())
    };

    let upstream_bypass = if args.allow_net {
        Vec::new()
    } else if args.external_proxy.is_some() {
        args.external_proxy_bypass.clone()
    } else {
        let mut bypass = prepared.upstream_bypass.clone();
        bypass.extend(args.external_proxy_bypass.clone());
        bypass
    };

    let has_domain_filter = network_profile.is_some() || !allow_domain.is_empty();
    let has_credentials = !credentials.is_empty();
    let would_activate = has_domain_filter || has_credentials || upstream_proxy_addr.is_some();

    if matches!(prepared.caps.network_mode(), nono::NetworkMode::Blocked) {
        if would_activate {
            warn!(
                "--block-net is active; ignoring proxy configuration \
                 that would re-enable network access"
            );
            if !silent {
                eprintln!(
                    "  [nono] Warning: --block-net overrides proxy/credential settings. \
                     Network remains fully blocked."
                );
            }
        }
        return Ok(ProxyLaunchOptions {
            allow_bind_ports,
            network_block: prepared.network_block_requested,
            ..ProxyLaunchOptions::default()
        });
    }

    let (plain_entries, endpoint_entries): (Vec<_>, Vec<_>) = allow_domain
        .into_iter()
        .partition(|e| !matches!(e, crate::profile::AllowDomainEntry::WithEndpoints { endpoints, .. } if !endpoints.is_empty()));

    let domain_filter = if network_profile.is_some() || !plain_entries.is_empty() {
        Some(DomainFilterIntent {
            network_profile,
            allow_domain: plain_entries,
            reject_domain,
        })
    } else {
        None
    };

    let approval_mode =
        resolve_network_approval_mode(args, prepared.profile_network_approval_mode.as_deref());

    let endpoint_filter = if !endpoint_entries.is_empty() {
        debug_assert!(
            endpoint_entries
                .iter()
                .all(|e| matches!(e, crate::profile::AllowDomainEntry::WithEndpoints { endpoints, .. } if !endpoints.is_empty())),
            "EndpointFilterIntent invariant violated: all entries must have non-empty endpoints"
        );
        Some(EndpointFilterIntent {
            routes: endpoint_entries,
        })
    } else {
        None
    };

    let credentials_intent = if has_credentials || !prepared.custom_credentials.is_empty() {
        Some(CredentialProxyIntent {
            credentials,
            custom_credentials: prepared.custom_credentials.clone(),
        })
    } else {
        None
    };

    let upstream_proxy = upstream_proxy_addr.map(|address| UpstreamProxyIntent {
        address,
        bypass: upstream_bypass,
    });

    let proxy_ca_validity = args
        .proxy_ca_validity
        .map(|days| std::time::Duration::from_secs(u64::from(days) * 24 * 60 * 60));

    #[cfg(target_os = "macos")]
    let tls_intercept = if args.trust_proxy_ca || proxy_ca_validity.is_some() {
        Some(TlsInterceptIntent {
            trust_proxy_ca: args.trust_proxy_ca,
            ca_validity: proxy_ca_validity,
        })
    } else {
        None
    };
    #[cfg(not(target_os = "macos"))]
    let tls_intercept = if proxy_ca_validity.is_some() {
        Some(TlsInterceptIntent {
            ca_validity: proxy_ca_validity,
        })
    } else {
        None
    };

    let open_url = if !prepared.open_url_origins.is_empty()
        || prepared.open_url_allow_localhost
        || prepared.allow_launch_services_active
    {
        Some(OpenUrlIntent {
            origins: prepared.open_url_origins.clone(),
            allow_localhost: prepared.open_url_allow_localhost,
            allow_launch_services: prepared.allow_launch_services_active,
        })
    } else {
        None
    };

    let approval_mode =
        resolve_network_approval_mode(args, prepared.profile_network_approval_mode.as_deref());

    let opts = ProxyLaunchOptions {
        domain_filter,
        endpoint_filter,
        credentials: credentials_intent,
        upstream_proxy,
        tls_intercept,
        open_url,
        allow_bind_ports,
        proxy_port: args.proxy_port,
        network_approval_mode: approval_mode,
        network_approval_timeout_secs: resolve_approval_timeout_secs(
            prepared.profile_network_approval_timeout_secs,
        ),
        profile_name: args.profile.clone(),
        network_block: prepared.network_block_requested,
        network_approval_mode: approval_mode,
        network_approval_timeout_secs: resolve_approval_timeout_secs(
            prepared.profile_network_approval_timeout_secs,
        ),
        profile_name: args.profile.clone(),
    };

    // Infra-only flags make no sense without an activating proxy feature.
    if !opts.is_active() {
        if opts.tls_intercept.is_some() {
            return Err(NonoError::ConfigParse(
                "--trust-proxy-ca / --proxy-ca-validity require a proxy feature \
                 (--allow-domain, --credential, or --upstream-proxy)"
                    .to_string(),
            ));
        }
        if args.proxy_port.is_some() {
            return Err(NonoError::ConfigParse(
                "--proxy-port requires a proxy feature (--allow-domain, --credential, \
                 or --upstream-proxy)"
                    .to_string(),
            ));
        }
    }

    Ok(opts)
}

pub(crate) fn resolve_effective_proxy_settings(
    args: &SandboxArgs,
    prepared: &PreparedSandbox,
) -> EffectiveProxySettings {
    if args.allow_net {
        return EffectiveProxySettings {
            network_profile: None,
            allow_domain: Vec::new(),
            reject_domain: Vec::new(),
            credentials: Vec::new(),
        };
    }

    let network_profile = args
        .network_profile
        .clone()
        .or_else(|| prepared.network_profile.clone());
    let mut allow_domain = prepared.allow_domain.clone();
    allow_domain.extend(args.allow_proxy.iter().map(|s| parse_allow_domain_arg(s)));
    let reject_domain = prepared.reject_domain.clone();
    let mut credentials = prepared.credentials.clone();
    credentials.extend(args.proxy_credential.clone());

    EffectiveProxySettings {
        network_profile,
        allow_domain,
        reject_domain,
        credentials,
    }
}

/// Parse a `--allow-domain` CLI argument into an `AllowDomainEntry`.
///
/// Accepts either:
/// - A plain hostname: `github.com` → `Plain("github.com")`
/// - A URL with a path pattern: `https://github.com/atko-cic/**` →
///   `WithEndpoints { domain: "github.com", endpoints: [{method: "*", path: "/atko-cic/**"}] }`
fn parse_allow_domain_arg(input: &str) -> crate::profile::AllowDomainEntry {
    if let Ok(parsed) = url::Url::parse(input) {
        let domain = parsed.host_str().unwrap_or(input).to_string();
        let path = parsed.path();
        if path.is_empty() || path == "/" {
            crate::profile::AllowDomainEntry::Plain(domain)
        } else {
            crate::profile::AllowDomainEntry::WithEndpoints {
                domain,
                endpoints: vec![nono_proxy::config::EndpointRule {
                    method: "*".to_string(),
                    path: path.to_string(),
                }],
            }
        }
    } else {
        crate::profile::AllowDomainEntry::Plain(input.to_string())
    }
}

pub(crate) fn merge_dedup_ports(a: &[u16], b: &[u16]) -> Vec<u16> {
    let mut ports = a.to_vec();
    ports.extend_from_slice(b);
    ports.sort_unstable();
    ports.dedup();
    ports
}

fn resolve_network_approval_mode(
    args: &SandboxArgs,
    profile_approval_mode: Option<&str>,
) -> NetworkApprovalMode {
    use crate::cli::NetworkApprovalArg;

    if let Some(ref mode) = args.network_approval {
        match mode {
            NetworkApprovalArg::Ask => NetworkApprovalMode::Ask,
        }
    } else if let Ok(val) = std::env::var("NONO_NETWORK_APPROVAL") {
        match val.to_lowercase().as_str() {
            "ask" => NetworkApprovalMode::Ask,
            _ => NetworkApprovalMode::Off,
        }
    } else if let Some(mode) = profile_approval_mode {
        match mode.to_lowercase().as_str() {
            "ask" => NetworkApprovalMode::Ask,
            _ => NetworkApprovalMode::Off,
        }
    } else if let Ok(Some(config)) = crate::config::user::load_user_config() {
        match config
            .network
            .approval_mode
            .as_deref()
            .unwrap_or("off")
            .to_lowercase()
            .as_str()
        {
            "ask" => NetworkApprovalMode::Ask,
            _ => NetworkApprovalMode::Off,
        }
    } else {
        NetworkApprovalMode::Off
    }
}

fn resolve_approval_timeout_secs(profile_timeout: Option<u64>) -> u64 {
    if let Ok(val) = std::env::var("NONO_NETWORK_APPROVAL_TIMEOUT") {
        if let Ok(secs) = val.parse::<u64>() {
            return secs.clamp(5, 300);
        }
    }
    if let Some(secs) = profile_timeout {
        return secs.clamp(5, 300);
    }
    if let Ok(Some(config)) = crate::config::user::load_user_config() {
        if let Some(secs) = config.network.approval_timeout_secs {
            return secs.clamp(5, 300);
        }
    }
    60
}

pub(crate) fn build_proxy_config_from_flags(
    proxy: &ProxyLaunchOptions,
) -> Result<nono_proxy::config::ProxyConfig> {
    let net_policy_json = crate::config::embedded::embedded_network_policy_json();
    let net_policy = network_policy::load_network_policy(net_policy_json)?;

    let mut resolved = if let Some(profile_name) = proxy
        .domain_filter
        .as_ref()
        .and_then(|d| d.network_profile.as_ref())
    {
        network_policy::resolve_network_profile(&net_policy, profile_name)?
    } else {
        network_policy::ResolvedNetworkPolicy {
            hosts: Vec::new(),
            suffixes: Vec::new(),
            routes: Vec::new(),
            profile_credentials: Vec::new(),
        }
    };

    let mut all_credentials = resolved.profile_credentials.clone();
    if let Some(ref creds) = proxy.credentials {
        for cred in &creds.credentials {
            if !all_credentials.contains(cred) {
                all_credentials.push(cred.clone());
            }
        }
    }

    let empty_custom_credentials = std::collections::HashMap::new();
    let custom_credentials = proxy
        .credentials
        .as_ref()
        .map(|c| &c.custom_credentials)
        .unwrap_or(&empty_custom_credentials);

    let mut routes =
        network_policy::resolve_credentials(&net_policy, &all_credentials, custom_credentials)?;

    let plain_allow_domain = proxy
        .domain_filter
        .as_ref()
        .map(|d| d.allow_domain.as_slice())
        .unwrap_or(&[]);
    let (mut plain_hosts, _) =
        network_policy::partition_allow_domain(&net_policy, plain_allow_domain)?;

    let endpoint_allow_domain = proxy
        .endpoint_filter
        .as_ref()
        .map(|e| e.routes.as_slice())
        .unwrap_or(&[]);
    let (_, endpoint_routes) =
        network_policy::partition_allow_domain(&net_policy, endpoint_allow_domain)?;
    // Endpoint-restricted domains need filter allowlist access so the proxy
    // can reach upstream after TLS interception (h2 checks the filter at
    // connection setup, before per-stream route matching).
    for route in &endpoint_routes {
        if let Some(hp) = route.upstream.strip_prefix("https://") {
            plain_hosts.push(hp.to_string());
        } else if let Some(hp) = route.upstream.strip_prefix("http://") {
            plain_hosts.push(hp.to_string());
        }
    }
    routes.extend(endpoint_routes);
    resolved.routes = routes;

    let allow_domain_flat: Vec<String> = plain_allow_domain
        .iter()
        .chain(endpoint_allow_domain.iter())
        .map(|e| e.domain().to_string())
        .collect();
    let expanded_allow_domain =
        network_policy::expand_proxy_allow(&net_policy, &allow_domain_flat);
    let reject_domain = proxy
        .domain_filter
        .as_ref()
        .map(|d| d.reject_domain.as_slice())
        .unwrap_or(&[]);
    let mut proxy_config =
        network_policy::build_proxy_config(&resolved, &expanded_allow_domain, reject_domain);
    proxy_config.strict_filter = proxy.network_block;
    if let Some(ref domain_filter) = proxy.domain_filter {
        if !domain_filter.reject_domain.is_empty() {
            proxy_config.rejected_hosts = domain_filter.reject_domain.clone();
        }
    }

    if let Some(ref upstream) = proxy.upstream_proxy {
        proxy_config.external_proxy = Some(nono_proxy::config::ExternalProxyConfig {
            address: upstream.address.clone(),
            auth: None,
            bypass_hosts: upstream.bypass.clone(),
        });
    }

    if let Some(port) = proxy.proxy_port {
        proxy_config.bind_port = port;
    }

    proxy_config.ca_validity = proxy.tls_intercept.as_ref().and_then(|t| t.ca_validity);

    Ok(proxy_config)
}

pub(crate) fn start_proxy_runtime(
    proxy: &ProxyLaunchOptions,
    caps: &mut CapabilitySet,
) -> Result<ActiveProxyRuntime> {
    if !proxy.is_active() {
        return Ok(ActiveProxyRuntime {
            env_vars: Vec::new(),
            handle: None,
            approval_backend: None,
        });
    }

    let mut proxy_config = build_proxy_config_from_flags(proxy)?;
    proxy_config.direct_connect_ports = caps.tcp_connect_ports().to_vec();

    // Wire up TLS interception: pick a session-scoped directory for the
    // ephemeral CA bundle and merge any parent `SSL_CERT_FILE` so corporate
    // trust survives our env-var override.
    if let Some(dir) = prepare_intercept_ca_dir()? {
        proxy_config.intercept_ca_dir = Some(dir);
        proxy_config.intercept_parent_ca_pems = read_parent_ssl_cert_file();
    }

    #[cfg(target_os = "macos")]
    if proxy
        .tls_intercept
        .as_ref()
        .is_some_and(|t| t.trust_proxy_ca)
    {
        if proxy_config.intercept_ca_dir.is_some() {
            let validity = proxy
                .tls_intercept
                .as_ref()
                .and_then(|t| t.ca_validity)
                .unwrap_or(nono_proxy::tls_intercept::ca::CA_VALIDITY_DEFAULT);
            proxy_config.preloaded_ca = crate::macos_trust::load_or_generate_proxy_ca(validity);
        } else {
            tracing::warn!(
                "--trust-proxy-ca has no effect without TLS-intercepting credential routes"
            );
        }
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| NonoError::SandboxInit(format!("Failed to start proxy runtime: {}", e)))?;

    let (approval_backend, approval_tx, runtime_filter) = match proxy.network_approval_mode {
        NetworkApprovalMode::Off => (None, None, None),
        NetworkApprovalMode::Ask => {
            let host_filter = HostFilter::deny_all();
            let runtime_filter = RuntimeHostFilter::new(host_filter);
            let proxy_runtime_filter =
                nono_proxy::filter::RuntimeProxyFilter::new(runtime_filter.clone());

            let (tx, mut rx) = tokio::sync::mpsc::channel::<nono_proxy::ApprovalChannelRequest>(16);

            let config_writer = match proxy.profile_name.as_deref() {
                Some(name) => Some(crate::network_approval::ConfigWriter::new(name)),
                None => Some(crate::network_approval::ConfigWriter::new("default")),
            };

            let backend = NetworkApprovalBackend::new(
                proxy.network_approval_mode,
                runtime_filter,
                proxy.network_approval_timeout_secs,
                config_writer,
            );
            let backend_arc = std::sync::Arc::new(backend);

            let backend_clone = std::sync::Arc::clone(&backend_arc);
            rt.spawn(async move {
                while let Some(req) = rx.recv().await {
                    let decision = backend_clone
                        .request_network_approval_async(&req.request)
                        .await;
                    let _ = req.response_tx.send(decision);
                }
            });

            (Some(backend_arc), Some(tx), Some(proxy_runtime_filter))
        }
    };

    let handle = rt
        .block_on(async {
            nono_proxy::server::start_with_approval(
                proxy_config.clone(),
                runtime_filter,
                approval_tx,
                std::process::id(),
                &format!("nono-{}", std::process::id()),
                Duration::from_secs(proxy.network_approval_timeout_secs),
            )
            .await
        })
        .map_err(|e| NonoError::SandboxInit(format!("Failed to start proxy: {}", e)))?;

    let port = handle.port;
    if proxy.allow_bind_ports.is_empty() {
        info!("Network proxy started on localhost:{}", port);
    } else {
        info!(
            "Network proxy started on localhost:{}, bind ports: {:?}",
            port, proxy.allow_bind_ports
        );
    }

    // Per-route diagnostic banner. Lifts credential resolution status —
    // including misses — to the user-visible info level so the silent
    // "WARN at debug" failure mode (issue #797) becomes immediately
    // discoverable.
    let route_rows = handle.route_diagnostics(&proxy_config);
    if !route_rows.is_empty() {
        info!("Proxy routes:");
        for (prefix, summary) in &route_rows {
            info!("  /{}  {}", prefix, summary);
        }
        if handle.intercept_ca_path().is_some() {
            info!(
                "TLS interception trust bundle: {}",
                handle
                    .intercept_ca_path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default()
            );
        }
    }

    let proxy_diagnostics = handle.diagnostics();
    if !proxy_diagnostics.is_empty() {
        crate::output::print_proxy_diagnostics(proxy_diagnostics);
    }
    caps.set_network_mode_mut(nono::NetworkMode::ProxyOnly {
        port,
        bind_ports: proxy.allow_bind_ports.clone(),
    });

    // Grant the sandboxed child a read capability on the ephemeral
    // trust bundle so `SSL_CERT_FILE` etc. are actually openable after
    // the sandbox is applied. Only when interception is active.
    //
    // The bundle lives under `~/.nono/sessions/...`, which the protected-root
    // deny rules (`emit_protected_root_deny_rules`) cover with
    // `(deny file-read-data (subpath "~/.nono"))`. On macOS, action specificity
    // beats path specificity in Seatbelt: a `file-read*` allow on a literal
    // path is shadowed by an action-specific `file-read-data` deny on a
    // containing subpath. To override, emit action-matching `file-read-data`
    // and `file-read-metadata` allows as platform rules, which are appended
    // after the deny and win by both action specificity and last-match.
    //
    // On Linux, Landlock cannot express deny-within-allow, so the protected-
    // root rules don't shadow the grant; a plain FS cap is sufficient.
    if let Some(ca_path) = handle.intercept_ca_path() {
        #[cfg(target_os = "macos")]
        {
            let path_str = crate::policy::path_to_utf8(ca_path)?;
            let escaped = crate::policy::escape_seatbelt_path(path_str)?;
            caps.add_platform_rule(format!("(allow file-read-data (literal \"{}\"))", escaped))?;
            caps.add_platform_rule(format!(
                "(allow file-read-metadata (literal \"{}\"))",
                escaped
            ))?;
        }
        #[cfg(not(target_os = "macos"))]
        {
            caps.allow_file_mut(ca_path, AccessMode::Read)
                .map_err(|e| {
                    NonoError::SandboxInit(format!(
                        "Failed to grant read capability on TLS-intercept bundle '{}': {}",
                        ca_path.display(),
                        e
                    ))
                })?;
        }
        debug!(
            "Granted sandboxed child read access to TLS-intercept trust bundle: {}",
            ca_path.display()
        );
    }

    let mut env_vars: Vec<(String, String)> = Vec::new();
    for (key, value) in handle.env_vars() {
        env_vars.push((key, value));
    }

    for (key, value) in handle.credential_env_vars(&proxy_config) {
        env_vars.push((key, value));
    }

    std::mem::forget(rt);

    Ok(ActiveProxyRuntime {
        env_vars,
        handle: Some(handle),
        approval_backend,
    })
}

/// Choose the directory the proxy will write the TLS-intercept trust bundle
/// into. Conventionally `$XDG_STATE_HOME/nono/sessions/<random>/`, kept owner-only.
///
/// Returns `Ok(None)` if no `HOME` is set (rare edge cases like CI). We log
/// a warning rather than failing because TLS interception is opt-in: a
/// missing directory just means CONNECTs to L7-bearing routes will get the
/// usual 403, which is a coherent fallback rather than a hard error.
fn prepare_intercept_ca_dir() -> Result<Option<PathBuf>> {
    let dir = match crate::session::ensure_sessions_dir() {
        Ok(base) => base,
        Err(e) => {
            warn!("cannot resolve session registry for TLS-intercept setup: {e}; skipping");
            return Ok(None);
        }
    };
    // PID + start-time-nanos disambiguates concurrent invocations without
    // pulling in a randomness dep. Cryptographic uniqueness isn't the
    // goal; we just need two `nono` processes started at the same second
    // not to share a directory.
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let suffix = format!("{}-{:09}", pid, nanos);
    let dir = dir.join(format!("intercept-{suffix}"));
    if let Err(e) = std::fs::create_dir_all(&dir) {
        warn!(
            "failed to create TLS-intercept dir '{}': {}; skipping interception",
            dir.display(),
            e
        );
        return Ok(None);
    }
    set_intercept_ca_dir_permissions(&dir)?;
    Ok(Some(dir))
}

#[cfg(unix)]
fn set_intercept_ca_dir_permissions(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
        NonoError::SandboxInit(format!(
            "failed to set owner-only permissions on TLS-intercept dir '{}': {e}",
            dir.display()
        ))
    })
}

#[cfg(not(unix))]
fn set_intercept_ca_dir_permissions(_dir: &Path) -> Result<()> {
    Ok(())
}

/// Read the parent process's `SSL_CERT_FILE`, if set, so any corporate
/// CAs configured on the host are merged into the intercept trust bundle.
///
/// On any read failure we log at warn and return `None` — the proxy will
/// continue without merging, and the agent may lose trust for corp hosts.
/// Aborting feels too aggressive: nono is opt-in, and TLS interception is
/// opt-in within nono, so a corp-trust mismatch is a recoverable misconfig
/// not a security failure.
fn read_parent_ssl_cert_file() -> Option<Vec<u8>> {
    let path = std::env::var_os("SSL_CERT_FILE")?;
    match std::fs::read(&path) {
        Ok(bytes) => {
            debug!(
                "merging parent SSL_CERT_FILE '{}' ({} bytes) into TLS-intercept trust bundle",
                std::path::Path::new(&path).display(),
                bytes.len()
            );
            Some(bytes)
        }
        Err(e) => {
            warn!(
                "could not read parent SSL_CERT_FILE '{}': {} — corporate CAs configured on \
                 the host will not be trusted by the sandboxed child",
                std::path::Path::new(&path).display(),
                e
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn set_intercept_ca_dir_permissions_fails_closed() -> Result<()> {
        let tmp = tempfile::tempdir().map_err(NonoError::Io)?;
        let missing = tmp.path().join("missing");

        let err = set_intercept_ca_dir_permissions(&missing)
            .err()
            .ok_or_else(|| {
                NonoError::SandboxInit("expected missing intercept dir to fail".to_string())
            })?;

        assert!(matches!(err, NonoError::SandboxInit(_)));
        assert!(err.to_string().contains("TLS-intercept dir"));
        Ok(())
    }

    #[test]
    fn test_parse_allow_domain_arg_plain_hostname() {
        let entry = parse_allow_domain_arg("github.com");
        assert_eq!(
            entry,
            crate::profile::AllowDomainEntry::Plain("github.com".to_string())
        );
    }

    #[test]
    fn test_parse_allow_domain_arg_url_with_path() {
        let entry = parse_allow_domain_arg("https://github.com/atko-cic/**");
        match entry {
            crate::profile::AllowDomainEntry::WithEndpoints { domain, endpoints } => {
                assert_eq!(domain, "github.com");
                assert_eq!(endpoints.len(), 1);
                assert_eq!(endpoints[0].method, "*");
                assert_eq!(endpoints[0].path, "/atko-cic/**");
            }
            _ => panic!("expected WithEndpoints, got: {:?}", entry),
        }
    }

    #[test]
    fn test_parse_allow_domain_arg_url_root_is_plain() {
        let entry = parse_allow_domain_arg("https://api.example.com/");
        assert_eq!(
            entry,
            crate::profile::AllowDomainEntry::Plain("api.example.com".to_string())
        );
    }

    #[test]
    fn test_parse_allow_domain_arg_url_no_path_is_plain() {
        let entry = parse_allow_domain_arg("https://api.example.com");
        assert_eq!(
            entry,
            crate::profile::AllowDomainEntry::Plain("api.example.com".to_string())
        );
    }

    #[test]
    fn test_parse_allow_domain_arg_deep_path() {
        let entry = parse_allow_domain_arg("https://github.com/org/repo/tree/**");
        match entry {
            crate::profile::AllowDomainEntry::WithEndpoints { domain, endpoints } => {
                assert_eq!(domain, "github.com");
                assert_eq!(endpoints[0].path, "/org/repo/tree/**");
            }
            _ => panic!("expected WithEndpoints"),
        }
    }

    /// `network_block: true` must set `strict_filter` on the generated `ProxyConfig`.
    #[test]
    fn test_build_proxy_config_propagates_network_block_to_strict_filter() {
        let proxy = ProxyLaunchOptions {
            network_block: true,
            ..ProxyLaunchOptions::default()
        };
        let config = build_proxy_config_from_flags(&proxy).expect("build_proxy_config_from_flags");
        assert!(
            config.strict_filter,
            "network_block: true must set strict_filter on ProxyConfig"
        );
    }

    #[test]
    fn test_build_proxy_config_strict_filter_off_when_no_block() {
        let proxy = ProxyLaunchOptions {
            network_block: false,
            ..ProxyLaunchOptions::default()
        };
        let config = build_proxy_config_from_flags(&proxy).expect("build_proxy_config_from_flags");
        assert!(
            !config.strict_filter,
            "strict_filter must default off when network_block is false"
        );
    }

    /// `{ "domain": "cdn.example.com" }` (no `endpoints` key) deserializes via serde default
    /// to `WithEndpoints { endpoints: [] }`, which is semantically identical to `Plain`.
    /// The partition must route it to `plain_entries` — not `endpoint_entries` — or the
    /// domain silently disappears from the allowlist.
    #[test]
    fn test_object_form_domain_with_no_endpoints_key_is_treated_as_plain() {
        use crate::profile::AllowDomainEntry;

        // Mirrors exactly: { "network": { "allow_domain": [ { "domain": "cdn.example.com" } ] } }
        let entries: Vec<AllowDomainEntry> = serde_json::from_str(r#"[
            "plain.example.com",
            { "domain": "object.example.com" },
            { "domain": "filtered.example.com", "endpoints": [{ "method": "GET", "path": "/v1/**" }] }
        ]"#)
        .expect("deserialize allow_domain entries");

        let (plain, endpoint): (Vec<_>, Vec<_>) = entries
            .into_iter()
            .partition(|e| !matches!(e, AllowDomainEntry::WithEndpoints { endpoints, .. } if !endpoints.is_empty()));

        assert_eq!(
            plain.len(),
            2,
            "both Plain and no-endpoints-key object must land in plain bucket"
        );
        assert_eq!(
            endpoint.len(),
            1,
            "only the entry with actual endpoint rules goes to endpoint bucket"
        );

        assert!(
            plain
                .iter()
                .any(|e| matches!(e, AllowDomainEntry::Plain(d) if d == "plain.example.com"))
        );
        assert!(plain.iter().any(|e| matches!(e, AllowDomainEntry::WithEndpoints { domain, .. } if domain == "object.example.com")));
        assert!(endpoint.iter().any(|e| matches!(e, AllowDomainEntry::WithEndpoints { domain, .. } if domain == "filtered.example.com")));
    }

    /// A profile with only `custom_credentials` set (no enabled `credentials`,
    /// no `network_profile`, no `allow_domain`, no upstream proxy) should not
    /// activate the proxy. Custom credential entries are route definitions, not
    /// enabled routes.
    #[test]
    fn test_proxy_is_inactive_when_only_custom_credentials_are_set() {
        use crate::profile::CustomCredentialDef;
        use crate::sandbox_prepare::PreparedSandbox;
        use nono::CapabilitySet;
        use nono_proxy::config::InjectMode;
        use std::collections::HashMap;

        let mut custom_credentials: HashMap<String, CustomCredentialDef> = HashMap::new();
        custom_credentials.insert(
            "mockhttp".to_string(),
            CustomCredentialDef {
                upstream: "https://mockhttp.org".to_string(),
                credential_key: Some("env://MOCK_API_KEY".to_string()),
                auth: None,
                inject_mode: InjectMode::Header,
                inject_header: "Authorization".to_string(),
                credential_format: Some("Bearer {}".to_string()),
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                proxy: None,
                env_var: Some("MOCK_API_KEY".to_string()),
                endpoint_rules: vec![],
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                aws_auth: None,
            },
        );

        let prepared = PreparedSandbox {
            caps: CapabilitySet::new(),
            secrets: Vec::new(),
            session_hooks: crate::profile::SessionHooks::default(),
            rollback_exclude_patterns: Vec::new(),
            rollback_exclude_globs: Vec::new(),
            network_profile: None,
            allow_domain: Vec::new(),
            reject_domain: Vec::new(),
            credentials: Vec::new(),
            custom_credentials,
            upstream_proxy: None,
            upstream_bypass: Vec::new(),
            listen_ports: Vec::new(),
            capability_elevation: false,
            #[cfg(target_os = "linux")]
            wsl2_proxy_policy: crate::profile::Wsl2ProxyPolicy::Error,
            #[cfg(target_os = "linux")]
            af_unix_mediation: crate::profile::LinuxAfUnixMediation::Off,
            allow_launch_services_active: false,
            allow_gpu_active: false,
            open_url_origins: Vec::new(),
            open_url_allow_localhost: false,
            bypass_protection_paths: Vec::new(),
            ignored_denial_paths: Vec::new(),
            suppressed_system_service_operations: Vec::new(),
            allowed_env_vars: None,
            denied_env_vars: None,
            set_vars: None,
            network_block_requested: false,
            profile_network_approval_mode: None,
            profile_network_approval_timeout_secs: None,
        };

        let args = crate::cli::SandboxArgs::default();
        let opts = prepare_proxy_launch_options(&args, &prepared, true)
            .expect("prepare_proxy_launch_options");

        assert!(
            !opts.is_active(),
            "proxy must stay inactive when only custom credential definitions are present"
        );
        assert!(
            opts.credentials.is_some(),
            "custom credential definitions should still be carried for network profile overrides"
        );
    }
}
