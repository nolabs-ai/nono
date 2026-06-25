//! Standalone `nono proxy` command.
//!
//! Runs the network-filtering / credential-injection proxy as a foreground
//! server, with no sandboxed child. Unlike the `run`/`shell`/`wrap` paths —
//! which start the proxy as a side effect and wire its env vars into the
//! sandboxed process — this command prints the connection details (proxy URL,
//! token, env vars) for the user to point their own tools at, then blocks
//! until Ctrl-C.
//!
//! Proxy settings are loaded from a profile (`--profile`) and extended /
//! overridden by explicit flags, reusing the same config-building machinery as
//! the sandboxed path (`proxy_runtime::build_proxy_config_from_flags`).

use crate::cli::ProxyArgs;
use crate::launch_runtime::{
    CredentialProxyIntent, DomainFilterIntent, EndpointFilterIntent, ProxyLaunchOptions,
    TlsInterceptIntent, UpstreamProxyIntent,
};
use crate::profile;
use crate::proxy_runtime::{apply_tls_intercept_config, build_proxy_config_from_flags};
use colored::Colorize;
use nono::{NonoError, Result};
use tracing::info;

/// Run the standalone proxy server until Ctrl-C.
pub(crate) fn run_proxy(args: ProxyArgs, silent: bool) -> Result<()> {
    // Fail secure: an open proxy (`--no-auth`) must stay on loopback so other
    // hosts can't reach it. Refuse a non-loopback bind without auth.
    if args.no_auth && !args.listen.is_loopback() {
        return Err(NonoError::ConfigParse(format!(
            "--no-auth requires a loopback --listen address (got {}); refusing to start an \
             open proxy reachable from other hosts",
            args.listen
        )));
    }

    let proxy = build_launch_options(&args)?;
    let mut proxy_config = build_proxy_config_from_flags(&proxy)?;

    // Bind + auth settings come from the standalone flags, not the profile.
    proxy_config.bind_addr = args.listen;
    proxy_config.bind_port = args.port;
    proxy_config.require_auth = !args.no_auth;

    // An explicit `--pass` pins the proxy credential to a caller-chosen value
    // instead of a random per-session token. Reject a blank password so it
    // can't collapse to an effectively-absent secret. `--no-auth` and `--pass`
    // are mutually exclusive at the clap layer.
    if let Some(ref pass) = args.pass {
        if pass.is_empty() {
            return Err(NonoError::ConfigParse(
                "--pass requires a non-empty password".to_string(),
            ));
        }
        proxy_config.session_token = Some(zeroize::Zeroizing::new(pass.clone()));
    }

    // Share the same TLS-intercept wiring as the sandboxed path.
    apply_tls_intercept_config(&mut proxy_config, &proxy)?;

    // Build the credential-capture backend (for `cmd://` credential routes) and
    // approval registry from the profile, mirroring `start_proxy_runtime`. Without
    // these, `cmd://` routes fail with "managed credential unavailable" because the
    // proxy has no backend to invoke the capture command.
    let credential_capture_backend = crate::proxy_runtime::build_credential_capture_backend(
        &proxy.credential_capture,
        proxy.session_id.clone(),
    )?;
    let approval_registry =
        crate::approval_runtime::build_proxy_approval_registry(proxy.command_policies.as_ref())?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| NonoError::SandboxInit(format!("Failed to start proxy runtime: {}", e)))?;

    let handle = rt
        .block_on(async {
            nono_proxy::server::start_with_approval_and_capture_registry(
                proxy_config.clone(),
                approval_registry,
                credential_capture_backend,
            )
            .await
        })
        .map_err(|e| NonoError::SandboxInit(format!("Failed to start proxy: {}", e)))?;

    print_connection_info(&handle, &proxy_config, args.no_auth, silent);

    // Block the foreground until the user interrupts, then shut down cleanly.
    rt.block_on(async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::warn!("failed to listen for Ctrl-C: {}; shutting down", e);
        }
    });

    if !silent {
        eprintln!("\n  [nono] Shutting down proxy...");
    }
    handle.shutdown();
    info!("Proxy server stopped");
    Ok(())
}

/// Merge profile-derived settings (if `--profile` was given) with explicit
/// CLI flags into a `ProxyLaunchOptions`. Profile values come first; CLI flags
/// extend (allow-domains, credentials) or override (network profile, upstream
/// proxy) — matching `proxy_runtime::resolve_effective_proxy_settings`.
fn build_launch_options(args: &ProxyArgs) -> Result<ProxyLaunchOptions> {
    let loaded = match args.profile {
        Some(ref name) => Some(profile::load_profile(name)?),
        None => None,
    };
    let network = loaded.as_ref().map(|p| &p.network);

    let network_profile = args
        .network_profile
        .clone()
        .or_else(|| network.and_then(|n| n.resolved_network_profile().map(String::from)));

    let mut allow_domain: Vec<profile::AllowDomainEntry> =
        network.map(|n| n.allow_domain.clone()).unwrap_or_default();
    allow_domain.extend(
        args.allow_proxy
            .iter()
            .map(|s| crate::proxy_runtime::parse_allow_domain_arg(s)),
    );

    let mut credentials: Vec<String> = network
        .map(|n| n.resolved_credentials().to_vec())
        .unwrap_or_default();
    for cred in &args.proxy_credential {
        if !credentials.contains(cred) {
            credentials.push(cred.clone());
        }
    }

    let custom_credentials = network
        .map(|n| n.custom_credentials.clone())
        .unwrap_or_default();

    // `cmd://` credential routes resolve through the credential-capture
    // backend, which is built from the profile's top-level `credential_capture`
    // map (and gated by `command_policies` for approvals). Carry both through
    // so the standalone proxy injects captured credentials the same way the
    // sandboxed `run`/`shell`/`wrap` paths do.
    let credential_capture = loaded
        .as_ref()
        .map(|p| p.credential_capture.clone())
        .unwrap_or_default();
    let command_policies = loaded.as_ref().and_then(|p| p.command_policies.clone());

    let upstream_proxy_addr = args
        .external_proxy
        .clone()
        .or_else(|| network.and_then(|n| n.upstream_proxy.clone()));

    let mut upstream_bypass: Vec<String> = network
        .map(|n| n.upstream_bypass.clone())
        .unwrap_or_default();
    upstream_bypass.extend(args.external_proxy_bypass.clone());

    // Bypass entries only make sense with an upstream proxy ("route these
    // direct instead of through the upstream proxy"). Without one they would
    // be silently dropped by the `upstream_proxy_addr.map(...)` below, so
    // reject the combination up front — mirroring `validate_external_proxy_bypass`
    // on the sandboxed path.
    if !upstream_bypass.is_empty() && upstream_proxy_addr.is_none() {
        return Err(NonoError::ConfigParse(
            "--upstream-bypass requires --upstream-proxy \
             (or upstream_proxy in profile network config)"
                .to_string(),
        ));
    }

    // Split allow-domain entries into plain CONNECT-tunnel hosts and
    // endpoint-restricted routes (which require TLS interception), mirroring
    // `prepare_proxy_launch_options` on the sandboxed path.
    let (plain_entries, endpoint_entries): (Vec<_>, Vec<_>) = allow_domain
        .into_iter()
        .partition(|e| !matches!(e, profile::AllowDomainEntry::WithEndpoints { endpoints, .. } if !endpoints.is_empty()));

    let domain_filter = if network_profile.is_some() || !plain_entries.is_empty() {
        Some(DomainFilterIntent {
            network_profile,
            allow_domain: plain_entries,
        })
    } else {
        None
    };

    let endpoint_filter = if endpoint_entries.is_empty() {
        None
    } else {
        Some(EndpointFilterIntent {
            routes: endpoint_entries,
        })
    };

    let credentials_intent = if credentials.is_empty() && custom_credentials.is_empty() {
        None
    } else {
        Some(CredentialProxyIntent {
            credentials,
            custom_credentials,
            // The standalone proxy command has no `--allow-endpoint` flag, so
            // there are no per-credential endpoint restrictions to apply.
            endpoint_restrictions: Vec::new(),
        })
    };

    let upstream_proxy = upstream_proxy_addr.map(|address| UpstreamProxyIntent {
        address,
        bypass: upstream_bypass,
    });

    let ca_validity = args
        .proxy_ca_validity
        .map(|days| std::time::Duration::from_secs(u64::from(days) * 24 * 60 * 60));

    #[cfg(target_os = "macos")]
    let tls_intercept = if args.trust_proxy_ca || ca_validity.is_some() {
        Some(TlsInterceptIntent {
            trust_proxy_ca: args.trust_proxy_ca,
            ca_validity,
        })
    } else {
        None
    };
    #[cfg(not(target_os = "macos"))]
    let tls_intercept = if ca_validity.is_some() {
        Some(TlsInterceptIntent { ca_validity })
    } else {
        None
    };

    Ok(ProxyLaunchOptions {
        domain_filter,
        endpoint_filter,
        credentials: credentials_intent,
        upstream_proxy,
        tls_intercept,
        command_policies,
        credential_capture,
        session_id: crate::session::generate_session_id(),
        ..ProxyLaunchOptions::default()
    })
}

/// Print the proxy URL, env vars, and per-route diagnostics to stdout.
fn print_connection_info(
    handle: &nono_proxy::server::ProxyHandle,
    config: &nono_proxy::config::ProxyConfig,
    no_auth: bool,
    silent: bool,
) {
    let addr = config.bind_addr;
    let port = handle.port;

    if silent {
        return;
    }

    println!();
    println!("  {} {}:{}", "nono proxy listening on".bold(), addr, port);

    if no_auth {
        println!(
            "  {}",
            "auth disabled (--no-auth): any local process can use this proxy".yellow()
        );
        println!("  proxy URL: http://{}:{}", addr, port);
    } else {
        // The token-bearing URL works with standard clients (Basic auth via
        // userinfo). Surface it directly plus the raw token for Bearer clients.
        println!(
            "  proxy URL: {}",
            format!("http://nono:{}@{}:{}", &*handle.token, addr, port).cyan()
        );
        println!("  token:     {}", (*handle.token).dimmed());
        println!();
        println!(
            "  export HTTPS_PROXY=http://nono:{}@{}:{}",
            &*handle.token, addr, port
        );
        println!(
            "  export HTTP_PROXY=http://nono:{}@{}:{}",
            &*handle.token, addr, port
        );
    }

    let route_rows = handle.route_diagnostics(config);
    if !route_rows.is_empty() {
        println!();
        println!("  {}", "routes:".bold());
        for (prefix, summary) in &route_rows {
            println!("    /{}  {}", prefix, summary);
        }
    }

    if let Some(ca_path) = handle.intercept_ca_path() {
        println!();
        println!("  TLS interception trust bundle: {}", ca_path.display());
    }

    println!();
    println!("  {}", "Press Ctrl-C to stop.".dimmed());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::{ENV_LOCK, EnvVarGuard};
    use clap::Parser;

    /// `ProxyArgs` fields bind to `NONO_*` env vars (e.g. `NONO_PROFILE`),
    /// which would otherwise leak from the surrounding environment and make
    /// these tests non-hermetic. Clear them for the duration of the test.
    const PROXY_ENV_VARS: &[&str] = &[
        "NONO_PROFILE",
        "NONO_NETWORK_PROFILE",
        "NONO_ALLOW_DOMAIN",
        "NONO_UPSTREAM_PROXY",
        "NONO_UPSTREAM_BYPASS",
        "NONO_PROXY_CA_VALIDITY",
        "NONO_TRUST_PROXY_CA",
        "NONO_CREDENTIAL",
    ];

    fn cleared_env() -> EnvVarGuard {
        let pairs: Vec<(&'static str, &str)> = PROXY_ENV_VARS.iter().map(|k| (*k, "")).collect();
        let guard = EnvVarGuard::set_all(&pairs);
        for key in PROXY_ENV_VARS {
            guard.remove(key);
        }
        guard
    }

    fn parse_args(extra: &[&str]) -> ProxyArgs {
        let mut argv = vec!["proxy"];
        argv.extend_from_slice(extra);
        ProxyArgs::try_parse_from(argv).expect("parse proxy args")
    }

    #[test]
    fn upstream_bypass_without_upstream_proxy_is_rejected() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _env = cleared_env();
        let args = parse_args(&["--upstream-bypass", "example.com"]);
        let err = build_launch_options(&args).expect_err("bypass without upstream must fail");
        assert!(matches!(err, NonoError::ConfigParse(_)), "got {err:?}");
    }

    #[test]
    fn upstream_bypass_with_upstream_proxy_is_accepted() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _env = cleared_env();
        let args = parse_args(&[
            "--upstream-proxy",
            "127.0.0.1:8080",
            "--upstream-bypass",
            "example.com",
        ]);
        let opts = build_launch_options(&args).expect("bypass with upstream is valid");
        let upstream = opts.upstream_proxy.expect("upstream proxy carried through");
        assert_eq!(upstream.address, "127.0.0.1:8080");
        assert_eq!(upstream.bypass, vec!["example.com".to_string()]);
    }

    #[test]
    fn upstream_proxy_alone_carries_through() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _env = cleared_env();
        let args = parse_args(&["--upstream-proxy", "127.0.0.1:8080"]);
        let opts = build_launch_options(&args).expect("upstream alone is valid");
        let upstream = opts.upstream_proxy.expect("upstream proxy carried through");
        assert_eq!(upstream.address, "127.0.0.1:8080");
        assert!(upstream.bypass.is_empty());
    }

    #[test]
    fn no_upstream_flags_yields_no_upstream_proxy() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _env = cleared_env();
        let args = parse_args(&[]);
        let opts = build_launch_options(&args).expect("empty args are valid");
        assert!(opts.upstream_proxy.is_none());
    }

    #[test]
    fn no_profile_yields_empty_credential_capture() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _env = cleared_env();
        let args = parse_args(&[]);
        let opts = build_launch_options(&args).expect("empty args are valid");
        assert!(opts.credential_capture.is_empty());
        assert!(opts.command_policies.is_none());
        // A session id is always minted so the capture backend can scope caches.
        assert!(!opts.session_id.is_empty());
    }

    #[test]
    fn profile_credential_capture_carries_through() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _env = cleared_env();
        let dir = tempfile::tempdir().expect("tmpdir");
        let profile_path = dir.path().join("capture.json");
        std::fs::write(
            &profile_path,
            r#"{
                "meta": { "name": "capture-test" },
                "credential_capture": {
                    "github": {
                        "command": ["true", "auth", "github"],
                        "cache_path_regex": "^/(?:repos/|orgs/|raw/)?([^/]+)",
                        "timeout_secs": 60
                    }
                }
            }"#,
        )
        .expect("write profile");

        let args = parse_args(&["--profile", profile_path.to_str().expect("valid utf8")]);
        let opts = build_launch_options(&args).expect("profile with capture is valid");
        let entry = opts
            .credential_capture
            .get("github")
            .expect("github capture entry carried through");
        assert_eq!(entry.command, vec!["true", "auth", "github"]);
    }
}
