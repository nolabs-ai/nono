use crate::capability_ext::CapabilitySetExt;
use crate::cli::{SandboxArgs, WhyArgs, WhyOp, WhyScope};
use crate::query_ext::ScopeQuery;
use crate::{network_policy, policy, profile, query_ext, sandbox_state};
use nono::{AccessMode, CapabilitySet, NonoError, Result};

struct WhyContext {
    caps: CapabilitySet,
    overridden_paths: Vec<std::path::PathBuf>,
    allowed_domains: Vec<String>,
}

/// Resolve the proxy domain allowlist from a profile's network config.
fn resolve_allowed_domains(profile: &profile::Profile) -> Vec<String> {
    let policy_json = crate::config::embedded::embedded_network_policy_json();
    let net_policy = match network_policy::load_network_policy(policy_json) {
        Ok(p) => p,
        Err(_) => return profile.network.allow_domain.clone(),
    };

    let mut domains = Vec::new();

    if let Some(net_profile_name) = profile.network.resolved_network_profile() {
        if let Ok(resolved) = network_policy::resolve_network_profile(&net_policy, net_profile_name)
        {
            domains.extend(resolved.hosts);
            for suffix in &resolved.suffixes {
                let wildcard = if suffix.starts_with('.') {
                    format!("*{}", suffix)
                } else {
                    format!("*.{}", suffix)
                };
                domains.push(wildcard);
            }
        }
    }

    domains.extend(network_policy::expand_proxy_allow(
        &net_policy,
        &profile.network.allow_domain,
    ));

    domains
}

pub(crate) fn run_why(args: WhyArgs) -> Result<()> {
    use query_ext::{print_result, query_network, query_path, query_scope, QueryResult};
    use sandbox_state::load_sandbox_state;

    let ctx: WhyContext = if args.self_query {
        match load_sandbox_state() {
            Some(state) => {
                let paths = state.bypass_protection_as_paths();
                WhyContext {
                    caps: state.to_caps()?,
                    overridden_paths: paths,
                    // f72ea31: populate from persisted sandbox state so --self
                    // --host correctly reports ProxyOnly filtering.
                    allowed_domains: state.allowed_domains.clone(),
                }
            }
            None => {
                let result = QueryResult::NotSandboxed {
                    message: "Not running inside a nono sandbox".to_string(),
                };
                if args.json {
                    let json = serde_json::to_string_pretty(&result).map_err(|e| {
                        NonoError::ConfigParse(format!("JSON serialization failed: {}", e))
                    })?;
                    println!("{}", json);
                } else {
                    print_result(&result);
                }
                return Ok(());
            }
        }
    } else if let Some(ref profile_name) = args.profile {
        let profile = profile::load_profile(profile_name)?;
        let workdir = args
            .workdir
            .clone()
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| std::path::PathBuf::from("."));

        let sandbox_args = SandboxArgs {
            allow: args.allow.clone(),
            read: args.read.clone(),
            write: args.write.clone(),
            allow_file: args.allow_file.clone(),
            read_file: args.read_file.clone(),
            write_file: args.write_file.clone(),
            block_net: args.block_net,
            workdir: args.workdir.clone(),
            ..SandboxArgs::default()
        };

        let mut override_paths = Vec::new();
        for tmpl in &profile.policy.bypass_protection {
            let expanded = profile::expand_vars(tmpl, &workdir)?;
            if expanded.exists() {
                if let Ok(canonical) = expanded.canonicalize() {
                    override_paths.push(canonical);
                }
            } else {
                override_paths.push(expanded);
            }
        }

        let allowed_domains = resolve_allowed_domains(&profile);

        let prepared = CapabilitySet::from_profile(&profile, &workdir, &sandbox_args)?;
        let mut caps = prepared.caps;
        if prepared.needs_unlink_overrides {
            policy::apply_unlink_overrides(&mut caps);
        }
        WhyContext {
            caps,
            overridden_paths: override_paths,
            allowed_domains,
        }
    } else {
        let sandbox_args = SandboxArgs {
            allow: args.allow.clone(),
            read: args.read.clone(),
            write: args.write.clone(),
            allow_file: args.allow_file.clone(),
            read_file: args.read_file.clone(),
            write_file: args.write_file.clone(),
            block_net: args.block_net,
            workdir: args.workdir.clone(),
            ..SandboxArgs::default()
        };

        let prepared = CapabilitySet::from_args(&sandbox_args)?;
        let mut caps = prepared.caps;
        if prepared.needs_unlink_overrides {
            policy::apply_unlink_overrides(&mut caps);
        }
        WhyContext {
            caps,
            overridden_paths: vec![],
            allowed_domains: vec![],
        }
    };

    let result = if let Some(ref path) = args.path {
        let op = match args.op {
            Some(WhyOp::Read) => AccessMode::Read,
            Some(WhyOp::Write) => AccessMode::Write,
            Some(WhyOp::ReadWrite) => AccessMode::ReadWrite,
            None => AccessMode::Read,
        };
        query_path(path, op, &ctx.caps, &ctx.overridden_paths)?
    } else if let Some(ref host) = args.host {
        query_network(host, args.port, &ctx.caps, &ctx.allowed_domains)
    } else if let Some(ref scope) = args.scope {
        query_scope(scope_query(scope), &ctx.caps)
    } else {
        return Err(NonoError::ConfigParse(
            "--path, --host, or --scope is required".to_string(),
        ));
    };

    if args.json {
        let json = serde_json::to_string_pretty(&result)
            .map_err(|e| NonoError::ConfigParse(format!("JSON serialization failed: {}", e)))?;
        println!("{}", json);
    } else {
        print_result(&result);
    }

    Ok(())
}

fn scope_query(scope: &WhyScope) -> ScopeQuery {
    match scope {
        WhyScope::Signal => ScopeQuery::Signal,
        WhyScope::AbstractUnixSocket => ScopeQuery::AbstractUnixSocket,
    }
}
