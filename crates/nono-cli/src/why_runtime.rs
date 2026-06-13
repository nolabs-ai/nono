use crate::capability_ext::CapabilitySetExt;
use crate::cli::{SandboxArgs, WhyArgs, WhyOp, WhyScope};
use crate::command_policy::{
    CommandFromConfig, CommandPoliciesConfig, CommandSandboxConfig, InvocationPolicyConfig,
};
use crate::query_ext::ScopeQuery;
use crate::{network_policy, policy, profile, query_ext, sandbox_state};
use nono::{AccessMode, CapabilitySet, NonoError, Result};

struct WhyContext {
    caps: CapabilitySet,
    overridden_paths: Vec<std::path::PathBuf>,
    allowed_domains: Vec<String>,
    domain_endpoints: Vec<sandbox_state::DomainEndpointState>,
    command_policies: Option<CommandPoliciesConfig>,
}

/// Resolve the proxy domain allowlist from a profile's network config.
fn resolve_allowed_domains(profile: &profile::Profile) -> Vec<String> {
    let policy_json = crate::config::embedded::embedded_network_policy_json();
    let net_policy = match network_policy::load_network_policy(policy_json) {
        Ok(p) => p,
        Err(_) => {
            return profile
                .network
                .allow_domain
                .iter()
                .map(|e| e.domain().to_string())
                .collect();
        }
    };

    let mut domains = Vec::new();

    if let Some(net_profile_name) = profile.network.resolved_network_profile()
        && let Ok(resolved) = network_policy::resolve_network_profile(&net_policy, net_profile_name)
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

    let plain_entries: Vec<String> = profile
        .network
        .allow_domain
        .iter()
        .map(|e| e.domain().to_string())
        .collect();
    domains.extend(network_policy::expand_proxy_allow(
        &net_policy,
        &plain_entries,
    ));

    domains
}

/// Extract domain endpoint restrictions from a profile's allow_domain entries.
fn resolve_domain_endpoints(profile: &profile::Profile) -> Vec<sandbox_state::DomainEndpointState> {
    profile
        .network
        .allow_domain
        .iter()
        .filter_map(|e| match e {
            profile::AllowDomainEntry::WithEndpoints { domain, endpoints }
                if !endpoints.is_empty() =>
            {
                Some(sandbox_state::DomainEndpointState {
                    domain: domain.clone(),
                    endpoints: endpoints
                        .iter()
                        .map(|r| sandbox_state::EndpointRuleState {
                            method: r.method.clone(),
                            path: r.path.clone(),
                        })
                        .collect(),
                })
            }
            _ => None,
        })
        .collect()
}

pub(crate) fn run_why(args: WhyArgs) -> Result<()> {
    use query_ext::{QueryResult, print_result, query_network, query_path, query_scope};
    use sandbox_state::load_sandbox_state;

    let ctx: WhyContext = if args.self_query {
        match load_sandbox_state() {
            Some(state) => {
                let paths = state.bypass_protection_as_paths();
                let domain_endpoints = state.domain_endpoints.clone();
                WhyContext {
                    caps: state.to_caps()?,
                    overridden_paths: paths,
                    allowed_domains: state.allowed_domains.clone(),
                    domain_endpoints,
                    command_policies: None,
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
        for tmpl in &profile.filesystem.bypass_protection {
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
        let domain_endpoints = resolve_domain_endpoints(&profile);
        let command_policies = profile.command_policies.clone();

        let prepared = CapabilitySet::from_profile(&profile, &workdir, &sandbox_args)?;
        let mut caps = prepared.caps;
        if prepared.needs_unlink_overrides {
            policy::apply_unlink_overrides(&mut caps);
        }
        WhyContext {
            caps,
            overridden_paths: override_paths,
            allowed_domains,
            domain_endpoints,
            command_policies,
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
            domain_endpoints: vec![],
            command_policies: None,
        }
    };

    let result = if let Some(ref command) = args.command {
        query_command_policy(
            command,
            &args.caller,
            &args.command_args,
            ctx.command_policies.as_ref(),
        )
    } else if let Some(ref path) = args.path {
        let op = match args.op {
            Some(WhyOp::Read) => AccessMode::Read,
            Some(WhyOp::Write) => AccessMode::Write,
            Some(WhyOp::ReadWrite) => AccessMode::ReadWrite,
            None => AccessMode::Read,
        };
        query_path(path, op, &ctx.caps, &ctx.overridden_paths)?
    } else if let Some(ref host) = args.host {
        query_network(
            host,
            args.port,
            &ctx.caps,
            &ctx.allowed_domains,
            &ctx.domain_endpoints,
        )
    } else if let Some(ref scope) = args.scope {
        query_scope(scope_query(scope), &ctx.caps)
    } else {
        return Err(NonoError::ConfigParse(
            "--command, --path, --host, or --scope is required".to_string(),
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

fn query_command_policy(
    command: &str,
    caller: &str,
    command_args: &[String],
    policies: Option<&CommandPoliciesConfig>,
) -> query_ext::QueryResult {
    let Some(policies) = policies else {
        return query_ext::QueryResult::Denied {
            reason: "command_policy_unavailable".to_string(),
            details: Some(
                "Command-policy queries require a profile context. Re-run with `--profile <name>`."
                    .to_string(),
            ),
            policy_source: Some("command_policies".to_string()),
            matching_capability: None,
            suggested_flag: Some("--profile <name>".to_string()),
            endpoint_rules: None,
        };
    };

    let Some(command_policy) = policies.commands.get(command) else {
        return query_ext::QueryResult::Denied {
            reason: "command_not_policy_controlled".to_string(),
            details: Some(format!(
                "Command '{command}' is not present under command_policies.commands."
            )),
            policy_source: Some("command_policies.commands".to_string()),
            matching_capability: None,
            suggested_flag: None,
            endpoint_rules: None,
        };
    };

    let Some(from_policy) = command_policy.from.get(caller) else {
        return query_ext::QueryResult::Denied {
            reason: format!("missing from.{caller}"),
            details: Some(format!(
                "Command '{command}' has no command_policies.commands.{command}.from.{caller} edge."
            )),
            policy_source: Some(format!("command_policies.commands.{command}.from.{caller}")),
            matching_capability: None,
            suggested_flag: None,
            endpoint_rules: None,
        };
    };

    let (sandbox, invocation_policy) = match from_policy {
        CommandFromConfig::Deny(value) => {
            return query_ext::QueryResult::Denied {
                reason: "command_policy_denied".to_string(),
                details: Some(format!(
                    "command_policies.commands.{command}.from.{caller} is explicit {value:?}."
                )),
                policy_source: Some(format!("command_policies.commands.{command}.from.{caller}")),
                matching_capability: None,
                suggested_flag: None,
                endpoint_rules: None,
            };
        }
        CommandFromConfig::Policy(sandbox) => (sandbox.as_ref(), None),
        CommandFromConfig::Edge(edge) => (&edge.sandbox, edge.invocation_policy.as_ref()),
    };

    let endpoint_note = endpoint_policy_note(sandbox);
    let Some(invocation_policy) = invocation_policy else {
        return query_ext::QueryResult::Allowed {
            reason: "command_edge_allowed".to_string(),
            granted_path: None,
            access: Some(format!(
                "Command '{command}' from '{caller}' has no invocation_policy; argv is not additionally filtered.{endpoint_note}"
            )),
            source: Some(format!("command_policies.commands.{command}.from.{caller}")),
            endpoint_rules: None,
        };
    };

    let mut argv = Vec::with_capacity(command_args.len() + 1);
    argv.push(command.as_bytes().to_vec());
    argv.extend(command_args.iter().map(|arg| arg.as_bytes().to_vec()));

    match evaluate_invocation_policy_for_why(invocation_policy, &argv) {
        Ok(WhyInvocationPolicyOutcome::Allow) => query_ext::QueryResult::Allowed {
            reason: "invocation_policy_allowed".to_string(),
            granted_path: None,
            access: Some(format!(
                "Command '{command}' from '{caller}' matches invocation_policy allow rules.{endpoint_note}"
            )),
            source: Some(format!(
                "command_policies.commands.{command}.from.{caller}.invocation_policy"
            )),
            endpoint_rules: None,
        },
        Ok(WhyInvocationPolicyOutcome::Deny { reason }) => query_ext::QueryResult::Denied {
            reason,
            details: Some(format!(
                "Command '{command}' from '{caller}' with argv [{}] is denied by invocation_policy. This is an Tool Sandbox  command/argument policy denial, not a filesystem path denial.{endpoint_note}",
                command_args.join(" ")
            )),
            policy_source: Some(format!(
                "command_policies.commands.{command}.from.{caller}.invocation_policy"
            )),
            matching_capability: None,
            suggested_flag: None,
            endpoint_rules: None,
        },
        Ok(WhyInvocationPolicyOutcome::Approve {
            backend,
            timeout_secs,
            reason,
            rule_label,
        }) => query_ext::QueryResult::ApprovalRequired {
            reason: reason.unwrap_or_else(|| "invocation_policy approval required".to_string()),
            details: Some(format!(
                "Command '{command}' from '{caller}' with argv [{}] matches {rule_label}. Backend: {}. Timeout: {}.{endpoint_note}",
                command_args.join(" "),
                backend.unwrap_or_else(|| "<default>".to_string()),
                timeout_secs
                    .map(|secs| format!("{secs}s"))
                    .unwrap_or_else(|| "<default>".to_string()),
            )),
            policy_source: Some(format!(
                "command_policies.commands.{command}.from.{caller}.invocation_policy"
            )),
        },
        Err(err) => query_ext::QueryResult::Denied {
            reason: "command_policy_query_failed".to_string(),
            details: Some(err.to_string()),
            policy_source: Some(format!(
                "command_policies.commands.{command}.from.{caller}.invocation_policy"
            )),
            matching_capability: None,
            suggested_flag: None,
            endpoint_rules: None,
        },
    }
}

enum WhyInvocationPolicyOutcome {
    Allow,
    Deny {
        reason: String,
    },
    Approve {
        backend: Option<String>,
        timeout_secs: Option<u64>,
        reason: Option<String>,
        rule_label: String,
    },
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn evaluate_invocation_policy_for_why(
    policy: &InvocationPolicyConfig,
    argv: &[Vec<u8>],
) -> Result<WhyInvocationPolicyOutcome> {
    match crate::tool_sandbox::evaluate_invocation_policy(policy, argv, &[])? {
        crate::tool_sandbox::InvocationPolicyOutcome::Allow => {
            Ok(WhyInvocationPolicyOutcome::Allow)
        }
        crate::tool_sandbox::InvocationPolicyOutcome::Deny { reason } => {
            Ok(WhyInvocationPolicyOutcome::Deny { reason })
        }
        crate::tool_sandbox::InvocationPolicyOutcome::Approve {
            backend,
            timeout_secs,
            reason,
            rule_label,
        } => Ok(WhyInvocationPolicyOutcome::Approve {
            backend,
            timeout_secs,
            reason,
            rule_label,
        }),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn evaluate_invocation_policy_for_why(
    _policy: &InvocationPolicyConfig,
    _argv: &[Vec<u8>],
) -> Result<WhyInvocationPolicyOutcome> {
    Err(NonoError::ConfigParse(
        "tool-sandbox command-policy queries are only available on Linux and macOS".to_string(),
    ))
}

fn endpoint_policy_note(sandbox: &CommandSandboxConfig) -> String {
    let endpoint_policy_count = sandbox
        .credentials
        .iter()
        .filter(|grant| match grant {
            crate::command_policy::CommandCredentialGrantConfig::Name(_) => false,
            crate::command_policy::CommandCredentialGrantConfig::Policy(policy) => {
                policy.endpoint_policy.is_some()
            }
        })
        .count();

    if endpoint_policy_count == 0 {
        String::new()
    } else {
        format!(
            " This command also grants {endpoint_policy_count} proxy credential endpoint_policy layer(s); HTTP method/path rules may still deny the underlying request."
        )
    }
}

fn scope_query(scope: &WhyScope) -> ScopeQuery {
    match scope {
        WhyScope::Signal => ScopeQuery::Signal,
        WhyScope::AbstractUnixSocket => ScopeQuery::AbstractUnixSocket,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_policy::{
        ArgvMatcherConfig, CommandEdgeConfig, CommandPolicyConfig, InvocationPolicyConfig,
        InvocationRuleConfig, PolicyDecision, PolicyDecisionConfig,
    };
    use std::collections::BTreeMap;

    fn gh_policy() -> CommandPoliciesConfig {
        CommandPoliciesConfig {
            commands: BTreeMap::from([(
                "gh".to_string(),
                CommandPolicyConfig {
                    from: BTreeMap::from([(
                        "session".to_string(),
                        CommandFromConfig::Edge(Box::new(CommandEdgeConfig {
                            sandbox: CommandSandboxConfig::default(),
                            invocation_policy: Some(InvocationPolicyConfig {
                                default: PolicyDecisionConfig::Decision(PolicyDecision::Deny),
                                deny: vec![InvocationRuleConfig {
                                    argv: Some(ArgvMatcherConfig {
                                        prefix: Some(vec![
                                            "issue".to_string(),
                                            "comment".to_string(),
                                        ]),
                                        exact: None,
                                        contains: None,
                                    }),
                                    env: BTreeMap::new(),
                                    backend: None,
                                    reason: Some(
                                        "agents may read issues but not comment on them"
                                            .to_string(),
                                    ),
                                    timeout_secs: None,
                                }],
                                approve: vec![],
                                allow: vec![InvocationRuleConfig {
                                    argv: Some(ArgvMatcherConfig {
                                        prefix: Some(vec!["issue".to_string(), "view".to_string()]),
                                        exact: None,
                                        contains: None,
                                    }),
                                    env: BTreeMap::new(),
                                    backend: None,
                                    reason: None,
                                    timeout_secs: None,
                                }],
                            }),
                        })),
                    )]),
                    ..CommandPolicyConfig::default()
                },
            )]),
            ..CommandPoliciesConfig::default()
        }
    }

    #[test]
    fn command_policy_query_reports_argv_deny_reason() {
        let policies = gh_policy();
        let args = vec![
            "issue".to_string(),
            "comment".to_string(),
            "1052".to_string(),
        ];

        let result = query_command_policy("gh", "session", &args, Some(&policies));

        match result {
            query_ext::QueryResult::Denied {
                reason,
                details,
                policy_source,
                ..
            } => {
                assert_eq!(reason, "agents may read issues but not comment on them");
                assert!(
                    details
                        .as_deref()
                        .is_some_and(|value| value.contains("not a filesystem path denial"))
                );
                assert_eq!(
                    policy_source.as_deref(),
                    Some("command_policies.commands.gh.from.session.invocation_policy")
                );
            }
            other => panic!("expected denied command-policy result, got {other:?}"),
        }
    }

    #[test]
    fn command_policy_query_reports_argv_allow() {
        let policies = gh_policy();
        let args = vec!["issue".to_string(), "view".to_string(), "1052".to_string()];

        let result = query_command_policy("gh", "session", &args, Some(&policies));

        assert!(matches!(
            result,
            query_ext::QueryResult::Allowed {
                reason,
                ..
            } if reason == "invocation_policy_allowed"
        ));
    }
}
