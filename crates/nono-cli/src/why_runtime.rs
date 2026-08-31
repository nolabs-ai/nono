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
    deny_paths: Vec<std::path::PathBuf>,
    overridden_paths: Vec<std::path::PathBuf>,
    allowed_domains: Vec<String>,
    denied_domains: Vec<String>,
    domain_endpoints: Vec<sandbox_state::DomainEndpointState>,
    command_policies: Option<CommandPoliciesConfig>,
}

/// Resolve the proxy domain allowlist from a profile's network config.
///
/// Errors rather than degrading: a half-resolved allowlist answers wrongly in
/// both directions, and `nono run` already refuses to start on these.
fn resolve_allowed_domains(profile: &profile::Profile) -> Result<Vec<String>> {
    let policy_json = crate::config::embedded::embedded_network_policy_json();
    let net_policy = network_policy::load_network_policy(policy_json)?;

    let mut domains = Vec::new();

    if let Some(net_profile_name) = profile.network.resolved_network_profile() {
        let resolved = network_policy::resolve_network_profile(&net_policy, net_profile_name)?;
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

    Ok(domains)
}

/// Resolve the proxy domain denylist from a profile's network config.
fn resolve_denied_domains(profile: &profile::Profile) -> Result<Vec<String>> {
    let policy_json = crate::config::embedded::embedded_network_policy_json();
    let net_policy = network_policy::load_network_policy(policy_json)?;
    Ok(network_policy::expand_proxy_deny(
        &net_policy,
        &profile.network.deny_domain,
    ))
}

/// Merge `--allow-domain` overrides into a resolved allowlist.
fn merge_cli_allow_domains(
    mut domains: Vec<String>,
    cli_entries: &[String],
) -> Result<Vec<String>> {
    if cli_entries.is_empty() {
        return Ok(domains);
    }
    let policy_json = crate::config::embedded::embedded_network_policy_json();
    let net_policy = network_policy::load_network_policy(policy_json)?;
    domains.extend(network_policy::expand_proxy_allow(&net_policy, cli_entries));
    Ok(domains)
}

/// Merge `--deny-domain` overrides into a resolved denylist.
fn merge_cli_deny_domains(mut domains: Vec<String>, cli_entries: &[String]) -> Result<Vec<String>> {
    if cli_entries.is_empty() {
        return Ok(domains);
    }
    let policy_json = crate::config::embedded::embedded_network_policy_json();
    let net_policy = network_policy::load_network_policy(policy_json)?;
    domains.extend(network_policy::expand_proxy_deny(&net_policy, cli_entries));
    Ok(domains)
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

    // When running inside a sandbox, the state file records the inode each
    // file-level grant resolved to at sandbox start. Landlock rules bind to
    // that inode, so a grant whose file was since replaced is enforced against
    // the wrong (old) inode — detect those up front so path queries can report
    // them instead of a misleading plain ALLOWED.
    //
    // `--self` answers entirely from the state file, so it keeps the strict
    // loader (fail loud on a bad NONO_CAP_FILE). All other modes only use the
    // state for staleness hints and worked without it before — they use the
    // lenient loader so an unreadable state file (common inside the sandbox)
    // degrades to "no hints" instead of breaking the query.
    let sandbox_state = if args.self_query {
        load_sandbox_state()
    } else {
        sandbox_state::try_load_sandbox_state()
    };
    let stale_file_grants = sandbox_state
        .as_ref()
        .map(detect_stale_file_grants)
        .unwrap_or_default();

    let ctx: WhyContext = if args.self_query {
        match sandbox_state {
            Some(state) => {
                let paths = state.bypass_protection_as_paths();
                let domain_endpoints = state.domain_endpoints.clone();
                WhyContext {
                    caps: state.to_caps()?,
                    deny_paths: state.deny_paths_as_paths(),
                    overridden_paths: paths,
                    allowed_domains: state.allowed_domains.clone(),
                    denied_domains: state.denied_domains.clone(),
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
        let profile = profile::load_profile_with_extends(profile_name, &args.extends)?;
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

        let allowed_domains =
            merge_cli_allow_domains(resolve_allowed_domains(&profile)?, &args.allow_proxy)?;
        let denied_domains =
            merge_cli_deny_domains(resolve_denied_domains(&profile)?, &args.deny_proxy)?;
        let domain_endpoints = resolve_domain_endpoints(&profile);
        let command_policies = profile.command_policies.clone();

        let prepared = CapabilitySet::from_profile(&profile, &workdir, &sandbox_args)?;
        let mut caps = prepared.caps;
        if prepared.needs_unlink_overrides {
            policy::apply_unlink_overrides(&mut caps);
        }
        WhyContext {
            caps,
            deny_paths: prepared.deny_paths,
            overridden_paths: override_paths,
            allowed_domains,
            denied_domains,
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
            deny_paths: prepared.deny_paths,
            overridden_paths: vec![],
            allowed_domains: merge_cli_allow_domains(Vec::new(), &args.allow_proxy)?,
            denied_domains: merge_cli_deny_domains(Vec::new(), &args.deny_proxy)?,
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
        let result = match matching_deny_path(path, &ctx.deny_paths) {
            Some(deny_path) => QueryResult::Denied {
                reason: "filesystem_deny".to_string(),
                details: Some(format!(
                    "Path is covered by filesystem.deny rule: {}",
                    deny_path.display()
                )),
                policy_source: Some("filesystem.deny".to_string()),
                matching_capability: None,
                suggested_flag: None,
                endpoint_rules: None,
            },
            None => query_path(path, op, &ctx.caps, &ctx.overridden_paths)?,
        };
        apply_file_grant_staleness(
            result,
            path,
            op,
            &ctx.caps,
            &ctx.overridden_paths,
            &stale_file_grants,
        )?
    } else if let Some(ref host) = args.host {
        query_network(
            host,
            args.port,
            &ctx.caps,
            &ctx.allowed_domains,
            &ctx.denied_domains,
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

/// Return the most specific deny path that covers a query path.
///
/// Deny paths are retained separately from allow capabilities because macOS
/// Seatbelt deny rules take precedence over a broader allow rule. Resolve the
/// query through existing ancestors so missing leaf paths (the common
/// create-file case) compare the same way as the rules installed at launch.
fn matching_deny_path<'a>(
    path: &std::path::Path,
    deny_paths: &'a [std::path::PathBuf],
) -> Option<&'a std::path::PathBuf> {
    let resolved = nono::try_canonicalize(path);
    deny_paths
        .iter()
        .filter(|deny| {
            let resolved_deny = nono::try_canonicalize(deny);
            resolved.starts_with(&resolved_deny)
        })
        .max_by_key(|deny| deny.as_os_str().len())
}

/// A file-level grant whose Landlock rule no longer matches the file at the
/// granted path: the file was replaced (new inode) or removed after sandbox
/// start, so the kernel rule — bound to the old inode — no longer applies.
struct StaleFileGrant {
    /// Resolved path of the grant (as recorded in the state file).
    path: String,
    /// Access mode string of the grant ("read", "write", "readwrite").
    access: String,
    /// Capability source of the grant, for attribution.
    source: Option<String>,
    /// (dev, ino) recorded at sandbox start.
    grant_id: (u64, u64),
    /// Current (dev, ino) at the granted path; `None` if the path is gone.
    current_id: Option<(u64, u64)>,
}

impl StaleFileGrant {
    fn describe(&self) -> String {
        match self.current_id {
            Some((dev, ino)) => format!(
                "the file at {} was replaced after sandbox start \
                 (inode {}:{} when the sandbox started, {}:{} now)",
                self.path, self.grant_id.0, self.grant_id.1, dev, ino
            ),
            None => format!("the file at {} was removed after sandbox start", self.path),
        }
    }
}

/// Compare each file-level grant's recorded (dev, ino) against a fresh stat of
/// the granted path. Only meaningful on Linux, where Landlock binds rules to
/// inodes; macOS Seatbelt rules are path-based and never go stale this way.
#[cfg(target_os = "linux")]
fn detect_stale_file_grants(state: &sandbox_state::SandboxState) -> Vec<StaleFileGrant> {
    use std::os::unix::fs::MetadataExt;

    state
        .fs
        .iter()
        .filter_map(|cap| {
            if !cap.is_file {
                return None;
            }
            let grant_id = (cap.dev?, cap.ino?);
            let current_id = std::fs::metadata(&cap.path)
                .ok()
                .map(|md| (md.dev(), md.ino()));
            if current_id == Some(grant_id) {
                return None;
            }
            Some(StaleFileGrant {
                path: cap.path.clone(),
                access: cap.access.clone(),
                source: cap.source.clone(),
                grant_id,
                current_id,
            })
        })
        .collect()
}

#[cfg(not(target_os = "linux"))]
fn detect_stale_file_grants(_state: &sandbox_state::SandboxState) -> Vec<StaleFileGrant> {
    Vec::new()
}

/// Correct a path-query verdict for stale file grants.
///
/// If the query was answered by a file-level grant whose inode changed since
/// sandbox start, the kernel will deny the access despite the grant. Re-query
/// without the stale file grants: another (directory) grant may still cover
/// the path with a live rule — then the answer stays ALLOWED via that grant,
/// with a warning about the stale one. Otherwise report a denial that names
/// the real cause instead of a misleading ALLOWED.
fn apply_file_grant_staleness(
    result: query_ext::QueryResult,
    path: &std::path::Path,
    op: AccessMode,
    caps: &CapabilitySet,
    overridden_paths: &[std::path::PathBuf],
    stale_grants: &[StaleFileGrant],
) -> Result<query_ext::QueryResult> {
    let query_ext::QueryResult::Allowed {
        granted_path: Some(ref granted),
        ..
    } = result
    else {
        return Ok(result);
    };
    let Some(stale) = stale_grants.iter().find(|g| g.path == *granted) else {
        return Ok(result);
    };

    let mut fresh_caps = CapabilitySet::new();
    for cap in caps.fs_capabilities() {
        let cap_is_stale = cap.is_file
            && stale_grants
                .iter()
                .any(|g| std::path::Path::new(&g.path) == cap.resolved);
        if !cap_is_stale {
            fresh_caps.add_fs(cap.clone());
        }
    }

    match query_ext::query_path(path, op, &fresh_caps, overridden_paths)? {
        query_ext::QueryResult::Allowed {
            reason,
            granted_path,
            access,
            source,
            endpoint_rules,
            ..
        } => Ok(query_ext::QueryResult::Allowed {
            reason,
            granted_path,
            access,
            source,
            endpoint_rules,
            warning: Some(format!(
                "A more specific file grant is stale: {}. Landlock rules bind to the inode \
                 that was open when the sandbox started, so that grant no longer applies; \
                 access works only through the grant shown above.",
                stale.describe()
            )),
        }),
        _ => Ok(query_ext::QueryResult::Denied {
            reason: "stale_file_grant".to_string(),
            details: Some(format!(
                "The sandbox granted this file, but {}. Landlock rules bind to the inode, \
                 not the path, so the kernel still enforces the rule against the old inode \
                 and access at this path fails with EACCES despite the grant. Restart the \
                 sandbox to re-apply the grant to the current file.",
                stale.describe()
            )),
            policy_source: stale.source.clone(),
            matching_capability: Some(query_ext::CapabilityMatch {
                path: stale.path.clone(),
                access: stale.access.clone(),
                source: stale
                    .source
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
            }),
            suggested_flag: None,
            endpoint_rules: None,
        }),
    }
}

fn query_command_policy(
    command: &str,
    caller: &str,
    command_args: &[std::ffi::OsString],
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
            warning: None,
        };
    };

    use std::os::unix::ffi::OsStrExt;
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
            warning: None,
        },
        Ok(WhyInvocationPolicyOutcome::Deny { reason }) => query_ext::QueryResult::Denied {
            reason,
            details: Some(format!(
                "Command '{command}' from '{caller}' with argv [{}] is denied by invocation_policy. This is an Tool Sandbox  command/argument policy denial, not a filesystem path denial.{endpoint_note}",
                crate::command_display::format_command_line(command_args)
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
                crate::command_display::format_command_line(command_args),
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

    fn profile_from_json(json: &str) -> profile::Profile {
        serde_json::from_str(json).expect("parse profile")
    }

    /// Query a host against a profile the same way `run_why --profile` does.
    fn why_profile_host(json: &str, host: &str) -> query_ext::QueryResult {
        let profile = profile_from_json(json);
        let mut caps = CapabilitySet::new();
        if profile.network.block {
            caps.set_network_blocked(true);
        }
        query_ext::query_network(
            host,
            443,
            &caps,
            &resolve_allowed_domains(&profile).expect("resolve allowlist"),
            &resolve_denied_domains(&profile).expect("resolve denylist"),
            &resolve_domain_endpoints(&profile),
        )
    }

    fn reason_of(result: &query_ext::QueryResult) -> &str {
        match result {
            query_ext::QueryResult::Allowed { reason, .. }
            | query_ext::QueryResult::Denied { reason, .. } => reason,
            other => panic!("unexpected query result: {:?}", other),
        }
    }

    #[test]
    fn unknown_network_profile_is_an_error() {
        let profile = profile_from_json(r#"{"network":{"network_profile":"no-such-profile"}}"#);
        assert!(resolve_allowed_domains(&profile).is_err());
    }

    #[test]
    fn profile_host_outside_allowlist_is_denied() {
        let result = why_profile_host(
            r#"{"network":{"allow_domain":["docs.rs"]}}"#,
            "www.rfc-editor.org",
        );
        assert_eq!(reason_of(&result), "proxy_filtered");
    }

    #[test]
    fn profile_host_in_allowlist_is_allowed() {
        let result = why_profile_host(r#"{"network":{"allow_domain":["docs.rs"]}}"#, "docs.rs");
        assert_eq!(reason_of(&result), "proxy_allowed");
    }

    /// Matching is exact, not subtree: an apex entry grants no subdomains.
    #[test]
    fn profile_plain_entry_does_not_grant_subdomains() {
        let result = why_profile_host(
            r#"{"network":{"allow_domain":["auth0.com"]}}"#,
            "foo.auth0.com",
        );
        assert_eq!(reason_of(&result), "proxy_filtered");
    }

    /// `*.` grants subdomains only. The apex stays excluded.
    #[test]
    fn profile_wildcard_grants_subdomain_not_apex() {
        let config = r#"{"network":{"allow_domain":["*.auth0c.com"]}}"#;
        assert_eq!(
            reason_of(&why_profile_host(config, "x.auth0c.com")),
            "proxy_allowed"
        );
        assert_eq!(
            reason_of(&why_profile_host(config, "auth0c.com")),
            "proxy_filtered"
        );
    }

    #[test]
    fn explicit_deny_covers_missing_leaf_under_denied_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let denied = dir.path().join("blocked");
        let query = denied.join("future.txt");

        assert_eq!(
            matching_deny_path(&query, std::slice::from_ref(&denied)),
            Some(&denied)
        );
    }

    #[test]
    fn known_network_profile_contributes_hosts() {
        let profile = profile_from_json(r#"{"network":{"network_profile":"claude-code"}}"#);
        let domains = resolve_allowed_domains(&profile).expect("resolve allowlist");
        assert!(!domains.is_empty());
    }

    /// No proxy-activating feature means no proxy, so unrestricted is correct.
    #[test]
    fn profile_without_network_config_reports_allowed() {
        let result = why_profile_host(r#"{}"#, "anything.example.com");
        assert_eq!(reason_of(&result), "network_allowed");
    }

    /// #1742: deny_domain must win over allow_domain for the same host.
    #[test]
    fn profile_deny_domain_beats_allow_domain() {
        let config =
            r#"{"network":{"allow_domain":["pypi.org","example.com"],"deny_domain":["pypi.org"]}}"#;
        assert_eq!(
            reason_of(&why_profile_host(config, "pypi.org")),
            "domain_deny"
        );
        // Control: a host in allow_domain but not deny_domain stays allowed.
        assert_eq!(
            reason_of(&why_profile_host(config, "example.com")),
            "proxy_allowed"
        );
    }

    /// deny_domain also wins under a `network_profile` allowlist.
    #[test]
    fn profile_deny_domain_beats_network_profile() {
        let config =
            r#"{"network":{"network_profile":"claude-code","deny_domain":["api.anthropic.com"]}}"#;
        assert_eq!(
            reason_of(&why_profile_host(config, "api.anthropic.com")),
            "domain_deny"
        );
    }

    /// deny_domain alone (no allowlist) still denies its listed hosts.
    #[test]
    fn profile_deny_domain_alone_still_denies() {
        let config = r#"{"network":{"deny_domain":["evil.example.com"]}}"#;
        assert_eq!(
            reason_of(&why_profile_host(config, "evil.example.com")),
            "domain_deny"
        );
        assert_eq!(
            reason_of(&why_profile_host(config, "anything-else.example.com")),
            "proxy_allowed"
        );
    }

    /// Wildcard deny_domain entries are enforced too.
    #[test]
    fn profile_wildcard_deny_domain_matches_subdomains() {
        let config =
            r#"{"network":{"allow_domain":["*.npmjs.org"],"deny_domain":["*.npmjs.org"]}}"#;
        assert_eq!(
            reason_of(&why_profile_host(config, "registry.npmjs.org")),
            "domain_deny"
        );
    }

    #[test]
    fn profile_proxy_denies_cloud_metadata() {
        let result = why_profile_host(
            r#"{"network":{"allow_domain":["169.254.169.254"]}}"#,
            "169.254.169.254",
        );
        assert!(matches!(result, query_ext::QueryResult::Denied { .. }));
    }

    #[test]
    fn explicit_deny_does_not_match_sibling_prefix() {
        let dir = tempfile::tempdir().expect("tempdir");
        let denied = dir.path().join("blocked");
        let sibling = dir.path().join("blocked-backup");

        assert!(matching_deny_path(&sibling, &[denied]).is_none());
    }

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
            std::ffi::OsString::from("issue"),
            std::ffi::OsString::from("comment"),
            std::ffi::OsString::from("1052"),
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

    #[cfg(target_os = "linux")]
    mod stale_file_grants {
        use super::super::*;
        use nono::FsCapability;
        use tempfile::tempdir;

        /// Build a file grant + state, then atomically replace the file
        /// (write temp + rename), the same pattern systemd-resolved uses on
        /// /run/systemd/resolve/stub-resolv.conf.
        fn replaced_file_fixture() -> (
            tempfile::TempDir,
            std::path::PathBuf,
            CapabilitySet,
            sandbox_state::SandboxState,
        ) {
            let dir = tempdir().expect("tempdir");
            let target = dir.path().join("conf");
            std::fs::write(&target, "generation-1").expect("write target");

            let mut caps = CapabilitySet::new();
            caps.add_fs(FsCapability::new_file(&target, AccessMode::Read).expect("file cap"));
            let state = sandbox_state::SandboxState::from_caps(&caps, &[], &[], &[]);

            let tmp = dir.path().join("conf.tmp");
            std::fs::write(&tmp, "generation-2").expect("write tmp");
            std::fs::rename(&tmp, &target).expect("atomic replace");

            (dir, target, caps, state)
        }

        #[test]
        fn detect_ignores_fresh_and_in_place_rewritten_grants() {
            let dir = tempdir().expect("tempdir");
            let target = dir.path().join("conf");
            std::fs::write(&target, "generation-1").expect("write target");

            let mut caps = CapabilitySet::new();
            caps.add_fs(FsCapability::new_file(&target, AccessMode::Read).expect("file cap"));
            let state = sandbox_state::SandboxState::from_caps(&caps, &[], &[], &[]);

            assert!(detect_stale_file_grants(&state).is_empty());

            // In-place rewrite keeps the inode; the Landlock rule still applies.
            std::fs::write(&target, "generation-2").expect("rewrite in place");
            assert!(detect_stale_file_grants(&state).is_empty());
        }

        #[test]
        fn detect_flags_atomically_replaced_grant() {
            let (_dir, _target, _caps, state) = replaced_file_fixture();

            let stale = detect_stale_file_grants(&state);
            assert_eq!(stale.len(), 1);
            assert!(
                stale[0].current_id.is_some(),
                "replaced file still exists, just with a new inode"
            );
            assert_ne!(Some(stale[0].grant_id), stale[0].current_id);
        }

        #[test]
        fn detect_flags_removed_grant_target() {
            let dir = tempdir().expect("tempdir");
            let target = dir.path().join("conf");
            std::fs::write(&target, "generation-1").expect("write target");

            let mut caps = CapabilitySet::new();
            caps.add_fs(FsCapability::new_file(&target, AccessMode::Read).expect("file cap"));
            let state = sandbox_state::SandboxState::from_caps(&caps, &[], &[], &[]);

            std::fs::remove_file(&target).expect("remove target");

            let stale = detect_stale_file_grants(&state);
            assert_eq!(stale.len(), 1);
            assert_eq!(stale[0].current_id, None);
        }

        #[test]
        fn stale_grant_with_no_other_coverage_becomes_denied() {
            let (_dir, target, caps, state) = replaced_file_fixture();
            let stale = detect_stale_file_grants(&state);

            let result =
                query_ext::query_path(&target, AccessMode::Read, &caps, &[]).expect("query");
            assert!(
                matches!(result, query_ext::QueryResult::Allowed { .. }),
                "path-spec reasoning alone reports ALLOWED — the misleading answer"
            );

            let corrected =
                apply_file_grant_staleness(result, &target, AccessMode::Read, &caps, &[], &stale)
                    .expect("staleness pass");

            match corrected {
                query_ext::QueryResult::Denied {
                    reason,
                    details,
                    matching_capability,
                    ..
                } => {
                    assert_eq!(reason, "stale_file_grant");
                    assert!(
                        details
                            .as_deref()
                            .is_some_and(|d| d.contains("replaced after sandbox start"))
                    );
                    assert!(matching_capability.is_some());
                }
                other => panic!("expected stale_file_grant denial, got {other:?}"),
            }
        }

        #[test]
        fn stale_grant_covered_by_directory_grant_stays_allowed_with_warning() {
            let (dir, target, mut caps, state) = replaced_file_fixture();
            // The proposed policy fix: a directory grant survives replacement.
            caps.add_fs(FsCapability::new_dir(dir.path(), AccessMode::Read).expect("dir cap"));
            let stale = detect_stale_file_grants(&state);

            let result =
                query_ext::query_path(&target, AccessMode::Read, &caps, &[]).expect("query");
            let corrected =
                apply_file_grant_staleness(result, &target, AccessMode::Read, &caps, &[], &stale)
                    .expect("staleness pass");

            match corrected {
                query_ext::QueryResult::Allowed {
                    granted_path,
                    warning,
                    ..
                } => {
                    let dir_canonical = dir
                        .path()
                        .canonicalize()
                        .expect("canonicalize dir")
                        .display()
                        .to_string();
                    assert_eq!(granted_path.as_deref(), Some(dir_canonical.as_str()));
                    assert!(
                        warning.as_deref().is_some_and(|w| w.contains("stale")),
                        "warning must mention the stale file grant, got {warning:?}"
                    );
                }
                other => panic!("expected allowed-with-warning, got {other:?}"),
            }
        }

        #[test]
        fn results_not_matching_a_stale_grant_pass_through_unchanged() {
            let (_dir, target, caps, _state) = replaced_file_fixture();

            let result =
                query_ext::query_path(&target, AccessMode::Read, &caps, &[]).expect("query");
            let corrected = apply_file_grant_staleness(
                result.clone(),
                &target,
                AccessMode::Read,
                &caps,
                &[],
                &[], // nothing stale
            )
            .expect("staleness pass");

            match (result, corrected) {
                (
                    query_ext::QueryResult::Allowed {
                        granted_path: before,
                        ..
                    },
                    query_ext::QueryResult::Allowed {
                        granted_path: after,
                        warning,
                        ..
                    },
                ) => {
                    assert_eq!(before, after);
                    assert!(warning.is_none());
                }
                other => panic!("expected allowed passthrough, got {other:?}"),
            }
        }
    }

    #[test]
    fn command_policy_query_reports_argv_allow() {
        let policies = gh_policy();
        let args = vec![
            std::ffi::OsString::from("issue"),
            std::ffi::OsString::from("view"),
            std::ffi::OsString::from("1052"),
        ];

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
