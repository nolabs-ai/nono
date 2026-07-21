static PASSTHROUGH_INTERCEPT_ACTION: crate::command_policy::InterceptActionConfig =
    crate::command_policy::InterceptActionConfig::Passthrough;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) struct ResolvedInterceptAction<'a> {
    pub(super) action: &'a crate::command_policy::InterceptActionConfig,
    pub(super) rule_args: Option<&'a [String]>,
    /// Per-rule sandbox override for this matched invocation (passthrough).
    /// `None` for the fallthrough and rules without an override.
    pub(super) sandbox: Option<&'a crate::command_policy::CommandSandboxConfig>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl<'a> ResolvedInterceptAction<'a> {
    pub(super) fn passthrough() -> Self {
        Self {
            action: &PASSTHROUGH_INTERCEPT_ACTION,
            rule_args: None,
            sandbox: None,
        }
    }

    pub(super) fn rule_label(&self) -> String {
        match self.rule_args {
            Some([]) => "<catch-all>".to_string(),
            Some(args) => args.join(" "),
            None => "passthrough".to_string(),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn resolve_intercept_action<'a>(
    command_config: &'a crate::command_policy::CommandPolicyConfig,
    argv: &[Vec<u8>],
) -> ResolvedInterceptAction<'a> {
    // argv[0] is the synthesised command name; match against argv[1..].
    let shim_args: Vec<&[u8]> = argv.iter().skip(1).map(|v| v.as_slice()).collect();

    for rule in &command_config.intercept {
        if rule.args.is_empty() {
            return ResolvedInterceptAction {
                action: &rule.action,
                rule_args: Some(&rule.args),
                sandbox: rule.sandbox.as_ref(),
            };
        }
        if intercept_args_match(&rule.args, &shim_args) {
            return ResolvedInterceptAction {
                action: &rule.action,
                rule_args: Some(&rule.args),
                sandbox: rule.sandbox.as_ref(),
            };
        }
    }

    ResolvedInterceptAction::passthrough()
}

fn intercept_args_match(expected_args: &[String], shim_args: &[&[u8]]) -> bool {
    expected_args.is_empty()
        || (shim_args.len() >= expected_args.len()
            && shim_args.windows(expected_args.len()).any(|window| {
                expected_args
                    .iter()
                    .zip(window.iter())
                    .all(|(expected, actual)| expected.as_bytes() == *actual)
            }))
}

/// Resolve the env-expanded helper path and forwarded extra args for an `exec`
/// intercept action's `command`.
///
/// Returns `(helper_path, extra_args)` where `helper_path` is `command[0]`
/// after `$VAR` expansion (used as the lookup key into the plan's pre-resolved
/// `exec_helpers` map) and `extra_args` are `command[1..]` after `$VAR`
/// expansion, to be inserted ahead of the forwarded original args. Platform
/// dispatch resolves the actual `ResolvedCommandBinary` from its own state map
/// using `helper_path`, so this stays platform-agnostic.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn resolve_exec_command(
    command: &[String],
) -> nono::Result<(std::path::PathBuf, Vec<Vec<u8>>)> {
    let helper_raw = command.first().ok_or_else(|| {
        nono::NonoError::SandboxInit("tool-sandbox exec action has empty command".to_string())
    })?;
    let helper_path = std::path::PathBuf::from(crate::policy::expand_env_vars_strict(helper_raw)?);
    if !helper_path.is_absolute() {
        return Err(nono::NonoError::SandboxInit(format!(
            "tool-sandbox exec helper must be an absolute path; got '{}'",
            helper_path.display()
        )));
    }
    let mut extra_args = Vec::with_capacity(command.len().saturating_sub(1));
    for arg in command.iter().skip(1) {
        extra_args.push(crate::policy::expand_env_vars_strict(arg)?.into_bytes());
    }
    Ok((helper_path, extra_args))
}

/// Looks up the pre-resolved binary rather than re-resolving it, to reuse the
/// TOCTOU-protected identity captured at plan-build time.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn resolve_exec_helper<'a>(
    exec_helpers: &'a std::collections::BTreeMap<
        std::path::PathBuf,
        crate::command_policy::ResolvedCommandBinary,
    >,
    command: &[String],
) -> nono::Result<(
    &'a crate::command_policy::ResolvedCommandBinary,
    Vec<Vec<u8>>,
)> {
    let (helper_path, extra_args) = resolve_exec_command(command)?;
    let helper = exec_helpers.get(&helper_path).ok_or_else(|| {
        nono::NonoError::SandboxInit(format!(
            "tool-sandbox exec helper not pre-resolved: {}",
            helper_path.display()
        ))
    })?;
    Ok((helper, extra_args))
}

/// True if any command whose `exec` intercept resolves to `canonical_helper`
/// opts into `allow_writable_executable`.
///
/// Expansion/canonicalize failures resolve to "not exempted" rather than
/// erroring, so an unrelated command's bad env var can't abort plan build.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn command_referencing_exec_helper_allows_writable(
    config: &crate::command_policy::CommandPoliciesConfig,
    canonical_helper: &std::path::Path,
) -> bool {
    config.commands.values().any(|command| {
        if !command.allow_writable_executable {
            return false;
        }
        command.intercept.iter().any(|rule| {
            let crate::command_policy::InterceptActionConfig::Exec {
                command: exec_command,
            } = &rule.action
            else {
                return false;
            };
            let Some(helper_raw) = exec_command.first() else {
                return false;
            };
            crate::policy::expand_env_vars_strict(helper_raw)
                .ok()
                .and_then(|expanded| std::path::PathBuf::from(expanded).canonicalize().ok())
                .is_some_and(|canonical| canonical == canonical_helper)
        })
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InvocationPolicyOutcome {
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
pub(crate) fn evaluate_invocation_policy(
    policy: &crate::command_policy::InvocationPolicyConfig,
    argv: &[Vec<u8>],
    env: &[Vec<u8>],
) -> nono::Result<InvocationPolicyOutcome> {
    let args = invocation_args(argv)?;
    let env = invocation_env(env)?;

    for (index, rule) in policy.deny.iter().enumerate() {
        if invocation_rule_matches(rule, &args, &env) {
            return Ok(InvocationPolicyOutcome::Deny {
                reason: rule
                    .reason
                    .clone()
                    .unwrap_or_else(|| format!("invocation_policy.deny[{index}]")),
            });
        }
    }
    for (index, rule) in policy.approve.iter().enumerate() {
        if invocation_rule_matches(rule, &args, &env) {
            return Ok(InvocationPolicyOutcome::Approve {
                backend: rule.backend.clone(),
                timeout_secs: rule.timeout_secs,
                reason: rule.reason.clone(),
                rule_label: format!("invocation_policy.approve[{index}]"),
            });
        }
    }
    for rule in &policy.allow {
        if invocation_rule_matches(rule, &args, &env) {
            return Ok(InvocationPolicyOutcome::Allow);
        }
    }

    Ok(match &policy.default {
        crate::command_policy::PolicyDecisionConfig::Decision(
            crate::command_policy::PolicyDecision::Allow,
        ) => InvocationPolicyOutcome::Allow,
        crate::command_policy::PolicyDecisionConfig::Decision(
            crate::command_policy::PolicyDecision::Deny,
        ) => InvocationPolicyOutcome::Deny {
            reason: "invocation_policy.default deny".to_string(),
        },
        crate::command_policy::PolicyDecisionConfig::Decision(
            crate::command_policy::PolicyDecision::Approve,
        ) => InvocationPolicyOutcome::Approve {
            backend: None,
            timeout_secs: None,
            reason: None,
            rule_label: "invocation_policy.default".to_string(),
        },
        crate::command_policy::PolicyDecisionConfig::RoutedApproval(route) => {
            match route.decision {
                crate::command_policy::PolicyDecision::Allow => InvocationPolicyOutcome::Allow,
                crate::command_policy::PolicyDecision::Deny => InvocationPolicyOutcome::Deny {
                    reason: "invocation_policy.default deny".to_string(),
                },
                crate::command_policy::PolicyDecision::Approve => {
                    InvocationPolicyOutcome::Approve {
                        backend: route.backend.clone(),
                        timeout_secs: route.timeout_secs,
                        reason: None,
                        rule_label: "invocation_policy.default".to_string(),
                    }
                }
            }
        }
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn invocation_args(argv: &[Vec<u8>]) -> nono::Result<Vec<String>> {
    argv.iter()
        .skip(1)
        .map(|arg| {
            std::str::from_utf8(arg).map(str::to_owned).map_err(|_| {
                nono::NonoError::SandboxInit("tool-sandbox argv is not UTF-8".to_string())
            })
        })
        .collect()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn invocation_env(env: &[Vec<u8>]) -> nono::Result<std::collections::BTreeMap<String, String>> {
    let mut result = std::collections::BTreeMap::new();
    for entry in env {
        let Some((name, value)) = split_env_entry_for_policy(entry) else {
            continue;
        };
        let name = std::str::from_utf8(name).map_err(|_| {
            nono::NonoError::SandboxInit("tool-sandbox env name is not UTF-8".to_string())
        })?;
        let value = std::str::from_utf8(value).map_err(|_| {
            nono::NonoError::SandboxInit("tool-sandbox env value is not UTF-8".to_string())
        })?;
        result.insert(name.to_string(), value.to_string());
    }
    Ok(result)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn split_env_entry_for_policy(entry: &[u8]) -> Option<(&[u8], &[u8])> {
    let pos = entry.iter().position(|b| *b == b'=')?;
    Some((&entry[..pos], &entry[pos.saturating_add(1)..]))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn proxy_port_from_env(env: &[Vec<u8>]) -> Option<u16> {
    env.iter().find_map(|entry| {
        let (name, value) = split_env_entry_for_policy(entry)?;
        if !matches!(
            name,
            b"HTTPS_PROXY" | b"HTTP_PROXY" | b"https_proxy" | b"http_proxy"
        ) {
            return None;
        }
        let value = std::str::from_utf8(value).ok()?;
        loopback_http_proxy_port(value)
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn loopback_http_proxy_port(value: &str) -> Option<u16> {
    let parsed = url::Url::parse(value).ok()?;
    if parsed.scheme() != "http" {
        return None;
    }
    let host = parsed.host_str()?;
    if !matches!(host, "127.0.0.1" | "localhost" | "::1") {
        return None;
    }
    parsed.port()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn load_supervisor_credential_source(
    source: &crate::command_policy::AmbientCredentialSourceConfig,
) -> nono::Result<Vec<u8>> {
    match source {
        crate::command_policy::AmbientCredentialSourceConfig::Keystore { key } => {
            let secret = nono::keystore::load_secret_by_ref(nono::keystore::DEFAULT_SERVICE, key)?;
            Ok(secret.as_bytes().to_vec())
        }
        crate::command_policy::AmbientCredentialSourceConfig::Command {
            command,
            args,
            timeout_secs,
        } => load_command_credential_source(command, args, *timeout_secs),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn load_command_credential_source(
    command: &str,
    args: &[String],
    timeout_secs: Option<u64>,
) -> nono::Result<Vec<u8>> {
    let timeout = std::time::Duration::from_secs(timeout_secs.unwrap_or(30));
    let mut child = std::process::Command::new(command)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|err| {
            nono::NonoError::SandboxInit(format!(
                "failed to start supervisor credential source '{command}': {err}"
            ))
        })?;

    let start = std::time::Instant::now();
    loop {
        if child
            .try_wait()
            .map_err(|err| {
                nono::NonoError::SandboxInit(format!(
                    "failed to wait for supervisor credential source '{command}': {err}"
                ))
            })?
            .is_some()
        {
            break;
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(nono::NonoError::SandboxInit(format!(
                "supervisor credential source '{command}' timed out after {}s",
                timeout.as_secs()
            )));
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }

    let output = child.wait_with_output().map_err(|err| {
        nono::NonoError::SandboxInit(format!(
            "failed to collect supervisor credential source '{command}': {err}"
        ))
    })?;
    if !output.status.success() {
        return Err(nono::NonoError::SandboxInit(format!(
            "supervisor credential source '{command}' failed with exit code {}",
            output
                .status
                .code()
                .map_or_else(|| "unknown".to_string(), |code| code.to_string())
        )));
    }
    let mut value = output.stdout;
    while matches!(value.last(), Some(b'\r' | b'\n')) {
        value.pop();
    }
    Ok(value)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn invocation_rule_matches(
    rule: &crate::command_policy::InvocationRuleConfig,
    args: &[String],
    env: &std::collections::BTreeMap<String, String>,
) -> bool {
    if let Some(argv) = &rule.argv
        && !argv_matcher_matches(argv, args)
    {
        return false;
    }
    for (name, matcher) in &rule.env {
        let Some(value) = env.get(name) else {
            return false;
        };
        if let Some(expected) = &matcher.equals
            && value != expected
        {
            return false;
        }
        if !matcher.one_of.is_empty() && !matcher.one_of.iter().any(|expected| expected == value) {
            return false;
        }
    }
    true
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn argv_matcher_matches(
    matcher: &crate::command_policy::ArgvMatcherConfig,
    args: &[String],
) -> bool {
    if let Some(exact) = &matcher.exact {
        return args == exact.as_slice();
    }
    if let Some(prefix) = &matcher.prefix {
        return args.len() >= prefix.len()
            && prefix
                .iter()
                .zip(args.iter())
                .all(|(expected, actual)| expected == actual);
    }
    if let Some(contains) = &matcher.contains {
        return contains.is_empty()
            || (args.len() >= contains.len()
                && args
                    .windows(contains.len())
                    .any(|window| window == contains.as_slice()));
    }
    false
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) struct ResolvedApprovalRoute {
    pub(super) backend: String,
    pub(super) timeout_secs: u64,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn resolve_approval_route(
    config: &crate::command_policy::CommandPoliciesConfig,
    backend: Option<&str>,
    timeout_secs: Option<u64>,
) -> nono::Result<ResolvedApprovalRoute> {
    let backend_name = backend
        .or(config.approval_defaults.backend.as_deref())
        .ok_or_else(|| nono::NonoError::BlockedCommand {
            command: "approval".to_string(),
            reason: "missing approval backend".to_string(),
        })?;
    let Some(backend_config) = config.approval_backends.get(backend_name) else {
        return Err(nono::NonoError::BlockedCommand {
            command: "approval".to_string(),
            reason: format!("unknown approval backend '{backend_name}'"),
        });
    };
    Ok(ResolvedApprovalRoute {
        backend: backend_name.to_string(),
        timeout_secs: timeout_secs
            .or(backend_config.timeout_secs)
            .or(config.approval_defaults.timeout_secs)
            .unwrap_or(60),
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn policy_credential_names(
    policy: &crate::command_policy::CommandSandboxConfig,
) -> Vec<&str> {
    let mut names = Vec::with_capacity(policy.use_credentials.len() + policy.credentials.len());
    names.extend(policy.use_credentials.iter().map(String::as_str));
    names.extend(
        policy
            .credentials
            .iter()
            .map(|credential| match credential {
                crate::command_policy::CommandCredentialGrantConfig::Name(name) => name.as_str(),
                crate::command_policy::CommandCredentialGrantConfig::Policy(policy) => {
                    policy.name.as_str()
                }
            }),
    );
    names
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn reject_unenforced_resources(
    command: &str,
    policy: &crate::command_policy::CommandSandboxConfig,
) -> nono::Result<()> {
    if policy.resources.is_some() {
        return Err(nono::NonoError::BlockedCommand {
            command: command.to_string(),
            reason:
                "sandbox.resources is parsed by tool-sandbox Schema 2 but not yet enforced by this runtime"
                    .to_string(),
        });
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn shim_error_message(error: &nono::NonoError) -> String {
    match error {
        nono::NonoError::BlockedCommand { reason, .. }
            if reason.starts_with("Tool execution chain denied.") =>
        {
            reason.clone()
        }
        _ => error.to_string(),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn format_tool_chain_denial(
    command: &str,
    caller_command: Option<&str>,
    profile_name: Option<&str>,
    error: &nono::NonoError,
) -> Option<String> {
    let nono::NonoError::BlockedCommand { reason, .. } = error else {
        return None;
    };

    let profile = profile_name
        .filter(|name| !name.is_empty())
        .map(|name| format!(" in profile '{name}'"))
        .unwrap_or_default();

    if let Some(caller) = caller_command {
        if reason.as_str() == format!("{caller}.can_use missing") {
            return Some(format!(
                "Tool execution chain denied. '{command}' is blocked because tool '{caller}' is not allowed to invoke it{profile}. Policy: command_policies.commands.\"{caller}\".can_use must include \"{command}\"."
            ));
        }
        if reason.as_str() == format!("from.{caller} explicit deny") {
            return Some(format!(
                "Tool execution chain denied. '{command}' is blocked because the edge from tool '{caller}' is explicitly denied{profile}. Policy: command_policies.commands.\"{command}\".from.\"{caller}\" is \"deny\"."
            ));
        }
        if reason.as_str() == format!("missing from.{caller}") {
            return Some(format!(
                "Tool execution chain denied. '{command}' is blocked because no policy edge from tool '{caller}' is defined{profile}. Policy: command_policies.commands.\"{command}\".from.\"{caller}\" is missing."
            ));
        }
    }

    match reason.as_str() {
        "from.session explicit deny" => Some(format!(
            "Tool execution chain denied. '{command}' is blocked because direct session invocation is explicitly denied{profile}. Policy: command_policies.commands.\"{command}\".from.session is \"deny\"."
        )),
        "missing session sandbox" => Some(format!(
            "Tool execution chain denied. '{command}' is blocked because no direct session sandbox is defined{profile}. Policy: define command_policies.commands.\"{command}\".sandbox or command_policies.commands.\"{command}\".from.session."
        )),
        _ => None,
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod intercept_tests {
    use super::*;
    use crate::command_policy::{
        ApprovalBackendConfig, ApprovalBackendType, ArgvMatcherConfig, CommandPoliciesConfig,
        CommandPolicyConfig, CommandResourceConfig, CommandSandboxConfig, EnvMatcherConfig,
        InterceptActionConfig, InterceptRuleConfig, InvocationPolicyConfig, InvocationRuleConfig,
        PolicyDecision, PolicyDecisionConfig,
    };
    use std::collections::BTreeMap;

    #[test]
    fn resolve_intercept_action_tracks_matched_rule_label() {
        let config = CommandPolicyConfig {
            intercept: vec![InterceptRuleConfig {
                args: vec!["push".to_string(), "--force".to_string()],
                action: InterceptActionConfig::Approve { timeout_secs: None },
                sandbox: None,
            }],
            ..CommandPolicyConfig::default()
        };
        let argv = vec![b"git".to_vec(), b"push".to_vec(), b"--force".to_vec()];

        let resolved = resolve_intercept_action(&config, &argv);

        assert_eq!(resolved.rule_label(), "push --force");
        assert!(matches!(
            resolved.action,
            InterceptActionConfig::Approve { .. }
        ));
    }

    #[test]
    fn resolve_intercept_action_matches_after_leading_global_args() {
        let config = CommandPolicyConfig {
            intercept: vec![InterceptRuleConfig {
                args: vec!["push".to_string(), "--force".to_string()],
                action: InterceptActionConfig::Approve { timeout_secs: None },
                sandbox: None,
            }],
            ..CommandPolicyConfig::default()
        };
        let argv = vec![
            b"git".to_vec(),
            b"-c".to_vec(),
            b"foo=bar".to_vec(),
            b"push".to_vec(),
            b"--force".to_vec(),
        ];

        let resolved = resolve_intercept_action(&config, &argv);

        assert_eq!(resolved.rule_label(), "push --force");
        assert!(matches!(
            resolved.action,
            InterceptActionConfig::Approve { .. }
        ));
    }

    #[test]
    fn resolve_intercept_action_falls_through_when_rule_sequence_is_absent() {
        let config = CommandPolicyConfig {
            intercept: vec![InterceptRuleConfig {
                args: vec!["push".to_string(), "--force".to_string()],
                action: InterceptActionConfig::Approve { timeout_secs: None },
                sandbox: None,
            }],
            ..CommandPolicyConfig::default()
        };
        let argv = vec![
            b"git".to_vec(),
            b"-c".to_vec(),
            b"foo=bar".to_vec(),
            b"pull".to_vec(),
            b"--force".to_vec(),
        ];

        let resolved = resolve_intercept_action(&config, &argv);

        assert_eq!(resolved.rule_label(), "passthrough");
        assert!(matches!(
            resolved.action,
            InterceptActionConfig::Passthrough
        ));
    }

    #[test]
    fn resolve_intercept_action_labels_catch_all_rule() {
        let config = CommandPolicyConfig {
            intercept: vec![InterceptRuleConfig {
                args: Vec::new(),
                action: InterceptActionConfig::Approve { timeout_secs: None },
                sandbox: None,
            }],
            ..CommandPolicyConfig::default()
        };
        let argv = vec![b"git".to_vec(), b"status".to_vec()];

        let resolved = resolve_intercept_action(&config, &argv);

        assert_eq!(resolved.rule_label(), "<catch-all>");
        assert!(matches!(
            resolved.action,
            InterceptActionConfig::Approve { .. }
        ));
    }

    #[test]
    fn resolve_intercept_action_exposes_rule_sandbox_override() {
        let override_sandbox = CommandSandboxConfig {
            use_credentials: vec!["github".to_string()],
            ..CommandSandboxConfig::default()
        };
        let config = CommandPolicyConfig {
            intercept: vec![
                InterceptRuleConfig {
                    args: vec!["with-override".to_string()],
                    action: InterceptActionConfig::Passthrough,
                    sandbox: Some(override_sandbox.clone()),
                },
                InterceptRuleConfig {
                    args: vec!["no-override".to_string()],
                    action: InterceptActionConfig::Passthrough,
                    sandbox: None,
                },
            ],
            ..CommandPolicyConfig::default()
        };

        let with = resolve_intercept_action(&config, &[b"git".to_vec(), b"with-override".to_vec()]);
        assert_eq!(with.sandbox, Some(&override_sandbox));

        let without =
            resolve_intercept_action(&config, &[b"git".to_vec(), b"no-override".to_vec()]);
        assert_eq!(without.sandbox, None);

        // Fallthrough (no matching rule) also has no override.
        let fallthrough = resolve_intercept_action(&config, &[b"git".to_vec(), b"other".to_vec()]);
        assert_eq!(fallthrough.sandbox, None);
    }

    #[test]
    fn invocation_policy_denies_before_broader_allow() -> nono::Result<()> {
        let policy = InvocationPolicyConfig {
            default: PolicyDecisionConfig::Decision(PolicyDecision::Deny),
            deny: vec![InvocationRuleConfig {
                argv: Some(ArgvMatcherConfig {
                    prefix: Some(vec!["apply".to_string()]),
                    exact: None,
                    contains: None,
                }),
                env: BTreeMap::new(),
                backend: None,
                reason: Some("mutating command".to_string()),
                timeout_secs: None,
            }],
            allow: vec![InvocationRuleConfig {
                argv: Some(ArgvMatcherConfig {
                    prefix: Some(vec!["apply".to_string(), "-refresh-only".to_string()]),
                    exact: None,
                    contains: None,
                }),
                env: BTreeMap::new(),
                backend: None,
                reason: None,
                timeout_secs: None,
            }],
            approve: Vec::new(),
        };
        let argv = vec![
            b"terraform".to_vec(),
            b"apply".to_vec(),
            b"-refresh-only".to_vec(),
        ];
        let outcome = evaluate_invocation_policy(&policy, &argv, &[])?;

        assert_eq!(
            outcome,
            InvocationPolicyOutcome::Deny {
                reason: "mutating command".to_string()
            }
        );
        Ok(())
    }

    #[test]
    fn invocation_policy_matches_env_and_contains_argv() -> nono::Result<()> {
        let mut env_match = BTreeMap::new();
        env_match.insert(
            "ENVIRONMENT".to_string(),
            EnvMatcherConfig {
                one_of: vec!["STAGING".to_string(), "PROD".to_string()],
                equals: None,
            },
        );
        let policy = InvocationPolicyConfig {
            default: PolicyDecisionConfig::Decision(PolicyDecision::Deny),
            allow: vec![InvocationRuleConfig {
                argv: Some(ArgvMatcherConfig {
                    contains: Some(vec!["--repo".to_string(), "acme/widget".to_string()]),
                    exact: None,
                    prefix: None,
                }),
                env: env_match,
                backend: None,
                reason: None,
                timeout_secs: None,
            }],
            deny: Vec::new(),
            approve: Vec::new(),
        };
        let argv = vec![
            b"gh".to_vec(),
            b"issue".to_vec(),
            b"list".to_vec(),
            b"--repo".to_vec(),
            b"acme/widget".to_vec(),
        ];
        let env = vec![b"ENVIRONMENT=STAGING".to_vec()];
        let outcome = evaluate_invocation_policy(&policy, &argv, &env)?;

        assert_eq!(outcome, InvocationPolicyOutcome::Allow);
        Ok(())
    }

    #[test]
    fn non_terminal_approval_route_resolves() {
        let mut config = CommandPoliciesConfig::default();
        config.approval_defaults.backend = Some("security-review".to_string());
        config.approval_backends.insert(
            "security-review".to_string(),
            ApprovalBackendConfig {
                backend_type: ApprovalBackendType::Webhook,
                url: Some("https://approvals.example/tool-sandbox".to_string()),
                timeout_secs: Some(30),
                mode: None,
                backends: Vec::new(),
            },
        );

        let route = resolve_approval_route(&config, None, None).expect("approval route");

        assert_eq!(route.backend, "security-review");
        assert_eq!(route.timeout_secs, 30);
    }

    #[test]
    fn resources_fail_closed_until_runtime_enforcement_exists() {
        let policy = CommandSandboxConfig {
            resources: Some(CommandResourceConfig::default()),
            ..CommandSandboxConfig::default()
        };

        let err = reject_unenforced_resources("terraform", &policy)
            .err()
            .map(|err| err.to_string());

        assert!(matches!(
            err,
            Some(message)
                if message.contains("sandbox.resources is parsed by tool-sandbox Schema 2 but not yet enforced")
        ));
    }

    #[test]
    fn resolve_exec_command_expands_helper_and_extra_args() {
        let _lock = match crate::test_env::ENV_LOCK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let var = "NONO_TEST_EXEC_LIBEXEC";
        let _env = crate::test_env::EnvVarGuard::set_all(&[(var, "/opt/vendor/libexec")]);
        let command = vec![
            format!("${var}/gh-wrapper"),
            format!("${var}/data"),
            "literal".to_string(),
        ];
        let (helper, extra) = resolve_exec_command(&command).expect("resolve");
        assert_eq!(
            helper,
            std::path::PathBuf::from("/opt/vendor/libexec/gh-wrapper")
        );
        let rendered: Vec<String> = extra
            .iter()
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect();
        assert_eq!(rendered, vec!["/opt/vendor/libexec/data", "literal"]);
    }

    #[test]
    fn resolve_exec_command_rejects_empty_command() {
        assert!(resolve_exec_command(&[]).is_err());
    }

    #[test]
    fn resolve_exec_command_rejects_relative_helper() {
        assert!(resolve_exec_command(&["relative/helper".to_string()]).is_err());
    }
}
