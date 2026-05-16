//! Ephemeral Tool Isolation profile model and validation.
//!
//! This module deliberately stops at profile semantics. Runtime resolution
//! (PATH lookup, inode capture, Landlock probing, and child launch) builds on
//! this typed config after profile inheritance has been resolved.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
#[cfg(any(test, target_os = "linux", target_os = "macos"))]
use std::ffi::OsString;
#[cfg(any(test, target_os = "linux", target_os = "macos"))]
use std::fs;
#[cfg(any(test, target_os = "linux", target_os = "macos"))]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
#[cfg(any(test, target_os = "linux", target_os = "macos"))]
use std::path::PathBuf;

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommandPolicyValidationScope {
    Syntax,
    Resolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CommandPolicyActivation {
    Inactive,
    Active,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct CommandPolicyFinding {
    pub code: &'static str,
    pub message: String,
}

impl CommandPolicyFinding {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct CommandPolicyValidationReport {
    pub activation: CommandPolicyActivation,
    pub errors: Vec<CommandPolicyFinding>,
    pub warnings: Vec<CommandPolicyFinding>,
    pub info: Vec<CommandPolicyFinding>,
}

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedCommandBinaries {
    pub commands: BTreeMap<String, ResolvedCommandBinary>,
    pub warnings: Vec<CommandPolicyFinding>,
}

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedCommandBinary {
    pub name: String,
    pub canonical_path: PathBuf,
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mtime_nanos: i128,
    pub sha256: String,
    pub duplicate_paths: Vec<PathBuf>,
    pub shape: ResolvedExecutableShape,
}

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ResolvedExecutableKind {
    Elf,
    ShebangScript,
    Other,
}

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ResolvedExecutableShape {
    pub kind: ResolvedExecutableKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interpreter: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interpreter_args: Vec<String>,
}

impl Default for CommandPolicyValidationReport {
    fn default() -> Self {
        Self {
            activation: CommandPolicyActivation::Inactive,
            errors: Vec::new(),
            warnings: Vec::new(),
            info: Vec::new(),
        }
    }
}

impl CommandPolicyValidationReport {
    #[cfg(test)]
    pub(crate) fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }

    pub(crate) fn into_result(self) -> nono::Result<()> {
        if self.errors.is_empty() {
            return Ok(());
        }

        let mut messages = Vec::with_capacity(self.errors.len());
        for finding in self.errors {
            messages.push(format!("{}: {}", finding.code, finding.message));
        }

        Err(nono::NonoError::ProfileParse(format!(
            "invalid command_policies: {}",
            messages.join("; ")
        )))
    }

    fn error(&mut self, code: &'static str, message: impl Into<String>) {
        self.errors.push(CommandPolicyFinding::new(code, message));
    }

    fn warning(&mut self, code: &'static str, message: impl Into<String>) {
        self.warnings.push(CommandPolicyFinding::new(code, message));
    }

    fn info(&mut self, code: &'static str, message: impl Into<String>) {
        self.info.push(CommandPolicyFinding::new(code, message));
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommandPoliciesConfig {
    #[serde(default)]
    pub executable_dirs: Vec<String>,
    #[serde(default)]
    pub session_can_use: Vec<String>,
    #[serde(default)]
    pub credentials: BTreeMap<String, CommandCredentialConfig>,
    #[serde(default)]
    pub commands: BTreeMap<String, CommandPolicyConfig>,
    #[serde(default)]
    pub deny_direct_exec_bypass: Vec<String>,
}

impl CommandPoliciesConfig {
    pub(crate) fn is_active(&self) -> bool {
        !self.commands.is_empty()
    }

    fn has_non_command_fields(&self) -> bool {
        !self.executable_dirs.is_empty()
            || !self.session_can_use.is_empty()
            || !self.credentials.is_empty()
            || !self.deny_direct_exec_bypass.is_empty()
    }

    pub(crate) fn merge_child(&self, child: &Self) -> Self {
        let mut credentials = self.credentials.clone();
        for (name, credential) in &child.credentials {
            credentials
                .entry(name.clone())
                .or_insert_with(|| credential.clone());
        }

        let mut commands = self.commands.clone();
        for (name, child_command) in &child.commands {
            commands
                .entry(name.clone())
                .and_modify(|base_command| {
                    *base_command = base_command.merge_child(child_command);
                })
                .or_insert_with(|| child_command.clone());
        }

        Self {
            executable_dirs: dedup_append(&self.executable_dirs, &child.executable_dirs),
            session_can_use: dedup_append(&self.session_can_use, &child.session_can_use),
            credentials,
            commands,
            deny_direct_exec_bypass: dedup_append(
                &self.deny_direct_exec_bypass,
                &child.deny_direct_exec_bypass,
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommandCredentialConfig {
    #[serde(rename = "type")]
    pub credential_type: CommandCredentialType,
    #[serde(default)]
    pub socket: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub env_var: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum CommandCredentialType {
    SshAgent,
    RawFile,
}

/// Action to take when an [`InterceptRuleConfig`] matches.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InterceptActionConfig {
    /// Fork the child and stream stdio normally (default when no rule matches).
    #[default]
    Passthrough,
    /// Return `stdout` to the shim immediately; no child is forked; exit code 0.
    Respond {
        /// Static stdout payload returned to the caller.
        stdout: String,
    },
    /// Fork the child, capture its stdout/stderr, and return the buffered output
    /// in the shim response. Primary use: credential-bearing output scanned by
    /// the token broker before reaching the agent.
    Capture,
    /// Block and route through `ApprovalBackend` before forking the child.
    /// On denial the shim receives an error response; no child is forked.
    Approve {
        /// Per-rule approval timeout. `None` uses the global default.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout_secs: Option<u64>,
    },
}

/// A sub-command mediation rule on a [`CommandPolicyConfig`].
///
/// Rules are evaluated in order; the first match wins. An empty `args` list
/// is a catch-all and must appear last in the list. If no rule matches the
/// default action is `Passthrough`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterceptRuleConfig {
    /// Argument prefix to match against argv[1..] of the shim invocation.
    /// An empty list is a catch-all.
    pub args: Vec<String>,
    /// Action to take when this rule matches.
    #[serde(default)]
    pub action: InterceptActionConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommandPolicyConfig {
    #[serde(default)]
    pub executable: Option<String>,
    #[serde(default)]
    pub can_use: Vec<String>,
    #[serde(default)]
    pub sandbox: Option<CommandSandboxConfig>,
    #[serde(default)]
    pub from: BTreeMap<String, CommandFromConfig>,
    #[serde(default)]
    pub allow_direct_exec_bypass: Vec<String>,
    #[serde(default)]
    pub allow_direct_exec_bypass_with_credentials: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub intercept: Vec<InterceptRuleConfig>,
}

impl CommandPolicyConfig {
    fn merge_child(&self, child: &Self) -> Self {
        let mut from = self.from.clone();
        for (caller, child_from) in &child.from {
            from.entry(caller.clone())
                .and_modify(|base_from| {
                    *base_from = base_from.merge_child(child_from);
                })
                .or_insert_with(|| child_from.clone());
        }

        Self {
            executable: self.executable.clone().or_else(|| child.executable.clone()),
            can_use: dedup_append(&self.can_use, &child.can_use),
            sandbox: merge_optional_sandbox(&self.sandbox, &child.sandbox),
            from,
            allow_direct_exec_bypass: dedup_append(
                &self.allow_direct_exec_bypass,
                &child.allow_direct_exec_bypass,
            ),
            allow_direct_exec_bypass_with_credentials: self
                .allow_direct_exec_bypass_with_credentials
                || child.allow_direct_exec_bypass_with_credentials,
            // Parent intercept rules fire first. Child rules are appended after.
            // Parent catch-alls thus shadow any child rules that follow them,
            // which is the correct monotonic-widening behaviour.
            intercept: {
                let mut rules = self.intercept.clone();
                for child_rule in &child.intercept {
                    if !rules.contains(child_rule) {
                        rules.push(child_rule.clone());
                    }
                }
                rules
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum CommandFromConfig {
    Deny(String),
    Policy(Box<CommandSandboxConfig>),
}

impl CommandFromConfig {
    fn merge_child(&self, child: &Self) -> Self {
        match (self, child) {
            (Self::Policy(base), Self::Policy(child_policy)) => {
                Self::Policy(Box::new(base.merge_child(child_policy)))
            }
            // Inherited allow/deny entries are monotonic. A child cannot
            // erase a parent decision by changing the variant.
            (base, _) => base.clone(),
        }
    }

    fn is_explicit_deny(&self) -> bool {
        matches!(self, Self::Deny(value) if value == "deny")
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommandSandboxConfig {
    #[serde(default)]
    pub fs_read: Vec<String>,
    #[serde(default)]
    pub fs_read_file: Vec<String>,
    #[serde(default)]
    pub fs_write: Vec<String>,
    #[serde(default)]
    pub fs_write_file: Vec<String>,
    #[serde(default)]
    pub use_credentials: Vec<String>,
    #[serde(default)]
    pub argv_prepend: Vec<String>,
    #[serde(default)]
    pub network: Option<CommandNetworkConfig>,
    #[serde(default)]
    pub environment: Option<CommandEnvironmentConfig>,
    #[serde(default)]
    pub allow_raw_file_credentials_in_chained_policy: bool,
}

impl CommandSandboxConfig {
    fn merge_child(&self, child: &Self) -> Self {
        Self {
            fs_read: dedup_append(&self.fs_read, &child.fs_read),
            fs_read_file: dedup_append(&self.fs_read_file, &child.fs_read_file),
            fs_write: dedup_append(&self.fs_write, &child.fs_write),
            fs_write_file: dedup_append(&self.fs_write_file, &child.fs_write_file),
            use_credentials: dedup_append(&self.use_credentials, &child.use_credentials),
            argv_prepend: append_args(&self.argv_prepend, &child.argv_prepend),
            network: merge_optional_network(&self.network, &child.network),
            environment: merge_optional_environment(&self.environment, &child.environment),
            allow_raw_file_credentials_in_chained_policy: self
                .allow_raw_file_credentials_in_chained_policy
                || child.allow_raw_file_credentials_in_chained_policy,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommandNetworkConfig {
    #[serde(default)]
    pub allow_all: bool,
    #[serde(default)]
    pub allow_domain: Vec<String>,
    #[serde(default)]
    pub tcp_connect_ports: Vec<u16>,
    #[serde(default)]
    pub tcp_bind_ports: Vec<u16>,
    #[serde(default)]
    pub proxy_helper: Option<String>,
}

impl CommandNetworkConfig {
    fn merge_child(&self, child: &Self) -> Self {
        Self {
            allow_all: self.allow_all || child.allow_all,
            allow_domain: dedup_append(&self.allow_domain, &child.allow_domain),
            tcp_connect_ports: dedup_append(&self.tcp_connect_ports, &child.tcp_connect_ports),
            tcp_bind_ports: dedup_append(&self.tcp_bind_ports, &child.tcp_bind_ports),
            proxy_helper: child
                .proxy_helper
                .clone()
                .or_else(|| self.proxy_helper.clone()),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommandEnvironmentConfig {
    #[serde(default)]
    pub allow_vars: Option<Vec<String>>,
    #[serde(default)]
    pub set_vars: BTreeMap<String, String>,
}

impl CommandEnvironmentConfig {
    fn merge_child(&self, child: &Self) -> Self {
        let mut set_vars = self.set_vars.clone();
        for (name, value) in &child.set_vars {
            set_vars
                .entry(name.clone())
                .or_insert_with(|| value.clone());
        }
        Self {
            allow_vars: match (&self.allow_vars, &child.allow_vars) {
                (None, None) => None,
                (Some(base), None) => Some(base.clone()),
                (None, Some(child_vars)) => Some(child_vars.clone()),
                (Some(base), Some(child_vars)) => Some(dedup_append(base, child_vars)),
            },
            set_vars,
        }
    }
}

pub(crate) fn validate_command_policies(
    config: Option<&CommandPoliciesConfig>,
    scope: CommandPolicyValidationScope,
) -> CommandPolicyValidationReport {
    let mut report = CommandPolicyValidationReport::default();
    let Some(config) = config else {
        return report;
    };

    if !config.is_active() {
        if config.has_non_command_fields() {
            report.error(
                "inactive_non_empty",
                "command_policies has no policy commands but contains other ETI fields",
            );
        }
        return report;
    }

    report.activation = CommandPolicyActivation::Active;
    report.info(
        "active",
        format!(
            "ETI active with {} policy-controlled command(s)",
            config.commands.len()
        ),
    );

    validate_identifier_set("command", config.commands.keys(), &mut report);
    validate_identifier_set("credential", config.credentials.keys(), &mut report);
    validate_identifier_list("session_can_use", &config.session_can_use, &mut report);
    validate_absolute_file_path_list(
        "command_policies.deny_direct_exec_bypass",
        &config.deny_direct_exec_bypass,
        &mut report,
    );

    for (name, credential) in &config.credentials {
        validate_credential(name, credential, &mut report);
    }

    for (command_name, command) in &config.commands {
        validate_command(command_name, command, config, scope, &mut report);
    }

    if scope == CommandPolicyValidationScope::Resolved {
        validate_resolved_references(config, &mut report);
    }

    report
}

pub(crate) fn validate_legacy_blocked_command_interactions(
    config: Option<&CommandPoliciesConfig>,
    legacy_blocked_commands: &[String],
    allowed_commands: &[String],
) -> CommandPolicyValidationReport {
    let mut report = CommandPolicyValidationReport::default();
    let Some(config) = config else {
        return report;
    };
    if !config.is_active() {
        return report;
    }

    report.activation = CommandPolicyActivation::Active;
    validate_identifier_list("commands.allow", allowed_commands, &mut report);

    let allowed: HashSet<&String> = allowed_commands.iter().collect();
    let mut deny_only_commands = BTreeSet::new();
    for command_name in legacy_blocked_commands {
        validate_identifier("legacy blocked command", command_name, &mut report);
        if allowed.contains(command_name) {
            continue;
        }
        if config.commands.contains_key(command_name) {
            report.error(
                "policy_blocked_command_conflict",
                format!(
                    "command '{command_name}' is both policy-controlled and legacy blocked; use commands.allow to override the legacy blocked entry before ETI command-control resolution"
                ),
            );
            continue;
        }
        deny_only_commands.insert(command_name.clone());
    }

    if !deny_only_commands.is_empty() {
        report.info(
            "legacy_blocked_folded",
            format!(
                "folded {} legacy blocked command(s) into active ETI as deny-only entries",
                deny_only_commands.len()
            ),
        );
    }

    report
}

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
pub(crate) fn resolve_policy_command_binaries(
    config: &CommandPoliciesConfig,
    path_env: Option<OsString>,
) -> nono::Result<ResolvedCommandBinaries> {
    let mut commands = BTreeMap::new();
    let mut warnings = Vec::new();
    let search_dirs = command_search_dirs(config, path_env)?;

    for (command_name, command) in &config.commands {
        let (selected, duplicate_paths) = if let Some(executable) = &command.executable {
            (exact_command_match(command_name, executable)?, Vec::new())
        } else {
            let matches = find_command_matches(command_name, &search_dirs)?;
            let Some(selected) = matches.first() else {
                return Err(nono::NonoError::ProfileParse(format!(
                    "command policy '{command_name}' could not be resolved on PATH"
                )));
            };

            let duplicate_paths = duplicate_distinct_inode_paths(selected, &matches);
            if !duplicate_paths.is_empty() {
                let rendered = duplicate_paths
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                warnings.push(CommandPolicyFinding::new(
                    "duplicate_path_command",
                    format!(
                        "command policy '{command_name}' resolved to {}, but other executable '{command_name}' entries exist on PATH: {rendered}; only the resolved binary is controlled by this policy",
                        selected.canonical_path.display()
                    ),
                ));
            }
            (selected.clone(), duplicate_paths)
        };

        if selected.shape.kind == ResolvedExecutableKind::ShebangScript {
            let interpreter = selected
                .shape
                .interpreter
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<unknown>".to_string());
            warnings.push(CommandPolicyFinding::new(
                "script_entrypoint",
                format!(
                    "command policy '{command_name}' resolved to script {}; child policy must grant interpreter/runtime {} explicitly",
                    selected.canonical_path.display(),
                    interpreter
                ),
            ));
        }

        commands.insert(
            command_name.clone(),
            ResolvedCommandBinary {
                name: command_name.clone(),
                canonical_path: selected.canonical_path.clone(),
                dev: selected.dev,
                ino: selected.ino,
                size: selected.size,
                mtime_nanos: selected.mtime_nanos,
                sha256: selected.sha256.clone(),
                duplicate_paths,
                shape: selected.shape.clone(),
            },
        );
    }

    Ok(ResolvedCommandBinaries { commands, warnings })
}

fn validate_command(
    command_name: &str,
    command: &CommandPolicyConfig,
    config: &CommandPoliciesConfig,
    scope: CommandPolicyValidationScope,
    report: &mut CommandPolicyValidationReport,
) {
    validate_identifier_list(
        &format!("commands.{command_name}.can_use"),
        &command.can_use,
        report,
    );

    if let Some(executable) = &command.executable {
        validate_absolute_file_path_list(
            &format!("commands.{command_name}.executable"),
            std::slice::from_ref(executable),
            report,
        );
    }

    if let Some(session_policy) = command.from.get("session") {
        if command.sandbox.is_some() {
            report.error(
                "ambiguous_session_policy",
                format!("command '{command_name}' defines both top-level sandbox and from.session"),
            );
        }
        if session_policy.is_explicit_deny() && command.sandbox.is_some() {
            report.error(
                "conflicting_session_deny",
                format!("command '{command_name}' defines sandbox and from.session = \"deny\""),
            );
        }
    }

    if !command.allow_direct_exec_bypass.is_empty() {
        validate_absolute_file_path_list(
            &format!("commands.{command_name}.allow_direct_exec_bypass"),
            &command.allow_direct_exec_bypass,
            report,
        );
        report.warning(
            "direct_exec_bypass",
            format!(
                "command '{command_name}' allows direct canonical exec bypass outside child-ETI"
            ),
        );
        if command_uses_credentials(command) && !command.allow_direct_exec_bypass_with_credentials {
            report.error(
                "credential_bypass_requires_opt_in",
                format!(
                    "command '{command_name}' uses credentials and allow_direct_exec_bypass without allow_direct_exec_bypass_with_credentials"
                ),
            );
        }
    }

    if let Some(sandbox) = &command.sandbox {
        validate_sandbox(command_name, "session", sandbox, config, scope, report);
    }

    for (caller, from_policy) in &command.from {
        if caller == "user" {
            report.error(
                "reserved_caller",
                format!("command '{command_name}' uses from.user; use from.session"),
            );
        } else if caller != "session" {
            validate_identifier(&format!("commands.{command_name}.from"), caller, report);
        }

        match from_policy {
            CommandFromConfig::Deny(value) => {
                if value != "deny" {
                    report.error(
                        "invalid_explicit_deny",
                        format!(
                            "command '{command_name}' from.{caller} string value must be \"deny\""
                        ),
                    );
                }
            }
            CommandFromConfig::Policy(policy) => {
                validate_sandbox(command_name, caller, policy, config, scope, report);
            }
        }
    }

    validate_intercept_rules(command_name, &command.intercept, report);
}

fn validate_intercept_rules(
    command_name: &str,
    rules: &[InterceptRuleConfig],
    report: &mut CommandPolicyValidationReport,
) {
    let mut saw_catch_all = false;
    for (i, rule) in rules.iter().enumerate() {
        if saw_catch_all {
            report.error(
                "intercept_rule_after_catch_all",
                format!(
                    "command '{command_name}' intercept rule {i} appears after a catch-all (empty args) rule"
                ),
            );
        }
        if rule.args.is_empty() {
            saw_catch_all = true;
        }
        if let InterceptActionConfig::Respond { stdout } = &rule.action
            && stdout.len() > 1024 * 1024
        {
            report.error(
                "intercept_respond_stdout_too_large",
                format!("command '{command_name}' intercept rule {i} respond stdout exceeds 1 MiB"),
            );
        }
    }
}

fn validate_sandbox(
    command_name: &str,
    caller: &str,
    sandbox: &CommandSandboxConfig,
    config: &CommandPoliciesConfig,
    scope: CommandPolicyValidationScope,
    report: &mut CommandPolicyValidationReport,
) {
    validate_identifier_list(
        &format!("commands.{command_name}.from.{caller}.use_credentials"),
        &sandbox.use_credentials,
        report,
    );

    if let Some(environment) = &sandbox.environment {
        validate_environment(command_name, caller, environment, report);
    }

    validate_argv_prepend(command_name, caller, &sandbox.argv_prepend, report);

    if let Some(network) = &sandbox.network {
        validate_network(command_name, caller, network, report);
    }

    if scope == CommandPolicyValidationScope::Resolved {
        validate_sandbox_credentials(command_name, caller, sandbox, config, report);
    }
}

fn validate_argv_prepend(
    command_name: &str,
    caller: &str,
    argv_prepend: &[String],
    report: &mut CommandPolicyValidationReport,
) {
    for arg in argv_prepend {
        if arg.contains('\0') {
            report.error(
                "invalid_argv_prepend",
                format!("command '{command_name}' from.{caller} argv_prepend contains NUL"),
            );
        }
    }
}

fn validate_credential(
    name: &str,
    credential: &CommandCredentialConfig,
    report: &mut CommandPolicyValidationReport,
) {
    match credential.credential_type {
        CommandCredentialType::SshAgent => {
            if credential.socket.as_deref().unwrap_or_default().is_empty() {
                report.error(
                    "invalid_credential",
                    format!("ssh-agent credential '{name}' must define socket"),
                );
            }
            if credential.path.is_some() || credential.env_var.is_some() {
                report.error(
                    "invalid_credential",
                    format!("ssh-agent credential '{name}' cannot define path or env_var"),
                );
            }
        }
        CommandCredentialType::RawFile => {
            if credential.path.as_deref().unwrap_or_default().is_empty() {
                report.error(
                    "invalid_credential",
                    format!("raw-file credential '{name}' must define path"),
                );
            }
            if credential.socket.is_some() {
                report.error(
                    "invalid_credential",
                    format!("raw-file credential '{name}' cannot define socket"),
                );
            }
        }
    }
}

fn validate_environment(
    command_name: &str,
    caller: &str,
    environment: &CommandEnvironmentConfig,
    report: &mut CommandPolicyValidationReport,
) {
    if let Some(allow_vars) = &environment.allow_vars {
        for pattern in allow_vars {
            if pattern.is_empty() {
                report.error(
                    "invalid_environment_pattern",
                    format!("command '{command_name}' from.{caller} has empty allow_vars pattern"),
                );
            }
            if pattern.matches('*').count() > 1 {
                report.error(
                    "invalid_environment_pattern",
                    format!(
                        "command '{command_name}' from.{caller} allow_vars pattern '{pattern}' contains multiple wildcards"
                    ),
                );
            }
        }

        if let Some(error) =
            crate::exec_strategy::validate_env_var_patterns(allow_vars, "allow_vars")
        {
            report.error(
                "invalid_environment_pattern",
                format!("command '{command_name}' from.{caller}: {error}"),
            );
        }
    }

    for name in environment.set_vars.keys() {
        if !valid_set_var_name(name) {
            report.error(
                "invalid_environment_set_var",
                format!(
                    "command '{command_name}' from.{caller} has invalid set_vars name '{name}'"
                ),
            );
        }
    }
    for (name, value) in &environment.set_vars {
        if value.contains('\0') {
            report.error(
                "invalid_environment_set_var",
                format!("command '{command_name}' from.{caller} set_vars value for '{name}' contains NUL"),
            );
        }
    }
}

fn valid_set_var_name(name: &str) -> bool {
    !name.is_empty()
        && name != "PATH"
        && !name.starts_with("NONO_")
        && !name.contains('*')
        && !name.contains('=')
        && !name.contains('\0')
}

fn validate_network(
    command_name: &str,
    caller: &str,
    network: &CommandNetworkConfig,
    report: &mut CommandPolicyValidationReport,
) {
    if network.allow_all
        && (!network.allow_domain.is_empty()
            || !network.tcp_connect_ports.is_empty()
            || !network.tcp_bind_ports.is_empty()
            || network.proxy_helper.is_some())
    {
        report.error(
            "conflicting_network_policy",
            format!(
                "command '{command_name}' from.{caller} uses allow_all with narrower network rules"
            ),
        );
    }

    if network.allow_all {
        report.warning(
            "allow_all_network",
            format!("command '{command_name}' from.{caller} allows unrestricted child network"),
        );
    }

    let proxy_helper = network.proxy_helper.as_deref().unwrap_or_default();
    if !network.allow_domain.is_empty() && proxy_helper.is_empty() {
        report.error(
            "unenforceable_allow_domain",
            format!(
                "command '{command_name}' from.{caller} uses allow_domain without proxy_helper"
            ),
        );
    }

    if !network.tcp_connect_ports.is_empty() || !network.tcp_bind_ports.is_empty() {
        report.warning(
            "raw_tcp_ports",
            format!(
                "command '{command_name}' from.{caller} uses raw TCP port rules; these are not hostname-filtered"
            ),
        );
    }
}

fn validate_sandbox_credentials(
    command_name: &str,
    caller: &str,
    sandbox: &CommandSandboxConfig,
    config: &CommandPoliciesConfig,
    report: &mut CommandPolicyValidationReport,
) {
    for credential_name in &sandbox.use_credentials {
        let Some(credential) = config.credentials.get(credential_name) else {
            report.error(
                "unknown_credential",
                format!(
                    "command '{command_name}' from.{caller} references unknown credential '{credential_name}'"
                ),
            );
            continue;
        };

        if caller != "session"
            && credential.credential_type == CommandCredentialType::RawFile
            && !sandbox.allow_raw_file_credentials_in_chained_policy
        {
            report.error(
                "raw_file_credential_in_chained_policy",
                format!(
                    "command '{command_name}' from.{caller} references raw-file credential '{credential_name}' without allow_raw_file_credentials_in_chained_policy"
                ),
            );
        }
    }
}

fn validate_resolved_references(
    config: &CommandPoliciesConfig,
    report: &mut CommandPolicyValidationReport,
) {
    let command_names: BTreeSet<&String> = config.commands.keys().collect();

    for command_name in &config.session_can_use {
        if !command_names.contains(command_name) {
            report.error(
                "unknown_session_command",
                format!("session_can_use references unknown command '{command_name}'"),
            );
            continue;
        }

        if let Some(command) = config.commands.get(command_name)
            && matches!(
                command.from.get("session"),
                Some(CommandFromConfig::Deny(value)) if value == "deny"
            )
        {
            report.error(
                "contradictory_session_allow",
                format!(
                    "session_can_use includes '{command_name}' but from.session is explicit deny"
                ),
            );
        }
    }

    for (caller_name, caller_command) in &config.commands {
        for callee_name in &caller_command.can_use {
            if !command_names.contains(callee_name) {
                report.error(
                    "unknown_chained_command",
                    format!(
                        "command '{caller_name}' can_use references unknown command '{callee_name}'"
                    ),
                );
                continue;
            }

            if let Some(callee_command) = config.commands.get(callee_name)
                && matches!(
                    callee_command.from.get(caller_name),
                    Some(CommandFromConfig::Deny(value)) if value == "deny"
                )
            {
                report.error(
                    "contradictory_chained_allow",
                    format!(
                        "command '{caller_name}' can_use includes '{callee_name}' but {callee_name}.from.{caller_name} is explicit deny"
                    ),
                );
            }
        }
    }
}

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone)]
struct CommandSearchDir {
    path: PathBuf,
    explicit: bool,
}

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone)]
struct CommandMatch {
    canonical_path: PathBuf,
    dev: u64,
    ino: u64,
    size: u64,
    mtime_nanos: i128,
    sha256: String,
    shape: ResolvedExecutableShape,
}

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
fn command_search_dirs(
    config: &CommandPoliciesConfig,
    path_env: Option<OsString>,
) -> nono::Result<Vec<CommandSearchDir>> {
    let mut dirs = Vec::new();
    if let Some(path_env) = path_env {
        for dir in std::env::split_paths(&path_env) {
            if !dir.as_os_str().is_empty() {
                dirs.push(CommandSearchDir {
                    path: dir,
                    explicit: false,
                });
            }
        }
    }

    for configured_dir in &config.executable_dirs {
        let dir = PathBuf::from(configured_dir);
        let metadata = fs::metadata(&dir).map_err(|err| {
            nono::NonoError::ProfileParse(format!(
                "command_policies.executable_dirs entry '{}' is not readable: {err}",
                dir.display()
            ))
        })?;
        if !metadata.is_dir() {
            return Err(nono::NonoError::ProfileParse(format!(
                "command_policies.executable_dirs entry '{}' is not a directory",
                dir.display()
            )));
        }
        dirs.push(CommandSearchDir {
            path: dir,
            explicit: true,
        });
    }

    Ok(dirs)
}

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
fn find_command_matches(
    command_name: &str,
    search_dirs: &[CommandSearchDir],
) -> nono::Result<Vec<CommandMatch>> {
    let mut matches = Vec::new();
    let mut explicit_errors = Vec::new();

    for dir in search_dirs {
        let candidate = dir.path.join(command_name);
        match candidate_command_match(&candidate) {
            Ok(Some(command_match)) => matches.push(command_match),
            Ok(None) => {}
            Err(err) if dir.explicit => {
                explicit_errors.push(format!("{}: {err}", candidate.display()))
            }
            Err(_) => {}
        }
    }

    if !explicit_errors.is_empty() {
        return Err(nono::NonoError::ProfileParse(format!(
            "failed to inspect configured executable_dirs for command '{command_name}': {}",
            explicit_errors.join("; ")
        )));
    }

    Ok(matches)
}

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
fn exact_command_match(command_name: &str, executable: &str) -> nono::Result<CommandMatch> {
    let path = PathBuf::from(executable);
    match candidate_command_match(&path)? {
        Some(command_match) => Ok(command_match),
        None => Err(nono::NonoError::ProfileParse(format!(
            "command policy '{command_name}' executable '{}' is not an executable file",
            path.display()
        ))),
    }
}

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
fn candidate_command_match(candidate: &Path) -> nono::Result<Option<CommandMatch>> {
    let metadata = match fs::metadata(candidate) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(nono::NonoError::ProfileParse(err.to_string())),
    };

    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Ok(None);
    }

    let canonical_path = candidate.canonicalize().map_err(|err| {
        nono::NonoError::ProfileParse(format!(
            "failed to canonicalize command candidate '{}': {err}",
            candidate.display()
        ))
    })?;
    let canonical_metadata = fs::metadata(&canonical_path).map_err(|err| {
        nono::NonoError::ProfileParse(format!(
            "failed to stat command candidate '{}': {err}",
            canonical_path.display()
        ))
    })?;
    let bytes = fs::read(&canonical_path).map_err(|err| {
        nono::NonoError::ProfileParse(format!(
            "failed to hash command candidate '{}': {err}",
            canonical_path.display()
        ))
    })?;
    let sha256 = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let shape = classify_executable_shape(&canonical_path, &bytes)?;

    let mtime_nanos = (canonical_metadata.mtime() as i128)
        .saturating_mul(1_000_000_000)
        .saturating_add(canonical_metadata.mtime_nsec() as i128);
    Ok(Some(CommandMatch {
        canonical_path,
        dev: canonical_metadata.dev(),
        ino: canonical_metadata.ino(),
        size: canonical_metadata.size(),
        mtime_nanos,
        sha256,
        shape,
    }))
}

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
fn classify_executable_shape(path: &Path, bytes: &[u8]) -> nono::Result<ResolvedExecutableShape> {
    if bytes.starts_with(b"\x7fELF") {
        return Ok(ResolvedExecutableShape {
            kind: ResolvedExecutableKind::Elf,
            interpreter: None,
            interpreter_args: Vec::new(),
        });
    }

    if let Some(line) = bytes.strip_prefix(b"#!") {
        let line_end = line
            .iter()
            .position(|byte| *byte == b'\n')
            .unwrap_or(line.len());
        let shebang = &line[..line_end];
        let shebang = std::str::from_utf8(shebang).map_err(|err| {
            nono::NonoError::ProfileParse(format!(
                "script command '{}' has non-UTF-8 shebang: {err}",
                path.display()
            ))
        })?;
        let mut parts = shebang.split_whitespace();
        let interpreter = parts
            .next()
            .ok_or_else(|| {
                nono::NonoError::ProfileParse(format!(
                    "script command '{}' has an empty shebang",
                    path.display()
                ))
            })
            .map(PathBuf::from)?;
        return Ok(ResolvedExecutableShape {
            kind: ResolvedExecutableKind::ShebangScript,
            interpreter: Some(interpreter),
            interpreter_args: parts.map(ToString::to_string).collect(),
        });
    }

    Ok(ResolvedExecutableShape {
        kind: ResolvedExecutableKind::Other,
        interpreter: None,
        interpreter_args: Vec::new(),
    })
}

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
fn duplicate_distinct_inode_paths(
    selected: &CommandMatch,
    matches: &[CommandMatch],
) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    let mut duplicates = Vec::new();
    for command_match in matches.iter().skip(1) {
        if command_match.dev == selected.dev && command_match.ino == selected.ino {
            continue;
        }
        if seen.insert((command_match.dev, command_match.ino)) {
            duplicates.push(command_match.canonical_path.clone());
        }
    }
    duplicates
}

fn command_uses_credentials(command: &CommandPolicyConfig) -> bool {
    command
        .sandbox
        .as_ref()
        .is_some_and(sandbox_uses_credentials)
        || command.from.values().any(|from_policy| match from_policy {
            CommandFromConfig::Policy(policy) => sandbox_uses_credentials(policy),
            CommandFromConfig::Deny(_) => false,
        })
}

fn sandbox_uses_credentials(sandbox: &CommandSandboxConfig) -> bool {
    !sandbox.use_credentials.is_empty()
}

fn validate_absolute_file_path_list(
    label: &str,
    paths: &[String],
    report: &mut CommandPolicyValidationReport,
) {
    for path in paths {
        let parsed = Path::new(path);
        if !parsed.is_absolute() {
            report.error(
                "invalid_exec_bypass_path",
                format!("{label} entry '{path}' must be an absolute file path"),
            );
        }
        if path.contains('\0') {
            report.error(
                "invalid_exec_bypass_path",
                format!("{label} entry contains NUL"),
            );
        }
    }
}

fn validate_identifier_set<'a>(
    label: &str,
    names: impl Iterator<Item = &'a String>,
    report: &mut CommandPolicyValidationReport,
) {
    let mut folded = HashSet::new();
    for name in names {
        validate_identifier(label, name, report);
        let lower = name.to_ascii_lowercase();
        if !folded.insert(lower) {
            report.error(
                "case_fold_collision",
                format!("{label} name '{name}' collides with another {label} name by case"),
            );
        }
    }
}

fn validate_identifier_list(
    label: &str,
    names: &[String],
    report: &mut CommandPolicyValidationReport,
) {
    for name in names {
        validate_identifier(label, name, report);
    }
}

fn validate_identifier(label: &str, name: &str, report: &mut CommandPolicyValidationReport) {
    if !is_valid_identifier(name) {
        report.error(
            "invalid_identifier",
            format!(
                "{label} name '{name}' must match [A-Za-z0-9._+-]+ and must not be '.', '..', 'session', contain '/', or contain NUL"
            ),
        );
    }
}

fn is_valid_identifier(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.eq_ignore_ascii_case("session")
        && !name.contains('/')
        && !name.contains('\0')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
}

fn merge_optional_sandbox(
    base: &Option<CommandSandboxConfig>,
    child: &Option<CommandSandboxConfig>,
) -> Option<CommandSandboxConfig> {
    match (base, child) {
        (None, None) => None,
        (Some(base), None) => Some(base.clone()),
        (None, Some(child)) => Some(child.clone()),
        (Some(base), Some(child)) => Some(base.merge_child(child)),
    }
}

fn merge_optional_network(
    base: &Option<CommandNetworkConfig>,
    child: &Option<CommandNetworkConfig>,
) -> Option<CommandNetworkConfig> {
    match (base, child) {
        (None, None) => None,
        (Some(base), None) => Some(base.clone()),
        (None, Some(child)) => Some(child.clone()),
        (Some(base), Some(child)) => Some(base.merge_child(child)),
    }
}

fn merge_optional_environment(
    base: &Option<CommandEnvironmentConfig>,
    child: &Option<CommandEnvironmentConfig>,
) -> Option<CommandEnvironmentConfig> {
    match (base, child) {
        (None, None) => None,
        (Some(base), None) => Some(base.clone()),
        (None, Some(child)) => Some(child.clone()),
        (Some(base), Some(child)) => Some(base.merge_child(child)),
    }
}

fn dedup_append<T: Eq + std::hash::Hash + Clone>(base: &[T], child: &[T]) -> Vec<T> {
    let mut seen = HashSet::with_capacity(base.len() + child.len());
    let mut result = Vec::with_capacity(base.len() + child.len());
    for item in base.iter().chain(child.iter()) {
        if seen.insert(item) {
            result.push(item.clone());
        }
    }
    result
}

fn append_args(base: &[String], child: &[String]) -> Vec<String> {
    base.iter().chain(child.iter()).cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use tempfile::tempdir;

    fn active_git_config() -> CommandPoliciesConfig {
        let mut commands = BTreeMap::new();
        commands.insert(
            "git".to_string(),
            CommandPolicyConfig {
                sandbox: Some(CommandSandboxConfig {
                    fs_read: vec![".".to_string()],
                    ..Default::default()
                }),
                ..Default::default()
            },
        );

        CommandPoliciesConfig {
            session_can_use: vec!["git".to_string()],
            commands,
            ..Default::default()
        }
    }

    fn write_executable(path: &Path, contents: &[u8]) {
        fs::write(path, contents).expect("write executable");
        let mut permissions = fs::metadata(path).expect("stat executable").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("make executable");
    }

    #[test]
    fn inactive_empty_policy_is_valid() {
        let report = validate_command_policies(
            Some(&CommandPoliciesConfig::default()),
            CommandPolicyValidationScope::Resolved,
        );

        assert!(report.is_ok());
        assert_eq!(report.activation, CommandPolicyActivation::Inactive);
    }

    #[test]
    fn inactive_non_empty_policy_is_invalid() {
        let config = CommandPoliciesConfig {
            session_can_use: vec!["git".to_string()],
            ..Default::default()
        };

        let report =
            validate_command_policies(Some(&config), CommandPolicyValidationScope::Resolved);

        assert!(!report.is_ok());
        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.code == "inactive_non_empty")
        );
    }

    #[test]
    fn active_policy_validates_references() {
        let report = validate_command_policies(
            Some(&active_git_config()),
            CommandPolicyValidationScope::Resolved,
        );

        assert!(report.is_ok());
        assert_eq!(report.activation, CommandPolicyActivation::Active);
    }

    #[test]
    fn session_identifier_is_reserved_case_insensitively() {
        let mut config = active_git_config();
        config
            .commands
            .insert("Session".to_string(), CommandPolicyConfig::default());

        let report =
            validate_command_policies(Some(&config), CommandPolicyValidationScope::Resolved);

        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.code == "invalid_identifier")
        );
    }

    #[test]
    fn explicit_session_deny_conflicts_with_session_can_use() {
        let mut config = active_git_config();
        if let Some(git) = config.commands.get_mut("git") {
            git.sandbox = None;
            git.from.insert(
                "session".to_string(),
                CommandFromConfig::Deny("deny".to_string()),
            );
        }

        let report =
            validate_command_policies(Some(&config), CommandPolicyValidationScope::Resolved);

        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.code == "contradictory_session_allow")
        );
    }

    #[test]
    fn top_level_sandbox_and_from_session_is_ambiguous() {
        let mut config = active_git_config();
        if let Some(git) = config.commands.get_mut("git") {
            git.from.insert(
                "session".to_string(),
                CommandFromConfig::Policy(Box::default()),
            );
        }

        let report =
            validate_command_policies(Some(&config), CommandPolicyValidationScope::Resolved);

        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.code == "ambiguous_session_policy")
        );
    }

    #[test]
    fn allow_domain_without_proxy_helper_is_invalid() {
        let mut config = active_git_config();
        if let Some(git) = config.commands.get_mut("git") {
            git.sandbox = Some(CommandSandboxConfig {
                network: Some(CommandNetworkConfig {
                    allow_domain: vec!["github.com".to_string()],
                    ..Default::default()
                }),
                ..Default::default()
            });
        }

        let report =
            validate_command_policies(Some(&config), CommandPolicyValidationScope::Resolved);

        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.code == "unenforceable_allow_domain")
        );
    }

    #[test]
    fn allow_all_network_is_explicit_warning() {
        let mut config = active_git_config();
        if let Some(git) = config.commands.get_mut("git") {
            git.sandbox = Some(CommandSandboxConfig {
                network: Some(CommandNetworkConfig {
                    allow_all: true,
                    ..Default::default()
                }),
                ..Default::default()
            });
        }

        let report =
            validate_command_policies(Some(&config), CommandPolicyValidationScope::Resolved);

        assert!(report.errors.is_empty());
        assert!(
            report
                .warnings
                .iter()
                .any(|finding| finding.code == "allow_all_network")
        );
    }

    #[test]
    fn allow_all_network_rejects_narrower_rules() {
        let mut config = active_git_config();
        if let Some(git) = config.commands.get_mut("git") {
            git.sandbox = Some(CommandSandboxConfig {
                network: Some(CommandNetworkConfig {
                    allow_all: true,
                    tcp_connect_ports: vec![22],
                    ..Default::default()
                }),
                ..Default::default()
            });
        }

        let report =
            validate_command_policies(Some(&config), CommandPolicyValidationScope::Resolved);

        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.code == "conflicting_network_policy")
        );
    }

    #[test]
    fn raw_file_credential_requires_chained_opt_in() {
        let mut commands = BTreeMap::new();
        commands.insert(
            "git".to_string(),
            CommandPolicyConfig {
                can_use: vec!["ssh".to_string()],
                sandbox: Some(CommandSandboxConfig::default()),
                ..Default::default()
            },
        );
        commands.insert(
            "ssh".to_string(),
            CommandPolicyConfig {
                from: BTreeMap::from([(
                    "git".to_string(),
                    CommandFromConfig::Policy(Box::new(CommandSandboxConfig {
                        use_credentials: vec!["key".to_string()],
                        ..Default::default()
                    })),
                )]),
                ..Default::default()
            },
        );

        let config = CommandPoliciesConfig {
            credentials: BTreeMap::from([(
                "key".to_string(),
                CommandCredentialConfig {
                    credential_type: CommandCredentialType::RawFile,
                    socket: None,
                    path: Some("/tmp/key".to_string()),
                    env_var: None,
                },
            )]),
            commands,
            ..Default::default()
        };

        let report =
            validate_command_policies(Some(&config), CommandPolicyValidationScope::Resolved);

        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.code == "raw_file_credential_in_chained_policy")
        );
    }

    #[test]
    fn environment_rejects_non_trailing_wildcards() {
        let mut config = active_git_config();
        if let Some(git) = config.commands.get_mut("git") {
            git.sandbox = Some(CommandSandboxConfig {
                environment: Some(CommandEnvironmentConfig {
                    allow_vars: Some(vec!["*TOKEN".to_string(), "A**".to_string()]),
                    ..Default::default()
                }),
                ..Default::default()
            });
        }

        let report =
            validate_command_policies(Some(&config), CommandPolicyValidationScope::Resolved);

        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.code == "invalid_environment_pattern")
        );
    }

    #[test]
    fn environment_rejects_invalid_set_vars() {
        let mut config = active_git_config();
        if let Some(git) = config.commands.get_mut("git") {
            git.sandbox = Some(CommandSandboxConfig {
                environment: Some(CommandEnvironmentConfig {
                    set_vars: BTreeMap::from([
                        ("".to_string(), "value".to_string()),
                        ("PATH".to_string(), "value".to_string()),
                        ("NONO_ETI_SOCKET".to_string(), "value".to_string()),
                        ("BAD*NAME".to_string(), "value".to_string()),
                        ("BAD=NAME".to_string(), "value".to_string()),
                        ("GOOD".to_string(), "bad\0value".to_string()),
                    ]),
                    ..Default::default()
                }),
                ..Default::default()
            });
        }

        let report =
            validate_command_policies(Some(&config), CommandPolicyValidationScope::Resolved);

        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.code == "invalid_environment_set_var")
        );
    }

    #[test]
    fn argv_prepend_rejects_nul() {
        let mut config = active_git_config();
        if let Some(git) = config.commands.get_mut("git") {
            git.sandbox = Some(CommandSandboxConfig {
                argv_prepend: vec!["bad\0arg".to_string()],
                ..Default::default()
            });
        }

        let report =
            validate_command_policies(Some(&config), CommandPolicyValidationScope::Resolved);

        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.code == "invalid_argv_prepend")
        );
    }

    #[test]
    fn merge_preserves_inherited_policy_and_appends_child_grants() {
        let mut base = active_git_config();
        if let Some(git) = base.commands.get_mut("git")
            && let Some(sandbox) = &mut git.sandbox
        {
            sandbox.argv_prepend = vec!["--base".to_string()];
            sandbox.environment = Some(CommandEnvironmentConfig {
                allow_vars: Some(vec!["PATH".to_string()]),
                set_vars: BTreeMap::from([("GIT_SSH".to_string(), "ssh".to_string())]),
            });
        }
        let child = CommandPoliciesConfig {
            commands: BTreeMap::from([(
                "git".to_string(),
                CommandPolicyConfig {
                    sandbox: Some(CommandSandboxConfig {
                        fs_write: vec![".".to_string()],
                        argv_prepend: vec!["--child".to_string()],
                        environment: Some(CommandEnvironmentConfig {
                            allow_vars: Some(vec!["GIT_*".to_string()]),
                            set_vars: BTreeMap::from([
                                ("GIT_SSH".to_string(), "/tmp/evil".to_string()),
                                ("GIT_SSH_VARIANT".to_string(), "ssh".to_string()),
                            ]),
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };

        let merged = base.merge_child(&child);
        let git = merged
            .commands
            .get("git")
            .expect("merged git command should exist");
        let sandbox = git
            .sandbox
            .as_ref()
            .expect("merged git sandbox should exist");

        assert_eq!(sandbox.fs_read, vec!["."]);
        assert_eq!(sandbox.fs_write, vec!["."]);
        assert_eq!(
            sandbox.argv_prepend,
            vec!["--base".to_string(), "--child".to_string()]
        );
        assert_eq!(
            sandbox
                .environment
                .as_ref()
                .and_then(|environment| environment.allow_vars.as_ref())
                .expect("merged env vars should exist"),
            &vec!["PATH".to_string(), "GIT_*".to_string()]
        );
        assert_eq!(
            &sandbox
                .environment
                .as_ref()
                .expect("merged env should exist")
                .set_vars,
            &BTreeMap::from([
                ("GIT_SSH".to_string(), "ssh".to_string()),
                ("GIT_SSH_VARIANT".to_string(), "ssh".to_string()),
            ])
        );
    }

    #[test]
    fn command_resolution_uses_first_original_path_match() {
        let dir = tempdir().expect("tempdir");
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        fs::create_dir_all(&first).expect("create first dir");
        fs::create_dir_all(&second).expect("create second dir");
        write_executable(&first.join("git"), b"first");
        write_executable(&second.join("git"), b"second");

        let path_env =
            std::env::join_paths([first.as_path(), second.as_path()]).expect("join PATH entries");
        let resolved =
            resolve_policy_command_binaries(&active_git_config(), Some(path_env)).expect("resolve");
        let git = resolved
            .commands
            .get("git")
            .expect("git resolution should exist");

        assert_eq!(
            git.canonical_path,
            first
                .join("git")
                .canonicalize()
                .expect("canonical first git")
        );
        assert_eq!(
            git.duplicate_paths,
            vec![
                second
                    .join("git")
                    .canonicalize()
                    .expect("canonical second git")
            ]
        );
        assert!(
            resolved
                .warnings
                .iter()
                .any(|finding| finding.code == "duplicate_path_command")
        );
    }

    #[test]
    fn command_resolution_ignores_duplicate_alias_to_same_inode() {
        let dir = tempdir().expect("tempdir");
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        fs::create_dir_all(&first).expect("create first dir");
        fs::create_dir_all(&second).expect("create second dir");
        write_executable(&first.join("git"), b"first");
        symlink(first.join("git"), second.join("git")).expect("symlink git");

        let path_env =
            std::env::join_paths([first.as_path(), second.as_path()]).expect("join PATH entries");
        let resolved =
            resolve_policy_command_binaries(&active_git_config(), Some(path_env)).expect("resolve");
        let git = resolved
            .commands
            .get("git")
            .expect("git resolution should exist");

        assert!(git.duplicate_paths.is_empty());
        assert!(resolved.warnings.is_empty());
    }

    #[test]
    fn command_resolution_searches_configured_executable_dirs_after_path() {
        let dir = tempdir().expect("tempdir");
        let path_dir = dir.path().join("path");
        let configured = dir.path().join("configured");
        fs::create_dir_all(&path_dir).expect("create path dir");
        fs::create_dir_all(&configured).expect("create configured dir");
        write_executable(&configured.join("git"), b"configured");

        let mut config = active_git_config();
        config.executable_dirs = vec![configured.to_string_lossy().into_owned()];
        let path_env = std::env::join_paths([path_dir.as_path()]).expect("join PATH entries");
        let resolved = resolve_policy_command_binaries(&config, Some(path_env)).expect("resolve");
        let git = resolved
            .commands
            .get("git")
            .expect("git resolution should exist");

        assert_eq!(
            git.canonical_path,
            configured
                .join("git")
                .canonicalize()
                .expect("canonical configured git")
        );
    }

    #[test]
    fn command_resolution_uses_exact_executable_binding() {
        let dir = tempdir().expect("tempdir");
        let path_dir = dir.path().join("path");
        let exact_dir = dir.path().join("exact");
        fs::create_dir_all(&path_dir).expect("create path dir");
        fs::create_dir_all(&exact_dir).expect("create exact dir");
        write_executable(&path_dir.join("git"), b"path");
        write_executable(&exact_dir.join("git"), b"exact");

        let mut config = active_git_config();
        config
            .commands
            .get_mut("git")
            .expect("git command")
            .executable = Some(exact_dir.join("git").to_string_lossy().into_owned());
        let path_env = std::env::join_paths([path_dir.as_path()]).expect("join PATH entries");
        let resolved = resolve_policy_command_binaries(&config, Some(path_env)).expect("resolve");
        let git = resolved
            .commands
            .get("git")
            .expect("git resolution should exist");

        assert_eq!(
            git.canonical_path,
            exact_dir
                .join("git")
                .canonicalize()
                .expect("canonical exact git")
        );
        assert!(git.duplicate_paths.is_empty());
    }

    #[test]
    fn command_resolution_classifies_shebang_scripts() {
        let dir = tempdir().expect("tempdir");
        let bin_dir = dir.path().join("bin");
        fs::create_dir_all(&bin_dir).expect("create bin dir");
        write_executable(
            &bin_dir.join("git"),
            b"#!/usr/bin/python3 -sP\nprint('ok')\n",
        );

        let path_env = std::env::join_paths([bin_dir.as_path()]).expect("join PATH entries");
        let resolved =
            resolve_policy_command_binaries(&active_git_config(), Some(path_env)).expect("resolve");
        let git = resolved
            .commands
            .get("git")
            .expect("git resolution should exist");

        assert_eq!(git.shape.kind, ResolvedExecutableKind::ShebangScript);
        assert_eq!(
            git.shape.interpreter,
            Some(PathBuf::from("/usr/bin/python3"))
        );
        assert_eq!(git.shape.interpreter_args, vec!["-sP".to_string()]);
        assert!(
            resolved
                .warnings
                .iter()
                .any(|finding| finding.code == "script_entrypoint")
        );
    }

    #[test]
    fn command_resolution_fails_closed_when_command_is_missing() {
        let dir = tempdir().expect("tempdir");
        let path_env = std::env::join_paths([dir.path()]).expect("join PATH entries");
        let err = resolve_policy_command_binaries(&active_git_config(), Some(path_env))
            .expect_err("missing command should fail");

        assert!(
            err.to_string().contains("could not be resolved"),
            "missing command error should be clear: {err}"
        );
    }

    #[test]
    fn legacy_blocked_command_conflicts_with_policy_command_when_active() {
        let report = validate_legacy_blocked_command_interactions(
            Some(&active_git_config()),
            &["git".to_string()],
            &[],
        );

        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.code == "policy_blocked_command_conflict")
        );
    }

    #[test]
    fn allowed_commands_override_only_legacy_blocked_entries() {
        let report = validate_legacy_blocked_command_interactions(
            Some(&active_git_config()),
            &["git".to_string()],
            &["git".to_string()],
        );

        assert!(report.is_ok());
        assert!(report.info.is_empty());
    }

    #[test]
    fn legacy_blocked_commands_do_not_activate_eti_by_themselves() {
        let report = validate_legacy_blocked_command_interactions(
            Some(&CommandPoliciesConfig::default()),
            &["rm".to_string()],
            &[],
        );

        assert!(report.is_ok());
        assert_eq!(report.activation, CommandPolicyActivation::Inactive);
    }

    #[test]
    fn legacy_blocked_command_names_must_be_shim_safe_when_eti_active() {
        let report = validate_legacy_blocked_command_interactions(
            Some(&active_git_config()),
            &["bad/name".to_string()],
            &[],
        );

        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.code == "invalid_identifier")
        );
    }

    #[test]
    fn credential_using_command_requires_second_bypass_opt_in() {
        let mut config = active_git_config();
        config.credentials.insert(
            "agent".to_string(),
            CommandCredentialConfig {
                credential_type: CommandCredentialType::SshAgent,
                socket: Some("$SSH_AUTH_SOCK".to_string()),
                path: None,
                env_var: None,
            },
        );
        if let Some(git) = config.commands.get_mut("git") {
            git.allow_direct_exec_bypass = vec!["/usr/bin/git".to_string()];
            if let Some(sandbox) = git.sandbox.as_mut() {
                sandbox.use_credentials = vec!["agent".to_string()];
            }
        }

        let report =
            validate_command_policies(Some(&config), CommandPolicyValidationScope::Resolved);

        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.code == "credential_bypass_requires_opt_in")
        );
    }

    #[test]
    fn direct_bypass_paths_must_be_absolute() {
        let mut config = active_git_config();
        config
            .deny_direct_exec_bypass
            .push("relative/aws".to_string());
        if let Some(git) = config.commands.get_mut("git") {
            git.allow_direct_exec_bypass = vec!["usr/bin/git".to_string()];
        }

        let report =
            validate_command_policies(Some(&config), CommandPolicyValidationScope::Resolved);

        assert_eq!(
            report
                .errors
                .iter()
                .filter(|finding| finding.code == "invalid_exec_bypass_path")
                .count(),
            2
        );
    }

    #[test]
    fn credential_using_command_accepts_explicit_bypass_opt_in() {
        let mut config = active_git_config();
        config.credentials.insert(
            "agent".to_string(),
            CommandCredentialConfig {
                credential_type: CommandCredentialType::SshAgent,
                socket: Some("$SSH_AUTH_SOCK".to_string()),
                path: None,
                env_var: None,
            },
        );
        if let Some(git) = config.commands.get_mut("git") {
            git.allow_direct_exec_bypass = vec!["/usr/bin/git".to_string()];
            git.allow_direct_exec_bypass_with_credentials = true;
            if let Some(sandbox) = git.sandbox.as_mut() {
                sandbox.use_credentials = vec!["agent".to_string()];
            }
        }

        let report =
            validate_command_policies(Some(&config), CommandPolicyValidationScope::Resolved);

        assert!(
            !report
                .errors
                .iter()
                .any(|finding| finding.code == "credential_bypass_requires_opt_in")
        );
    }

    // -- InterceptRuleConfig / InterceptActionConfig --

    #[test]
    fn intercept_action_default_is_passthrough() {
        assert_eq!(
            InterceptActionConfig::default(),
            InterceptActionConfig::Passthrough
        );
    }

    #[test]
    fn intercept_action_serde_roundtrip() {
        let respond = InterceptActionConfig::Respond {
            stdout: "hello\n".to_string(),
        };
        let json = serde_json::to_string(&respond).expect("serialize");
        let back: InterceptActionConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(respond, back);

        let approve = InterceptActionConfig::Approve {
            timeout_secs: Some(30),
        };
        let json = serde_json::to_string(&approve).expect("serialize");
        let back: InterceptActionConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(approve, back);

        let passthrough = InterceptActionConfig::Passthrough;
        let json = serde_json::to_string(&passthrough).expect("serialize");
        let back: InterceptActionConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(passthrough, back);
    }

    #[test]
    fn intercept_rule_merge_child_appends_child_rules() {
        let parent_rule = InterceptRuleConfig {
            args: vec!["push".to_string()],
            action: InterceptActionConfig::Approve { timeout_secs: None },
        };
        let child_rule = InterceptRuleConfig {
            args: vec!["fetch".to_string()],
            action: InterceptActionConfig::Passthrough,
        };
        let parent = CommandPolicyConfig {
            intercept: vec![parent_rule.clone()],
            ..Default::default()
        };
        let child = CommandPolicyConfig {
            intercept: vec![child_rule.clone()],
            ..Default::default()
        };
        let merged = parent.merge_child(&child);
        assert_eq!(merged.intercept, vec![parent_rule, child_rule]);
    }

    #[test]
    fn intercept_rule_merge_child_does_not_duplicate() {
        let rule = InterceptRuleConfig {
            args: vec!["push".to_string()],
            action: InterceptActionConfig::Passthrough,
        };
        let parent = CommandPolicyConfig {
            intercept: vec![rule.clone()],
            ..Default::default()
        };
        let child = CommandPolicyConfig {
            intercept: vec![rule.clone()],
            ..Default::default()
        };
        let merged = parent.merge_child(&child);
        assert_eq!(merged.intercept.len(), 1);
    }

    #[test]
    fn validate_intercept_catch_all_must_be_last() {
        let mut config = active_git_config();
        if let Some(git) = config.commands.get_mut("git") {
            git.intercept = vec![
                InterceptRuleConfig {
                    args: vec![],
                    action: InterceptActionConfig::Passthrough,
                },
                InterceptRuleConfig {
                    args: vec!["push".to_string()],
                    action: InterceptActionConfig::Approve { timeout_secs: None },
                },
            ];
        }
        let report =
            validate_command_policies(Some(&config), CommandPolicyValidationScope::Resolved);
        assert!(
            report
                .errors
                .iter()
                .any(|f| f.code == "intercept_rule_after_catch_all"),
            "expected intercept_rule_after_catch_all error"
        );
    }

    #[test]
    fn validate_intercept_catch_all_last_is_valid() {
        let mut config = active_git_config();
        if let Some(git) = config.commands.get_mut("git") {
            git.intercept = vec![
                InterceptRuleConfig {
                    args: vec!["push".to_string()],
                    action: InterceptActionConfig::Approve { timeout_secs: None },
                },
                InterceptRuleConfig {
                    args: vec![],
                    action: InterceptActionConfig::Passthrough,
                },
            ];
        }
        let report =
            validate_command_policies(Some(&config), CommandPolicyValidationScope::Resolved);
        assert!(
            !report
                .errors
                .iter()
                .any(|f| f.code == "intercept_rule_after_catch_all"),
            "unexpected intercept_rule_after_catch_all error"
        );
    }

    #[test]
    fn validate_intercept_respond_stdout_too_large() {
        let mut config = active_git_config();
        if let Some(git) = config.commands.get_mut("git") {
            git.intercept = vec![InterceptRuleConfig {
                args: vec![],
                action: InterceptActionConfig::Respond {
                    stdout: "x".repeat(1024 * 1024 + 1),
                },
            }];
        }
        let report =
            validate_command_policies(Some(&config), CommandPolicyValidationScope::Resolved);
        assert!(
            report
                .errors
                .iter()
                .any(|f| f.code == "intercept_respond_stdout_too_large"),
            "expected intercept_respond_stdout_too_large error"
        );
    }
}
