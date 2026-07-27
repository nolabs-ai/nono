use crate::cli::RunArgs;
use crate::config;
use crate::proxy_runtime::prepare_proxy_launch_options;
use crate::sandbox_prepare::{
    PreparedSandbox, prepare_sandbox, print_allow_gpu_warning, print_allow_launch_services_warning,
    validate_proxy_conflicts,
};
use crate::{exec_strategy, instruction_deny, profile, trust_scan};
use colored::Colorize;
use nono::{AccessMode, CapabilitySet, FsCapability, NonoError, Result};
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::PathBuf;
use tracing::{info, warn};

pub(crate) fn rollback_base_exclusions() -> Vec<String> {
    [
        ".git",
        ".hg",
        ".svn",
        "target",
        "node_modules",
        "__pycache__",
        ".venv",
        ".DS_Store",
    ]
    .iter()
    .map(|entry| String::from(*entry))
    .collect()
}

pub(crate) struct LaunchPlan {
    pub(crate) program: OsString,
    pub(crate) cmd_args: Vec<OsString>,
    pub(crate) caps: CapabilitySet,
    /// Resolved filesystem deny paths (groups + profile `filesystem.deny`).
    /// Threaded to the tool-sandbox so a mediated command's live working
    /// directory can be rejected when it falls under a path the agent is denied.
    pub(crate) deny_paths: Vec<PathBuf>,
    pub(crate) loaded_secrets: Vec<nono::LoadedSecret>,
    pub(crate) flags: ExecutionFlags,
}

#[derive(Clone, Default)]
pub(crate) struct SessionLaunchOptions {
    pub(crate) session_id: Option<String>,
    pub(crate) detached_start: bool,
    pub(crate) session_name: Option<String>,
    pub(crate) profile_name: Option<String>,
    pub(crate) detach_sequence: Option<Vec<u8>>,
}

#[derive(Clone, Default)]
pub(crate) struct RollbackLaunchOptions {
    pub(crate) requested: bool,
    pub(crate) disabled: bool,
    pub(crate) prompt_disabled: bool,
    pub(crate) audit_disabled: bool,
    pub(crate) no_audit_integrity: bool,
    pub(crate) audit_integrity: bool,
    pub(crate) audit_sign_key: Option<String>,
    pub(crate) destination: Option<PathBuf>,
    pub(crate) track_all: bool,
    pub(crate) skip_dirs: Vec<String>,
    pub(crate) include: Vec<String>,
    pub(crate) exclude_patterns: Vec<String>,
    pub(crate) exclude_globs: Vec<String>,
}

#[derive(Clone, Default)]
pub(crate) struct TrustLaunchOptions {
    pub(crate) scan_root: PathBuf,
    pub(crate) policy: Option<nono::trust::TrustPolicy>,
    pub(crate) scan_performed: bool,
    pub(crate) interception_active: bool,
    pub(crate) protected_paths: Vec<PathBuf>,
}

/// Plain CONNECT-tunnel domain allowlist entries and an optional network profile.
#[derive(Clone, Debug, Default)]
pub(crate) struct DomainFilterIntent {
    pub(crate) network_profile: Option<String>,
    /// Only `AllowDomainEntry::Plain` entries — endpoint-bearing entries live in
    /// `EndpointFilterIntent`.
    pub(crate) allow_domain: Vec<profile::AllowDomainEntry>,
    /// Domains to deny regardless of the allowlist.
    pub(crate) deny_domain: Vec<String>,
}

/// `WithEndpoints` allow-domain entries that require TLS interception so the
/// proxy can inspect method and path before forwarding.
/// All entries must be `AllowDomainEntry::WithEndpoints` (enforced by `debug_assert`
/// at construction in `prepare_proxy_launch_options`).
#[derive(Clone, Debug, Default)]
pub(crate) struct EndpointFilterIntent {
    pub(crate) routes: Vec<profile::AllowDomainEntry>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct CredentialProxyIntent {
    pub(crate) credentials: Vec<String>,
    pub(crate) custom_credentials: HashMap<String, profile::CustomCredentialDef>,
    /// Per-credential endpoint restrictions from `--allow-endpoint SERVICE:METHOD:PATH`,
    /// pre-parsed into `(service_name, rule)` pairs.
    pub(crate) endpoint_restrictions: Vec<(String, nono_proxy::config::EndpointRule)>,
}

#[derive(Clone, Debug)]
pub(crate) struct UpstreamProxyIntent {
    pub(crate) address: String,
    pub(crate) bypass: Vec<String>,
}

/// TLS interception configuration supplied by the user. Presence means the user
/// configured TLS intercept settings; it does not by itself activate the proxy.
#[derive(Clone, Debug, Default)]
pub(crate) struct TlsInterceptIntent {
    /// macOS only: reuse a persistent CA bundle across sessions.
    #[cfg(target_os = "macos")]
    pub(crate) trust_proxy_ca: bool,
    pub(crate) ca_validity: Option<std::time::Duration>,
    pub(crate) ca_env_vars: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct OpenUrlIntent {
    pub(crate) origins: Vec<String>,
    pub(crate) allow_localhost: bool,
    pub(crate) allow_launch_services: bool,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ProxyLaunchOptions {
    pub(crate) domain_filter: Option<DomainFilterIntent>,
    pub(crate) endpoint_filter: Option<EndpointFilterIntent>,
    pub(crate) credentials: Option<CredentialProxyIntent>,
    pub(crate) upstream_proxy: Option<UpstreamProxyIntent>,
    pub(crate) tls_intercept: Option<TlsInterceptIntent>,
    pub(crate) open_url: Option<OpenUrlIntent>,
    pub(crate) allow_bind_ports: Vec<u16>,
    pub(crate) proxy_port: Option<u16>,
    /// When `true`, the proxy denies any host not explicitly allowed rather
    /// than falling back to allow-all. Set when the user combined proxy
    /// features with `--block-net` or profile `network.block`.
    pub(crate) strict_filter: bool,
    pub(crate) proxy_leaf_validity: Option<std::time::Duration>,
    pub(crate) command_policies: Option<crate::command_policy::CommandPoliciesConfig>,
    /// Environment variables the proxy must source (e.g. credential-bearing
    /// values) for tool-sandbox brokered commands.
    pub(crate) proxy_source_env_vars: HashMap<String, String>,
    /// Per-credential base-URL environment variables injected into tool-sandbox
    /// brokered commands so they target the proxy reverse-route.
    pub(crate) tool_sandbox_base_url_env_vars: HashMap<String, String>,
    /// Credential names that are brokered to tool-sandbox commands via the proxy.
    pub(crate) tool_sandbox_proxy_credentials: HashSet<String>,
    /// Proxy/supervisor session identifier, propagated to credential-capture.
    pub(crate) session_id: String,
    /// Supervisor-side CLI command credential-capture entries.
    pub(crate) credential_capture: HashMap<String, profile::CredentialCaptureEntry>,
    /// Declarative OAuth provider definitions.
    pub(crate) credential_providers: HashMap<String, profile::CredentialProviderDef>,
    /// Declarative OAuth provider route bindings.
    pub(crate) credential_routes: Vec<profile::CredentialRouteDef>,
    /// Enable HTTP/2 negotiation for upstream connections.
    pub(crate) enable_h2: bool,
    /// Profile-declared client-side proxy bypass entries for generated
    /// NO_PROXY/no_proxy.
    pub(crate) no_proxy: Vec<String>,
}

impl ProxyLaunchOptions {
    pub(crate) fn is_active(&self) -> bool {
        self.domain_filter.is_some()
            || self.endpoint_filter.is_some()
            || self
                .credentials
                .as_ref()
                .is_some_and(|credentials| !credentials.credentials.is_empty())
            || !self.credential_routes.is_empty()
            || self.upstream_proxy.is_some()
    }
}

/// Resolved network intent, derived from CLI flags and profile before any
/// proxy is started. This is the single source of truth for which network
/// mode the sandbox will run in.
///
/// Variants are ordered by decreasing restriction:
/// - `BlockAll` — OS sandbox denies all outbound connections.
/// - `ProxyFiltered` — outbound connections are gated through the nono proxy.
/// - `Unrestricted` — no network restriction.
#[derive(Clone, Debug, Default)]
pub(crate) enum NetworkIntent {
    /// `--allow-net` or default when no network flags are given: no restriction.
    #[default]
    Unrestricted,
    /// `--block-net` or profile `network.block` with no active proxy override:
    /// outbound connections are denied by the OS sandbox.
    BlockAll,
    /// Proxy-activating features are configured. Proxy starts only if
    /// `ProxyLaunchOptions::is_active()` — custom credentials alone do not.
    ProxyFiltered(Box<ProxyLaunchOptions>),
}

impl NetworkIntent {
    pub(crate) fn is_proxy_active(&self) -> bool {
        matches!(self, Self::ProxyFiltered(opts) if opts.is_active())
    }

    pub(crate) fn proxy_options(&self) -> Option<&ProxyLaunchOptions> {
        match self {
            Self::ProxyFiltered(opts) => Some(opts),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub(crate) struct ExecutionFlags {
    pub(crate) strategy: exec_strategy::ExecStrategy,
    pub(crate) workdir: PathBuf,
    pub(crate) no_diagnostics: bool,
    pub(crate) diagnostics_json: bool,
    pub(crate) diagnostic_verbosity: u8,
    pub(crate) silent: bool,
    #[cfg(target_os = "linux")]
    pub(crate) capability_elevation: bool,
    #[cfg(target_os = "linux")]
    pub(crate) wsl2_proxy_policy: crate::profile::Wsl2ProxyPolicy,
    #[cfg(target_os = "linux")]
    pub(crate) af_unix_mediation: crate::profile::LinuxAfUnixMediation,
    #[cfg(target_os = "linux")]
    pub(crate) sandbox_policy: crate::profile::LinuxSandboxPolicy,
    #[cfg(target_os = "linux")]
    pub(crate) proc_comm_notify: bool,
    pub(crate) bypass_protection_paths: Vec<PathBuf>,
    pub(crate) ignored_denial_paths: Vec<PathBuf>,
    pub(crate) suppressed_system_service_operations: Vec<String>,
    pub(crate) profile_display_name: Option<String>,
    pub(crate) session: SessionLaunchOptions,
    pub(crate) rollback: RollbackLaunchOptions,
    pub(crate) trust: TrustLaunchOptions,
    pub(crate) network: NetworkIntent,
    pub(crate) redaction_policy: nono::ScrubPolicy,
    pub(crate) session_hooks: profile::SessionHooks,
    pub(crate) allowed_env_vars: Option<Vec<String>>,
    pub(crate) denied_env_vars: Option<Vec<String>>,
    /// Expanded `environment.set_vars` (key, expanded-value), `None` if absent.
    pub(crate) set_vars: Option<Vec<(String, String)>>,
    pub(crate) startup_timeout_secs: Option<u64>,
    pub(crate) command_policies: Option<crate::command_policy::CommandPoliciesConfig>,
    /// Command binaries already resolved while validating `command_policies`,
    /// reused when building the tool-sandbox plan instead of re-resolving.
    pub(crate) resolved_command_binaries: Option<crate::command_policy::ResolvedCommandBinaries>,
}

impl ExecutionFlags {
    /// Build flags from a fully-prepared sandbox, with sensible defaults for
    /// fields that are not sourced from the profile (strategy, workdir, etc.).
    /// Call sites override only what they need via struct update syntax:
    ///   `ExecutionFlags { strategy: ..., ..ExecutionFlags::from_prepared(&p, silent)? }`
    pub(crate) fn from_prepared(
        prepared: &crate::sandbox_prepare::PreparedSandbox,
        silent: bool,
    ) -> Result<Self> {
        let cwd = std::env::current_dir()
            .map_err(|e| NonoError::SandboxInit(format!("Failed to get cwd: {e}")))?;
        Ok(Self {
            strategy: exec_strategy::ExecStrategy::Supervised,
            workdir: cwd.clone(),
            no_diagnostics: false,
            diagnostics_json: false,
            diagnostic_verbosity: 0,
            silent,
            #[cfg(target_os = "linux")]
            capability_elevation: prepared.capability_elevation,
            #[cfg(target_os = "linux")]
            wsl2_proxy_policy: prepared.wsl2_proxy_policy,
            #[cfg(target_os = "linux")]
            af_unix_mediation: prepared.af_unix_mediation,
            #[cfg(target_os = "linux")]
            sandbox_policy: prepared.sandbox_policy,
            #[cfg(target_os = "linux")]
            proc_comm_notify: prepared.proc_comm_notify,
            bypass_protection_paths: prepared.bypass_protection_paths.clone(),
            ignored_denial_paths: prepared.ignored_denial_paths.clone(),
            suppressed_system_service_operations: prepared
                .suppressed_system_service_operations
                .clone(),
            profile_display_name: prepared.profile_display_name.clone(),
            session: SessionLaunchOptions::default(),
            rollback: RollbackLaunchOptions::default(),
            trust: TrustLaunchOptions {
                scan_root: cwd,
                ..TrustLaunchOptions::default()
            },
            network: NetworkIntent::default(),
            redaction_policy: nono::ScrubPolicy::secure_default(),
            session_hooks: prepared.session_hooks.clone(),
            allowed_env_vars: prepared.allowed_env_vars.clone(),
            denied_env_vars: prepared.denied_env_vars.clone(),
            set_vars: prepared.set_vars.clone(),
            startup_timeout_secs: None,
            command_policies: prepared.command_policies.clone(),
            resolved_command_binaries: prepared.resolved_command_binaries.clone(),
        })
    }
}

pub(crate) fn prepare_run_launch_plan(
    run_args: RunArgs,
    program: OsString,
    cmd_args: Vec<OsString>,
    silent: bool,
) -> Result<LaunchPlan> {
    let detach_sequence = load_configured_detach_sequence()?;
    let redaction_policy = load_configured_redaction_policy()?;
    let args = run_args.sandbox;
    let no_diagnostics = run_args.no_diagnostics;
    let diagnostics_json = run_args.diagnostics_json;
    let rollback = run_args.rollback;
    let no_rollback_prompt = run_args.no_rollback_prompt;
    let no_audit = run_args.no_audit;
    let no_audit_integrity = run_args.no_audit_integrity;
    let audit_sign_key = run_args.audit_sign_key.clone();
    let trust_override = run_args.trust_override;
    let startup_timeout_secs = run_args.startup_timeout_secs;

    if no_audit && !silent {
        eprintln!("  [nono] Warning: --no-audit disables session and command-policy audit events.");
    }
    if no_audit_integrity && !silent {
        eprintln!(
            "  [nono] Warning: --no-audit-integrity disables Merkle audit integrity; audit events are written without an integrity summary."
        );
    }

    if audit_sign_key
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
        && (no_audit || no_audit_integrity)
    {
        return Err(NonoError::ConfigParse(
            "--audit-sign-key requires audit integrity to be enabled".to_string(),
        ));
    }

    let mut prepared = prepare_sandbox(&args, silent)?;
    validate_proxy_conflicts(&args, &prepared)?;
    validate_rollback_destination(run_args.rollback_dest.as_ref(), &prepared)?;

    if prepared.allow_launch_services_active {
        print_allow_launch_services_warning(silent);
    }
    if prepared.allow_gpu_active {
        print_allow_gpu_warning(silent);
    }

    if run_args.capability_elevation {
        prepared.capability_elevation = true;
    }

    // On WSL2, seccomp user notification returns EBUSY (microsoft/WSL#9548).
    // Disable features that depend on it and warn the user.
    #[cfg(target_os = "linux")]
    if nono::is_wsl2() && prepared.capability_elevation {
        let banner_showed_wsl2_link = nono::Sandbox::detect_abi()
            .ok()
            .is_some_and(|abi| !abi.has_network() || !abi.has_ioctl_dev() || !abi.has_scoping());
        if banner_showed_wsl2_link {
            eprintln!("  [nono] WSL2: capability elevation disabled");
        } else {
            eprintln!(
                "  [nono] WSL2: capability elevation disabled \
                 (https://nono.sh/docs/cli/internals/wsl2)"
            );
        }
        prepared.capability_elevation = false;
    }

    let scan_root = resolve_requested_workdir(args.workdir.as_ref());
    let trust = prepare_trust_launch_options(
        &mut prepared,
        scan_root.clone(),
        trust_override,
        &run_args.skip_dir,
        silent,
    )?;

    #[cfg(target_os = "linux")]
    if prepared.capability_elevation {
        prepared.caps.set_extensions_enabled(true);
    }

    let session_id = std::env::var(crate::DETACHED_SESSION_ID_ENV)
        .ok()
        .filter(|id| !id.is_empty())
        .unwrap_or_else(crate::session::generate_session_id);
    let network = prepare_proxy_launch_options(&args, &prepared, silent, session_id.clone())?;
    let rollback_options = prepare_rollback_launch_options(
        &run_args.rollback_exclude,
        run_args.rollback_all,
        &run_args.skip_dir,
        &run_args.rollback_include,
        &prepared,
    );

    let strategy = select_exec_strategy(
        rollback,
        network.is_proxy_active(),
        prepared.capability_elevation,
        trust.interception_active,
        run_args.detached,
    );

    let flags = ExecutionFlags {
        strategy,
        workdir: resolve_requested_workdir(args.workdir.as_ref()),
        no_diagnostics,
        diagnostics_json,
        diagnostic_verbosity: args.verbose,
        session: SessionLaunchOptions {
            session_id: Some(session_id),
            detached_start: run_args.detached,
            session_name: run_args.name,
            profile_name: args.profile.clone(),
            detach_sequence,
        },
        rollback: RollbackLaunchOptions {
            requested: rollback,
            disabled: run_args.no_rollback,
            prompt_disabled: no_rollback_prompt,
            audit_disabled: no_audit,
            no_audit_integrity,
            audit_integrity: run_args.audit_integrity,
            audit_sign_key,
            destination: run_args.rollback_dest,
            ..rollback_options
        },
        trust,
        network,
        redaction_policy,
        startup_timeout_secs,
        ..ExecutionFlags::from_prepared(&prepared, silent)?
    };
    Ok(LaunchPlan {
        program,
        cmd_args,
        caps: prepared.caps,
        deny_paths: prepared.deny_paths,
        loaded_secrets: prepared.secrets,
        flags,
    })
}

pub(crate) fn load_configured_detach_sequence() -> Result<Option<Vec<u8>>> {
    Ok(config::user::load_user_config()?
        .and_then(|user_config| user_config.ui.detach_sequence)
        .map(|sequence| sequence.bytes().to_vec()))
}

pub(crate) fn load_configured_redaction_policy() -> Result<nono::ScrubPolicy> {
    config::user::load_user_config()?.map_or_else(
        || Ok(nono::ScrubPolicy::secure_default()),
        |user_config| user_config.redaction.to_scrub_policy(),
    )
}

fn prepare_trust_launch_options(
    prepared: &mut PreparedSandbox,
    scan_root: PathBuf,
    trust_override: bool,
    skip_dirs: &[String],
    silent: bool,
) -> Result<TrustLaunchOptions> {
    if trust_override {
        if !silent {
            eprintln!(
                "  {}",
                "WARNING: --trust-override active, skipping instruction file verification."
                    .yellow()
            );
        }
        return Ok(TrustLaunchOptions {
            scan_root,
            scan_performed: false,
            ..TrustLaunchOptions::default()
        });
    }

    let trust_policy = trust_scan::load_scan_policy(&scan_root, false, skip_dirs)?;
    let result = trust_scan::run_pre_exec_scan(&scan_root, &trust_policy, silent, skip_dirs)?;
    if !result.results.is_empty() {
        info!(
            "Trust scan: {} verified, {} blocked, {} warned ({} total files)",
            result.verified,
            result.blocked,
            result.warned,
            result.results.len()
        );
    }
    if !result.should_proceed() {
        return Err(NonoError::TrustVerification {
            path: String::new(),
            reason: "instruction files failed trust verification".to_string(),
        });
    }

    let verified = result.verified_paths();
    instruction_deny::write_protect_verified_files(&mut prepared.caps, &verified)?;

    for path in &verified {
        match FsCapability::new_file(path, AccessMode::Read) {
            Ok(mut cap) => {
                cap.source = nono::CapabilitySource::System;
                prepared.caps.add_fs(cap);
            }
            Err(e) => {
                warn!(
                    "Failed to create capability for verified subject {}: {}",
                    path.display(),
                    e
                );
            }
        }
    }

    Ok(TrustLaunchOptions {
        scan_root,
        policy: Some(trust_policy.clone()),
        scan_performed: true,
        interception_active: trust_interception_active(Some(&trust_policy)),
        protected_paths: verified,
    })
}

fn prepare_rollback_launch_options(
    rollback_exclude: &[String],
    rollback_all: bool,
    skip_dirs: &[String],
    rollback_include: &[String],
    prepared: &PreparedSandbox,
) -> RollbackLaunchOptions {
    let is_glob = |v: &String| v.contains('*') || v.contains('?') || v.contains('[');
    let (cli_exclude_globs, cli_exclude_patterns): (Vec<_>, Vec<_>) =
        rollback_exclude.iter().cloned().partition(is_glob);

    let mut exclude_patterns = prepared.rollback_exclude_patterns.clone();
    exclude_patterns.extend(cli_exclude_patterns);

    let mut exclude_globs = prepared.rollback_exclude_globs.clone();
    exclude_globs.extend(cli_exclude_globs);

    RollbackLaunchOptions {
        track_all: rollback_all,
        skip_dirs: skip_dirs.to_vec(),
        include: rollback_include.to_vec(),
        exclude_patterns,
        exclude_globs,
        ..RollbackLaunchOptions::default()
    }
}

fn validate_rollback_destination(
    rollback_dest: Option<&PathBuf>,
    prepared: &PreparedSandbox,
) -> Result<()> {
    let Some(dest) = rollback_dest else {
        return Ok(());
    };

    let dest_abs = {
        let mut current = dest.clone();
        loop {
            match current.canonicalize() {
                Ok(canonical) => break canonical,
                Err(_) => match current.parent() {
                    Some(parent) => current = parent.to_path_buf(),
                    None => break dest.clone(),
                },
            }
        }
    };

    let covered = prepared.caps.fs_capabilities().iter().any(|cap| {
        matches!(cap.access, AccessMode::Write | AccessMode::ReadWrite)
            && dest_abs.starts_with(&cap.resolved)
    });

    if covered {
        return Ok(());
    }

    Err(NonoError::ConfigParse(format!(
        "--rollback-dest '{}' is not covered by sandbox write permissions. \
         Add --allow {} to grant access, or omit --rollback-dest to use the default path ($XDG_STATE_HOME/nono/rollbacks/).",
        dest.display(),
        dest.display()
    )))
}

pub(crate) fn resolve_requested_workdir(workdir: Option<&PathBuf>) -> PathBuf {
    workdir
        .cloned()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."))
}

pub(crate) fn select_exec_strategy(
    rollback: bool,
    proxy_active: bool,
    capability_elevation: bool,
    trust_interception_active: bool,
    detached_start: bool,
) -> exec_strategy::ExecStrategy {
    let _ = (
        rollback,
        proxy_active,
        capability_elevation,
        trust_interception_active,
        detached_start,
    );
    exec_strategy::ExecStrategy::Supervised
}

pub(crate) fn trust_interception_active(policy: Option<&nono::trust::TrustPolicy>) -> bool {
    policy.is_some_and(|trust_policy| !trust_policy.includes.is_empty())
}

pub(crate) fn select_threading_context(
    has_loaded_secrets: bool,
    proxy_active: bool,
    trust_scan_performed: bool,
    trust_interception_active: bool,
) -> exec_strategy::ThreadingContext {
    if proxy_active || trust_scan_performed || trust_interception_active {
        exec_strategy::ThreadingContext::CryptoExpected
    } else if has_loaded_secrets {
        exec_strategy::ThreadingContext::KeyringExpected
    } else {
        exec_strategy::ThreadingContext::Strict
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::SandboxArgs;

    fn run_args_with_sandbox(sandbox: SandboxArgs) -> RunArgs {
        RunArgs {
            sandbox,
            detached: false,
            detach_timeout_secs: None,
            rollback: false,
            no_rollback_prompt: false,
            no_rollback: false,
            rollback_exclude: Vec::new(),
            rollback_include: Vec::new(),
            rollback_all: false,
            skip_dir: Vec::new(),
            rollback_dest: None,
            no_diagnostics: false,
            diagnostics_json: false,
            startup_timeout_secs: None,
            no_audit: false,
            no_audit_integrity: false,
            audit_integrity: false,
            audit_sign_key: None,
            trust_override: false,
            name: None,
            capability_elevation: false,
            command: Vec::new(),
            help: None,
        }
    }

    #[test]
    fn run_launch_plan_rejects_block_net_with_upstream_proxy() {
        let _env_lock = crate::test_env::ENV_LOCK.lock().expect("env lock");
        let test_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("test-env")
            .join(format!(
                "run-launch-block-net-upstream-proxy-{}",
                std::process::id()
            ));
        let home = test_root.join("home");
        let state = test_root.join("state");
        let config = test_root.join("config");
        let workdir = test_root.join("workdir");
        std::fs::create_dir_all(&home).expect("create test home");
        std::fs::create_dir_all(&state).expect("create test state");
        std::fs::create_dir_all(&config).expect("create test config");
        std::fs::create_dir_all(&workdir).expect("create test workdir");
        let _env = crate::test_env::EnvVarGuard::set_all(&[
            ("HOME", home.to_str().expect("home path is utf-8")),
            (
                "XDG_STATE_HOME",
                state.to_str().expect("state path is utf-8"),
            ),
            (
                "XDG_CONFIG_HOME",
                config.to_str().expect("config path is utf-8"),
            ),
        ]);

        let run_args = run_args_with_sandbox(SandboxArgs {
            allow_cwd: true,
            workdir: Some(workdir),
            block_net: true,
            external_proxy: Some("squid.corp:3128".to_string()),
            ..SandboxArgs::default()
        });

        let result = prepare_run_launch_plan(run_args, OsString::from("/bin/echo"), vec![], true);
        let Err(err) = result else {
            panic!("expected run launch plan to reject --block-net + --upstream-proxy");
        };
        assert!(
            err.to_string().contains("--block-net") && err.to_string().contains("--upstream-proxy"),
            "unexpected error: {err}"
        );
    }
}
