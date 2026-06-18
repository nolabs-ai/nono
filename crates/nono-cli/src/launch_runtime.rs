use crate::cli::RunArgs;
use crate::config;
use crate::proxy_runtime::prepare_proxy_launch_options;
use crate::sandbox_prepare::{
    PreparedSandbox, prepare_sandbox, print_allow_gpu_warning, print_allow_launch_services_warning,
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
#[derive(Clone, Default)]
pub(crate) struct DomainFilterIntent {
    pub(crate) network_profile: Option<String>,
    /// Only `AllowDomainEntry::Plain` entries — endpoint-bearing entries live in
    /// `EndpointFilterIntent`.
    pub(crate) allow_domain: Vec<profile::AllowDomainEntry>,
}

/// `WithEndpoints` allow-domain entries that require TLS interception so the
/// proxy can inspect method and path before forwarding.
/// All entries must be `AllowDomainEntry::WithEndpoints` (enforced by `debug_assert`
/// at construction in `prepare_proxy_launch_options`).
#[derive(Clone, Default)]
pub(crate) struct EndpointFilterIntent {
    pub(crate) routes: Vec<profile::AllowDomainEntry>,
}

#[derive(Clone, Default)]
pub(crate) struct CredentialProxyIntent {
    pub(crate) credentials: Vec<String>,
    pub(crate) custom_credentials: HashMap<String, profile::CustomCredentialDef>,
}

#[derive(Clone)]
pub(crate) struct UpstreamProxyIntent {
    pub(crate) address: String,
    pub(crate) bypass: Vec<String>,
}

/// TLS interception configuration supplied by the user. Presence means the user
/// configured TLS intercept settings; it does not by itself activate the proxy.
#[derive(Clone, Default)]
pub(crate) struct TlsInterceptIntent {
    /// macOS only: reuse a persistent CA bundle across sessions.
    #[cfg(target_os = "macos")]
    pub(crate) trust_proxy_ca: bool,
    pub(crate) ca_validity: Option<std::time::Duration>,
}

#[derive(Clone, Default)]
pub(crate) struct OpenUrlIntent {
    pub(crate) origins: Vec<String>,
    pub(crate) allow_localhost: bool,
    pub(crate) allow_launch_services: bool,
}

#[derive(Clone, Default)]
pub(crate) struct ProxyLaunchOptions {
    pub(crate) domain_filter: Option<DomainFilterIntent>,
    pub(crate) endpoint_filter: Option<EndpointFilterIntent>,
    pub(crate) credentials: Option<CredentialProxyIntent>,
    pub(crate) upstream_proxy: Option<UpstreamProxyIntent>,
    pub(crate) tls_intercept: Option<TlsInterceptIntent>,
    pub(crate) open_url: Option<OpenUrlIntent>,
    pub(crate) allow_bind_ports: Vec<u16>,
    pub(crate) proxy_port: Option<u16>,
    /// True when the user requested `network.block` or `--block-net`.
    /// Propagated to `ProxyConfig.strict_filter` so the filter denies
    /// unlisted hosts instead of falling back to allow-all.
    pub(crate) network_block: bool,
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
}

impl ProxyLaunchOptions {
    pub(crate) fn is_active(&self) -> bool {
        self.domain_filter.is_some()
            || self.endpoint_filter.is_some()
            || self
                .credentials
                .as_ref()
                .is_some_and(|credentials| !credentials.credentials.is_empty())
            || self.upstream_proxy.is_some()
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
    pub(crate) capability_elevation: bool,
    #[cfg(target_os = "linux")]
    pub(crate) wsl2_proxy_policy: crate::profile::Wsl2ProxyPolicy,
    #[cfg(target_os = "linux")]
    pub(crate) af_unix_mediation: crate::profile::LinuxAfUnixMediation,
    pub(crate) bypass_protection_paths: Vec<PathBuf>,
    pub(crate) ignored_denial_paths: Vec<PathBuf>,
    pub(crate) suppressed_system_service_operations: Vec<String>,
    pub(crate) profile_display_name: Option<String>,
    /// Path globs of Unix sockets to hide from the IPC-denial footer
    /// (`diagnostics.suppress_unix_sockets`). Reporting-only.
    pub(crate) suppressed_unix_socket_globs: Vec<String>,
    pub(crate) session: SessionLaunchOptions,
    pub(crate) rollback: RollbackLaunchOptions,
    pub(crate) trust: TrustLaunchOptions,
    pub(crate) proxy: ProxyLaunchOptions,
    pub(crate) redaction_policy: nono::ScrubPolicy,
    pub(crate) session_hooks: profile::SessionHooks,
    pub(crate) allowed_env_vars: Option<Vec<String>>,
    pub(crate) denied_env_vars: Option<Vec<String>>,
    /// Expanded `environment.set_vars` (key, expanded-value), `None` if absent.
    pub(crate) set_vars: Option<Vec<(String, String)>>,
    pub(crate) startup_timeout_secs: Option<u64>,
    pub(crate) command_policies: Option<crate::command_policy::CommandPoliciesConfig>,
}

impl ExecutionFlags {
    pub(crate) fn defaults(silent: bool) -> Result<Self> {
        Ok(Self {
            strategy: exec_strategy::ExecStrategy::Supervised,
            workdir: std::env::current_dir()
                .map_err(|e| NonoError::SandboxInit(format!("Failed to get cwd: {e}")))?,
            no_diagnostics: false,
            diagnostics_json: false,
            diagnostic_verbosity: 0,
            silent,
            capability_elevation: false,
            #[cfg(target_os = "linux")]
            wsl2_proxy_policy: crate::profile::Wsl2ProxyPolicy::Error,
            #[cfg(target_os = "linux")]
            af_unix_mediation: crate::profile::LinuxAfUnixMediation::Off,
            bypass_protection_paths: Vec::new(),
            ignored_denial_paths: Vec::new(),
            suppressed_system_service_operations: Vec::new(),
            profile_display_name: None,
            suppressed_unix_socket_globs: Vec::new(),
            session: SessionLaunchOptions::default(),
            rollback: RollbackLaunchOptions::default(),
            trust: TrustLaunchOptions {
                scan_root: std::env::current_dir()
                    .map_err(|e| NonoError::SandboxInit(format!("Failed to get cwd: {e}")))?,
                ..TrustLaunchOptions::default()
            },
            proxy: ProxyLaunchOptions::default(),
            redaction_policy: nono::ScrubPolicy::secure_default(),
            session_hooks: profile::SessionHooks::default(),
            allowed_env_vars: None,
            denied_env_vars: None,
            set_vars: None,
            startup_timeout_secs: None,
            command_policies: None,
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
    let proxy = prepare_proxy_launch_options(&args, &prepared, silent, session_id.clone())?;
    let rollback_options = prepare_rollback_launch_options(
        &run_args.rollback_exclude,
        run_args.rollback_all,
        &run_args.skip_dir,
        &run_args.rollback_include,
        &prepared,
    );

    let strategy = select_exec_strategy(
        rollback,
        proxy.is_active(),
        prepared.capability_elevation,
        trust.interception_active,
        run_args.detached,
    );

    Ok(LaunchPlan {
        program,
        cmd_args,
        caps: prepared.caps,
        loaded_secrets: prepared.secrets,
        flags: ExecutionFlags {
            strategy,
            workdir: resolve_requested_workdir(args.workdir.as_ref()),
            no_diagnostics,
            diagnostics_json,
            diagnostic_verbosity: args.verbose,
            silent,
            capability_elevation: prepared.capability_elevation,
            #[cfg(target_os = "linux")]
            wsl2_proxy_policy: prepared.wsl2_proxy_policy,
            #[cfg(target_os = "linux")]
            af_unix_mediation: prepared.af_unix_mediation,
            bypass_protection_paths: prepared.bypass_protection_paths,
            ignored_denial_paths: prepared.ignored_denial_paths,
            suppressed_system_service_operations: prepared.suppressed_system_service_operations,
            profile_display_name: prepared.profile_display_name,
            suppressed_unix_socket_globs: prepared.suppressed_unix_socket_globs,
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
            proxy,
            redaction_policy,
            session_hooks: prepared.session_hooks,
            allowed_env_vars: prepared.allowed_env_vars,
            denied_env_vars: prepared.denied_env_vars,
            set_vars: prepared.set_vars,
            startup_timeout_secs,
            command_policies: prepared.command_policies,
        },
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
