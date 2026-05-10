use crate::cli::RunArgs;
use crate::config;
use crate::proxy_runtime::prepare_proxy_launch_options;
use crate::sandbox_prepare::{
    prepare_sandbox, print_allow_gpu_warning, print_allow_launch_services_warning, PreparedSandbox,
};
use crate::{exec_strategy, instruction_deny, profile, trust_scan};
use colored::Colorize;
use nono::{AccessMode, CapabilitySet, FsCapability, NonoError, Result};
use std::collections::HashMap;
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

#[derive(Clone, Default)]
pub(crate) struct ProxyLaunchOptions {
    pub(crate) active: bool,
    pub(crate) network_profile: Option<String>,
    pub(crate) allow_domain: Vec<String>,
    pub(crate) credentials: Vec<String>,
    pub(crate) custom_credentials: HashMap<String, profile::CustomCredentialDef>,
    pub(crate) upstream_proxy: Option<String>,
    pub(crate) upstream_bypass: Vec<String>,
    pub(crate) allow_bind_ports: Vec<u16>,
    pub(crate) proxy_port: Option<u16>,
    pub(crate) open_url_origins: Vec<String>,
    pub(crate) open_url_allow_localhost: bool,
    pub(crate) allow_launch_services_active: bool,
}

#[derive(Clone)]
pub(crate) struct ExecutionFlags {
    pub(crate) strategy: exec_strategy::ExecStrategy,
    pub(crate) workdir: PathBuf,
    pub(crate) no_diagnostics: bool,
    pub(crate) silent: bool,
    pub(crate) capability_elevation: bool,
    #[cfg(target_os = "linux")]
    pub(crate) wsl2_proxy_policy: crate::profile::Wsl2ProxyPolicy,
    pub(crate) bypass_protection_paths: Vec<PathBuf>,
    pub(crate) session: SessionLaunchOptions,
    pub(crate) rollback: RollbackLaunchOptions,
    pub(crate) trust: TrustLaunchOptions,
    pub(crate) proxy: ProxyLaunchOptions,
    pub(crate) allowed_env_vars: Option<Vec<String>>,
}

impl ExecutionFlags {
    pub(crate) fn defaults(silent: bool) -> Result<Self> {
        Ok(Self {
            strategy: exec_strategy::ExecStrategy::Supervised,
            workdir: std::env::current_dir()
                .map_err(|e| NonoError::SandboxInit(format!("Failed to get cwd: {e}")))?,
            no_diagnostics: false,
            silent,
            capability_elevation: false,
            #[cfg(target_os = "linux")]
            wsl2_proxy_policy: crate::profile::Wsl2ProxyPolicy::Error,
            bypass_protection_paths: Vec::new(),
            session: SessionLaunchOptions::default(),
            rollback: RollbackLaunchOptions::default(),
            trust: TrustLaunchOptions {
                scan_root: std::env::current_dir()
                    .map_err(|e| NonoError::SandboxInit(format!("Failed to get cwd: {e}")))?,
                ..TrustLaunchOptions::default()
            },
            proxy: ProxyLaunchOptions::default(),
            allowed_env_vars: None,
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
    let args = run_args.sandbox;
    let no_diagnostics = run_args.no_diagnostics;
    let rollback = run_args.rollback;
    let no_rollback_prompt = run_args.no_rollback_prompt;
    let no_audit = run_args.no_audit;
    let no_audit_integrity = run_args.no_audit_integrity;
    let audit_sign_key = run_args.audit_sign_key.clone();
    let trust_override = run_args.trust_override;

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

    let proxy = prepare_proxy_launch_options(&args, &prepared, silent)?;
    let rollback_options = prepare_rollback_launch_options(
        &run_args.rollback_exclude,
        run_args.rollback_all,
        &run_args.skip_dir,
        &run_args.rollback_include,
        &prepared,
    );

    let strategy = select_exec_strategy(
        rollback,
        proxy.active,
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
            silent,
            capability_elevation: prepared.capability_elevation,
            #[cfg(target_os = "linux")]
            wsl2_proxy_policy: prepared.wsl2_proxy_policy,
            bypass_protection_paths: prepared.bypass_protection_paths,
            session: SessionLaunchOptions {
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
            allowed_env_vars: prepared.allowed_env_vars,
        },
    })
}

pub(crate) fn load_configured_detach_sequence() -> Result<Option<Vec<u8>>> {
    Ok(config::user::load_user_config()?
        .and_then(|user_config| user_config.ui.detach_sequence)
        .map(|sequence| sequence.bytes().to_vec()))
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
         Add --allow {} to grant access, or omit --rollback-dest to use the default path (~/.nono/rollbacks/).",
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
