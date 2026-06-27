use crate::cli::{RunArgs, SandboxArgs, ShellArgs, WrapArgs};
use crate::exec_strategy;
use crate::execution_runtime::execute_sandboxed;
use crate::launch_runtime::{
    ExecutionFlags, LaunchPlan, SessionLaunchOptions, load_configured_detach_sequence,
    load_configured_redaction_policy, prepare_run_launch_plan, resolve_requested_workdir,
    select_exec_strategy,
};
use crate::output;
use crate::profile;
use crate::proxy_runtime::prepare_proxy_launch_options;
use crate::sandbox_prepare::{
    prepare_sandbox, print_allow_gpu_warning, print_allow_launch_services_warning,
    should_auto_enable_claude_launch_services, validate_block_net_conflicts,
    validate_external_proxy_bypass,
};
use crate::theme;
use nono::{CapabilitySet, NonoError, Result};
use std::ffi::OsString;
use std::path::PathBuf;
use tracing::warn;

/// Check whether the loaded profile specifies a `binary` field that should be
/// honoured. Only user-authored profiles (user overrides or file-path based)
/// are allowed to set the target binary. Pack/registry and built-in profiles
/// are not trusted to dictate which binary runs.
fn resolve_profile_binary(
    profile_name: &str,
    loaded: &profile::Profile,
    silent: bool,
) -> Option<String> {
    let binary = loaded.binary.as_ref()?;

    let is_user_profile =
        profile::is_user_override(profile_name) || profile::is_file_path_ref(profile_name);

    if !is_user_profile {
        if !silent {
            warn!(
                "Profile '{profile_name}' specifies binary '{binary}' but is not a user profile; ignoring",
            );
        }
        return None;
    }
    Some(binary.clone())
}

/// Resolve the program to execute: if the profile specifies a `binary` field
/// (and is a user profile), use it. If the CLI also provides a trailing
/// command, warn that the profile binary takes precedence.
fn resolve_program_from_profile_or_cli(
    cli_command: &[String],
    loaded_profile: Option<(&str, &profile::Profile)>,
    silent: bool,
) -> Result<(OsString, Vec<OsString>)> {
    let profile_binary =
        loaded_profile.and_then(|(name, prof)| resolve_profile_binary(name, prof, silent));

    if let Some(binary) = profile_binary {
        if !cli_command.is_empty() && !silent {
            crate::output::print_warning(&format!(
                "Profile specifies binary '{}'; ignoring trailing command '{}'",
                binary,
                cli_command.join(" ")
            ));
        }
        let program = OsString::from(&binary);
        Ok((program, Vec::new()))
    } else if !cli_command.is_empty() {
        let mut iter = cli_command.iter();
        let program = OsString::from(iter.next().ok_or(NonoError::NoCommand)?);
        let cmd_args: Vec<OsString> = iter.map(OsString::from).collect();
        Ok((program, cmd_args))
    } else {
        Err(NonoError::NoCommand)
    }
}

pub(crate) fn run_sandbox(mut run_args: RunArgs, silent: bool) -> Result<()> {
    let command = run_args.command.clone();

    // Load profile once and reuse for binary resolution and command_args.
    let loaded_profile = match run_args.sandbox.profile.as_ref() {
        Some(name) => Some((name.clone(), profile::load_profile(name)?)),
        None => None,
    };

    // Resolve the program: profile `binary` takes precedence over CLI trailing command.
    let (program, mut cmd_args) = resolve_program_from_profile_or_cli(
        &command,
        loaded_profile.as_ref().map(|(n, p)| (n.as_str(), p)),
        silent,
    )?;

    if should_auto_enable_claude_launch_services(&run_args.sandbox, &program, &cmd_args) {
        warn!(
            "Auto-enabling --allow-launch-services for Claude Code because no refresh-capable local auth was detected"
        );
        run_args.sandbox.allow_launch_services = true;
    }
    let args = run_args.sandbox.clone();

    // Append profile command_args if applicable
    if let Some((_, ref loaded)) = loaded_profile
        && !loaded.command_args.is_empty()
    {
        let all_packs_installed = loaded.packs.iter().all(|pack_ref| {
            let parts: Vec<&str> = pack_ref.splitn(2, '/').collect();
            if parts.len() != 2 {
                return false;
            }
            crate::package::package_install_dir(parts[0], parts[1])
                .map(|dir| dir.exists())
                .unwrap_or(false)
        });

        if all_packs_installed || loaded.packs.is_empty() {
            let workdir = args
                .workdir
                .clone()
                .or_else(|| std::env::current_dir().ok())
                .unwrap_or_else(|| PathBuf::from("."));
            for arg in &loaded.command_args {
                let expanded = profile::expand_vars(arg, &workdir)?;
                cmd_args.push(OsString::from(expanded));
            }
        }
    }

    if args.dry_run {
        let prepared = prepare_sandbox(&args, silent)?;
        validate_block_net_conflicts(&args, &prepared)?;
        validate_external_proxy_bypass(&args, &prepared)?;
        if !prepared.secrets.is_empty() && !silent {
            eprintln!(
                "  Would inject {} credential(s) as environment variables",
                prepared.secrets.len()
            );
        }
        let redaction_policy = load_configured_redaction_policy()?;
        output::print_dry_run(&program, &cmd_args, &redaction_policy, silent);
        return Ok(());
    }

    let launch_plan = prepare_run_launch_plan(run_args, program, cmd_args, silent)?;
    execute_sandboxed(launch_plan)
}

pub(crate) fn run_shell(args: ShellArgs, silent: bool) -> Result<()> {
    let shell_path = args
        .shell
        .or_else(|| {
            std::env::var("SHELL")
                .ok()
                .filter(|shell| !shell.is_empty())
                .map(std::path::PathBuf::from)
        })
        .unwrap_or_else(|| std::path::PathBuf::from("/bin/sh"));

    if args.sandbox.dry_run {
        let prepared = prepare_sandbox(&args.sandbox, silent)?;
        if !prepared.secrets.is_empty() && !silent {
            eprintln!(
                "  Would inject {} credential(s) as environment variables",
                prepared.secrets.len()
            );
        }
        let redaction_policy = load_configured_redaction_policy()?;
        output::print_dry_run(shell_path.as_os_str(), &[], &redaction_policy, silent);
        return Ok(());
    }

    let prepared = prepare_sandbox(&args.sandbox, silent)?;

    if prepared.allow_launch_services_active {
        print_allow_launch_services_warning(silent);
    }
    if prepared.allow_gpu_active {
        print_allow_gpu_warning(silent);
    }

    if !silent {
        eprintln!("{}", {
            let theme = theme::current();
            theme::fg("Exit the shell with Ctrl-D or 'exit'.", theme.subtext)
        });
        eprintln!();
    }

    let session_id = std::env::var(crate::DETACHED_SESSION_ID_ENV)
        .ok()
        .filter(|id| !id.is_empty())
        .unwrap_or_else(crate::session::generate_session_id);
    let network =
        prepare_proxy_launch_options(&args.sandbox, &prepared, silent, session_id.clone())?;
    let strategy = select_exec_strategy(
        false,
        network.is_proxy_active(),
        prepared.capability_elevation,
        false,
        false,
    );

    execute_sandboxed(LaunchPlan {
        program: shell_path.into_os_string(),
        cmd_args: vec![],
        caps: prepared.caps,
        loaded_secrets: prepared.secrets,
        flags: ExecutionFlags {
            strategy,
            workdir: resolve_requested_workdir(args.sandbox.workdir.as_ref()),
            no_diagnostics: true,
            capability_elevation: prepared.capability_elevation,
            #[cfg(target_os = "linux")]
            wsl2_proxy_policy: prepared.wsl2_proxy_policy,
            #[cfg(target_os = "linux")]
            af_unix_mediation: prepared.af_unix_mediation,
            bypass_protection_paths: prepared.bypass_protection_paths,
            ignored_denial_paths: prepared.ignored_denial_paths,
            suppressed_system_service_operations: prepared.suppressed_system_service_operations,
            allowed_env_vars: prepared.allowed_env_vars,
            denied_env_vars: prepared.denied_env_vars,
            set_vars: prepared.set_vars,
            startup_timeout_secs: args.startup_timeout_secs,
            command_policies: prepared.command_policies,
            session_hooks: prepared.session_hooks,
            network,
            redaction_policy: load_configured_redaction_policy()?,
            session: SessionLaunchOptions {
                session_id: Some(session_id),
                session_name: args.name,
                detach_sequence: load_configured_detach_sequence()?,
                ..SessionLaunchOptions::default()
            },
            ..ExecutionFlags::defaults(silent)?
        },
    })
}

/// `nono wrap` execs the target directly (no supervising parent), so it never
/// creates the cgroup that enforces a memory ceiling. Accepting a limit here would
/// run unenforced — or under `--dry-run` advertise a cap we won't honor. Fail
/// closed instead, like the proxy / AF_UNIX guards below. Covers both `--memory`
/// and a manifest `resources.memory_bytes` (both are in `caps` by now).
fn reject_resource_limits_under_wrap(caps: &CapabilitySet) -> Result<()> {
    if caps
        .resource_limits()
        .is_some_and(|limits| !limits.is_empty())
    {
        return Err(NonoError::ConfigParse(
            "nono wrap does not support --memory / resources.memory_bytes because direct \
             exec cannot create the enforcement cgroup. Use `nono run` instead."
                .to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn run_wrap(wrap_args: WrapArgs, silent: bool) -> Result<()> {
    let args: SandboxArgs = wrap_args.sandbox.into();
    let command = wrap_args.command;
    let no_diagnostics = wrap_args.no_diagnostics;

    if command.is_empty() {
        return Err(NonoError::NoCommand);
    }

    let mut command_iter = command.into_iter();
    let program = OsString::from(command_iter.next().ok_or(NonoError::NoCommand)?);
    let cmd_args: Vec<OsString> = command_iter.map(OsString::from).collect();

    if args.dry_run {
        let prepared = prepare_sandbox(&args, silent)?;
        reject_resource_limits_under_wrap(&prepared.caps)?;
        if !prepared.secrets.is_empty() && !silent {
            eprintln!(
                "  Would inject {} credential(s) as environment variables",
                prepared.secrets.len()
            );
        }
        let redaction_policy = load_configured_redaction_policy()?;
        output::print_dry_run(&program, &cmd_args, &redaction_policy, silent);
        return Ok(());
    }

    let prepared = prepare_sandbox(&args, silent)?;
    reject_resource_limits_under_wrap(&prepared.caps)?;

    if prepared.upstream_proxy.is_some()
        || matches!(
            prepared.caps.network_mode(),
            nono::NetworkMode::ProxyOnly { .. }
        )
    {
        return Err(NonoError::ConfigParse(
            "nono wrap does not support proxy mode (activated by profile network settings). \
             Use `nono run` instead."
                .to_string(),
        ));
    }

    #[cfg(target_os = "linux")]
    if prepared.af_unix_mediation.is_pathname() {
        return Err(NonoError::ConfigParse(
            "nono wrap does not support linux.af_unix_mediation = \"pathname\" because direct \
             exec cannot run the seccomp supervisor. Use `nono run` instead."
                .to_string(),
        ));
    }

    if prepared.allow_launch_services_active {
        print_allow_launch_services_warning(silent);
    }
    if prepared.allow_gpu_active {
        print_allow_gpu_warning(silent);
    }

    execute_sandboxed(LaunchPlan {
        program,
        cmd_args,
        caps: prepared.caps,
        loaded_secrets: prepared.secrets,
        flags: ExecutionFlags {
            strategy: exec_strategy::ExecStrategy::Direct,
            workdir: resolve_requested_workdir(args.workdir.as_ref()),
            no_diagnostics,
            bypass_protection_paths: prepared.bypass_protection_paths,
            ignored_denial_paths: prepared.ignored_denial_paths,
            suppressed_system_service_operations: prepared.suppressed_system_service_operations,
            allowed_env_vars: prepared.allowed_env_vars,
            denied_env_vars: prepared.denied_env_vars,
            set_vars: prepared.set_vars,
            command_policies: prepared.command_policies,
            session_hooks: prepared.session_hooks,
            ..ExecutionFlags::defaults(silent)?
        },
    })
}

#[cfg(test)]
mod tests {
    use super::reject_resource_limits_under_wrap;
    use nono::{CapabilitySet, ResourceLimits};

    #[test]
    fn wrap_rejects_caps_carrying_a_memory_limit() {
        // `nono wrap` execs directly and cannot create the enforcement cgroup,
        // so a requested memory ceiling must be refused (fail-closed) rather than
        // silently dropped and run unenforced.
        let caps = CapabilitySet::new().with_resource_limits(ResourceLimits {
            memory_bytes: Some(64 * 1024 * 1024),
        });
        assert!(reject_resource_limits_under_wrap(&caps).is_err());
    }

    #[test]
    fn wrap_allows_caps_without_a_ceiling() {
        // No limit set at all -> wrap proceeds normally.
        assert!(reject_resource_limits_under_wrap(&CapabilitySet::new()).is_ok());

        // A present-but-empty limit set carries no ceiling, so it is not a
        // silently-dropped enforcement request and must be allowed.
        let caps = CapabilitySet::new().with_resource_limits(ResourceLimits::default());
        assert!(reject_resource_limits_under_wrap(&caps).is_ok());
    }
}
