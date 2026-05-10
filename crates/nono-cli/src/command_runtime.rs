use crate::cli::{RunArgs, SandboxArgs, ShellArgs, WrapArgs};
use crate::exec_strategy;
use crate::execution_runtime::execute_sandboxed;
use crate::launch_runtime::{
    load_configured_detach_sequence, prepare_run_launch_plan, resolve_requested_workdir,
    select_exec_strategy, ExecutionFlags, LaunchPlan, SessionLaunchOptions,
};
use crate::output;
use crate::profile;
use crate::proxy_runtime::prepare_proxy_launch_options;
use crate::sandbox_prepare::{
    prepare_sandbox, print_allow_gpu_warning, print_allow_launch_services_warning,
    should_auto_enable_claude_launch_services, validate_external_proxy_bypass,
};
use crate::theme;
use nono::{NonoError, Result};
use std::ffi::OsString;
use std::path::PathBuf;
use tracing::warn;

pub(crate) fn run_sandbox(mut run_args: RunArgs, silent: bool) -> Result<()> {
    let command = run_args.command.clone();

    if command.is_empty() {
        return Err(NonoError::NoCommand);
    }

    let mut command_iter = command.into_iter();
    let program = OsString::from(command_iter.next().ok_or(NonoError::NoCommand)?);
    let mut cmd_args: Vec<OsString> = command_iter.map(OsString::from).collect();
    if should_auto_enable_claude_launch_services(&run_args.sandbox, &program, &cmd_args) {
        warn!(
            "Auto-enabling --allow-launch-services for Claude Code because no refresh-capable local auth was detected"
        );
        run_args.sandbox.allow_launch_services = true;
    }
    let args = run_args.sandbox.clone();

    if let Some(ref profile_name) = args.profile {
        let loaded = profile::load_profile(profile_name)?;
        if !loaded.command_args.is_empty() {
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
    }

    if args.dry_run {
        let prepared = prepare_sandbox(&args, silent)?;
        validate_external_proxy_bypass(&args, &prepared)?;
        if !prepared.secrets.is_empty() && !silent {
            eprintln!(
                "  Would inject {} credential(s) as environment variables",
                prepared.secrets.len()
            );
        }
        output::print_dry_run(&program, &cmd_args, silent);
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
        output::print_dry_run(shell_path.as_os_str(), &[], silent);
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

    let proxy = prepare_proxy_launch_options(&args.sandbox, &prepared, silent)?;
    let strategy = select_exec_strategy(
        false,
        proxy.active,
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
            bypass_protection_paths: prepared.bypass_protection_paths,
            allowed_env_vars: prepared.allowed_env_vars,
            proxy,
            session: SessionLaunchOptions {
                session_name: args.name,
                detach_sequence: load_configured_detach_sequence()?,
                ..SessionLaunchOptions::default()
            },
            ..ExecutionFlags::defaults(silent)?
        },
    })
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
        if !prepared.secrets.is_empty() && !silent {
            eprintln!(
                "  Would inject {} credential(s) as environment variables",
                prepared.secrets.len()
            );
        }
        output::print_dry_run(&program, &cmd_args, silent);
        return Ok(());
    }

    let prepared = prepare_sandbox(&args, silent)?;

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
            allowed_env_vars: prepared.allowed_env_vars,
            ..ExecutionFlags::defaults(silent)?
        },
    })
}
