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

#[cfg(target_os = "linux")]
fn reject_run_only_sandbox_policy(
    command: &str,
    args: &SandboxArgs,
    prepared: &crate::sandbox_prepare::PreparedSandbox,
) -> Result<()> {
    if args.sandbox_policy.is_some() {
        return Err(NonoError::ConfigParse(format!(
            "--sandbox-policy is only supported by `nono run`; `nono {command}` has no proxy supervisor. Use `nono run` instead."
        )));
    }

    if prepared.explicit_sandbox_policy.is_some() {
        return Err(NonoError::ConfigParse(format!(
            "profiles containing linux.sandbox_policy are only supported by `nono run`; `nono {command}` has no proxy supervisor. Remove linux.sandbox_policy or use `nono run`."
        )));
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn reject_run_only_sandbox_policy(
    _command: &str,
    _args: &SandboxArgs,
    _prepared: &crate::sandbox_prepare::PreparedSandbox,
) -> Result<()> {
    Ok(())
}

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

/// Strip `unsafe_macos_seatbelt_rules` — top-level and nested inside
/// command/`from`/intercept sandboxes — unless the profile is user-authored
/// (user override or file-path profile). Raw Seatbelt rules are as powerful
/// as an arbitrary `binary` override (they can grant anything, including
/// `(allow default)`), so pack/registry/built-in profiles are not trusted to
/// set them. Mirrors `resolve_profile_binary`.
///
/// Structured sandbox overrides (fs/network/credentials) are left untouched
/// for all profiles; only raw Seatbelt S-expressions are gated.
pub(crate) fn strip_untrusted_unsafe_seatbelt_rules(
    profile_name: &str,
    profile: &mut profile::Profile,
    command_policies: Option<&mut crate::command_policy::CommandPoliciesConfig>,
    silent: bool,
) {
    let is_user_profile =
        profile::is_user_override(profile_name) || profile::is_file_path_ref(profile_name);
    if is_user_profile {
        return;
    }

    if !profile.unsafe_macos_seatbelt_rules.is_empty() {
        if !silent {
            warn!(
                "Profile '{profile_name}' sets {} raw Seatbelt rule(s) via unsafe_macos_seatbelt_rules but is not a user profile; ignoring",
                profile.unsafe_macos_seatbelt_rules.len()
            );
        }
        profile.unsafe_macos_seatbelt_rules.clear();
    }

    if let Some(command_policies) = command_policies {
        let locations = crate::command_policy::nested_unsafe_seatbelt_rules(command_policies);
        if !locations.is_empty() {
            if !silent {
                for location in locations
                    .iter()
                    .map(|(location, _rule)| location)
                    .collect::<std::collections::BTreeSet<_>>()
                {
                    warn!(
                        "Profile '{profile_name}' sets raw Seatbelt rule(s) at {location} but is not a user profile; ignoring",
                    );
                }
            }
            crate::command_policy::clear_unsafe_seatbelt_rules(command_policies);
        }
    }
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
        Some(name) => Some((
            name.clone(),
            profile::load_profile_with_extends(name, &run_args.sandbox.extends)?,
        )),
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
        reject_run_only_sandbox_policy("shell", &args.sandbox, &prepared)?;
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
    reject_run_only_sandbox_policy("shell", &args.sandbox, &prepared)?;

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

    let flags = ExecutionFlags {
        strategy,
        workdir: resolve_requested_workdir(args.sandbox.workdir.as_ref()),
        no_diagnostics: true,
        startup_timeout_secs: args.startup_timeout_secs,
        network,
        redaction_policy: load_configured_redaction_policy()?,
        session: SessionLaunchOptions {
            session_id: Some(session_id),
            session_name: args.name,
            detach_sequence: load_configured_detach_sequence()?,
            ..SessionLaunchOptions::default()
        },
        ..ExecutionFlags::from_prepared(&prepared, silent)?
    };
    execute_sandboxed(LaunchPlan {
        program: shell_path.into_os_string(),
        cmd_args: vec![],
        caps: prepared.caps,
        deny_paths: prepared.deny_paths,
        loaded_secrets: prepared.secrets,
        flags,
    })
}

/// `nono wrap` execs the target directly (no supervising parent), so it never
/// creates the cgroup that enforces resource ceilings. Accepting a limit here would
/// run unenforced — or under `--dry-run` advertise a cap we won't honor. Fail
/// closed instead, like the proxy / AF_UNIX guards below. Covers `--memory`,
/// `--max-processes`, and their manifest `resources.*` equivalents (all in `caps`
/// by now).
fn reject_resource_limits_under_wrap(caps: &CapabilitySet) -> Result<()> {
    if caps
        .resource_limits()
        .is_some_and(|limits| !limits.is_empty())
    {
        return Err(NonoError::ConfigParse(
            "nono wrap does not support resource limits (--memory / --max-processes / \
             resources.*) because direct exec cannot create the enforcement cgroup. \
             Use `nono run` instead."
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
        reject_run_only_sandbox_policy("wrap", &args, &prepared)?;
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
    reject_run_only_sandbox_policy("wrap", &args, &prepared)?;

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

    #[cfg(target_os = "linux")]
    if prepared.proc_comm_notify {
        return Err(NonoError::ConfigParse(
            "nono wrap does not support NVIDIA GPU thread-name mediation because direct \
             exec cannot run the seccomp supervisor. Use `nono run --allow-gpu` instead."
                .to_string(),
        ));
    }

    if prepared.allow_launch_services_active {
        print_allow_launch_services_warning(silent);
    }
    if prepared.allow_gpu_active {
        print_allow_gpu_warning(silent);
    }

    let flags = ExecutionFlags {
        strategy: exec_strategy::ExecStrategy::Direct,
        workdir: resolve_requested_workdir(args.workdir.as_ref()),
        no_diagnostics,
        ..ExecutionFlags::from_prepared(&prepared, silent)?
    };
    execute_sandboxed(LaunchPlan {
        program,
        cmd_args,
        caps: prepared.caps,
        deny_paths: prepared.deny_paths,
        loaded_secrets: prepared.secrets,
        flags,
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
            max_processes: None,
        });
        assert!(reject_resource_limits_under_wrap(&caps).is_err());
    }

    #[test]
    fn wrap_rejects_caps_carrying_a_process_limit() {
        // Same fail-closed rule for a process-count ceiling: wrap can't enforce it
        // either, so it must be refused rather than run unenforced.
        let caps = CapabilitySet::new().with_resource_limits(ResourceLimits {
            memory_bytes: None,
            max_processes: Some(64),
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

#[cfg(test)]
mod strip_untrusted_unsafe_seatbelt_rules_tests {
    use super::strip_untrusted_unsafe_seatbelt_rules;
    use crate::command_policy::{CommandPoliciesConfig, CommandPolicyConfig, CommandSandboxConfig};
    use crate::profile;

    // `is_file_path_ref` is pure string logic (no filesystem access), so a
    // name ending in `.json` is treated as a trusted, user-authored profile
    // reference without needing to touch `XDG_CONFIG_HOME`.
    const TRUSTED_NAME: &str = "./scratch-profile.json";
    const UNTRUSTED_NAME: &str = "hardened";

    #[test]
    fn strips_top_level_rules_for_untrusted_profile() {
        let mut profile = profile::Profile {
            unsafe_macos_seatbelt_rules: vec!["(allow default)".to_string()],
            ..profile::Profile::default()
        };

        strip_untrusted_unsafe_seatbelt_rules(UNTRUSTED_NAME, &mut profile, None, true);

        assert!(profile.unsafe_macos_seatbelt_rules.is_empty());
    }

    #[test]
    fn retains_top_level_rules_for_trusted_profile() {
        let mut profile = profile::Profile {
            unsafe_macos_seatbelt_rules: vec!["(allow default)".to_string()],
            ..profile::Profile::default()
        };

        strip_untrusted_unsafe_seatbelt_rules(TRUSTED_NAME, &mut profile, None, true);

        assert_eq!(
            profile.unsafe_macos_seatbelt_rules,
            vec!["(allow default)".to_string()]
        );
    }

    #[test]
    fn strips_nested_command_sandbox_rules_for_untrusted_profile() {
        let mut profile = profile::Profile::default();
        let mut policies = CommandPoliciesConfig::default();
        policies.commands.insert(
            "git".to_string(),
            CommandPolicyConfig {
                sandbox: Some(CommandSandboxConfig {
                    unsafe_macos_seatbelt_rules: vec!["(allow iokit-open)".to_string()],
                    fs_read: vec!["/tmp".to_string()],
                    ..CommandSandboxConfig::default()
                }),
                ..CommandPolicyConfig::default()
            },
        );

        strip_untrusted_unsafe_seatbelt_rules(
            UNTRUSTED_NAME,
            &mut profile,
            Some(&mut policies),
            true,
        );

        let sandbox = policies.commands["git"].sandbox.as_ref().expect("sandbox");
        assert!(sandbox.unsafe_macos_seatbelt_rules.is_empty());
        // Structured overrides are not gated by provenance — only raw
        // Seatbelt rules are.
        assert_eq!(sandbox.fs_read, vec!["/tmp".to_string()]);
    }

    #[test]
    fn retains_nested_command_sandbox_rules_for_trusted_profile() {
        let mut profile = profile::Profile::default();
        let mut policies = CommandPoliciesConfig::default();
        policies.commands.insert(
            "git".to_string(),
            CommandPolicyConfig {
                sandbox: Some(CommandSandboxConfig {
                    unsafe_macos_seatbelt_rules: vec!["(allow iokit-open)".to_string()],
                    ..CommandSandboxConfig::default()
                }),
                ..CommandPolicyConfig::default()
            },
        );

        strip_untrusted_unsafe_seatbelt_rules(
            TRUSTED_NAME,
            &mut profile,
            Some(&mut policies),
            true,
        );

        let sandbox = policies.commands["git"].sandbox.as_ref().expect("sandbox");
        assert_eq!(
            sandbox.unsafe_macos_seatbelt_rules,
            vec!["(allow iokit-open)".to_string()]
        );
    }
}
