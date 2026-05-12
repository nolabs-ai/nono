#[cfg(not(target_os = "windows"))]
use crate::launch_runtime::select_threading_context;
use crate::launch_runtime::LaunchPlan;
use crate::proxy_runtime::start_proxy_runtime;
use crate::supervised_runtime::{execute_supervised_runtime, SupervisedRuntimeContext};
use crate::{config, exec_strategy, output, sandbox_state};
use nono::{CapabilitySet, NonoError, Result, Sandbox};
use std::path::Path;
use tracing::{error, info};

fn apply_pre_fork_sandbox(
    strategy: exec_strategy::ExecStrategy,
    caps: &CapabilitySet,
    silent: bool,
) -> Result<()> {
    if matches!(strategy, exec_strategy::ExecStrategy::Direct) {
        output::print_applying_sandbox(silent);

        #[cfg(target_os = "linux")]
        {
            let detected = Sandbox::detect_abi()?;
            info!("Direct mode: detected {}", detected);
            Sandbox::apply_with_abi(caps, &detected)?;
        }

        #[cfg(not(target_os = "linux"))]
        {
            Sandbox::apply(caps)?;
        }
    }
    Ok(())
}

fn cleanup_capability_state_file(cap_file_path: &std::path::Path) {
    if cap_file_path.exists() {
        let _ = std::fs::remove_file(cap_file_path);
    }
}

fn next_capability_state_file_path() -> std::path::PathBuf {
    use rand::RngExt;

    let mut rng = rand::rng();
    let bytes: [u8; 8] = rng.random();
    let suffix = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    std::env::temp_dir().join(format!(".nono-{suffix}.json"))
}

pub(crate) fn execution_start_dir(
    workdir: &std::path::Path,
    _caps: &CapabilitySet,
) -> Result<std::path::PathBuf> {
    let workdir_canonical =
        workdir
            .canonicalize()
            .map_err(|e| NonoError::PathCanonicalization {
                path: workdir.to_path_buf(),
                source: e,
            })?;

    #[cfg(target_os = "windows")]
    {
        Ok(workdir_canonical)
    }

    #[cfg(not(target_os = "windows"))]
    if _caps.path_covered(&workdir_canonical) {
        Ok(workdir_canonical)
    } else {
        Ok(std::path::PathBuf::from("/"))
    }
}

fn recommended_builtin_profile(program: &Path) -> Option<&'static str> {
    let name = program.file_name()?.to_str()?;
    match name {
        "claude" => Some("claude-code"),
        "codex" => Some("codex"),
        "opencode" => Some("opencode"),
        "openclaw" => Some("openclaw"),
        "swival" => Some("swival"),
        _ => None,
    }
}

pub(crate) fn execute_sandboxed(plan: LaunchPlan) -> Result<()> {
    let LaunchPlan {
        program,
        cmd_args,
        mut caps,
        loaded_secrets,
        // Plan 18.1-03 G-06: kept as owned local binding so downstream
        // `SupervisedRuntimeContext.loaded_profile: Option<&Profile>`
        // reference lives for the entire execute_sandboxed scope (which is
        // also the process lifetime — execute_supervised_runtime does not
        // return until the child exits, and the caller std::process::exit's).
        loaded_profile,
        flags,
    } = plan;
    let rollback = &flags.rollback;
    let trust = &flags.trust;
    let proxy = &flags.proxy;
    let session = &flags.session;

    if let Some(blocked) =
        config::check_blocked_command(&program, caps.allowed_commands(), caps.blocked_commands())?
    {
        return Err(NonoError::BlockedCommand {
            command: blocked,
            reason: "This command is blocked by default due to destructive potential. 
                     Use --allow-command to override if you understand the risks."
                .to_string(),
        });
    }

    let command: Vec<String> = std::iter::once(program.to_string_lossy().into_owned())
        .chain(
            cmd_args
                .iter()
                .map(|arg| arg.to_string_lossy().into_owned()),
        )
        .collect();

    if command.is_empty() {
        return Err(NonoError::NoCommand);
    }

    let resolved_program = exec_strategy::resolve_program(&command[0])?;
    let recommended_profile = if flags.session.profile_name.is_none() {
        recommended_builtin_profile(&resolved_program)
    } else {
        None
    };

    let recommended_program_name = resolved_program
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(&command[0]);

    if let Some(profile) = recommended_profile {
        output::print_profile_hint(recommended_program_name, profile, flags.silent);
    }
    let cap_file = write_capability_state_file(&caps, &flags.override_deny_paths, flags.silent);
    let cap_file_path = cap_file.as_ref().cloned().unwrap_or_else(|| {
        #[cfg(target_os = "windows")]
        return std::path::PathBuf::from("NUL");
        #[cfg(not(target_os = "windows"))]
        return std::path::PathBuf::from("/dev/null");
    });

    for secret in &loaded_secrets {
        if exec_strategy::is_dangerous_env_var(&secret.env_var) {
            return Err(NonoError::ConfigParse(format!(
                "secret mapping targets dangerous environment variable: {}",
                secret.env_var
            )));
        }
    }

    let strategy = flags.strategy;

    if matches!(strategy, exec_strategy::ExecStrategy::Supervised) {
        output::print_supervised_info(flags.silent, rollback.requested, proxy.active);
    }

    // Fail-secure guard (D-02): if the user's intent is proxy-only mode
    // (caps were set to ProxyOnly by a profile or credential path at
    // capability_ext.rs:535) but `proxy.active` is false (no network profile,
    // no credentials, no upstream proxy — see proxy_runtime.rs lines 52-78),
    // the sandboxed process would have no proxy to route traffic through.
    // Fail before `start_proxy_runtime` and before any WFP/sandbox activation.
    if matches!(caps.network_mode(), nono::NetworkMode::ProxyOnly { .. }) && !proxy.active {
        return Err(NonoError::SandboxInit(
            "Cannot use proxy-only mode without a network profile or credential configuration."
                .to_string(),
        ));
    }

    let active_proxy = start_proxy_runtime(proxy, &mut caps)?;
    let proxy_env_vars = active_proxy.env_vars;
    let proxy_handle = active_proxy.handle;

    let current_dir = execution_start_dir(&flags.workdir, &caps)?;

    // AUD-03 SHA-256 portion (upstream 02ee0bd1): capture the canonical
    // path + SHA-256 of the executable BEFORE sandbox apply so the audit
    // trail commits to exactly the bytes the supervisor handed off. Only
    // computed for Supervised strategy (Direct/Monitor record nothing).
    // Hash failure is non-fatal for the launch path: `crate::exec_identity::compute`
    // bubbles `NonoError::CommandExecution`; we propagate that so the user
    // sees a concrete diagnostic rather than running with no audit identity.
    let executable_identity = if matches!(strategy, exec_strategy::ExecStrategy::Supervised) {
        Some(crate::exec_identity::compute(&resolved_program)?)
    } else {
        None
    };

    apply_pre_fork_sandbox(strategy, &caps, flags.silent)?;

    // Generate per-session runtime capability expansion credentials BEFORE
    // building `env_vars` so the owned strings outlive the `ExecConfig`.
    //
    // `NONO_SESSION_TOKEN`: 32 random bytes, hex-encoded (64 chars). This is
    // the secret the sandboxed child must echo back on every
    // `RequestCapability` message; the supervisor validates it in constant
    // time before invoking any approval backend.
    //
    // `NONO_SUPERVISOR_PIPE`: rendezvous file path where the supervisor
    // capability pipe server binds. Unique per session id to avoid collisions.
    //
    // Never log `windows_session_token`.
    #[cfg(target_os = "windows")]
    let windows_session_token: String = {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|e| {
            NonoError::SandboxInit(format!("Failed to generate session token: {e}"))
        })?;
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    #[cfg(target_os = "windows")]
    let windows_cap_pipe_path: std::path::PathBuf =
        std::env::temp_dir().join(format!("nono-cap-{}.pipe", flags.session.session_id));
    #[cfg(target_os = "windows")]
    let windows_cap_pipe_path_str: String = windows_cap_pipe_path.to_string_lossy().into_owned();

    let mut env_vars: Vec<(&str, &str)> = loaded_secrets
        .iter()
        .map(|secret| (secret.env_var.as_str(), secret.value.as_str()))
        .collect();
    for (key, value) in &proxy_env_vars {
        env_vars.push((key.as_str(), value.as_str()));
    }
    #[cfg(target_os = "windows")]
    {
        env_vars.push(("NONO_SESSION_TOKEN", windows_session_token.as_str()));
        env_vars.push(("NONO_SUPERVISOR_PIPE", windows_cap_pipe_path_str.as_str()));
    }

    #[cfg(not(target_os = "windows"))]
    let threading = select_threading_context(
        !loaded_secrets.is_empty(),
        proxy.active,
        trust.scan_performed,
        trust.interception_active,
    );

    #[cfg(not(target_os = "windows"))]
    info!(
        "Executing with strategy: {:?}, threading: {:?}",
        strategy, threading
    );

    #[cfg(target_os = "windows")]
    info!("Executing with strategy: {:?}", strategy);

    #[cfg(target_os = "linux")]
    let seccomp_proxy_fallback = {
        let needs_proxy = matches!(caps.network_mode(), nono::NetworkMode::ProxyOnly { .. });
        if needs_proxy && nono::is_wsl2() {
            let needs_seccomp_fallback = !Sandbox::detect_abi()
                .ok()
                .is_some_and(|abi| abi.has_network());
            if needs_seccomp_fallback {
                match flags.wsl2_proxy_policy {
                    crate::profile::Wsl2ProxyPolicy::Error => {
                        return Err(NonoError::SandboxInit(
                            "WSL2: proxy-only network mode cannot be kernel-enforced. 
                             seccomp user notification returns EBUSY on WSL2 and Landlock V4 
                             (per-port TCP filtering) is not available on this kernel.


                             The sandboxed process would be able to bypass the credential proxy 
                             and open arbitrary outbound connections.


                             To allow degraded execution (credential proxy without network lockdown), 
                             set wsl2_proxy_policy: \"insecure_proxy\" in your profile's security config.


                             See: https://nono.sh/docs/cli/internals/wsl2"
                                .to_string(),
                        ));
                    }
                    crate::profile::Wsl2ProxyPolicy::InsecureProxy => {
                        eprintln!(
                            "  [nono] WARNING: WSL2 insecure proxy mode — credential proxy active 
                             but network is NOT kernel-enforced. The sandboxed process can bypass 
                             the proxy and open arbitrary outbound connections."
                        );
                    }
                }
            }
            false
        } else if needs_proxy {
            !Sandbox::detect_abi()
                .ok()
                .is_some_and(|abi| abi.has_network())
        } else {
            false
        }
    };

    #[cfg(not(target_os = "windows"))]
    let config = exec_strategy::ExecConfig {
        command: &command,
        resolved_program: &resolved_program,
        caps: &caps,
        env_vars,
        cap_file: cap_file.as_deref(),
        current_dir: &current_dir,
        no_diagnostics: flags.no_diagnostics || flags.silent,
        threading,
        protected_paths: &trust.protected_paths,
        profile_save_base: flags
            .session
            .profile_name
            .as_deref()
            .or(recommended_profile),
        startup_timeout: if should_apply_startup_timeout(recommended_profile, &cmd_args) {
            recommended_profile.map(|profile| exec_strategy::StartupTimeoutConfig {
                timeout: PROFILE_HINT_STARTUP_TIMEOUT,
                program: recommended_program_name,
                profile,
            })
        } else {
            None
        },
        capability_elevation: flags.capability_elevation,
        #[cfg(target_os = "linux")]
        seccomp_proxy_fallback,
        allowed_env_vars: flags.allowed_env_vars.clone(),
        denied_env_vars: flags.denied_env_vars.clone(),
    };
    #[cfg(target_os = "windows")]
    let config = exec_strategy::ExecConfig {
        command: &command,
        resolved_program: &resolved_program,
        caps: &caps,
        env_vars,
        cap_file: cap_file.as_deref(),
        current_dir: &current_dir,
        session_sid: Some(exec_strategy::generate_session_sid()),
        interactive_shell: flags.interactive_shell,
        session_token: Some(windows_session_token.clone()),
        cap_pipe_rendezvous_path: Some(windows_cap_pipe_path.clone()),
        allowed_env_vars: flags.allowed_env_vars.clone(),
        denied_env_vars: flags.denied_env_vars.clone(),
    };

    // Resource limits are now kernel-enforced on Linux (cgroup v2) and macOS
    // (setrlimit). The old "not enforced on linux/macos" warnings were removed
    // in Phase 25 Plan 01. Enforcement is wired inside execute_direct and
    // execute_supervised_runtime via apply_resource_limits_unix.

    match strategy {
        exec_strategy::ExecStrategy::Direct => {
            #[cfg(target_os = "windows")]
            {
                let exit_code = exec_strategy::execute_direct(
                    &config,
                    &flags.resource_limits,
                    Some(flags.session.session_id.as_str()),
                )?;
                cleanup_capability_state_file(&cap_file_path);
                drop(config);
                drop(loaded_secrets);
                std::process::exit(exit_code);
            }
            #[cfg(not(target_os = "windows"))]
            {
                exec_strategy::execute_direct(
                    &config,
                    // Phase 25-01: kernel-level resource enforcement (Linux cgroup v2, macOS setrlimit).
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    &flags.resource_limits,
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    flags.session.session_id.as_str(),
                )?;
                unreachable!("execute_direct only returns on error");
            }
        }
        exec_strategy::ExecStrategy::Supervised => {
            let exit_code = execute_supervised_runtime(SupervisedRuntimeContext {
                config: &config,
                caps: &caps,
                command: &command,
                capability_elevation: flags.capability_elevation,
                session,
                rollback,
                trust,
                proxy,
                proxy_handle: proxy_handle.as_ref(),
                executable_identity: executable_identity.as_ref(),
                silent: flags.silent,
                resource_limits: &flags.resource_limits,
                // Plan 18.1-03 G-06: pass a reference to the owned
                // `loaded_profile` binding so `execute_supervised_runtime`
                // can call `Profile::resolve_aipc_allowlist()` at Windows
                // `SupervisorConfig` construction time.
                loaded_profile: loaded_profile.as_ref(),
            })?;

            cleanup_capability_state_file(&cap_file_path);
            drop(config);
            drop(loaded_secrets);
            std::process::exit(exit_code);
        }
    }
}

fn write_capability_state_file(
    caps: &CapabilitySet,
    override_deny_paths: &[std::path::PathBuf],
    silent: bool,
) -> Option<std::path::PathBuf> {
    let state = sandbox_state::SandboxState::from_caps(caps, override_deny_paths);

    for _ in 0..8 {
        let cap_file = next_capability_state_file_path();
        match state.write_to_file(&cap_file) {
            Ok(()) => return Some(cap_file),
            Err(NonoError::ConfigWrite { source, .. })
                if source.kind() == std::io::ErrorKind::AlreadyExists =>
            {
                continue;
            }
            Err(e) => {
                error!(
                    "Failed to write capability state file: {}. 
                     Sandboxed processes will not be able to query their own capabilities using 'nono why --self'.",
                    e
                );
                if !silent {
                    eprintln!(
                        "  WARNING: Capability state file could not be written.
  
                         The sandbox is active, but 'nono why --self' will not work inside this sandbox."
                    );
                }
                return None;
            }
        }
    }

    error!(
        "Failed to allocate a unique capability state file after repeated collisions. 
         Sandboxed processes will not be able to query their own capabilities using 'nono why --self'."
    );
    if !silent {
        eprintln!(
            "  WARNING: Capability state file could not be written.
  
             The sandbox is active, but 'nono why --self' will not work inside this sandbox."
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use super::recommended_builtin_profile;
    use std::path::Path;

    #[test]
    fn recommended_builtin_profile_matches_known_agent_commands() {
        assert_eq!(
            recommended_builtin_profile(Path::new("/usr/local/bin/claude")),
            Some("claude-code")
        );
        assert_eq!(
            recommended_builtin_profile(Path::new("/usr/local/bin/codex")),
            Some("codex")
        );
    }

    #[test]
    fn recommended_builtin_profile_ignores_unknown_commands() {
        assert_eq!(recommended_builtin_profile(Path::new("/usr/bin/env")), None);
    }
}
