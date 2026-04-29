use crate::audit_attestation::prepare_audit_signer;
use crate::launch_runtime::{select_threading_context, LaunchPlan};
use crate::proxy_runtime::start_proxy_runtime;
use crate::supervised_runtime::{execute_supervised_runtime, SupervisedRuntimeContext};
use crate::{command_blocking_deprecation, config, exec_strategy, output, sandbox_state};
use nono::undo::{ContentHash, ExecutableIdentity};
use nono::{CapabilitySet, NonoError, Result, Sandbox};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Duration;
use tracing::{error, info};

const PROFILE_HINT_STARTUP_TIMEOUT: Duration = Duration::from_secs(10);

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

        output::print_sandbox_active(silent);
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

fn compute_executable_identity(resolved_program: &std::path::Path) -> Result<ExecutableIdentity> {
    let canonical_path = resolved_program.canonicalize().map_err(|e| {
        NonoError::CommandExecution(std::io::Error::new(
            e.kind(),
            format!(
                "Failed to canonicalize executable {}: {e}",
                resolved_program.display()
            ),
        ))
    })?;
    let mut file = File::open(&canonical_path).map_err(|e| {
        NonoError::CommandExecution(std::io::Error::new(
            e.kind(),
            format!(
                "Failed to open executable {}: {e}",
                canonical_path.display()
            ),
        ))
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = file.read(&mut buffer).map_err(|e| {
            NonoError::CommandExecution(std::io::Error::new(
                e.kind(),
                format!(
                    "Failed to read executable {}: {e}",
                    canonical_path.display()
                ),
            ))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(ExecutableIdentity {
        resolved_path: canonical_path,
        sha256: ContentHash::from_bytes(hasher.finalize().into()),
    })
}

pub(crate) fn execution_start_dir(
    workdir: &std::path::Path,
    caps: &CapabilitySet,
) -> Result<std::path::PathBuf> {
    let workdir_canonical =
        workdir
            .canonicalize()
            .map_err(|e| NonoError::PathCanonicalization {
                path: workdir.to_path_buf(),
                source: e,
            })?;

    if caps.path_covered(&workdir_canonical) {
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
        "swival" => Some("swival"),
        _ => None,
    }
}

fn should_apply_startup_timeout(
    recommended_profile: Option<&str>,
    cmd_args: &[impl AsRef<std::ffi::OsStr>],
) -> bool {
    recommended_profile.is_some() && cmd_args.is_empty()
}

pub(crate) fn execute_sandboxed(plan: LaunchPlan) -> Result<()> {
    let LaunchPlan {
        program,
        cmd_args,
        mut caps,
        loaded_secrets,
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
            reason: command_blocking_deprecation::BLOCKED_COMMAND_REASON.to_string(),
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
    let cap_file_path = cap_file.unwrap_or_else(|| std::path::PathBuf::from("/dev/null"));

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

    let active_proxy = start_proxy_runtime(proxy, &mut caps)?;
    let proxy_env_vars = active_proxy.env_vars;
    let proxy_handle = active_proxy.handle;

    let current_dir = execution_start_dir(&flags.workdir, &caps)?;
    let executable_identity = if matches!(strategy, exec_strategy::ExecStrategy::Supervised) {
        Some(compute_executable_identity(&resolved_program)?)
    } else {
        None
    };
    let audit_signer = prepare_audit_signer(rollback.audit_sign_key.as_deref())?;
    if audit_signer.is_some() && !matches!(strategy, exec_strategy::ExecStrategy::Supervised) {
        return Err(NonoError::ConfigParse(
            "--audit-sign-key requires supervised execution".to_string(),
        ));
    }
    apply_pre_fork_sandbox(strategy, &caps, flags.silent)?;

    let mut env_vars: Vec<(&str, &str)> = loaded_secrets
        .iter()
        .map(|secret| (secret.env_var.as_str(), secret.value.as_str()))
        .collect();
    for (key, value) in &proxy_env_vars {
        env_vars.push((key.as_str(), value.as_str()));
    }

    let threading = select_threading_context(
        !loaded_secrets.is_empty(),
        proxy.active,
        trust.scan_performed,
        trust.interception_active,
    );

    info!(
        "Executing with strategy: {:?}, threading: {:?}",
        strategy, threading
    );

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
                            "WSL2: proxy-only network mode cannot be kernel-enforced. \
                             seccomp user notification returns EBUSY on WSL2 and Landlock V4 \
                             (per-port TCP filtering) is not available on this kernel.\n\n\
                             The sandboxed process would be able to bypass the credential proxy \
                             and open arbitrary outbound connections.\n\n\
                             To allow degraded execution (credential proxy without network lockdown), \
                             set wsl2_proxy_policy: \"insecure_proxy\" in your profile's security config.\n\n\
                             See: https://nono.sh/docs/cli/internals/wsl2"
                                .to_string(),
                        ));
                    }
                    crate::profile::Wsl2ProxyPolicy::InsecureProxy => {
                        eprintln!(
                            "  [nono] WARNING: WSL2 insecure proxy mode — credential proxy active \
                             but network is NOT kernel-enforced. The sandboxed process can bypass \
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

    let config = exec_strategy::ExecConfig {
        command: &command,
        resolved_program: &resolved_program,
        caps: &caps,
        env_vars,
        cap_file: &cap_file_path,
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
        allowed_env_vars: flags.allowed_env_vars,
    };

    match strategy {
        exec_strategy::ExecStrategy::Direct => {
            exec_strategy::execute_direct(&config)?;
            unreachable!("execute_direct only returns on error");
        }
        exec_strategy::ExecStrategy::Supervised => {
            let exit_code = execute_supervised_runtime(SupervisedRuntimeContext {
                config: &config,
                caps: &caps,
                command: &command,
                session,
                rollback,
                trust,
                proxy,
                proxy_handle: proxy_handle.as_ref(),
                executable_identity: executable_identity.as_ref(),
                audit_signer: audit_signer.as_ref(),
                silent: flags.silent,
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
                    "Failed to write capability state file: {}. \
                     Sandboxed processes will not be able to query their own capabilities using 'nono why --self'.",
                    e
                );
                if !silent {
                    eprintln!(
                        "  WARNING: Capability state file could not be written.\n  \
                         The sandbox is active, but 'nono why --self' will not work inside this sandbox."
                    );
                }
                return None;
            }
        }
    }

    error!(
        "Failed to allocate a unique capability state file after repeated collisions. \
         Sandboxed processes will not be able to query their own capabilities using 'nono why --self'."
    );
    if !silent {
        eprintln!(
            "  WARNING: Capability state file could not be written.\n  \
             The sandbox is active, but 'nono why --self' will not work inside this sandbox."
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{
        compute_executable_identity, recommended_builtin_profile, should_apply_startup_timeout,
    };
    use sha2::{Digest, Sha256};
    use std::fs;
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

    #[test]
    fn startup_timeout_applies_only_to_bare_interactive_profiled_tools() {
        let no_args: [&str; 0] = [];
        assert!(should_apply_startup_timeout(Some("claude-code"), &no_args));
        assert!(!should_apply_startup_timeout(
            Some("claude-code"),
            &["--version"]
        ));
        assert!(!should_apply_startup_timeout(None, &no_args));
    }

    #[test]
    fn compute_executable_identity_hashes_canonical_binary_bytes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let binary = dir.path().join("tool");
        fs::write(&binary, b"#!/bin/sh\necho hello\n").expect("write binary");

        let identity = compute_executable_identity(&binary).expect("compute identity");
        let expected = Sha256::digest(b"#!/bin/sh\necho hello\n");

        assert_eq!(
            identity.resolved_path,
            binary.canonicalize().expect("canonical")
        );
        assert_eq!(identity.sha256.as_bytes(), &<[u8; 32]>::from(expected));
    }
}
