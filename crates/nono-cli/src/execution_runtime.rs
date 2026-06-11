use crate::audit_attestation::prepare_audit_signer;
#[cfg(unix)]
use crate::hook_runtime;
use crate::launch_runtime::{LaunchPlan, select_threading_context};
use crate::proxy_runtime::start_proxy_runtime;
use crate::supervised_runtime::{SupervisedRuntimeContext, execute_supervised_runtime};
use crate::{
    DETACHED_SESSION_ID_ENV, command_blocking_deprecation, config, exec_strategy, output,
    sandbox_state, session,
};
use nono::undo::{ContentHash, ExecutableIdentity};
use nono::{CapabilitySet, NonoError, Result, Sandbox};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Duration;
use tracing::{error, info, warn};

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
    let known_builtin_profile = recommended_builtin_profile(&resolved_program);
    let recommended_profile = if flags.session.profile_name.is_none() {
        known_builtin_profile
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
    let allowed_domain_strs: Vec<String> = flags
        .proxy
        .allow_domain
        .iter()
        .map(|e| e.domain().to_string())
        .collect();
    let domain_endpoints: Vec<sandbox_state::DomainEndpointState> = flags
        .proxy
        .allow_domain
        .iter()
        .filter_map(|e| match e {
            crate::profile::AllowDomainEntry::WithEndpoints { domain, endpoints }
                if !endpoints.is_empty() =>
            {
                Some(sandbox_state::DomainEndpointState {
                    domain: domain.clone(),
                    endpoints: endpoints
                        .iter()
                        .map(|r| sandbox_state::EndpointRuleState {
                            method: r.method.clone(),
                            path: r.path.clone(),
                        })
                        .collect(),
                })
            }
            _ => None,
        })
        .collect();
    let cap_file = write_capability_state_file(
        &caps,
        &flags.bypass_protection_paths,
        &allowed_domain_strs,
        &domain_endpoints,
        flags.silent,
    );
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

    // Session id shared across before- and after-hook so paired setup/teardown
    // scripts see the same NONO_SESSION_ID. Only allocated when at least one
    // hook is configured.
    let hook_session_id: Option<String> =
        (flags.session_hooks.before.is_some() || flags.session_hooks.after.is_some()).then(|| {
            std::env::var(DETACHED_SESSION_ID_ENV)
                .ok()
                .filter(|id| !id.is_empty())
                .unwrap_or_else(session::generate_session_id)
        });

    // ---- Before-hook execution (Unix-only) ----
    #[cfg(unix)]
    let hook_env_vars_owned: Vec<(String, String)> = flags
        .session_hooks
        .before
        .as_ref()
        .zip(hook_session_id.as_deref())
        .map(|(before, session_id)| {
            match hook_runtime::execute_before_hook(before, session_id, &current_dir) {
                Ok(env) => {
                    if !env.is_empty() {
                        info!(
                            "Before-hook exported {} env vars (script: {})",
                            env.len(),
                            before.script.display()
                        );
                    }
                    env
                }
                Err(e) => {
                    warn!("Before-hook failed (continuing): {e}");
                    Vec::new()
                }
            }
        })
        .unwrap_or_default();
    #[cfg(not(unix))]
    let hook_env_vars_owned: Vec<(String, String)> = Vec::new();

    let mut env_vars: Vec<(&str, &str)> = loaded_secrets
        .iter()
        .map(|secret| (secret.env_var.as_str(), secret.value.as_str()))
        .collect();
    for (key, value) in &proxy_env_vars {
        env_vars.push((key.as_str(), value.as_str()));
    }

    // Hook env vars have lowest priority: prepend so secrets and proxy override.
    for (key, value) in hook_env_vars_owned.iter().rev() {
        env_vars.insert(0, (key.as_str(), value.as_str()));
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

    #[cfg(target_os = "linux")]
    if flags.af_unix_mediation.is_pathname() && nono::sandbox::is_wsl2() {
        return Err(NonoError::SandboxInit(
            "WSL2: linux.af_unix_mediation = \"pathname\" requires seccomp user notification, \
             but WSL2 reports EBUSY for seccomp notify listeners. Disable AF_UNIX mediation or \
             run on native Linux."
                .to_string(),
        ));
    }

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
        ignored_denial_paths: &flags.ignored_denial_paths,
        suppressed_system_service_operations: &flags.suppressed_system_service_operations,
        startup_timeout: flags
            .startup_timeout_secs
            .filter(|&secs| secs > 0)
            .map(|secs| exec_strategy::StartupTimeoutConfig {
                timeout: Duration::from_secs(secs),
                program: recommended_program_name,
                recommended_profile: known_builtin_profile,
            }),
        capability_elevation: flags.capability_elevation,
        #[cfg(target_os = "linux")]
        seccomp_proxy_fallback,
        #[cfg(target_os = "linux")]
        af_unix_mediation: flags.af_unix_mediation,
        allowed_env_vars: flags.allowed_env_vars,
        denied_env_vars: flags.denied_env_vars,
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
                credential_access: &flags.credential_access,
                proxy_handle: proxy_handle.as_ref(),
                executable_identity: executable_identity.as_ref(),
                audit_signer: audit_signer.as_ref(),
                redaction_policy: &flags.redaction_policy,
                silent: flags.silent,
            })?;

            // ---- After-hook execution (Unix-only) ----
            #[cfg(unix)]
            if let (Some(after), Some(session_id)) = (
                flags.session_hooks.after.as_ref(),
                hook_session_id.as_deref(),
            ) && let Err(e) =
                hook_runtime::execute_after_hook(after, session_id, &current_dir, exit_code)
            {
                warn!("After-hook failed: {e}");
            }

            cleanup_capability_state_file(&cap_file_path);
            drop(config);
            drop(loaded_secrets);
            // `std::process::exit` does NOT run destructors, so we must drop
            // the proxy handle explicitly to fire its `Drop` impl — that's
            // what removes the TLS-intercept trust bundle and its parent
            // session directory under `~/.nono/sessions/`. Without this
            // every supervised-mode session leaks a file + directory.
            drop(proxy_handle);
            std::process::exit(exit_code);
        }
    }
}

fn write_capability_state_file(
    caps: &CapabilitySet,
    bypass_protection_paths: &[std::path::PathBuf],
    allowed_domains: &[String],
    domain_endpoints: &[sandbox_state::DomainEndpointState],
    silent: bool,
) -> Option<std::path::PathBuf> {
    let state = sandbox_state::SandboxState::from_caps(
        caps,
        bypass_protection_paths,
        allowed_domains,
        domain_endpoints,
    );

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
    use super::{compute_executable_identity, recommended_builtin_profile};
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
