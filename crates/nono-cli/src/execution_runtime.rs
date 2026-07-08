use crate::audit_attestation::prepare_audit_signer;
#[cfg(unix)]
use crate::hook_runtime;
use crate::launch_runtime::{LaunchPlan, select_threading_context};
use crate::proxy_runtime::start_proxy_runtime;
use crate::supervised_runtime::{SupervisedRuntimeContext, execute_supervised_runtime};
use crate::{
    DETACHED_SESSION_ID_ENV, command_blocking_deprecation, config, exec_strategy, network_policy,
    output, sandbox_state, session,
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
    #[cfg(target_os = "linux")] sandbox_policy: crate::profile::LinuxSandboxPolicy,
) -> Result<()> {
    if matches!(strategy, exec_strategy::ExecStrategy::Direct) {
        output::print_applying_sandbox(silent);

        #[cfg(target_os = "linux")]
        {
            use crate::profile::LinuxSandboxPolicy;
            let detected = Sandbox::detect_abi()?;
            info!("Direct mode: detected {}", detected);
            match sandbox_policy {
                LinuxSandboxPolicy::Auto => {
                    Sandbox::apply_auto_with_abi(caps, &detected)?;
                }
                LinuxSandboxPolicy::Landlock => {
                    Sandbox::apply_landlock_with_abi(caps, &detected)?;
                }
                LinuxSandboxPolicy::External => {
                    Sandbox::apply_seccomp_with_abi(
                        caps,
                        &detected,
                        nono::sandbox::SeccompOpts::external_tcp(),
                    )?;
                    Sandbox::apply_external()?;
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            Sandbox::apply_auto(caps)?;
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
        deny_paths,
        loaded_secrets,
        flags,
    } = plan;
    let rollback = &flags.rollback;
    let trust = &flags.trust;
    let network = &flags.network;
    let proxy = network.proxy_options();
    let session = &flags.session;
    let tool_sandbox_active = flags
        .command_policies
        .as_ref()
        .is_some_and(crate::command_policy::CommandPoliciesConfig::is_active);
    if tool_sandbox_active {
        validate_command_policy_execution_support()?;
    }

    if !tool_sandbox_active
        && let Some(blocked) = config::check_blocked_command(
            &program,
            caps.allowed_commands(),
            caps.blocked_commands(),
        )?
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
    let plain_domain_entries = proxy
        .and_then(|p| p.domain_filter.as_ref())
        .map(|d| d.allow_domain.as_slice())
        .unwrap_or(&[]);
    let endpoint_domain_entries = proxy
        .and_then(|p| p.endpoint_filter.as_ref())
        .map(|e| e.routes.as_slice())
        .unwrap_or(&[]);
    let all_domain_entries: Vec<_> = plain_domain_entries
        .iter()
        .chain(endpoint_domain_entries.iter())
        .collect();
    // Expand network_profile hosts and domain group aliases into the sandbox state
    // so that `nono why --self` sees the same allowlist the proxy enforces at runtime.
    let plain_domain_strs: Vec<String> = all_domain_entries
        .iter()
        .map(|e| e.domain().to_string())
        .collect();
    let domain_filter = proxy.and_then(|p| p.domain_filter.as_ref());
    let allowed_domain_strs: Vec<String> = if domain_filter.is_some() {
        let policy_json = config::embedded::embedded_network_policy_json();
        match network_policy::load_network_policy(policy_json) {
            Ok(net_policy) => {
                let mut domains =
                    network_policy::expand_proxy_allow(&net_policy, &plain_domain_strs);
                if let Some(profile_name) = domain_filter.and_then(|d| d.network_profile.as_deref())
                {
                    match network_policy::resolve_network_profile(&net_policy, profile_name) {
                        Ok(resolved) => {
                            domains.extend(resolved.hosts);
                            for suffix in &resolved.suffixes {
                                let wildcard = if suffix.starts_with('.') {
                                    format!("*{suffix}")
                                } else {
                                    format!("*.{suffix}")
                                };
                                domains.push(wildcard);
                            }
                        }
                        Err(e) => {
                            warn!("failed to resolve network_profile for sandbox state: {e}");
                        }
                    }
                }
                domains
            }
            Err(e) => {
                warn!("failed to load network policy for sandbox state: {e}");
                plain_domain_strs
            }
        }
    } else {
        plain_domain_strs
    };
    let domain_endpoints: Vec<sandbox_state::DomainEndpointState> = all_domain_entries
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
    if tool_sandbox_active && !matches!(strategy, exec_strategy::ExecStrategy::Supervised) {
        return Err(NonoError::ConfigParse(
            "tool-sandbox command_policies require supervised execution".to_string(),
        ));
    }

    if matches!(strategy, exec_strategy::ExecStrategy::Supervised) {
        output::print_supervised_info(flags.silent, rollback.requested, network.is_proxy_active());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let shared_broker = crate::tool_sandbox::token_broker::new_shared_broker();
    let active_proxy = start_proxy_runtime(
        network,
        &mut caps,
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Some(shared_broker.clone()),
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        None,
    )?;
    let proxy_env_vars = active_proxy.env_vars;
    let tool_sandbox_proxy_credential_env_vars = active_proxy.tool_sandbox_credential_env_vars;
    let tool_sandbox_trust_bundle_paths = active_proxy.tool_sandbox_trust_bundle_paths;
    let proxy_handle = active_proxy.handle;

    let requested_workdir =
        flags
            .workdir
            .canonicalize()
            .map_err(|e| NonoError::PathCanonicalization {
                path: flags.workdir.to_path_buf(),
                source: e,
            })?;
    let current_dir = if tool_sandbox_active {
        requested_workdir.clone()
    } else {
        execution_start_dir(&flags.workdir, &caps)?
    };
    #[cfg(target_os = "linux")]
    let tool_sandbox_runtime = if let Some(command_policies) = flags
        .command_policies
        .as_ref()
        .filter(|config| config.is_active())
    {
        let runtime = crate::tool_sandbox::PreparedToolSandboxRuntime::prepare(
            crate::tool_sandbox::ToolSandboxPrepare {
                config: command_policies,
                resolved_command_binaries: flags.resolved_command_binaries.as_ref(),
                audit_context: crate::tool_sandbox::ToolSandboxAuditContext::new(
                    flags.profile_display_name.clone(),
                    flags.redaction_policy.clone(),
                ),
                allowed_commands: caps.allowed_commands(),
                blocked_commands: caps.blocked_commands(),
                outer_caps: &caps,
                deny_paths: &deny_paths,
                policy_root: &requested_workdir,
                proxy_credential_env_vars: &tool_sandbox_proxy_credential_env_vars,
                proxy_trust_bundle_paths: &tool_sandbox_trust_bundle_paths,
                shared_broker: Some(shared_broker.clone()),
            },
        )?;
        runtime.grant_outer_caps(&mut caps)?;
        Some(runtime)
    } else {
        None
    };
    #[cfg(target_os = "macos")]
    let tool_sandbox_runtime = if let Some(command_policies) = flags
        .command_policies
        .as_ref()
        .filter(|config| config.is_active())
    {
        let runtime = crate::tool_sandbox::PreparedToolSandboxRuntime::prepare(
            crate::tool_sandbox::ToolSandboxPrepare {
                config: command_policies,
                resolved_command_binaries: flags.resolved_command_binaries.as_ref(),
                audit_context: crate::tool_sandbox::ToolSandboxAuditContext::new(
                    flags.profile_display_name.clone(),
                    flags.redaction_policy.clone(),
                ),
                allowed_commands: caps.allowed_commands(),
                blocked_commands: caps.blocked_commands(),
                outer_caps: &caps,
                deny_paths: &deny_paths,
                policy_root: &requested_workdir,
                proxy_credential_env_vars: &tool_sandbox_proxy_credential_env_vars,
                proxy_trust_bundle_paths: &tool_sandbox_trust_bundle_paths,
                shared_broker: Some(shared_broker),
            },
        )?;
        runtime.grant_outer_caps(&mut caps)?;
        Some(runtime)
    } else {
        None
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let tool_sandbox_runtime: Option<crate::tool_sandbox::PreparedToolSandboxRuntime> = None;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let tool_sandbox_initial_shim = tool_sandbox_runtime
        .as_ref()
        .and_then(|runtime| runtime.shim_for_initial_command(&command[0]))
        .map(std::path::Path::to_path_buf);
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let exec_resolved_program = tool_sandbox_initial_shim
        .clone()
        .unwrap_or_else(|| resolved_program.clone());
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let exec_resolved_program = resolved_program.clone();

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if let Some(runtime) = tool_sandbox_runtime.as_ref()
        && let Some(err) = runtime.validate_initial_exec(&command[0], &resolved_program)?
    {
        return Err(err);
    }

    let executable_identity = if matches!(strategy, exec_strategy::ExecStrategy::Supervised) {
        Some(compute_executable_identity(&exec_resolved_program)?)
    } else {
        None
    };
    let audit_signer = prepare_audit_signer(rollback.audit_sign_key.as_deref())?;
    if audit_signer.is_some() && !matches!(strategy, exec_strategy::ExecStrategy::Supervised) {
        return Err(NonoError::ConfigParse(
            "--audit-sign-key requires supervised execution".to_string(),
        ));
    }

    apply_pre_fork_sandbox(
        strategy,
        &caps,
        flags.silent,
        #[cfg(target_os = "linux")]
        flags.sandbox_policy,
    )?;

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

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let brokered_secret_env_vars = if let Some(runtime) = tool_sandbox_runtime.as_ref() {
        runtime.broker_secret_env_vars(&loaded_secrets)?
    } else {
        Vec::new()
    };
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let mut env_vars: Vec<(&str, &str)> = if tool_sandbox_runtime.is_some() {
        brokered_secret_env_vars
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect()
    } else {
        loaded_secrets
            .iter()
            .map(|secret| (secret.env_var.as_str(), secret.value.as_str()))
            .collect()
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let mut env_vars: Vec<(&str, &str)> = loaded_secrets
        .iter()
        .map(|secret| (secret.env_var.as_str(), secret.value.as_str()))
        .collect();
    for (key, value) in &proxy_env_vars {
        env_vars.push((key.as_str(), value.as_str()));
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let tool_sandbox_env_vars = tool_sandbox_runtime
        .as_ref()
        .map(crate::tool_sandbox::PreparedToolSandboxRuntime::env_overrides)
        .unwrap_or_default();
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    for (key, value) in &tool_sandbox_env_vars {
        env_vars.push((key.as_str(), value.as_str()));
    }

    // Hook env vars have lowest priority: prepend so secrets and proxy override.
    for (key, value) in hook_env_vars_owned.iter().rev() {
        env_vars.insert(0, (key.as_str(), value.as_str()));
    }

    let threading = select_threading_context(
        !loaded_secrets.is_empty(),
        network.is_proxy_active(),
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
        let external_network = matches!(
            flags.sandbox_policy,
            crate::profile::LinuxSandboxPolicy::External
        );
        if external_network {
            false
        } else if needs_proxy && nono::is_wsl2() {
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

    #[cfg(target_os = "linux")]
    if flags.proc_comm_notify && nono::sandbox::is_wsl2() {
        return Err(NonoError::SandboxInit(
            "WSL2: NVIDIA GPU thread-name mediation requires seccomp user notification, \
             but WSL2 reports EBUSY for seccomp notify listeners. Disable --allow-gpu \
             or run on native Linux."
                .to_string(),
        ));
    }

    let config = exec_strategy::ExecConfig {
        command: &command,
        resolved_program: &exec_resolved_program,
        caps: &caps,
        env_vars,
        cap_file: &cap_file_path,
        current_dir: &current_dir,
        no_diagnostics: flags.no_diagnostics || flags.silent,
        diagnostics_json: flags.diagnostics_json,
        proxy_diagnostics: proxy_handle.as_ref().and_then(|handle| {
            let diagnostics = handle.diagnostics();
            if diagnostics.is_empty() {
                None
            } else {
                Some(diagnostics)
            }
        }),
        diagnostic_verbosity: flags.diagnostic_verbosity,
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
        #[cfg(target_os = "linux")]
        seccomp_policy: exec_strategy::SeccompPolicy {
            capability_elevation: flags.capability_elevation,
            proxy_fallback: seccomp_proxy_fallback,
            af_unix_mediation: flags.af_unix_mediation.is_pathname(),
            proc_comm_notify: flags.proc_comm_notify,
        },
        #[cfg(target_os = "linux")]
        sandbox_policy: flags.sandbox_policy,
        allowed_env_vars: flags.allowed_env_vars,
        denied_env_vars: flags.denied_env_vars,
        set_vars: flags.set_vars.unwrap_or_default(),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        tool_sandbox_runtime: tool_sandbox_runtime.as_ref(),
    };

    match strategy {
        exec_strategy::ExecStrategy::Direct => {
            exec_strategy::execute_direct(&config)?;
            unreachable!("execute_direct only returns on error");
        }
        exec_strategy::ExecStrategy::Supervised => {
            let exit_result = execute_supervised_runtime(SupervisedRuntimeContext {
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
                redaction_policy: &flags.redaction_policy,
                silent: flags.silent,
            });

            // Runtime dir cleanup must run on both Ok and Err paths because
            // `process::exit` (below for Ok, in main.rs for Err) bypasses Drop
            // chains, leaking the per-invocation /run/user/$UID/nono-tool-sandbox-* or
            // /tmp/nono-tool-sandbox-* dir otherwise.
            if let Some(rt) = tool_sandbox_runtime.as_ref() {
                rt.cleanup_runtime_dir();
            }

            let exit_code = exit_result?;

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
            crate::tool_sandbox::log_main_total();
            std::process::exit(exit_code);
        }
    }
}

fn validate_command_policy_execution_support() -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(NonoError::UnsupportedPlatform(
            "tool-sandbox command_policies are only supported on Linux and macOS".to_string(),
        ))
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
    use super::{
        compute_executable_identity, recommended_builtin_profile,
        validate_command_policy_execution_support,
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

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn command_policy_execution_supported_on_current_platform() {
        assert!(validate_command_policy_execution_support().is_ok());
    }
}
