//! nono CLI - Capability-based sandbox for AI agents
//!
//! This is the CLI binary that uses the nono library for OS-level sandboxing.

mod app_runtime;
mod approval_runtime;
mod audit_attestation;
mod audit_commands;
mod audit_event_reader;
mod audit_integrity;
mod audit_ledger;
mod audit_session;
mod capability_ext;
mod cli;
mod cli_bootstrap;
mod command_blocking_deprecation;
mod command_display;
mod command_policy;
mod command_runtime;
mod completions;
mod config;
mod credential_runtime;
mod deprecated_policy;
mod deprecated_schema;
mod deprecation_warnings;
mod diagnostic;
mod exec_strategy;
mod execution_runtime;
#[cfg(unix)]
mod hook_runtime;
mod instruction_deny;
mod jsonc;
mod launch_runtime;
mod learn;
mod learn_runtime;
mod legacy_cleanup;
#[cfg(target_os = "macos")]
mod macos_trust;
mod migration;
mod network_policy;
mod open_url_runtime;
mod output;
mod pack_update_hint;
mod package;
mod package_cmd;
mod package_status;
mod platform;
mod policy;
mod profile;
mod profile_cmd;
mod profile_runtime;
mod profile_save_runtime;
mod protected_paths;
mod proxy_runtime;
mod pty_proxy;
mod pull_ui;
mod query_ext;
mod registry_client;
mod rollback_commands;
mod rollback_preflight;
mod rollback_runtime;
mod rollback_session;
mod rollback_ui;
mod sandbox_log;
mod sandbox_prepare;
mod sandbox_state;
mod session;
mod session_commands;
mod setup;
mod startup_prompt;
mod startup_runtime;
mod state_paths;
mod supervised_runtime;
mod terminal_approval;
mod theme;
mod timeouts;
#[path = "tool-sandbox/mod.rs"]
mod tool_sandbox;
mod trust_cmd;
mod trust_intercept;
mod trust_keystore;
mod trust_scan;
mod update_check;
mod why_runtime;
mod wiring;

#[cfg(test)]
mod test_env;

use app_runtime::run as run_cli;
use clap::Parser;
use cli::Cli;
use cli_bootstrap::{
    collect_legacy_network_warnings, init_theme, init_tracing, normalize_legacy_flag_env_vars,
    print_legacy_network_warnings,
};
use command_blocking_deprecation::{
    collect_cli_warnings, print_warnings as print_deprecation_warnings,
};
use nono::Result;

const DETACHED_LAUNCH_ENV: &str = "NONO_DETACHED_LAUNCH";
const DETACHED_CWD_PROMPT_RESPONSE_ENV: &str = "NONO_DETACHED_CWD_PROMPT_RESPONSE";
const DETACHED_SESSION_ID_ENV: &str = "NONO_DETACHED_SESSION_ID";

pub(crate) use launch_runtime::rollback_base_exclusions;
pub(crate) use proxy_runtime::merge_dedup_ports;

fn main() {
    if tool_sandbox::maybe_run_internal_tool_sandbox_entrypoint() {
        return;
    }
    tool_sandbox::record_main_start();

    let legacy_network_warnings = collect_legacy_network_warnings();
    normalize_legacy_flag_env_vars();
    // Emit one deprecation warning per distinct legacy long flag before clap
    // parses. clap's `alias` rebinds `--override-deny` to `--bypass-protection`
    // silently; without this scan the user would never see a removal notice.
    let os_args: Vec<_> = std::env::args_os().collect();
    deprecated_schema::warn_for_deprecated_flags(&os_args);
    let cli = Cli::parse();
    init_tracing(&cli);
    init_theme(&cli);
    print_legacy_network_warnings(&legacy_network_warnings, cli.silent);
    let command_blocking_warnings = collect_cli_warnings(&cli);
    print_deprecation_warnings(&command_blocking_warnings, cli.silent);

    let cli_result = run_cli(cli);
    tool_sandbox::log_main_total();
    if let Err(e) = cli_result {
        if let nono::NonoError::ActionRequired(message) = &e {
            eprintln!("{message}");
            std::process::exit(1);
        }
        // User-initiated stops (declined prompt, non-TTY without
        // NONO_AUTO_MIGRATE) are surfaced as `NonoError::Cancelled`.
        // Their stderr message has already been printed at the call
        // site — exit non-zero but skip the ERROR log and the
        // duplicated `nono:` prefix so the output reads as an
        // intentional stop, not a fault.
        if matches!(e, nono::NonoError::Cancelled(_)) {
            std::process::exit(1);
        }
        eprintln!("nono: {}", e);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::SandboxArgs;
    use crate::execution_runtime::execution_start_dir;
    use crate::launch_runtime::{
        resolve_requested_workdir, select_exec_strategy, select_threading_context,
        trust_interception_active,
    };
    use crate::proxy_runtime::{EffectiveProxySettings, resolve_effective_proxy_settings};
    use crate::sandbox_prepare::PreparedSandbox;
    #[cfg(target_os = "linux")]
    use crate::sandbox_prepare::maybe_enable_gpu;
    use crate::sandbox_prepare::maybe_enable_macos_gpu;
    #[cfg(target_os = "macos")]
    use crate::sandbox_prepare::maybe_enable_macos_launch_services;
    use crate::startup_runtime::allows_pre_exec_update_check;
    use nono::{AccessMode, CapabilitySet, FsCapability};

    fn sandbox_args() -> SandboxArgs {
        SandboxArgs::default()
    }

    #[test]
    fn test_sensitive_paths_defined() {
        let loaded_policy = policy::load_embedded_policy().expect("policy must load");
        let paths = policy::get_sensitive_paths(&loaded_policy).expect("must resolve");
        assert!(paths.iter().any(|rule| rule.expanded_path.contains("ssh")));
        assert!(paths.iter().any(|rule| rule.expanded_path.contains("aws")));
    }

    #[test]
    fn test_dangerous_commands_defined() {
        let loaded_policy = policy::load_embedded_policy().expect("policy must load");
        let commands = policy::get_dangerous_commands(&loaded_policy);
        assert!(commands.contains("rm"));
        assert!(commands.contains("dd"));
        assert!(commands.contains("chmod"));
    }

    #[test]
    fn test_check_blocked_command_basic() {
        assert!(
            config::check_blocked_command("echo", &[], &[])
                .expect("policy must load")
                .is_none()
        );
        assert!(
            config::check_blocked_command("ls", &[], &[])
                .expect("policy must load")
                .is_none()
        );
        assert!(
            config::check_blocked_command("cat", &[], &[])
                .expect("policy must load")
                .is_none()
        );
    }

    #[test]
    fn test_check_blocked_command_with_path() {
        let blocked = vec!["rm".to_string(), "dd".to_string()];
        assert!(
            config::check_blocked_command("/bin/rm", &[], &blocked)
                .expect("policy must load")
                .is_some()
        );
        assert!(
            config::check_blocked_command("/usr/bin/dd", &[], &blocked)
                .expect("policy must load")
                .is_some()
        );
        assert!(
            config::check_blocked_command("./rm", &[], &blocked)
                .expect("policy must load")
                .is_some()
        );
    }

    #[test]
    fn test_check_blocked_command_allow_override() {
        let allowed = vec!["rm".to_string()];
        let blocked = vec!["rm".to_string(), "dd".to_string()];
        assert!(
            config::check_blocked_command("rm", &allowed, &blocked)
                .expect("policy must load")
                .is_none()
        );
        assert!(
            config::check_blocked_command("dd", &allowed, &blocked)
                .expect("policy must load")
                .is_some()
        );
    }

    #[test]
    fn test_check_blocked_command_extra_blocked() {
        let extra = vec!["custom-dangerous".to_string()];
        assert!(
            config::check_blocked_command("custom-dangerous", &[], &extra)
                .expect("policy must load")
                .is_some()
        );
        assert!(
            config::check_blocked_command("rm", &[], &extra)
                .expect("policy must load")
                .is_none()
        );
    }

    #[test]
    fn test_check_blocked_command_uses_resolved_policy_only() {
        assert!(
            config::check_blocked_command("rm", &[], &[])
                .expect("policy must load")
                .is_none()
        );
    }

    #[test]
    fn test_resolve_effective_proxy_settings_allow_net_clears_profile_proxy_state() {
        let args = SandboxArgs {
            allow_net: true,
            ..sandbox_args()
        };
        let prepared = PreparedSandbox {
            caps: CapabilitySet::new(),
            secrets: Vec::new(),
            profile_display_name: None,
            command_policies: None,
            session_hooks: crate::profile::SessionHooks::default(),
            rollback_exclude_patterns: Vec::new(),
            rollback_exclude_globs: Vec::new(),
            network_profile: Some("developer".to_string()),
            allow_domain: vec![profile::AllowDomainEntry::Plain(
                "docs.python.org".to_string(),
            )],
            credentials: vec!["github".to_string()],
            custom_credentials: std::collections::HashMap::new(),
            tls_intercept: None,
            upstream_proxy: None,
            upstream_bypass: Vec::new(),
            listen_ports: Vec::new(),
            capability_elevation: false,
            #[cfg(target_os = "linux")]
            wsl2_proxy_policy: crate::profile::Wsl2ProxyPolicy::Error,
            #[cfg(target_os = "linux")]
            af_unix_mediation: crate::profile::LinuxAfUnixMediation::Off,
            allow_launch_services_active: false,
            allow_gpu_active: false,
            open_url_origins: Vec::new(),
            open_url_allow_localhost: false,
            bypass_protection_paths: Vec::new(),
            ignored_denial_paths: Vec::new(),
            suppressed_system_service_operations: Vec::new(),
            allowed_env_vars: None,
            denied_env_vars: None,
            set_vars: None,
            network_block_requested: false,
        };

        let effective = resolve_effective_proxy_settings(&args, &prepared);

        assert_eq!(
            effective,
            EffectiveProxySettings {
                network_profile: None,
                allow_domain: Vec::new(),
                credentials: Vec::new(),
            }
        );
    }

    #[test]
    fn test_resolve_effective_proxy_settings_merges_cli_and_profile() {
        let args = SandboxArgs {
            network_profile: Some("minimal".to_string()),
            allow_proxy: vec!["example.com".to_string()],
            proxy_credential: vec!["openai".to_string()],
            ..sandbox_args()
        };
        let prepared = PreparedSandbox {
            caps: CapabilitySet::new(),
            secrets: Vec::new(),
            profile_display_name: None,
            command_policies: None,
            session_hooks: crate::profile::SessionHooks::default(),
            rollback_exclude_patterns: Vec::new(),
            rollback_exclude_globs: Vec::new(),
            network_profile: Some("developer".to_string()),
            allow_domain: vec![profile::AllowDomainEntry::Plain(
                "docs.python.org".to_string(),
            )],
            credentials: vec!["github".to_string()],
            custom_credentials: std::collections::HashMap::new(),
            tls_intercept: None,
            upstream_proxy: None,
            upstream_bypass: Vec::new(),
            listen_ports: Vec::new(),
            capability_elevation: false,
            #[cfg(target_os = "linux")]
            wsl2_proxy_policy: crate::profile::Wsl2ProxyPolicy::Error,
            #[cfg(target_os = "linux")]
            af_unix_mediation: crate::profile::LinuxAfUnixMediation::Off,
            allow_launch_services_active: false,
            allow_gpu_active: false,
            open_url_origins: Vec::new(),
            open_url_allow_localhost: false,
            bypass_protection_paths: Vec::new(),
            ignored_denial_paths: Vec::new(),
            suppressed_system_service_operations: Vec::new(),
            allowed_env_vars: None,
            denied_env_vars: None,
            set_vars: None,
            network_block_requested: false,
        };

        let effective = resolve_effective_proxy_settings(&args, &prepared);

        assert_eq!(
            effective,
            EffectiveProxySettings {
                network_profile: Some("minimal".to_string()),
                allow_domain: vec![
                    profile::AllowDomainEntry::Plain("docs.python.org".to_string()),
                    profile::AllowDomainEntry::Plain("example.com".to_string()),
                ],
                credentials: vec!["github".to_string(), "openai".to_string()],
            }
        );
    }

    #[test]
    fn test_trust_interception_inactive_for_default_policy() {
        let policy = nono::trust::TrustPolicy::default();

        assert!(!trust_interception_active(Some(&policy)));
    }

    #[test]
    fn test_trust_interception_active_when_includes_exist() {
        let policy = nono::trust::TrustPolicy {
            includes: vec!["SKILLS.md".to_string()],
            ..nono::trust::TrustPolicy::default()
        };

        assert!(trust_interception_active(Some(&policy)));
    }

    #[test]
    fn test_select_exec_strategy_uses_supervised_for_plain_run() {
        assert_eq!(
            select_exec_strategy(false, false, false, false, false),
            exec_strategy::ExecStrategy::Supervised
        );
    }

    #[test]
    fn test_select_exec_strategy_uses_supervised_for_rollback() {
        assert_eq!(
            select_exec_strategy(true, false, false, false, false),
            exec_strategy::ExecStrategy::Supervised
        );
    }

    #[test]
    fn test_select_exec_strategy_uses_supervised_for_proxy() {
        assert_eq!(
            select_exec_strategy(false, true, false, false, false),
            exec_strategy::ExecStrategy::Supervised
        );
    }

    #[test]
    fn test_select_exec_strategy_uses_supervised_for_capability_elevation() {
        assert_eq!(
            select_exec_strategy(false, false, true, false, false),
            exec_strategy::ExecStrategy::Supervised
        );
    }

    #[test]
    fn test_select_exec_strategy_uses_supervised_for_trust_interception() {
        assert_eq!(
            select_exec_strategy(false, false, false, true, false),
            exec_strategy::ExecStrategy::Supervised
        );
    }

    #[test]
    fn test_select_exec_strategy_uses_supervised_for_detached_start() {
        assert_eq!(
            select_exec_strategy(false, false, false, false, true),
            exec_strategy::ExecStrategy::Supervised
        );
    }

    #[test]
    fn test_pre_exec_update_check_disabled_for_execution_commands() {
        let run = Cli::parse_from(["nono", "run", "--allow", "/tmp", "--", "/bin/sh"]);
        assert!(!allows_pre_exec_update_check(&run.command));

        let shell = Cli::parse_from(["nono", "shell", "--allow", "/tmp"]);
        assert!(!allows_pre_exec_update_check(&shell.command));

        let wrap = Cli::parse_from(["nono", "wrap", "--allow", "/tmp", "--", "/bin/sh"]);
        assert!(!allows_pre_exec_update_check(&wrap.command));
    }

    #[test]
    fn test_pre_exec_update_check_disabled_for_completions() {
        // `nono completions` is used in shell init scripts such as
        // `eval "$(nono completions zsh)"`.  It never shows an update
        // notification (it is dispatched directly without
        // run_command_with_update), so spawning the background update-check
        // thread would incur network I/O with no benefit.
        let completions = Cli::parse_from(["nono", "completion", "zsh"]);
        assert!(!allows_pre_exec_update_check(&completions.command));
    }

    #[test]
    fn test_pre_exec_update_check_disabled_for_pack_update_hint_helper() {
        let helper = Cli::parse_from([
            "nono",
            "pack-update-hint-helper",
            "always-further/claude",
            "1.0.0",
        ]);
        assert!(!allows_pre_exec_update_check(&helper.command));
    }

    #[test]
    fn test_pre_exec_update_check_enabled_for_non_exec_commands() {
        let why = Cli::parse_from(["nono", "why", "--path", "/tmp", "--op", "read"]);
        assert!(allows_pre_exec_update_check(&why.command));

        let ps = Cli::parse_from(["nono", "ps"]);
        assert!(allows_pre_exec_update_check(&ps.command));
    }

    #[test]
    fn test_select_threading_context_uses_crypto_for_trust_scan() {
        assert_eq!(
            select_threading_context(false, false, true, false),
            exec_strategy::ThreadingContext::CryptoExpected
        );
    }

    #[test]
    fn test_select_threading_context_uses_keyring_for_secrets_only() {
        assert_eq!(
            select_threading_context(true, false, false, false),
            exec_strategy::ThreadingContext::KeyringExpected
        );
    }

    #[test]
    fn test_resolve_requested_workdir_prefers_explicit_path() {
        let explicit = std::path::PathBuf::from("/tmp/nono-workdir");
        assert_eq!(
            resolve_requested_workdir(Some(&explicit)),
            std::path::PathBuf::from("/tmp/nono-workdir")
        );
    }

    #[test]
    fn test_execution_start_dir_keeps_workdir_when_covered() {
        let dir = tempfile::tempdir().expect("tempdir");
        let canonical = dir.path().canonicalize().expect("canonicalize");
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_dir(dir.path(), AccessMode::Read).expect("grant"));

        let start_dir = execution_start_dir(dir.path(), &caps).expect("start dir");

        assert_eq!(start_dir, canonical);
    }

    #[test]
    fn test_execution_start_dir_falls_back_to_root_when_not_covered() {
        let dir = tempfile::tempdir().expect("tempdir");
        let caps = CapabilitySet::new();

        let start_dir = execution_start_dir(dir.path(), &caps).expect("start dir");

        assert_eq!(start_dir, std::path::PathBuf::from("/"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_maybe_enable_macos_launch_services_adds_rule_when_enabled() {
        let mut caps = CapabilitySet::new();

        let enabled = maybe_enable_macos_launch_services(
            &mut caps,
            true,
            true,
            &["https://claude.ai".to_string()],
            false,
        )
        .expect("launch services gate should apply");

        assert!(enabled, "launch services should be active");
        assert!(
            caps.platform_rules().iter().any(|r| r == "(allow lsopen)"),
            "lsopen platform rule should be present"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_maybe_enable_macos_launch_services_rejects_without_profile_opt_in() {
        let mut caps = CapabilitySet::new();

        let err = maybe_enable_macos_launch_services(
            &mut caps,
            true,
            false,
            &["https://claude.ai".to_string()],
            false,
        )
        .expect_err("missing profile opt-in should fail");

        assert!(
            err.to_string().contains("requires a profile"),
            "error should mention profile opt-in"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_maybe_enable_macos_launch_services_rejects_without_open_urls() {
        let mut caps = CapabilitySet::new();

        let err = maybe_enable_macos_launch_services(&mut caps, true, true, &[], false)
            .expect_err("missing open_urls should fail");

        assert!(
            err.to_string().contains("configure open_urls"),
            "error should mention open_urls"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_maybe_enable_macos_gpu_adds_rules_when_enabled() {
        let mut caps = CapabilitySet::new();

        let enabled = maybe_enable_macos_gpu(&mut caps, true, true).expect("gpu gate should apply");

        assert!(enabled);
        assert!(
            caps.platform_rules()
                .iter()
                .any(|r| r.contains("AGXDeviceUserClient")),
            "AGXDeviceUserClient platform rule should be present"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_maybe_enable_macos_gpu_rejects_without_profile_opt_in() {
        let mut caps = CapabilitySet::new();

        let err = maybe_enable_macos_gpu(&mut caps, true, false)
            .expect_err("missing profile opt-in should fail");

        assert!(
            err.to_string().contains("allow_gpu"),
            "error should mention allow_gpu"
        );
    }

    #[test]
    fn test_maybe_enable_macos_gpu_noop_without_flag() {
        let mut caps = CapabilitySet::new();

        let enabled =
            maybe_enable_macos_gpu(&mut caps, false, true).expect("should succeed without flag");

        assert!(!enabled);
        assert!(caps.platform_rules().is_empty());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn test_maybe_enable_macos_gpu_rejects_on_non_macos() {
        let mut caps = CapabilitySet::new();

        let err =
            maybe_enable_macos_gpu(&mut caps, true, true).expect_err("should fail on non-macOS");

        assert!(
            err.to_string().contains("only supported on macOS"),
            "error should mention macOS support"
        );
    }

    /// On Linux, maybe_enable_gpu should succeed if GPU devices exist, or return
    /// a clear "no GPU devices found" error if not. It must NOT hard-fail just
    /// because /dev/dri is absent — headless NVIDIA (CUDA-only) and AMD (ROCm-only)
    /// machines may lack DRM render nodes entirely.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_maybe_enable_gpu_linux_does_not_require_dri() {
        let mut caps = CapabilitySet::new();

        let result = maybe_enable_gpu(&mut caps, true, true);

        // On a GPU machine: Ok(true) with fs capabilities added.
        // On a non-GPU CI machine: Err mentioning "no GPU devices found".
        // Either outcome is correct. What must NOT happen is an error about
        // /dev/dri specifically, which would break NVIDIA/ROCm-only setups.
        match result {
            Ok(enabled) => {
                assert!(enabled, "should be active when devices are found");
                assert!(
                    caps.has_fs(),
                    "should have granted fs capabilities for GPU devices"
                );
            }
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("no GPU devices found"),
                    "error on non-GPU machine should be generic, not DRI-specific: {msg}"
                );
                // Verify the error lists all checked paths
                assert!(
                    msg.contains("renderD"),
                    "error should mention renderD: {msg}"
                );
                assert!(msg.contains("nvidia"), "error should mention nvidia: {msg}");
                assert!(msg.contains("kfd"), "error should mention kfd: {msg}");
            }
        }
    }
}
