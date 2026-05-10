//! This module exists to surface runtime warnings for the deprecated
//! `commands.{allow,deny}` fields, so it deliberately reads them.
#![allow(deprecated)]

use crate::cli::{Cli, Commands};
use crate::output;
use crate::profile::Profile;
use nono::manifest::CapabilityManifest;
use std::path::Path;

const DEPRECATION_SUMMARY: &str =
    "deprecated in v0.33.0: startup-only command gating, not kernel-enforced. \
     Child processes can bypass it. Prefer resource-based controls such as \
     add_deny_access, narrower filesystem grants, unlink_protection, and network policy.";
pub(crate) const BLOCKED_COMMAND_REASON: &str =
    "Command blocking is deprecated in v0.33.0 and only checks the directly-invoked \
     startup command. Child processes can bypass it. Prefer resource-based controls \
     such as add_deny_access, narrower filesystem grants, unlink_protection, and \
     network policy.";

fn format_commands(commands: &[String]) -> String {
    commands.join(", ")
}

fn warning_for_surface(surface: &str, commands: &[String]) -> String {
    if commands.is_empty() {
        format!("{surface} is {DEPRECATION_SUMMARY}")
    } else {
        format!(
            "{surface} is {DEPRECATION_SUMMARY} Configured commands: {}.",
            format_commands(commands)
        )
    }
}

pub(crate) fn collect_cli_warnings(cli: &Cli) -> Vec<String> {
    match &cli.command {
        Commands::Run(args) => {
            collect_sandbox_arg_warnings(&args.sandbox.allow_command, &args.sandbox.block_command)
        }
        Commands::Shell(args) => {
            collect_sandbox_arg_warnings(&args.sandbox.allow_command, &args.sandbox.block_command)
        }
        Commands::Wrap(args) => {
            collect_sandbox_arg_warnings(&args.sandbox.allow_command, &args.sandbox.block_command)
        }
        _ => Vec::new(),
    }
}

fn collect_sandbox_arg_warnings(
    allowed_commands: &[String],
    blocked_commands: &[String],
) -> Vec<String> {
    let mut warnings = Vec::new();

    if !allowed_commands.is_empty() {
        warnings.push(warning_for_surface(
            "CLI flag `--allow-command`",
            allowed_commands,
        ));
    }
    if !blocked_commands.is_empty() {
        warnings.push(warning_for_surface(
            "CLI flag `--block-command`",
            blocked_commands,
        ));
    }

    warnings
}

pub(crate) fn collect_profile_warnings(profile: &Profile) -> Vec<String> {
    let mut warnings = Vec::new();
    let profile_name = format!("profile `{}`", profile.meta.name);

    if !profile.commands.allow.is_empty() {
        warnings.push(warning_for_surface(
            &format!("{profile_name} field `commands.allow`"),
            &profile.commands.allow,
        ));
    }
    if !profile.commands.deny.is_empty() {
        warnings.push(warning_for_surface(
            &format!("{profile_name} field `commands.deny`"),
            &profile.commands.deny,
        ));
    }

    warnings
}

pub(crate) fn collect_manifest_warnings(
    manifest: &CapabilityManifest,
    manifest_path: &Path,
) -> Vec<String> {
    let mut warnings = Vec::new();

    if let Some(process) = manifest.process.as_ref() {
        if !process.allowed_commands.is_empty() {
            warnings.push(warning_for_surface(
                &format!(
                    "capability manifest `{}` field `process.allowed_commands`",
                    manifest_path.display()
                ),
                &process.allowed_commands,
            ));
        }
        if !process.blocked_commands.is_empty() {
            warnings.push(warning_for_surface(
                &format!(
                    "capability manifest `{}` field `process.blocked_commands`",
                    manifest_path.display()
                ),
                &process.blocked_commands,
            ));
        }
    }

    warnings
}

pub(crate) fn print_warnings(warnings: &[String], silent: bool) {
    if silent {
        return;
    }

    for warning in warnings {
        output::print_warning(warning);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_arg_warnings_include_allow_and_block_flags() {
        let warnings = collect_sandbox_arg_warnings(
            &["rm".to_string(), "chmod".to_string()],
            &["docker".to_string()],
        );

        assert_eq!(warnings.len(), 2);
        assert!(warnings[0].contains("`--allow-command`"));
        assert!(warnings[0].contains("rm, chmod"));
        assert!(warnings[1].contains("`--block-command`"));
        assert!(warnings[1].contains("docker"));
    }

    #[test]
    fn warning_for_surface_omits_empty_command_list_suffix() {
        let warning = warning_for_surface("CLI flag `--block-command`", &[]);

        assert!(warning.contains("CLI flag `--block-command`"));
        assert!(!warning.contains("Configured commands:"));
    }

    #[test]
    fn profile_warnings_include_allowed_and_denied_command_fields() {
        let profile: Profile = serde_json::from_str(
            r#"{
                "meta": { "name": "deprecated-commands" },
                "security": { "allowed_commands": ["rm"] },
                "policy": { "add_deny_commands": ["docker"] }
            }"#,
        )
        .expect("profile should deserialize");

        let warnings = collect_profile_warnings(&profile);
        assert_eq!(warnings.len(), 2);
        assert!(warnings[0].contains("commands.allow"));
        assert!(warnings[1].contains("commands.deny"));
    }

    #[test]
    fn manifest_warnings_include_process_command_fields() {
        let manifest = CapabilityManifest::from_json(
            r#"{
                "version": "0.1.0",
                "process": {
                    "allowed_commands": ["rm"],
                    "blocked_commands": ["docker"]
                }
            }"#,
        )
        .expect("manifest should deserialize");

        let warnings = collect_manifest_warnings(&manifest, Path::new("/tmp/caps.json"));
        assert_eq!(warnings.len(), 2);
        assert!(warnings[0].contains("process.allowed_commands"));
        assert!(warnings[1].contains("process.blocked_commands"));
    }
}
