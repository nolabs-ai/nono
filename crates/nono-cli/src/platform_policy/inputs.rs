//! Capture explicit launch inputs without retaining their values.
use crate::cli::{Cli, Commands};
use clap::{ArgMatches, Command, parser::ValueSource};
use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum InputSource {
    CommandLine,
    Environment,
}

pub(crate) type PolicyInputs = BTreeMap<String, InputSource>;

fn excluded(name: &str) -> bool {
    matches!(
        name,
        "help"
            | "version"
            | "silent"
            | "theme"
            | "log-file"
            | "verbose"
            | "no-diagnostics"
            | "diagnostics-json"
            | "suppress-save-prompt"
            | "name"
            | "detached"
            | "detach-timeout"
            | "startup-timeout"
            | "dry-run"
            | "rollback"
            | "no-rollback"
            | "no-rollback-prompt"
            | "rollback-exclude"
            | "rollback-include"
            | "rollback-all"
            | "rollback-dest"
    )
}

fn collect(command: &Command, matches: &ArgMatches, global_only: bool, inputs: &mut PolicyInputs) {
    for arg in command.get_arguments() {
        if arg.is_positional() || (global_only && !arg.is_global_set()) {
            continue;
        }
        let source = match matches.value_source(arg.get_id().as_str()) {
            Some(ValueSource::CommandLine) => InputSource::CommandLine,
            Some(ValueSource::EnvVariable) => InputSource::Environment,
            _ => continue,
        };
        let name = arg
            .get_long()
            .map(str::to_owned)
            .unwrap_or_else(|| arg.get_id().as_str().replace('_', "-"));
        if !excluded(&name) {
            inputs.insert(name, source);
        }
    }
}

pub(crate) fn capture(cli: &mut Cli, command: &Command, matches: &ArgMatches) -> Result<()> {
    let destination = match &mut cli.command {
        Commands::Run(args) => &mut args.sandbox.policy_inputs,
        Commands::Shell(args) => &mut args.sandbox.policy_inputs,
        Commands::Wrap(args) => &mut args.sandbox.policy_inputs,
        _ => return Ok(()),
    };
    let (name, submatches) = matches
        .subcommand()
        .ok_or_else(|| NonoError::ConfigParse("missing parsed launch command".into()))?;
    let definition = command
        .find_subcommand(name)
        .ok_or_else(|| NonoError::ConfigParse("missing launch argument definitions".into()))?;
    let mut inputs = PolicyInputs::new();
    collect(command, matches, true, &mut inputs);
    collect(definition, submatches, false, &mut inputs);
    *destination = inputs;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Arg, ArgAction, CommandFactory, FromArgMatches};
    use std::collections::BTreeSet;

    fn environment_keys(command: &Command, keys: &mut BTreeSet<String>) {
        for arg in command.get_arguments() {
            if let Some(key) = arg.get_env() {
                keys.insert(key.to_string_lossy().into_owned());
            }
        }
        for child in command.get_subcommands() {
            environment_keys(child, keys);
        }
    }

    fn parse(argv: &[&str], env: &[(&str, &str)]) -> Cli {
        let _lock = crate::test_env::ENV_LOCK.lock().expect("environment lock");
        let command = Cli::command();
        let mut keys = BTreeSet::new();
        environment_keys(&command, &mut keys);
        let bindings: Vec<_> = keys.iter().map(String::as_str).collect();
        let _reset = crate::test_env::EnvVarGuard::unset_all(&bindings);
        let _env = crate::test_env::EnvVarGuard::set_all(env);
        let mut command = Cli::command();
        let matches = command.try_get_matches_from_mut(argv).expect("arguments");
        let mut cli = Cli::from_arg_matches(&matches).expect("typed arguments");
        capture(&mut cli, &command, &matches).expect("capture");
        cli
    }

    fn inputs(cli: &Cli) -> &PolicyInputs {
        match &cli.command {
            Commands::Run(args) => &args.sandbox.policy_inputs,
            Commands::Shell(args) => &args.sandbox.policy_inputs,
            Commands::Wrap(args) => &args.sandbox.policy_inputs,
            _ => panic!("launch expected"),
        }
    }

    #[test]
    fn defaults_session_options_and_child_arguments_are_not_overrides() {
        for argv in [
            vec!["nono", "run", "--", "echo", "--allow", "child-secret"],
            vec![
                "nono",
                "shell",
                "--name",
                "session",
                "--startup-timeout",
                "10",
            ],
            vec![
                "nono",
                "--silent",
                "--theme",
                "latte",
                "run",
                "-vv",
                "--detach",
                "--detach-timeout",
                "10",
                "--dry-run",
                "--rollback",
                "--rollback-exclude",
                "node_modules",
                "--rollback-all",
                "--no-diagnostics",
                "--",
                "echo",
            ],
            vec![
                "nono",
                "wrap",
                "--dry-run",
                "--no-diagnostics",
                "--",
                "echo",
                "--profile",
                "child-profile",
            ],
        ] {
            assert!(inputs(&parse(&argv, &[])).is_empty(), "{argv:?}");
        }
    }

    #[test]
    fn run_options_outside_sandbox_args_are_recorded_without_values() {
        let cli = parse(
            &[
                "nono",
                "run",
                "--no-audit",
                "--trust-override",
                "--skip-dir",
                "private-dir",
                "--network-denial-audit-rate",
                "3",
                "--network-denial-audit-burst",
                "4",
                "--",
                "echo",
            ],
            &[],
        );
        for name in [
            "no-audit",
            "trust-override",
            "skip-dir",
            "network-denial-audit-rate",
            "network-denial-audit-burst",
        ] {
            assert_eq!(inputs(&cli).get(name), Some(&InputSource::CommandLine));
        }
        let cli = parse(
            &[
                "nono",
                "run",
                "--audit-sign-key",
                "env://secret-key",
                "--credential",
                "secret-credential",
                "--",
                "echo",
            ],
            &[],
        );
        assert!(inputs(&cli).contains_key("audit-sign-key"));
        assert!(inputs(&cli).contains_key("credential"));
        let text = serde_json::to_string(inputs(&cli)).expect("metadata");
        assert!(!text.contains("secret"));
        let cli = parse(&["nono", "run", "--no-audit-integrity", "--", "echo"], &[]);
        assert!(inputs(&cli).contains_key("no-audit-integrity"));
    }

    #[test]
    fn environment_inputs_include_explicit_false_and_cli_precedence() {
        let cli = parse(
            &["nono", "run", "--", "echo"],
            &[
                ("NONO_PROFILE", "env-profile"),
                ("NONO_TRUST_OVERRIDE", "false"),
            ],
        );
        assert_eq!(inputs(&cli).get("profile"), Some(&InputSource::Environment));
        assert_eq!(
            inputs(&cli).get("trust-override"),
            Some(&InputSource::Environment)
        );
        let Commands::Run(args) = cli.command else {
            panic!("run");
        };
        assert!(!args.trust_override);
        let cli = parse(
            &["nono", "run", "--profile", "cli-profile", "--", "echo"],
            &[("NONO_PROFILE", "env-profile")],
        );
        assert_eq!(inputs(&cli).get("profile"), Some(&InputSource::CommandLine));
        let Commands::Run(args) = cli.command else {
            panic!("run");
        };
        assert_eq!(args.sandbox.profile.as_deref(), Some("cli-profile"));
    }

    #[test]
    fn flattened_and_renamed_options_keep_their_canonical_names() {
        for argv in [
            vec![
                "nono",
                "run",
                "-a",
                ".",
                "--allow-domain",
                "example.com",
                "--record",
                "--",
                "echo",
            ],
            vec![
                "nono",
                "shell",
                "-a",
                ".",
                "--allow-domain",
                "example.com",
                "--record",
            ],
        ] {
            let cli = parse(&argv, &[]);
            assert_eq!(
                inputs(&cli).keys().map(String::as_str).collect::<Vec<_>>(),
                ["allow", "allow-domain", "record"]
            );
        }
        let cli = parse(&["nono", "wrap", "--profile", "default", "--", "echo"], &[]);
        let Commands::Wrap(args) = cli.command else {
            panic!("wrap");
        };
        let sandbox: crate::cli::SandboxArgs = args.sandbox.into();
        assert_eq!(
            sandbox.policy_inputs.get("profile"),
            Some(&InputSource::CommandLine)
        );
    }

    #[test]
    fn new_options_and_aliases_are_automatically_recorded() {
        let mut command = Command::new("test")
            .arg(
                Arg::new("future_field")
                    .long("future-policy-rule")
                    .alias("old-rule")
                    .short('R'),
            )
            .arg(Arg::new("short_only").short('G').action(ArgAction::SetTrue));
        let matches = command
            .try_get_matches_from_mut(["test", "--old-rule", "secret-value", "-G"])
            .expect("arguments");
        let mut inputs = PolicyInputs::new();
        collect(&command, &matches, false, &mut inputs);
        assert_eq!(
            inputs.keys().map(String::as_str).collect::<Vec<_>>(),
            ["future-policy-rule", "short-only"]
        );
        assert!(
            !serde_json::to_string(&inputs)
                .expect("metadata")
                .contains("secret-value")
        );
    }

    #[test]
    fn source_metadata_is_additive_to_legacy_policy_records() {
        let mut record = serde_json::json!({
            "management_mode":"advisory", "assignment_version":"assignment",
            "policy_source":"local", "overrides":["profile"]
        });
        let old: super::super::PolicySession =
            serde_json::from_value(record.clone()).expect("legacy record");
        assert!(old.override_sources.is_empty());
        assert_eq!(old.overrides, ["profile"]);
        record["override_sources"] = serde_json::json!({"profile":"environment"});
        let new: super::super::PolicySession = serde_json::from_value(record).expect("new record");
        assert_eq!(
            new.override_sources.get("profile"),
            Some(&InputSource::Environment)
        );
        assert_eq!(new.overrides, old.overrides);
    }

    #[test]
    fn new_global_options_are_recorded_once() {
        let _lock = crate::test_env::ENV_LOCK.lock().expect("environment lock");
        let mut command = Cli::command().arg(
            Arg::new("future_global")
                .long("future-global")
                .global(true)
                .action(ArgAction::SetTrue),
        );
        let matches = command
            .try_get_matches_from_mut(["nono", "--future-global", "run", "--", "echo"])
            .expect("arguments");
        let mut cli = Cli::from_arg_matches(&matches).expect("typed arguments");
        capture(&mut cli, &command, &matches).expect("capture");
        assert_eq!(
            inputs(&cli).get("future-global"),
            Some(&InputSource::CommandLine)
        );
        assert_eq!(
            inputs(&cli)
                .keys()
                .filter(|name| *name == "future-global")
                .count(),
            1
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_proxy_trust_is_recorded() {
        let cli = parse(&["nono", "run", "--trust-proxy-ca", "--", "echo"], &[]);
        assert_eq!(
            inputs(&cli).get("trust-proxy-ca"),
            Some(&InputSource::CommandLine)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_isolation_is_recorded() {
        let cli = parse(&["nono", "run", "--isolate", "ipc", "--", "echo"], &[]);
        assert_eq!(inputs(&cli).get("isolate"), Some(&InputSource::CommandLine));
    }
}
