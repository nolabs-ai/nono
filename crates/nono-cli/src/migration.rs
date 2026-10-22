//! Install prompt for a missing fully-qualified registry package profile.

use crate::cli::PullArgs;
use crate::package::PackageRef;
use crate::package_cmd;
use crate::registry_client::{PullReason, RegistryClient, resolve_registry_url};
use colored::Colorize;
use nono::Result;
use std::io::{self, IsTerminal, Write};

const ENV_AUTO_MIGRATE: &str = "NONO_AUTO_MIGRATE";
const ENV_NO_MIGRATE: &str = "NONO_NO_MIGRATE";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationOutcome {
    NotApplicable,
    Migrated,
    Skipped,
}

/// Check one exact package in the registry, then offer to install it.
pub fn check_and_pull_package(package_ref: &PackageRef) -> Result<MigrationOutcome> {
    if env_flag(ENV_NO_MIGRATE) {
        return Ok(MigrationOutcome::Skipped);
    }

    let client = RegistryClient::new(resolve_registry_url(None));
    if let Err(error) = client.fetch_package_status(package_ref, None) {
        tracing::debug!(
            "could not find registry package '{}': {error}",
            package_ref.key()
        );
        return Ok(MigrationOutcome::NotApplicable);
    }

    let auto = env_flag(ENV_AUTO_MIGRATE);
    let interactive =
        io::stderr().is_terminal() && crate::terminal_prompt::consent_prompt_available();
    if !auto && !interactive {
        emit_skipped_hint(package_ref, SkipReason::NonInteractive);
        return Ok(MigrationOutcome::Skipped);
    }
    if !auto && !confirm_pull(package_ref)? {
        emit_skipped_hint(package_ref, SkipReason::Declined);
        return Ok(MigrationOutcome::Skipped);
    }

    run_pull(&package_ref.key())?;
    Ok(MigrationOutcome::Migrated)
}

fn env_flag(key: &str) -> bool {
    matches!(
        std::env::var(key).ok().as_deref(),
        Some("1" | "true" | "yes")
    )
}

fn confirm_pull(package_ref: &PackageRef) -> Result<bool> {
    let mut err = io::stderr().lock();
    write_pull_prompt(&mut err, package_ref);
    drop(err);

    let line = crate::terminal_prompt::read_consent_line("  Continue? [y/N] ")?;
    Ok(is_affirmative_response(&line))
}

fn write_pull_prompt<W: Write>(err: &mut W, package_ref: &PackageRef) {
    let pack_ref = package_ref.key();
    let _ = writeln!(err);
    let _ = writeln!(err, "  {}  Install {}?", "⊕".cyan(), pack_ref.bold());
    let _ = writeln!(err);
    let _ = writeln!(
        err,
        "     The requested profile is this registry package's public profile."
    );
    let _ = writeln!(err);

    let label_w = "Provenance".len();
    write_field(err, "Namespace", &package_ref.namespace, label_w);
    write_field(
        err,
        "Provenance",
        "Sigstore cryptographic supply chain (verified on pull)",
        label_w,
    );
    let _ = writeln!(err);
}

fn is_affirmative_response(response: &str) -> bool {
    matches!(response.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

#[derive(Clone, Copy)]
enum SkipReason {
    Declined,
    NonInteractive,
}

fn emit_skipped_hint(package_ref: &PackageRef, reason: SkipReason) {
    let pack_ref = package_ref.key();
    let mut err = io::stderr().lock();
    let _ = writeln!(err);
    match reason {
        SkipReason::Declined => {
            let _ = writeln!(
                err,
                "  install skipped — install later with: {}",
                format!("nono pull {pack_ref}").bold()
            );
        }
        SkipReason::NonInteractive => {
            let _ = writeln!(err, "  install required but no TTY available. Either:");
            let _ = writeln!(err, "    {}", format!("nono pull {pack_ref}").bold());
            let _ = writeln!(
                err,
                "  or re-run with {} to install non-interactively.",
                "NONO_AUTO_MIGRATE=1".bold()
            );
        }
    }
    let _ = writeln!(err);
}

fn write_field<W: Write>(out: &mut W, label: &str, value: &str, label_w: usize) {
    let _ = writeln!(
        out,
        "     {label:<width$}   {value}",
        label = label.dimmed(),
        value = value,
        width = label_w,
    );
}

fn run_pull(pack_ref: &str) -> Result<()> {
    package_cmd::run_pull(
        PullArgs {
            package_ref: pack_ref.to_string(),
            registry: None,
            force: true,
            init: false,
            help: None,
        },
        PullReason::ProfileAuto,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::{ENV_LOCK, EnvVarGuard};

    #[test]
    fn env_flag_recognises_truthy_values() {
        let _g = match ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let _env = EnvVarGuard::set_all(&[("NONO_TEST_FLAG_VALUE", "1")]);
        assert!(env_flag("NONO_TEST_FLAG_VALUE"));
    }

    #[test]
    fn env_flag_rejects_other_values() {
        let _g = match ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let _env = EnvVarGuard::set_all(&[("NONO_TEST_FLAG_VALUE", "0")]);
        assert!(!env_flag("NONO_TEST_FLAG_VALUE"));
    }

    #[test]
    fn migration_confirmation_requires_explicit_yes() {
        assert!(is_affirmative_response("y"));
        assert!(is_affirmative_response(" YES \n"));
        assert!(!is_affirmative_response(""));
        assert!(!is_affirmative_response("n"));
        assert!(!is_affirmative_response("anything else"));
    }

    #[test]
    fn install_prompt_omits_legacy_first_time_guidance() {
        let package_ref =
            crate::package::parse_package_ref("nolabs-ai/claude").expect("valid package reference");
        let mut output = Vec::new();

        write_pull_prompt(&mut output, &package_ref);
        let output = String::from_utf8(output).expect("prompt is UTF-8");

        assert!(output.contains("Install nolabs-ai/claude?"));
        assert!(output.contains("Sigstore cryptographic supply chain"));
        assert!(!output.contains("First time seeing this prompt?"));
        assert!(!output.contains("github.com/nolabs-ai/nono/discussions/780"));
    }
}
