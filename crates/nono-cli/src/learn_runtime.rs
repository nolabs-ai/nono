use crate::cli::LearnArgs;
#[cfg(target_os = "macos")]
use crate::command_display::format_command_line;
use crate::profile_save_runtime::{
    PreparedProfileSave, SaveAction, command_name, confirm, patch_has_policy_overrides,
    print_patch_preview, print_profile_save, suggested_profile_name, write_profile,
};
use crate::{learn, profile};
use colored::Colorize;
use nono::{NonoError, Result};

pub(crate) fn run_learn(args: LearnArgs, silent: bool) -> Result<()> {
    print_learn_deprecation(&args, silent);

    #[cfg(target_os = "macos")]
    if !args.trace {
        return print_macos_run_guidance(&args, silent);
    }

    if !silent {
        eprintln!(
            "{}",
            "WARNING: nono learn runs the command WITHOUT any sandbox restrictions.".yellow()
        );
        eprintln!(
            "{}",
            "The command will have full access to your system to discover required paths.".yellow()
        );
        #[cfg(target_os = "macos")]
        eprintln!(
            "{}",
            "NOTE: macOS learn mode uses fs_usage which requires sudo.".yellow()
        );
        eprintln!();
        eprint!("Continue? [y/N] ");

        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| NonoError::LearnError(format!("Failed to read input: {}", e)))?;

        let input = input.trim().to_lowercase();
        if input != "y" && input != "yes" {
            eprintln!("Aborted.");
            return Ok(());
        }
        eprintln!();
    }

    eprintln!("nono learn - Tracing file accesses and network activity...\n");

    let result = learn::run_learn(&args)?;

    if args.json {
        println!("{}", result.to_json()?);
    } else {
        println!("{}", result.to_summary());
    }

    if (result.has_paths() || result.has_network_activity()) && !silent && !args.json {
        offer_save_profile(&result, &args.command, args.profile.as_deref())?;
    } else if result.has_paths() || result.has_network_activity() {
        if result.has_paths() {
            eprintln!(
                "\nTo use these paths, add them to your profile or use --read/--write/--allow and --read-file/--write-file/--allow-file flags."
            );
        }
        if result.has_network_activity() {
            eprintln!("Network activity detected. Use --block-net to restrict network access.");
        }
    }

    Ok(())
}

fn print_learn_deprecation(args: &LearnArgs, silent: bool) {
    if silent {
        return;
    }

    eprintln!(
        "{}",
        "DEPRECATED: nono learn is deprecated in v0.50.1; use `nono run` instead. Removal target: v1.0.0 (#445).".yellow()
    );
    if let Some(profile) = args.profile.as_deref() {
        eprintln!(
            "{}",
            format!(
                "Use: nono run --profile {} -- {}",
                profile,
                crate::command_display::format_command_line(&args.command)
            )
            .yellow()
        );
    } else {
        eprintln!(
            "{}",
            format!(
                "Use: nono run --profile <profile> -- {}",
                crate::command_display::format_command_line(&args.command)
            )
            .yellow()
        );
    }
    eprintln!(
        "{}",
        "`nono run` keeps the command sandboxed, reports denials, and offers to save profile updates."
            .yellow()
    );
    if args.trace {
        eprintln!(
            "{}",
            "Continuing with legacy unsandboxed trace mode for compatibility.".yellow()
        );
    }
    eprintln!();
}

#[cfg(target_os = "macos")]
fn print_macos_run_guidance(args: &LearnArgs, silent: bool) -> Result<()> {
    if args.json {
        return Err(NonoError::LearnError(
            "macOS run-based learning does not produce JSON. Use `nono learn --trace --json -- <command>` for the legacy unsandboxed tracer.".to_string(),
        ));
    }

    if silent {
        return Ok(());
    }

    let command = format_command_line(&args.command);
    eprintln!(
        "{}",
        "macOS learn now uses sandbox denials from `nono run`.".yellow()
    );
    eprintln!("This keeps the command sandboxed and reuses the existing profile-save prompt.");
    eprintln!();

    if let Some(profile) = args.profile.as_deref() {
        eprintln!("Run:");
        eprintln!("  nono run --profile {} -- {}", profile, command);
    } else {
        eprintln!("Run with the profile you want to improve:");
        eprintln!("  nono run --profile <profile> -- {}", command);
    }

    eprintln!();
    eprintln!(
        "When a path is denied, `nono run` will show diagnostics and offer to save a user profile patch."
    );
    eprintln!("Legacy unsandboxed tracing remains available with:");
    eprintln!("  nono learn --trace -- {}", command);

    Ok(())
}

fn offer_save_profile(
    result: &learn::LearnResult,
    command: &[String],
    compared_profile: Option<&str>,
) -> Result<()> {
    let cmd_name = command_name(command)?;

    // Compute the patch early so we can preview it before asking any questions.
    let patch = result.to_profile_patch()?;
    let has_overrides = patch_has_policy_overrides(&patch);

    eprintln!();
    print_patch_preview(&patch);

    if let Some(existing_profile) = compared_profile
        .filter(|name| profile::is_valid_profile_name(name) && profile::is_user_override(name))
    {
        let (prompt_text, default_yes) = if has_overrides {
            (
                format!(
                    "Update existing user profile '{}' with these paths, including policy overrides? [y/N] ",
                    existing_profile
                ),
                false,
            )
        } else {
            (
                format!(
                    "Update existing user profile '{}' with discovered paths? [Y/n] ",
                    existing_profile
                ),
                true,
            )
        };

        if confirm(&prompt_text, default_yes)? {
            let prepared =
                prepare_profile_save(result, &cmd_name, existing_profile, compared_profile)?;
            write_profile(&prepared)?;
            print_profile_save(&prepared, command);
        }
        return Ok(());
    }

    if let Some(suggested_name) = suggested_profile_name(compared_profile) {
        eprint!(
            "Save as user profile? Enter a name (suggested: {}, or press Enter to skip): ",
            suggested_name
        );
    } else {
        eprint!("Save as user profile? Enter a name (or press Enter to skip): ");
    }

    let input = read_input_line()?;
    let profile_name = input.trim();

    if profile_name.is_empty() {
        return Ok(());
    }

    if !profile::is_valid_profile_name(profile_name) {
        eprintln!(
            "{}",
            "Invalid profile name. Use only letters, numbers, and hyphens.".red()
        );
        return Ok(());
    }

    if compared_profile
        .filter(|name| profile::is_valid_profile_name(name) && !profile::is_user_override(name))
        .is_some_and(|name| name == profile_name)
    {
        eprintln!(
            "{}",
            format!(
                "Cannot save '{}' as a derived user profile because it would shadow the built-in profile it extends. Choose a different name.",
                profile_name
            )
            .red()
        );
        return Ok(());
    }

    if has_overrides
        && !confirm(
            "Save profile with the policy overrides shown above? [y/N] ",
            false,
        )?
    {
        return Ok(());
    }

    let prepared = prepare_profile_save(result, &cmd_name, profile_name, compared_profile)?;
    write_profile(&prepared)?;
    print_profile_save(&prepared, command);

    Ok(())
}

fn read_input_line() -> Result<String> {
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .map_err(|e| NonoError::LearnError(format!("Failed to read input: {}", e)))?;
    Ok(input)
}

fn prepare_profile_save(
    result: &learn::LearnResult,
    cmd_name: &str,
    profile_name: &str,
    compared_profile: Option<&str>,
) -> Result<PreparedProfileSave> {
    let profile_path = profile::get_user_profile_path(profile_name)?;

    if profile_path.exists() {
        let mut existing = profile::load_raw_profile_from_path(&profile_path)?;
        let patch = result.to_profile_patch()?;
        learn::merge_learned_profile_patch(&mut existing, &patch);

        return Ok(PreparedProfileSave {
            action: SaveAction::Updated,
            profile_name: profile_name.to_string(),
            profile_path,
            profile: existing,
        });
    }

    let extends = compared_profile
        .filter(|name| profile::is_valid_profile_name(name) && *name != profile_name)
        .map(|name| vec![name.to_string()]);
    let profile = result.to_named_profile(profile_name, cmd_name, extends)?;

    Ok(PreparedProfileSave {
        action: SaveAction::Created,
        profile_name: profile_name.to_string(),
        profile_path,
        profile,
    })
}
