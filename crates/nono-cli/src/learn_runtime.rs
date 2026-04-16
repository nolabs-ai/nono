use crate::cli::LearnArgs;
#[cfg(not(target_os = "windows"))]
use crate::profile_save_runtime::{
    command_name, confirm, patch_has_policy_overrides, print_patch_preview, print_profile_save,
    suggested_profile_name, write_profile, PreparedProfileSave, SaveAction,
};
use crate::learn;
#[cfg(not(target_os = "windows"))]
use crate::profile;
use colored::Colorize;
use nono::{NonoError, Result};

pub(crate) fn run_learn(args: LearnArgs, silent: bool) -> Result<()> {
    // D-02 / UAT Gap 1: on Windows, reject non-admin invocations immediately,
    // BEFORE the interactive warning prompt. This matches the phase 10 admin gate
    // contract — users should never see "Continue? [y/N]" if they cannot run learn
    // in the first place.
    #[cfg(target_os = "windows")]
    {
        if !crate::learn_windows::is_admin() {
            return Err(NonoError::LearnError(
                crate::learn_windows::NON_ADMIN_ERROR.to_string(),
            ));
        }
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

    #[cfg(not(target_os = "windows"))]
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
    #[cfg(target_os = "windows")]
    if result.has_paths() || result.has_network_activity() {
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

#[cfg(not(target_os = "windows"))]
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

#[cfg(not(target_os = "windows"))]
fn read_input_line() -> Result<String> {
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .map_err(|e| NonoError::LearnError(format!("Failed to read input: {}", e)))?;
    Ok(input)
}

#[cfg(not(target_os = "windows"))]
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
