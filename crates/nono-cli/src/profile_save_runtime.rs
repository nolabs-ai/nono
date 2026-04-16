use crate::{profile, query_ext};
use colored::Colorize;
use nono::diagnostic::{ErrorObservation, PolicyExplanation};
use nono::{AccessMode, CapabilitySet, NonoError, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy)]
pub(crate) enum SaveAction {
    Created,
    Updated,
}

pub(crate) struct PreparedProfileSave {
    pub(crate) action: SaveAction,
    pub(crate) profile_name: String,
    pub(crate) profile_path: PathBuf,
    pub(crate) profile: profile::Profile,
}

#[derive(Clone, Copy)]
struct PatchGrant {
    access: AccessMode,
    is_file: bool,
    override_deny: bool,
}

pub(crate) fn terminal_prompts_available() -> bool {
    std::io::stdin().is_terminal()
        || std::io::stderr().is_terminal()
        || std::fs::File::open("/dev/tty").is_ok()
}

pub(crate) fn offer_save_run_profile(
    policy_explanations: &[PolicyExplanation],
    error_observation: &ErrorObservation,
    caps: &CapabilitySet,
    command: &[String],
    compared_profile: Option<&str>,
) -> Result<()> {
    if compared_profile.is_none() || !terminal_prompts_available() {
        return Ok(());
    }

    let Some(patch) = build_run_profile_patch(policy_explanations, error_observation, caps)? else {
        return Ok(());
    };

    let cmd_name = command_name(command)?;
    let has_overrides = patch_has_policy_overrides(&patch);

    prompt_println("");
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
                    "Update existing user profile '{}' with denied paths? [Y/n] ",
                    existing_profile
                ),
                true,
            )
        };

        if confirm(&prompt_text, default_yes)? {
            let prepared = prepare_profile_save_from_patch(
                &patch,
                &cmd_name,
                existing_profile,
                compared_profile,
            )?;
            write_profile(&prepared)?;
            print_profile_save(&prepared, command);
            return Ok(());
        }
        return Ok(());
    }

    if let Some(suggested_name) = suggested_profile_name(compared_profile) {
        prompt_print(
            "Save denied paths as user profile? Enter a name (suggested: {}, or press Enter to skip): ",
            &[suggested_name.as_str()],
        );
    } else {
        prompt_print(
            "Save denied paths as user profile? Enter a name (or press Enter to skip): ",
            &[],
        );
    }

    let input = read_input_line()?;
    let profile_name = input.trim();

    if profile_name.is_empty() {
        return Ok(());
    }

    if !profile::is_valid_profile_name(profile_name) {
        prompt_println(&format!(
            "{}",
            "Invalid profile name. Use only letters, numbers, and hyphens.".red()
        ));
        return Ok(());
    }

    if compared_profile
        .filter(|name| profile::is_valid_profile_name(name) && !profile::is_user_override(name))
        .is_some_and(|name| name == profile_name)
    {
        prompt_println(&format!(
            "{}",
            format!(
                "Cannot save '{}' as a derived user profile because it would shadow the built-in profile it extends. Choose a different name.",
                profile_name
            )
            .red()
        ));
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

    let prepared =
        prepare_profile_save_from_patch(&patch, &cmd_name, profile_name, compared_profile)?;
    write_profile(&prepared)?;
    print_profile_save(&prepared, command);

    Ok(())
}

pub(crate) fn command_name(command: &[String]) -> Result<String> {
    command
        .first()
        .and_then(|command| std::path::Path::new(command).file_name())
        .and_then(|name| name.to_str())
        .map(ToOwned::to_owned)
        .ok_or_else(|| NonoError::LearnError("Cannot derive profile name from command".to_string()))
}

pub(crate) fn confirm(prompt: &str, default_yes: bool) -> Result<bool> {
    prompt_print(prompt, &[]);

    let input = read_input_line()?;
    let trimmed = input.trim();

    if trimmed.is_empty() {
        return Ok(default_yes);
    }

    Ok(trimmed.eq_ignore_ascii_case("y") || trimmed.eq_ignore_ascii_case("yes"))
}

pub(crate) fn suggested_profile_name(compared_profile: Option<&str>) -> Option<String> {
    compared_profile
        .filter(|name| profile::is_valid_profile_name(name) && !profile::is_user_override(name))
        .map(|name| format!("{}-local", name))
}

pub(crate) fn write_profile(prepared: &PreparedProfileSave) -> Result<()> {
    let profiles_dir = prepared.profile_path.parent().ok_or_else(|| {
        NonoError::LearnError("Failed to determine profiles directory".to_string())
    })?;
    std::fs::create_dir_all(profiles_dir).map_err(|e| {
        NonoError::LearnError(format!(
            "Failed to create profiles directory {}: {}",
            profiles_dir.display(),
            e
        ))
    })?;

    let profile_json = serde_json::to_string_pretty(&prepared.profile)
        .map_err(|e| NonoError::LearnError(format!("Failed to serialize profile: {}", e)))?;
    std::fs::write(&prepared.profile_path, format!("{profile_json}\n")).map_err(|e| {
        NonoError::LearnError(format!(
            "Failed to write profile to {}: {}",
            prepared.profile_path.display(),
            e
        ))
    })?;

    Ok(())
}

pub(crate) fn print_profile_save(prepared: &PreparedProfileSave, command: &[String]) {
    let status = match prepared.action {
        SaveAction::Created => "Profile saved:",
        SaveAction::Updated => "Profile updated:",
    };

    prompt_println(&format!(
        "\n{} {}",
        status.green(),
        prepared.profile_path.display()
    ));

    let override_count = prepared.profile.policy.override_deny.len();
    if override_count > 0 {
        prompt_println(&format!(
            "{}",
            format!(
                "  ({} path{} with policy.override_deny — review the profile before sharing)",
                override_count,
                if override_count == 1 { "" } else { "s" }
            )
            .yellow()
        ));
    }

    prompt_println(&format!(
        "Run with: {} {} -- {}",
        "nono run --profile".bold(),
        prepared.profile_name,
        command.join(" ")
    ));
}

/// Print a preview of what paths will be written to the profile.
///
/// Highlights `override_deny` entries with a visible warning since those
/// bypass nono's built-in sensitive-path protection.
pub(crate) fn print_patch_preview(patch: &profile::Profile) {
    let sections: &[(&str, &[String])] = &[
        ("read+write dirs", &patch.filesystem.allow),
        ("read dirs", &patch.filesystem.read),
        ("write dirs", &patch.filesystem.write),
        ("read+write files", &patch.filesystem.allow_file),
        ("read files", &patch.filesystem.read_file),
        ("write files", &patch.filesystem.write_file),
    ];

    let has_entries = sections.iter().any(|(_, paths)| !paths.is_empty());
    if !has_entries && patch.policy.override_deny.is_empty() {
        return;
    }

    prompt_println("[nono] Paths to be saved:");
    for (label, paths) in sections {
        for path in *paths {
            let is_override = patch.policy.override_deny.contains(path);
            if is_override {
                prompt_println(&format!("  {}  {} ({})", "⚠".yellow(), path, label));
            } else {
                prompt_println(&format!("  {}  ({})", path, label));
            }
        }
    }

    if !patch.policy.override_deny.is_empty() {
        prompt_println(&format!(
            "{}",
            "\n[nono] ⚠  The marked paths are normally blocked by security policy.".yellow()
        ));
        prompt_println(&format!(
            "{}",
            "[nono]    Saving them adds policy.override_deny, which weakens sandbox protection."
                .yellow()
        ));
    }
}

/// Return true if the patch includes any `policy.override_deny` entries.
pub(crate) fn patch_has_policy_overrides(patch: &profile::Profile) -> bool {
    !patch.policy.override_deny.is_empty()
}

fn prompt_print(template: &str, args: &[&str]) {
    let mut message = template.to_string();
    for arg in args {
        if let Some(idx) = message.find("{}") {
            message.replace_range(idx..idx + 2, arg);
        }
    }
    prompt_write(&message);
}

fn prompt_println(message: &str) {
    prompt_writeln(message);
}

fn open_tty_prompt_device() -> Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|e| NonoError::LearnError(format!("Failed to open /dev/tty: {}", e)))
}

fn open_tty_writer() -> Option<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/tty")
        .ok()
}

fn prompt_read_line() -> Result<String> {
    let mut input = String::new();
    let tty = open_tty_prompt_device()?;
    force_prompt_terminal_mode(&tty);
    let mut reader = std::io::BufReader::new(tty);
    reader
        .read_line(&mut input)
        .map_err(|e| NonoError::LearnError(format!("Failed to read input: {}", e)))?;
    Ok(input)
}

fn force_prompt_terminal_mode(tty: &std::fs::File) {
    let Ok(mut termios) = nix::sys::termios::tcgetattr(tty) else {
        return;
    };
    configure_prompt_termios(&mut termios);
    let _ = nix::sys::termios::tcsetattr(tty, nix::sys::termios::SetArg::TCSANOW, &termios);
    let _ = nix::sys::termios::tcflush(tty, nix::sys::termios::FlushArg::TCIFLUSH);
}

pub(crate) fn configure_prompt_termios(termios: &mut nix::sys::termios::Termios) {
    use nix::sys::termios::{
        ControlFlags, InputFlags, LocalFlags, OutputFlags, SpecialCharacterIndices,
    };

    termios.input_flags.remove(
        InputFlags::IGNBRK
            | InputFlags::BRKINT
            | InputFlags::PARMRK
            | InputFlags::ISTRIP
            | InputFlags::INLCR
            | InputFlags::IGNCR,
    );
    termios
        .input_flags
        .insert(InputFlags::ICRNL | InputFlags::IXON);

    termios.output_flags.insert(OutputFlags::OPOST);

    termios.local_flags.insert(
        LocalFlags::ECHO
            | LocalFlags::ECHONL
            | LocalFlags::ICANON
            | LocalFlags::ISIG
            | LocalFlags::IEXTEN,
    );

    termios
        .control_flags
        .remove(ControlFlags::CSIZE | ControlFlags::PARENB);
    termios.control_flags.insert(ControlFlags::CS8);

    termios.control_chars[SpecialCharacterIndices::VMIN as usize] = 1;
    termios.control_chars[SpecialCharacterIndices::VTIME as usize] = 0;
}

fn prompt_write(message: &str) {
    if let Some(mut tty) = open_tty_writer() {
        let _ = write!(tty, "{}", message);
        let _ = tty.flush();
        return;
    }

    eprint!("{}", message);
    let _ = std::io::stderr().flush();
}

fn prompt_writeln(message: &str) {
    if let Some(mut tty) = open_tty_writer() {
        let _ = writeln!(tty, "{}", message);
        let _ = tty.flush();
        return;
    }

    eprintln!("{}", message);
    let _ = std::io::stderr().flush();
}

pub(crate) fn prepare_profile_save_from_patch(
    patch: &profile::Profile,
    cmd_name: &str,
    profile_name: &str,
    compared_profile: Option<&str>,
) -> Result<PreparedProfileSave> {
    let profile_path = profile::get_user_profile_path(profile_name)?;

    if profile_path.exists() {
        let mut existing = profile::load_raw_profile_from_path(&profile_path)?;
        merge_profile_patch(&mut existing, patch);

        return Ok(PreparedProfileSave {
            action: SaveAction::Updated,
            profile_name: profile_name.to_string(),
            profile_path,
            profile: existing,
        });
    }

    let mut new_profile = patch.clone();
    let extends = compared_profile
        .filter(|name| profile::is_valid_profile_name(name) && *name != profile_name)
        .map(|name| vec![name.to_string()]);
    let has_base = extends.is_some();
    new_profile.extends = extends;
    new_profile.meta = profile::ProfileMeta {
        name: profile_name.to_string(),
        version: "1.0.0".to_string(),
        description: Some(if has_base {
            format!("Runtime-discovered path additions for {}", cmd_name)
        } else {
            format!("Runtime-discovered path profile for {}", cmd_name)
        }),
        author: None,
    };

    Ok(PreparedProfileSave {
        action: SaveAction::Created,
        profile_name: profile_name.to_string(),
        profile_path,
        profile: new_profile,
    })
}

fn read_input_line() -> Result<String> {
    prompt_read_line()
}

fn build_run_profile_patch(
    policy_explanations: &[PolicyExplanation],
    error_observation: &ErrorObservation,
    caps: &CapabilitySet,
) -> Result<Option<profile::Profile>> {
    let mut grants: BTreeMap<PathBuf, PatchGrant> = BTreeMap::new();

    for explanation in policy_explanations {
        add_patch_grant(
            &mut grants,
            &explanation.path,
            explanation.access,
            &explanation.reason,
        );
    }

    for hint in &error_observation.path_hints {
        match query_ext::query_path(&hint.path, hint.access, caps, &[]) {
            Ok(query_ext::QueryResult::Denied { reason, .. })
                if matches!(
                    reason.as_str(),
                    "sensitive_path" | "insufficient_access" | "path_not_granted"
                ) =>
            {
                add_patch_grant(&mut grants, &hint.path, hint.access, &reason);
            }
            _ => {}
        }
    }

    if grants.is_empty() {
        return Ok(None);
    }

    let home = crate::config::validated_home()?;
    let home_path = Path::new(&home);
    let mut allow = BTreeSet::new();
    let mut read = BTreeSet::new();
    let mut write = BTreeSet::new();
    let mut allow_file = BTreeSet::new();
    let mut read_file = BTreeSet::new();
    let mut write_file = BTreeSet::new();
    let mut override_deny = BTreeSet::new();

    for (path, grant) in grants {
        let shortened = shorten_path_for_profile(&path, home_path);
        if grant.override_deny {
            override_deny.insert(shortened.clone());
        }

        match (grant.access, grant.is_file) {
            (AccessMode::Read, false) => {
                read.insert(shortened);
            }
            (AccessMode::Write, false) => {
                write.insert(shortened);
            }
            (AccessMode::ReadWrite, false) => {
                allow.insert(shortened);
            }
            (AccessMode::Read, true) => {
                read_file.insert(shortened);
            }
            (AccessMode::Write, true) => {
                write_file.insert(shortened);
            }
            (AccessMode::ReadWrite, true) => {
                allow_file.insert(shortened);
            }
        }
    }

    let mut patch = profile::Profile::default();
    patch.filesystem.allow = allow.into_iter().collect();
    patch.filesystem.read = read.into_iter().collect();
    patch.filesystem.write = write.into_iter().collect();
    patch.filesystem.allow_file = allow_file.into_iter().collect();
    patch.filesystem.read_file = read_file.into_iter().collect();
    patch.filesystem.write_file = write_file.into_iter().collect();
    patch.policy.override_deny = override_deny.into_iter().collect();

    Ok(Some(patch))
}

fn add_patch_grant(
    grants: &mut BTreeMap<PathBuf, PatchGrant>,
    path: &Path,
    access: AccessMode,
    reason: &str,
) {
    let (flag, target) = query_ext::suggested_flag_parts(path, access);
    let is_file = matches!(flag, "--read-file" | "--write-file" | "--allow-file");

    match grants.get_mut(&target) {
        Some(existing) => {
            existing.access = merge_access(existing.access, access);
            existing.is_file |= is_file;
            existing.override_deny |= reason == "sensitive_path";
        }
        None => {
            grants.insert(
                target,
                PatchGrant {
                    access,
                    is_file,
                    override_deny: reason == "sensitive_path",
                },
            );
        }
    }
}

fn merge_access(existing: AccessMode, requested: AccessMode) -> AccessMode {
    if existing == requested {
        existing
    } else {
        AccessMode::ReadWrite
    }
}

pub(crate) fn merge_profile_patch(profile: &mut profile::Profile, patch: &profile::Profile) {
    profile.filesystem.allow =
        profile::dedup_append(&profile.filesystem.allow, &patch.filesystem.allow);
    profile.filesystem.read =
        profile::dedup_append(&profile.filesystem.read, &patch.filesystem.read);
    profile.filesystem.write =
        profile::dedup_append(&profile.filesystem.write, &patch.filesystem.write);
    profile.filesystem.allow_file =
        profile::dedup_append(&profile.filesystem.allow_file, &patch.filesystem.allow_file);
    profile.filesystem.read_file =
        profile::dedup_append(&profile.filesystem.read_file, &patch.filesystem.read_file);
    profile.filesystem.write_file =
        profile::dedup_append(&profile.filesystem.write_file, &patch.filesystem.write_file);
    profile.policy.override_deny =
        profile::dedup_append(&profile.policy.override_deny, &patch.policy.override_deny);
}

pub(crate) fn shorten_path_for_profile(path: &Path, home_path: &Path) -> String {
    if path.starts_with(home_path) {
        match path.strip_prefix(home_path) {
            Ok(relative) => format!("~/{}", relative.display()),
            Err(_) => path.display().to_string(),
        }
    } else {
        path.display().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::{EnvVarGuard, ENV_LOCK};
    use tempfile::TempDir;

    #[test]
    fn build_run_profile_patch_adds_override_deny_for_sensitive_file() {
        let _env_lock = ENV_LOCK.lock().expect("env lock");
        let temp_home = TempDir::new().expect("temp home");
        let _env = EnvVarGuard::set_all(&[("HOME", temp_home.path().to_str().expect("home path"))]);

        let target = temp_home.path().join(".claude").join("settings.json");
        std::fs::create_dir_all(target.parent().expect("parent")).expect("mkdir");
        std::fs::write(&target, b"{}").expect("write");

        let explanation = PolicyExplanation {
            path: target,
            access: AccessMode::Read,
            reason: "sensitive_path".to_string(),
            details: None,
            policy_source: None,
            suggested_flag: None,
        };

        let patch = build_run_profile_patch(
            &[explanation],
            &ErrorObservation::default(),
            &CapabilitySet::new(),
        )
        .expect("build patch")
        .expect("patch");

        assert_eq!(patch.filesystem.read_file, vec!["~/.claude/settings.json"]);
        assert_eq!(patch.policy.override_deny, vec!["~/.claude/settings.json"]);
    }

    #[test]
    fn build_run_profile_patch_merges_read_and_write_to_allow_file() {
        let _env_lock = ENV_LOCK.lock().expect("env lock");
        let temp_home = TempDir::new().expect("temp home");
        let _env = EnvVarGuard::set_all(&[("HOME", temp_home.path().to_str().expect("home path"))]);

        let target = temp_home.path().join("config.json");
        std::fs::write(&target, b"{}").expect("write");

        let read = PolicyExplanation {
            path: target.clone(),
            access: AccessMode::Read,
            reason: "path_not_granted".to_string(),
            details: None,
            policy_source: None,
            suggested_flag: Some(format!("--read-file {}", target.display())),
        };
        let write = PolicyExplanation {
            path: target,
            access: AccessMode::Write,
            reason: "insufficient_access".to_string(),
            details: None,
            policy_source: None,
            suggested_flag: None,
        };

        let patch = build_run_profile_patch(
            &[read, write],
            &ErrorObservation::default(),
            &CapabilitySet::new(),
        )
        .expect("build patch")
        .expect("patch");

        assert_eq!(patch.filesystem.allow_file, vec!["~/config.json"]);
        assert!(patch.filesystem.read_file.is_empty());
        assert!(patch.filesystem.write_file.is_empty());
    }

    #[test]
    fn prepare_profile_save_from_patch_updates_existing_user_profile() {
        let _env_lock = ENV_LOCK.lock().expect("env lock");
        let temp_home = TempDir::new().expect("temp home");
        let temp_config = TempDir::new().expect("temp config");
        let _env = EnvVarGuard::set_all(&[
            ("HOME", temp_home.path().to_str().expect("home path")),
            (
                "XDG_CONFIG_HOME",
                temp_config.path().to_str().expect("config path"),
            ),
        ]);

        let existing_path =
            profile::get_user_profile_path("claude-code-local").expect("profile path");
        std::fs::create_dir_all(existing_path.parent().expect("profile dir")).expect("mkdir");
        std::fs::write(
            &existing_path,
            "{\n  \"meta\": {\n    \"name\": \"claude-code-local\",\n    \"version\": \"1.0.0\"\n  },\n  \"filesystem\": {\n    \"read_file\": [\"~/old.json\"]\n  },\n  \"policy\": {\n    \"override_deny\": [\"~/old.json\"]\n  }\n}\n",
        )
        .expect("write profile");

        let mut patch = profile::Profile::default();
        patch.filesystem.read_file = vec!["~/.claude/settings.json".to_string()];
        patch.policy.override_deny = vec!["~/.claude/settings.json".to_string()];

        let prepared = prepare_profile_save_from_patch(
            &patch,
            "claude",
            "claude-code-local",
            Some("claude-code"),
        )
        .expect("prepare");

        assert!(matches!(prepared.action, SaveAction::Updated));
        assert_eq!(
            prepared.profile.filesystem.read_file,
            vec![
                "~/old.json".to_string(),
                "~/.claude/settings.json".to_string()
            ]
        );
        assert_eq!(
            prepared.profile.policy.override_deny,
            vec![
                "~/old.json".to_string(),
                "~/.claude/settings.json".to_string()
            ]
        );
    }
}
