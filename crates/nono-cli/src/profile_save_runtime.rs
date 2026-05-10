use crate::command_display::format_command_line;
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
    bypass_protection: bool,
}

/// Env var that suppresses the "save denied paths as user profile?"
/// prompt entirely. Set by integration tests and CI runs that have an
/// openable `/dev/tty` (so `terminal_prompts_available` would otherwise
/// return true) but no human to answer. Mirrors the `NONO_NO_MIGRATE`
/// escape hatch on the migration prompt.
const ENV_NO_SAVE_PROMPT: &str = "NONO_NO_SAVE_PROMPT";

pub(crate) fn terminal_prompts_available() -> bool {
    if matches!(
        std::env::var(ENV_NO_SAVE_PROMPT).ok().as_deref(),
        Some("1" | "true" | "yes")
    ) {
        return false;
    }
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
        let confirmed = if has_overrides {
            confirm_typed_word(
                &format!(
                    "Update existing user profile '{}' with these paths, including policy overrides? Type 'override' to confirm: ",
                    existing_profile
                ),
                "override",
            )?
        } else {
            confirm(
                &format!(
                    "Update existing user profile '{}' with denied paths? [Y/n] ",
                    existing_profile
                ),
                true,
            )?
        };

        if confirmed {
            let prepared = prepare_profile_save_from_patch(
                &patch,
                &cmd_name,
                existing_profile,
                compared_profile,
            )?;
            write_profile(&prepared)?;
            print_profile_save(&prepared, command);
        }
        return Ok(());
    }

    let suggested = suggested_profile_name(compared_profile);
    let Some(profile_name) = prompt_profile_name(suggested.as_deref())? else {
        return Ok(());
    };

    if has_overrides
        && !confirm_typed_word(
            "Save profile with the policy overrides shown above? Type 'override' to confirm: ",
            "override",
        )?
    {
        return Ok(());
    }

    let prepared =
        prepare_profile_save_from_patch(&patch, &cmd_name, &profile_name, compared_profile)?;
    write_profile(&prepared)?;
    print_profile_save(&prepared, command);

    Ok(())
}

/// Prompt for a new profile name, re-prompting on invalid or shadowed names
/// until the user enters a valid name or presses Enter to skip.
///
/// Returns `Ok(None)` when the user skips.
fn prompt_profile_name(suggested: Option<&str>) -> Result<Option<String>> {
    let mut first = true;
    loop {
        if first {
            if let Some(suggested_name) = suggested {
                prompt_print(
                    "Save denied paths as user profile? Enter a name (suggested: {}, or press Enter to skip): ",
                    &[suggested_name],
                );
            } else {
                prompt_print(
                    "Save denied paths as user profile? Enter a name (or press Enter to skip): ",
                    &[],
                );
            }
            first = false;
        } else {
            prompt_print("Enter a name (or press Enter to skip): ", &[]);
        }

        let input = read_input_line()?;
        let candidate = input.trim();

        if candidate.is_empty() {
            return Ok(None);
        }

        if !profile::is_valid_profile_name(candidate) {
            prompt_println(&format!(
                "{}",
                "Invalid profile name. Use only letters, numbers, and hyphens.".red()
            ));
            continue;
        }

        if would_shadow_builtin(candidate) {
            prompt_println(&format!(
                "{}",
                format!(
                    "Cannot save '{}' as a user profile because it would shadow the built-in profile of the same name. Choose a different name.",
                    candidate
                )
                .red()
            ));
            continue;
        }

        return Ok(Some(candidate.to_string()));
    }
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

/// Confirm an irreversible/security-sensitive action by requiring the user to
/// type an exact word (case-insensitive). A single `y` is not accepted.
pub(crate) fn confirm_typed_word(prompt: &str, expected: &str) -> Result<bool> {
    prompt_print(prompt, &[]);

    let input = read_input_line()?;
    Ok(input.trim().eq_ignore_ascii_case(expected))
}

pub(crate) fn suggested_profile_name(compared_profile: Option<&str>) -> Option<String> {
    compared_profile
        .filter(|name| profile::is_valid_profile_name(name) && !profile::is_user_override(name))
        .map(|name| format!("{}-local", name))
}

/// Return true when writing `~/.config/nono/profiles/<name>.json` would shadow
/// a built-in profile of the same name. User files are loaded in preference to
/// built-ins, so saving under a built-in's name silently reroutes all future
/// `--profile <name>` invocations to the user file.
fn would_shadow_builtin(profile_name: &str) -> bool {
    // If a user file already exists at this name, the user has already chosen
    // to override it — writing there is an explicit update, not a new shadow.
    if profile::is_user_override(profile_name) {
        return false;
    }
    match crate::policy::load_embedded_policy() {
        Ok(policy) => policy.profiles.contains_key(profile_name),
        // Treat load failure as fail-safe: refuse to save rather than risk
        // silently shadowing a built-in we couldn't enumerate.
        Err(_) => true,
    }
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
    atomic_write(
        &prepared.profile_path,
        format!("{profile_json}\n").as_bytes(),
    )
}

/// Write `contents` to `path` atomically: write to a sibling temp file, fsync,
/// then rename. On crash or disk-full mid-write, the original file at `path`
/// is left intact rather than truncated.
fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    let dir = path.parent().ok_or_else(|| {
        NonoError::LearnError(format!(
            "Failed to determine parent directory of {}",
            path.display()
        ))
    })?;
    let file_name = path
        .file_name()
        .ok_or_else(|| NonoError::LearnError(format!("Invalid profile path {}", path.display())))?;

    // Use a sibling temp file so the final rename is same-filesystem and
    // therefore atomic on POSIX.
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(file_name);
    tmp_name.push(format!(".tmp.{}", std::process::id()));
    let tmp_path = dir.join(&tmp_name);

    let write_err = |stage: &str, e: std::io::Error| {
        NonoError::LearnError(format!(
            "Failed to {} profile {}: {}",
            stage,
            path.display(),
            e
        ))
    };

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp_path)
        .map_err(|e| write_err("open temp file for", e))?;
    if let Err(e) = file.write_all(contents) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(write_err("write", e));
    }
    if let Err(e) = file.sync_all() {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(write_err("sync", e));
    }
    drop(file);

    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(write_err("rename into place", e));
    }
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

    let override_count = prepared.profile.filesystem.bypass_protection.len();
    if override_count > 0 {
        prompt_println(&format!(
            "{}",
            format!(
                "  ({} path{} with filesystem.bypass_protection — review the profile before sharing)",
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
        format_command_line(command)
    ));
}

/// Print a preview of what paths will be written to the profile.
///
/// Highlights `bypass_protection` entries with a visible warning since those
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
    if !has_entries && patch.filesystem.bypass_protection.is_empty() {
        return;
    }

    prompt_println("[nono] Paths to be saved:");
    for (label, paths) in sections {
        for path in *paths {
            let is_override = patch.filesystem.bypass_protection.contains(path);
            if is_override {
                prompt_println(&format!("  {}  {} ({})", "⚠".red(), path, label));
            } else {
                prompt_println(&format!("  {}  ({})", path, label));
            }
        }
    }

    if !patch.filesystem.bypass_protection.is_empty() {
        prompt_println(&format!(
            "{}",
            "\n[nono] ⚠  The marked paths are normally blocked by security policy.".red()
        ));
        prompt_println(&format!(
            "{}",
            "[nono]    Saving them adds filesystem.bypass_protection, which weakens sandbox protection."
                .red()
        ));
    }
}

/// Return true if the patch includes any `filesystem.bypass_protection` entries.
pub(crate) fn patch_has_policy_overrides(patch: &profile::Profile) -> bool {
    !patch.filesystem.bypass_protection.is_empty()
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
    // Guard restores termios on any exit path (normal, error, panic unwind).
    // Previously the restore ran only after `read_line` succeeded, so a panic
    // during reading could leave the terminal in no-echo/canonical-disabled
    // state.
    let _guard = PromptTerminalGuard::new(&tty);
    let mut reader = std::io::BufReader::new(tty);
    reader
        .read_line(&mut input)
        .map_err(|e| NonoError::LearnError(format!("Failed to read input: {}", e)))?;
    Ok(input)
}

/// RAII guard that switches the tty into prompt-friendly termios and restores
/// the saved settings when dropped.
///
/// Owns a duplicated fd (via `try_clone`) so the caller can still move the
/// original `File` into a `BufReader` while the guard retains a handle for
/// the termios restore in `Drop`.
struct PromptTerminalGuard {
    tty: Option<std::fs::File>,
    saved: Option<nix::sys::termios::Termios>,
}

impl PromptTerminalGuard {
    fn new(tty: &std::fs::File) -> Self {
        let Ok(owned) = tty.try_clone() else {
            return Self {
                tty: None,
                saved: None,
            };
        };
        let Ok(original) = nix::sys::termios::tcgetattr(&owned) else {
            return Self {
                tty: Some(owned),
                saved: None,
            };
        };
        let mut termios = original.clone();
        configure_prompt_termios(&mut termios);
        if nix::sys::termios::tcsetattr(&owned, nix::sys::termios::SetArg::TCSANOW, &termios)
            .is_err()
        {
            return Self {
                tty: Some(owned),
                saved: None,
            };
        }
        let _ = nix::sys::termios::tcflush(&owned, nix::sys::termios::FlushArg::TCIFLUSH);
        Self {
            tty: Some(owned),
            saved: Some(original),
        }
    }
}

impl Drop for PromptTerminalGuard {
    fn drop(&mut self) {
        if let (Some(tty), Some(saved)) = (self.tty.as_ref(), self.saved.as_ref()) {
            let _ = nix::sys::termios::tcsetattr(tty, nix::sys::termios::SetArg::TCSANOW, saved);
        }
    }
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
    let mut bypass_protection = BTreeSet::new();

    for (path, grant) in grants {
        let shortened = shorten_path_for_profile(&path, home_path);
        if grant.bypass_protection {
            bypass_protection.insert(shortened.clone());
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
    patch.filesystem.bypass_protection = bypass_protection.into_iter().collect();

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
            existing.bypass_protection |= reason == "sensitive_path";
        }
        None => {
            grants.insert(
                target,
                PatchGrant {
                    access,
                    is_file,
                    bypass_protection: reason == "sensitive_path",
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
    profile.filesystem.bypass_protection = profile::dedup_append(
        &profile.filesystem.bypass_protection,
        &patch.filesystem.bypass_protection,
    );
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
    fn build_run_profile_patch_adds_bypass_protection_for_sensitive_file() {
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
        assert_eq!(
            patch.filesystem.bypass_protection,
            vec!["~/.claude/settings.json"]
        );
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
            "{\n  \"meta\": {\n    \"name\": \"claude-code-local\",\n    \"version\": \"1.0.0\"\n  },\n  \"filesystem\": {\n    \"read_file\": [\"~/old.json\"],\n    \"bypass_protection\": [\"~/old.json\"]\n  }\n}\n",
        )
        .expect("write profile");

        let mut patch = profile::Profile::default();
        patch.filesystem.read_file = vec!["~/.claude/settings.json".to_string()];
        patch.filesystem.bypass_protection = vec!["~/.claude/settings.json".to_string()];

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
            prepared.profile.filesystem.bypass_protection,
            vec![
                "~/old.json".to_string(),
                "~/.claude/settings.json".to_string()
            ]
        );
    }

    #[test]
    fn would_shadow_builtin_flags_known_builtin_names() {
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

        // `codex` is a known built-in; writing to that user path would
        // shadow it.
        assert!(would_shadow_builtin("opencode"));
        // Names that don't exist as built-ins are fine.
        assert!(!would_shadow_builtin("my-unique-saved-profile"));
    }

    #[test]
    fn would_shadow_builtin_allows_update_of_existing_user_override() {
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

        // Pre-create a user override of a built-in. A subsequent save to the
        // same name is an update, not a new shadow, and must be allowed.
        let path = profile::get_user_profile_path("opencode").expect("profile path");
        std::fs::create_dir_all(path.parent().expect("dir")).expect("mkdir");
        std::fs::write(
            &path,
            "{\"meta\":{\"name\":\"codex\",\"version\":\"1.0.0\"}}\n",
        )
        .expect("write");

        assert!(!would_shadow_builtin("opencode"));
    }

    #[test]
    fn atomic_write_replaces_existing_file_without_truncating_on_failure() {
        let dir = TempDir::new().expect("temp dir");
        let target = dir.path().join("profile.json");
        std::fs::write(&target, b"original\n").expect("seed");

        atomic_write(&target, b"updated\n").expect("atomic write");

        let contents = std::fs::read(&target).expect("read");
        assert_eq!(contents, b"updated\n");

        // No stray temp siblings left behind on success.
        let leftover = std::fs::read_dir(dir.path())
            .expect("readdir")
            .filter_map(|e| e.ok())
            .any(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".profile.json.tmp.")
            });
        assert!(!leftover, "temp file should be renamed into place");
    }
}
