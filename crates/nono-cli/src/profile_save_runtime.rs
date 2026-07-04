use crate::command_display::format_command_line;
use crate::diagnostic::{ErrorObservation, PolicyExplanation};
use crate::theme;
use crate::{profile, query_ext};
use colored::Colorize;
use nono::SandboxViolation;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProfileSaveChoice {
    Grant,
    Suppress,
    Skip,
}

// ─── Interactive denial selector types ────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ItemAction {
    Grant,
    Suppress,
    Skip,
}

impl ItemAction {
    fn cycle(self) -> Self {
        match self {
            Self::Grant => Self::Suppress,
            Self::Suppress => Self::Skip,
            Self::Skip => Self::Grant,
        }
    }

    fn padded_label(self) -> &'static str {
        match self {
            Self::Grant => "grant   ",
            Self::Suppress => "suppress",
            Self::Skip => "skip    ",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProfileSection {
    Allow,
    Read,
    Write,
    AllowFile,
    ReadFile,
    WriteFile,
    UnsafeSeatbelt,
}

impl ProfileSection {
    fn display_label(self) -> &'static str {
        match self {
            Self::Allow => "read+write dirs",
            Self::Read => "read dirs",
            Self::Write => "write dirs",
            Self::AllowFile => "read+write files",
            Self::ReadFile => "read files",
            Self::WriteFile => "write files",
            Self::UnsafeSeatbelt => "unsafe seatbelt rule",
        }
    }
}

#[derive(Clone, Debug)]
struct DenialItem {
    path: String,
    section: ProfileSection,
    is_bypass: bool,
    action: ItemAction,
}

const DENIAL_SELECTOR_MAX_VISIBLE_ITEMS: usize = 15;

fn denial_selector_visible_range(
    item_count: usize,
    cursor: usize,
    max_visible: usize,
) -> (usize, usize) {
    if item_count <= max_visible || max_visible == 0 {
        return (0, item_count);
    }

    let half_window = max_visible / 2;
    let start = if cursor < half_window {
        0
    } else if cursor + half_window >= item_count {
        item_count - max_visible
    } else {
        cursor - half_window
    };

    (start, start + max_visible)
}

fn extract_denial_items(patch: &profile::Profile) -> Vec<DenialItem> {
    let mut items = Vec::new();
    let fs = &patch.filesystem;

    let sections: &[(&[String], ProfileSection)] = &[
        (&fs.allow, ProfileSection::Allow),
        (&fs.read, ProfileSection::Read),
        (&fs.write, ProfileSection::Write),
        (&fs.allow_file, ProfileSection::AllowFile),
        (&fs.read_file, ProfileSection::ReadFile),
        (&fs.write_file, ProfileSection::WriteFile),
    ];

    for (paths, section) in sections {
        for path in *paths {
            let is_bypass = fs.bypass_protection.contains(path);
            items.push(DenialItem {
                path: path.clone(),
                section: *section,
                is_bypass,
                action: ItemAction::Grant,
            });
        }
    }

    for rule in &patch.unsafe_macos_seatbelt_rules {
        items.push(DenialItem {
            path: rule.clone(),
            section: ProfileSection::UnsafeSeatbelt,
            is_bypass: false,
            action: ItemAction::Grant,
        });
    }

    items
}

/// Env var that suppresses the "save denied paths as user profile?"
/// prompt entirely. Set by integration tests and CI runs that have an
/// openable `/dev/tty` (so `terminal_prompts_available` would otherwise
/// return true) but no human to answer. Mirrors the `NONO_NO_MIGRATE`
/// escape hatch on the migration prompt.
const ENV_NO_SAVE_PROMPT: &str = "NONO_NO_SAVE_PROMPT";
const USER_PREFERENCES_SEATBELT_RULE: &str = "(allow user-preference-read)";

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
    sandbox_violations: &[SandboxViolation],
    ignored_denial_paths: &[PathBuf],
) -> Result<()> {
    if !terminal_prompts_available() {
        return Ok(());
    }

    let Some(patch) = build_run_profile_patch(
        policy_explanations,
        error_observation,
        caps,
        sandbox_violations,
        ignored_denial_paths,
    )?
    else {
        return Ok(());
    };

    let cmd_name = command_name(command)?;

    // Try the interactive selector first; fall back to the text prompt when
    // raw mode is unavailable (e.g. a dumb terminal or a redirected TTY).
    match interactive_denial_selector(&patch)? {
        Some(items) => {
            let Some(combined_patch) = build_combined_patch_from_items(&items) else {
                return Ok(());
            };
            offer_save_with_patch(&combined_patch, &cmd_name, command, compared_profile)
        }
        None => offer_save_text_prompt(&patch, &cmd_name, command, compared_profile),
    }
}

fn offer_save_with_patch(
    patch: &profile::Profile,
    cmd_name: &str,
    command: &[String],
    compared_profile: Option<&str>,
) -> Result<()> {
    let has_overrides = patch_has_policy_overrides(patch);
    if has_overrides
        && !confirm_typed_word(
            "Granting the shown entries includes policy overrides. Type 'override' to confirm: ",
            "override",
        )?
    {
        return Ok(());
    }

    let has_suppressions = !patch.filesystem.suppress_save_prompt.is_empty();

    if let Some(existing_profile) = compared_profile
        .filter(|name| profile::is_valid_profile_name(name) && profile::is_user_override(name))
    {
        let prepared =
            prepare_profile_save_from_patch(patch, cmd_name, existing_profile, compared_profile)?;
        write_profile(&prepared)?;
        print_profile_save(&prepared, command);
        if has_suppressions {
            print_suppression_save_note(patch);
        }
        return Ok(());
    }

    let suggested = suggested_run_profile_name(compared_profile, cmd_name);
    let Some(profile_name) = prompt_profile_name(suggested.as_deref())? else {
        return Ok(());
    };

    let prepared =
        prepare_profile_save_from_patch(patch, cmd_name, &profile_name, compared_profile)?;
    write_profile(&prepared)?;
    print_profile_save(&prepared, command);
    if has_suppressions {
        print_suppression_save_note(patch);
    }

    Ok(())
}

fn offer_save_text_prompt(
    patch: &profile::Profile,
    cmd_name: &str,
    command: &[String],
    compared_profile: Option<&str>,
) -> Result<()> {
    let has_overrides = patch_has_policy_overrides(patch);
    let suppress_patch = build_suppress_save_prompt_patch(patch);
    let _prompt_terminal = prepare_prompt_terminal();

    prompt_println("");
    print_patch_preview(patch);

    if let Some(existing_profile) = compared_profile
        .filter(|name| profile::is_valid_profile_name(name) && profile::is_user_override(name))
    {
        let choice = prompt_profile_save_choice(Some(existing_profile), suppress_patch.is_some())?;
        let Some(selected_patch) =
            selected_profile_save_patch(choice, patch, suppress_patch.as_ref(), has_overrides)?
        else {
            return Ok(());
        };

        let prepared = prepare_profile_save_from_patch(
            selected_patch,
            cmd_name,
            existing_profile,
            compared_profile,
        )?;
        write_profile(&prepared)?;
        print_profile_save(&prepared, command);
        if choice == ProfileSaveChoice::Suppress {
            print_suppression_save_note(selected_patch);
        }
        return Ok(());
    }

    let choice = prompt_profile_save_choice(None, suppress_patch.is_some())?;
    let Some(selected_patch) =
        selected_profile_save_patch(choice, patch, suppress_patch.as_ref(), has_overrides)?
    else {
        return Ok(());
    };

    let suggested = suggested_run_profile_name(compared_profile, cmd_name);
    let Some(profile_name) = prompt_profile_name(suggested.as_deref())? else {
        return Ok(());
    };

    let prepared =
        prepare_profile_save_from_patch(selected_patch, cmd_name, &profile_name, compared_profile)?;
    write_profile(&prepared)?;
    print_profile_save(&prepared, command);
    if choice == ProfileSaveChoice::Suppress {
        print_suppression_save_note(selected_patch);
    }

    Ok(())
}

fn selected_profile_save_patch<'a>(
    choice: ProfileSaveChoice,
    grant_patch: &'a profile::Profile,
    suppress_patch: Option<&'a profile::Profile>,
    has_overrides: bool,
) -> Result<Option<&'a profile::Profile>> {
    match choice {
        ProfileSaveChoice::Grant => {
            if has_overrides
                && !confirm_typed_word(
                    "Granting the shown entries includes policy overrides. Type 'override' to confirm: ",
                    "override",
                )?
            {
                return Ok(None);
            }
            Ok(Some(grant_patch))
        }
        ProfileSaveChoice::Suppress => Ok(suppress_patch),
        ProfileSaveChoice::Skip => Ok(None),
    }
}

/// Prompt for a new profile name, re-prompting on invalid or shadowed names
/// until the user enters a valid name. When a suggestion exists, Enter accepts
/// it; otherwise a typed name is required.
///
/// Returns `Ok(None)` only when the user explicitly types `skip`.
fn prompt_profile_name(suggested: Option<&str>) -> Result<Option<String>> {
    let mut first = true;
    loop {
        let prompt = if first {
            if let Some(suggested_name) = suggested {
                format!("User profile name [{}]: ", suggested_name)
            } else {
                "User profile name: ".to_string()
            }
        } else {
            match suggested {
                Some(suggested_name) => format!("Enter a name [{}]: ", suggested_name),
                None => "Enter a name: ".to_string(),
            }
        };
        prompt_print(&prompt, &[]);

        if first {
            first = false;
        }

        let input = read_input_line()?;
        let candidate = input.trim();

        if candidate.is_empty() {
            if let Some(suggested_name) = suggested {
                if !would_shadow_existing_profile(suggested_name) {
                    return Ok(Some(suggested_name.to_string()));
                }
                // The suggestion itself would shadow an existing profile
                // (possible if pack data changed since the suggestion was
                // generated). Require the user to enter a different name.
                prompt_println(&format!(
                    "{}",
                    format!(
                        "The suggested name '{}' would shadow an existing built-in or pack profile. Enter a different name, or type 'skip' to cancel.",
                        suggested_name
                    )
                    .red()
                ));
                continue;
            }
            prompt_println(&format!(
                "{}",
                "Profile name required. Type a name, or type 'skip' to cancel.".red()
            ));
            continue;
        }

        if candidate.eq_ignore_ascii_case("skip") {
            return Ok(None);
        }

        if !profile::is_valid_profile_name(candidate) {
            prompt_println(&format!(
                "{}",
                "Invalid profile name. Use only letters, numbers, and hyphens.".red()
            ));
            continue;
        }

        if would_shadow_existing_profile(candidate) {
            prompt_println(&format!(
                "{}",
                format!(
                    "Cannot save '{}' as a user profile because it would shadow an existing built-in or pack profile of the same name. Choose a different name.",
                    candidate
                )
                .red()
            ));
            continue;
        }

        return Ok(Some(candidate.to_string()));
    }
}

fn prompt_profile_save_choice(
    existing_profile: Option<&str>,
    can_suppress: bool,
) -> Result<ProfileSaveChoice> {
    loop {
        let prompt = match (existing_profile, can_suppress) {
            (Some(name), true) => format!(
                "Update user profile '{}' with suggestions? [g] grant / [s] suppress / [Enter] skip: ",
                name
            ),
            (Some(name), false) => format!(
                "Update existing user profile '{}' with the shown rules? [g] save / [Enter] skip: ",
                name
            ),
            (None, true) => {
                "Save suggestions to a user profile? [g] grant / [s] suppress / [Enter] skip: "
                    .to_string()
            }
            (None, false) => {
                "Save the shown rules in a user profile? [g] save / [Enter] skip: ".to_string()
            }
        };

        prompt_print(&prompt, &[]);

        let input = read_input_line()?;
        if let Some(choice) = parse_profile_save_choice(&input, can_suppress) {
            return Ok(choice);
        }

        let help = if can_suppress {
            "Enter g to grant, s to suppress, or press Enter to skip."
        } else {
            "Enter g to save, or press Enter to skip."
        };
        prompt_println(&format!("{}", help.red()));
    }
}

fn parse_profile_save_choice(input: &str, can_suppress: bool) -> Option<ProfileSaveChoice> {
    let normalized = input.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "" | "n" | "no" | "skip" => Some(ProfileSaveChoice::Skip),
        "g" | "grant" | "y" | "yes" | "save" => Some(ProfileSaveChoice::Grant),
        "s" | "suppress" | "suppress-save-prompt" | "no-nag" | "no_nag" | "nonag"
            if can_suppress =>
        {
            Some(ProfileSaveChoice::Suppress)
        }
        _ => None,
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
    let candidate = compared_profile
        .filter(|name| profile::is_valid_profile_name(name) && !profile::is_user_override(name))
        .map(|name| format!("{}-local", name))?;
    if would_shadow_existing_profile(&candidate) {
        return None;
    }
    Some(candidate)
}

fn suggested_run_profile_name(compared_profile: Option<&str>, cmd_name: &str) -> Option<String> {
    if let Some(name) = suggested_profile_name(compared_profile) {
        return Some(name);
    }

    let candidate = profile_name_from_command(cmd_name)?;
    if would_shadow_existing_profile(&candidate) {
        return None;
    }

    Some(candidate)
}

fn profile_name_from_command(cmd_name: &str) -> Option<String> {
    let mut out = String::with_capacity(cmd_name.len());
    let mut last_was_hyphen = false;

    for ch in cmd_name.chars() {
        let mapped = if ch.is_ascii_alphanumeric() {
            Some(ch.to_ascii_lowercase())
        } else if ch == '-' || ch == '_' || ch == '.' {
            Some('-')
        } else {
            None
        };

        if let Some(ch) = mapped {
            if ch == '-' {
                if out.is_empty() || last_was_hyphen {
                    continue;
                }
                last_was_hyphen = true;
            } else {
                last_was_hyphen = false;
            }
            out.push(ch);
        }
    }

    while out.ends_with('-') {
        out.pop();
    }

    if profile::is_valid_profile_name(&out) {
        Some(out)
    } else {
        None
    }
}

/// Return true when writing `$XDG_CONFIG_HOME/nono/profiles/<name>.json` would shadow
/// a built-in or installed pack profile of the same name. User files are loaded
/// in preference to built-ins and pack-store profiles, so saving under an
/// existing profile's name silently reroutes all future `--profile <name>`
/// invocations to the user file and intercepts any `"extends": "<name>"` chains.
pub(crate) fn would_shadow_existing_profile(profile_name: &str) -> bool {
    // If a user file already exists at this name, the user has already chosen
    // to override it — writing there is an explicit update, not a new shadow.
    if profile::is_user_override(profile_name) {
        return false;
    }
    // Only block names that match embedded built-ins. Pack profiles are
    // referenced by their full `org/name` key (e.g. `always-further/hermes`),
    // which is an invalid profile name, so a short user profile name like
    // `hermes` cannot shadow a pack profile.
    crate::policy::load_embedded_policy()
        .map(|policy| policy.profiles.contains_key(profile_name))
        .unwrap_or(true)
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
                "  ({} path{} with filesystem.bypass_protection - review the profile before sharing)",
                override_count,
                if override_count == 1 { "" } else { "s" }
            )
            .yellow()
        ));
    }
    let unsafe_rule_count = prepared.profile.unsafe_macos_seatbelt_rules.len()
        + prepared
            .profile
            .command_policies
            .as_ref()
            .map_or(0, |policies| {
                crate::command_policy::nested_unsafe_seatbelt_rules(policies).len()
            });
    if unsafe_rule_count > 0 {
        prompt_println(&format!(
            "{}",
            format!(
                "  ({} raw macOS Seatbelt rule{} via unsafe_macos_seatbelt_rules - review the profile before sharing)",
                unsafe_rule_count,
                if unsafe_rule_count == 1 { "" } else { "s" }
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

fn print_suppression_save_note(patch: &profile::Profile) {
    let count = patch.filesystem.suppress_save_prompt.len();
    if count == 0 {
        return;
    }

    prompt_println(&format!(
        "  ({} path suggestion{} suppressed; access is still denied)",
        count,
        if count == 1 { "" } else { "s" }
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

    let nested_unsafe_rules = patch
        .command_policies
        .as_ref()
        .map(crate::command_policy::nested_unsafe_seatbelt_rules)
        .unwrap_or_default();

    let has_entries = sections.iter().any(|(_, paths)| !paths.is_empty());
    let has_unsafe_rules =
        !patch.unsafe_macos_seatbelt_rules.is_empty() || !nested_unsafe_rules.is_empty();
    if !has_entries && patch.filesystem.bypass_protection.is_empty() && !has_unsafe_rules {
        return;
    }

    if has_entries {
        let t = theme::current();
        prompt_println(&format!(
            "{}",
            theme::fg("[nono] Paths to be saved as grants:", t.brand).bold()
        ));
        for (label, paths) in sections {
            for path in *paths {
                let is_override = patch.filesystem.bypass_protection.contains(path);
                if is_override {
                    prompt_println(&format!(
                        "  {}  {} ({})",
                        "⚠".red(),
                        theme::fg(path, t.text).bold(),
                        label
                    ));
                } else {
                    prompt_println(&format!(
                        "  {}  ({})",
                        theme::fg(path, t.text).bold(),
                        label
                    ));
                }
            }
        }
        prompt_println("");
        prompt_println(
            "[nono] Choose suppress to keep denying all listed paths and stop future save suggestions.",
        );
        prompt_println("[nono] CLI equivalent for one path: --suppress-save-prompt PATH");
    }

    if has_unsafe_rules {
        if has_entries {
            prompt_println("");
        }
        prompt_println("[nono] Unsafe macOS Seatbelt rules to be saved:");
        for rule in &patch.unsafe_macos_seatbelt_rules {
            prompt_println(&format!(
                "  {}  {}  (unsafe_macos_seatbelt_rules)",
                "⚠".red(),
                rule
            ));
        }
        for (location, rule) in &nested_unsafe_rules {
            prompt_println(&format!("  {}  {}  ({location})", "⚠".red(), rule));
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

    if has_unsafe_rules {
        prompt_println(&format!(
            "{}",
            "\n[nono] ⚠  The marked rules are raw macOS Seatbelt policy.".red()
        ));
        prompt_println(&format!(
            "{}",
            "[nono]    Saving them adds unsafe_macos_seatbelt_rules, which bypasses nono's capability model and can weaken sandbox protection."
                .red()
        ));
    }
}

/// Return true if the patch includes entries that bypass normal capability policy.
pub(crate) fn patch_has_policy_overrides(patch: &profile::Profile) -> bool {
    !patch.filesystem.bypass_protection.is_empty()
        || !patch.unsafe_macos_seatbelt_rules.is_empty()
        || patch.command_policies.as_ref().is_some_and(|policies| {
            !crate::command_policy::nested_unsafe_seatbelt_rules(policies).is_empty()
        })
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

fn prepare_prompt_terminal() -> Option<PromptTerminalGuard> {
    open_tty_prompt_device()
        .ok()
        .map(|tty| PromptTerminalGuard::new(&tty))
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

// ─── Raw terminal mode for interactive selector ───────────────────────────

enum Key {
    Up,
    Down,
    Space,
    Enter,
    CtrlC,
    Char(char),
}

struct RawTtyGuard {
    tty: std::fs::File,
    saved: nix::sys::termios::Termios,
}

impl RawTtyGuard {
    fn open() -> Result<Self> {
        let tty = open_tty_prompt_device()?;
        let saved = nix::sys::termios::tcgetattr(&tty)
            .map_err(|e| NonoError::LearnError(format!("tcgetattr: {e}")))?;
        let mut raw = saved.clone();
        configure_raw_termios(&mut raw);
        nix::sys::termios::tcsetattr(&tty, nix::sys::termios::SetArg::TCSANOW, &raw)
            .map_err(|e| NonoError::LearnError(format!("tcsetattr: {e}")))?;
        Ok(Self { tty, saved })
    }

    fn read_key(&mut self) -> Result<Key> {
        use std::io::Read;
        let mut buf = [0u8; 1];
        self.tty
            .read_exact(&mut buf)
            .map_err(|e| NonoError::LearnError(format!("tty read: {e}")))?;
        match buf[0] {
            0x1b => {
                // Switch to short-timeout non-blocking to detect escape sequences
                self.set_vmin_vtime(0, 1)?;
                let key = self.try_read_escape_sequence();
                let _ = self.set_vmin_vtime(1, 0);
                key
            }
            b' ' => Ok(Key::Space),
            b'\r' | b'\n' => Ok(Key::Enter),
            0x03 => Ok(Key::CtrlC),
            c => Ok(Key::Char(c as char)),
        }
    }

    fn try_read_escape_sequence(&mut self) -> Result<Key> {
        use std::io::Read;
        let mut buf = [0u8; 1];
        if self.tty.read(&mut buf).unwrap_or(0) == 0 {
            return Ok(Key::Char('\x1b'));
        }
        if buf[0] != b'[' {
            return Ok(Key::Char('\x1b'));
        }
        if self.tty.read(&mut buf).unwrap_or(0) == 0 {
            return Ok(Key::Char('\x1b'));
        }
        Ok(match buf[0] {
            b'A' => Key::Up,
            b'B' => Key::Down,
            _ => Key::Char('\x1b'),
        })
    }

    fn set_vmin_vtime(&self, vmin: u8, vtime: u8) -> Result<()> {
        use nix::sys::termios::SpecialCharacterIndices;
        let mut t = nix::sys::termios::tcgetattr(&self.tty)
            .map_err(|e| NonoError::LearnError(format!("tcgetattr: {e}")))?;
        t.control_chars[SpecialCharacterIndices::VMIN as usize] = vmin;
        t.control_chars[SpecialCharacterIndices::VTIME as usize] = vtime;
        nix::sys::termios::tcsetattr(&self.tty, nix::sys::termios::SetArg::TCSANOW, &t)
            .map_err(|e| NonoError::LearnError(format!("tcsetattr: {e}")))?;
        Ok(())
    }
}

impl Drop for RawTtyGuard {
    fn drop(&mut self) {
        let _ = write!(self.tty, "\x1b[?25h"); // restore cursor visibility
        let _ = self.tty.flush();
        let _ = nix::sys::termios::tcsetattr(
            &self.tty,
            nix::sys::termios::SetArg::TCSANOW,
            &self.saved,
        );
    }
}

fn configure_raw_termios(t: &mut nix::sys::termios::Termios) {
    use nix::sys::termios::{InputFlags, LocalFlags, SpecialCharacterIndices};
    t.local_flags
        .remove(LocalFlags::ICANON | LocalFlags::ECHO | LocalFlags::ECHONL | LocalFlags::ISIG);
    t.input_flags.remove(InputFlags::ICRNL | InputFlags::IXON);
    t.control_chars[SpecialCharacterIndices::VMIN as usize] = 1;
    t.control_chars[SpecialCharacterIndices::VTIME as usize] = 0;
}

// ─── Interactive selector rendering ───────────────────────────────────────

fn render_denial_selector(
    tty: &mut std::fs::File,
    items: &[DenialItem],
    cursor: usize,
    line_count: &mut usize,
    first_render: bool,
) -> Result<()> {
    if !first_render && *line_count > 0 {
        write!(tty, "\x1b[{}A", line_count)
            .map_err(|e| NonoError::LearnError(format!("tty write: {e}")))?;
    }

    let t = theme::current();
    let mut n = 0usize;

    macro_rules! tty_ln {
        ($($arg:tt)*) => {{
            write!(tty, "\r{}\x1b[K\r\n", format!($($arg)*))
                .map_err(|e| NonoError::LearnError(format!("tty write: {e}")))?;
            n += 1;
        }};
    }

    // Limit visible rows to prevent the list from exceeding the terminal
    // height. When the list is taller than the viewport the cursor-up escape
    // sequence is capped at the top of the screen, which corrupts the UI and
    // erases prior terminal history on subsequent redraws.
    let (start, end) =
        denial_selector_visible_range(items.len(), cursor, DENIAL_SELECTOR_MAX_VISIBLE_ITEMS);

    if items.len() > DENIAL_SELECTOR_MAX_VISIBLE_ITEMS {
        tty_ln!(
            "{}  {}",
            theme::fg(" [nono] Review denied paths", t.brand).bold(),
            theme::fg(
                &format!("({}-{} of {})", start + 1, end, items.len()),
                t.subtext
            )
        );
    } else {
        tty_ln!(
            "{}",
            theme::fg(" [nono] Review denied paths", t.brand).bold()
        );
    }
    tty_ln!(
        "  {}",
        "↑/↓ move  ·  Space cycle  ·  a grant-all  ·  d deny-all  ·  Enter confirm  ·  Esc cancel"
            .dimmed()
    );
    tty_ln!("");

    for (offset, item) in items[start..end].iter().enumerate() {
        let i = start + offset;
        let selected = i == cursor;

        let cursor_glyph = if selected {
            format!("{}", theme::fg("▶", t.brand))
        } else {
            " ".to_string()
        };

        let action_str = match item.action {
            ItemAction::Grant => {
                format!("{}", theme::fg(item.action.padded_label(), t.green).bold())
            }
            ItemAction::Suppress => {
                format!("{}", theme::fg(item.action.padded_label(), t.yellow))
            }
            ItemAction::Skip => {
                format!("{}", theme::fg(item.action.padded_label(), t.overlay))
            }
        };

        let bypass_prefix = if item.is_bypass {
            format!("{} ", "⚠".red())
        } else {
            String::new()
        };

        let path_str = if selected {
            format!("{}", theme::fg(&item.path, t.text).bold())
        } else {
            format!("{}", theme::fg(&item.path, t.subtext))
        };

        let label_str = format!("  ({})", theme::fg(item.section.display_label(), t.overlay));

        tty_ln!(
            "  {}  {}  {}{}{}",
            cursor_glyph,
            action_str,
            bypass_prefix,
            path_str,
            label_str
        );
    }

    tty_ln!("");
    *line_count = n;

    tty.flush()
        .map_err(|e| NonoError::LearnError(format!("tty flush: {e}")))?;
    Ok(())
}

fn erase_selector(tty: &mut std::fs::File, line_count: usize) -> Result<()> {
    if line_count == 0 {
        return Ok(());
    }
    write!(tty, "\x1b[{}A", line_count)
        .map_err(|e| NonoError::LearnError(format!("tty write: {e}")))?;
    for _ in 0..line_count {
        write!(tty, "\x1b[2K\r\n").map_err(|e| NonoError::LearnError(format!("tty write: {e}")))?;
    }
    write!(tty, "\x1b[{}A", line_count)
        .map_err(|e| NonoError::LearnError(format!("tty write: {e}")))?;
    tty.flush()
        .map_err(|e| NonoError::LearnError(format!("tty flush: {e}")))?;
    Ok(())
}

/// Run the keyboard-driven per-path denial selector.
///
/// Returns `None` when raw mode cannot be established (caller should fall back
/// to the text-based prompt). Returns `Some(items)` with the user's per-item
/// decisions when the interactive session completes.
fn interactive_denial_selector(patch: &profile::Profile) -> Result<Option<Vec<DenialItem>>> {
    let mut items = extract_denial_items(patch);
    if items.is_empty() {
        return Ok(Some(items));
    }

    let mut raw = match RawTtyGuard::open() {
        Ok(guard) => guard,
        Err(_) => return Ok(None),
    };

    write!(raw.tty, "\x1b[?25l") // hide cursor during interaction
        .map_err(|e| NonoError::LearnError(format!("tty write: {e}")))?;

    let mut cursor: usize = 0;
    let mut line_count: usize = 0;
    let mut first_render = true;

    loop {
        render_denial_selector(&mut raw.tty, &items, cursor, &mut line_count, first_render)?;
        first_render = false;

        match raw.read_key()? {
            Key::Up => {
                cursor = cursor.saturating_sub(1);
            }
            Key::Down => {
                if cursor + 1 < items.len() {
                    cursor += 1;
                }
            }
            Key::Space => {
                let next = items[cursor].action.cycle();
                // UnsafeSeatbelt items have no suppress mechanism — skip that state
                items[cursor].action = if items[cursor].section == ProfileSection::UnsafeSeatbelt
                    && next == ItemAction::Suppress
                {
                    next.cycle()
                } else {
                    next
                };
            }
            Key::Char('a') => {
                for item in &mut items {
                    item.action = ItemAction::Grant;
                }
            }
            Key::Char('d') => {
                for item in &mut items {
                    item.action = if item.section == ProfileSection::UnsafeSeatbelt {
                        ItemAction::Skip
                    } else {
                        ItemAction::Suppress
                    };
                }
            }
            Key::Enter => break,
            Key::CtrlC | Key::Char('\x1b') => {
                for item in &mut items {
                    item.action = ItemAction::Skip;
                }
                break;
            }
            Key::Char(_) => {}
        }
    }

    erase_selector(&mut raw.tty, line_count)?;
    Ok(Some(items))
}

// ─── Build patch from per-item decisions ──────────────────────────────────

fn build_combined_patch_from_items(items: &[DenialItem]) -> Option<profile::Profile> {
    let has_grants = items.iter().any(|i| i.action == ItemAction::Grant);
    let has_suppresses = items
        .iter()
        .any(|i| i.action == ItemAction::Suppress && i.section != ProfileSection::UnsafeSeatbelt);

    if !has_grants && !has_suppresses {
        return None;
    }

    let mut patch = profile::Profile::default();

    for item in items {
        match item.action {
            ItemAction::Grant => {
                match item.section {
                    ProfileSection::Allow => patch.filesystem.allow.push(item.path.clone()),
                    ProfileSection::Read => patch.filesystem.read.push(item.path.clone()),
                    ProfileSection::Write => patch.filesystem.write.push(item.path.clone()),
                    ProfileSection::AllowFile => {
                        patch.filesystem.allow_file.push(item.path.clone())
                    }
                    ProfileSection::ReadFile => patch.filesystem.read_file.push(item.path.clone()),
                    ProfileSection::WriteFile => {
                        patch.filesystem.write_file.push(item.path.clone())
                    }
                    ProfileSection::UnsafeSeatbelt => {
                        patch.unsafe_macos_seatbelt_rules.push(item.path.clone())
                    }
                }
                if item.is_bypass && !patch.filesystem.bypass_protection.contains(&item.path) {
                    patch.filesystem.bypass_protection.push(item.path.clone());
                }
            }
            ItemAction::Suppress => {
                if item.section != ProfileSection::UnsafeSeatbelt {
                    patch
                        .filesystem
                        .suppress_save_prompt
                        .push(item.path.clone());
                }
            }
            ItemAction::Skip => {}
        }
    }

    Some(patch)
}

fn prompt_write(message: &str) {
    if let Some(mut tty) = open_tty_writer() {
        let _ = write!(tty, "{}", prompt_inline_for_tty(message));
        let _ = tty.flush();
        return;
    }

    eprint!("{}", message);
    let _ = std::io::stderr().flush();
}

fn prompt_writeln(message: &str) {
    if let Some(mut tty) = open_tty_writer() {
        let _ = write!(tty, "{}", prompt_line_for_tty(message));
        let _ = tty.flush();
        return;
    }

    eprint!("{}", prompt_line(message));
    let _ = std::io::stderr().flush();
}

fn prompt_line(message: &str) -> String {
    format!("{message}\r\n")
}

fn prompt_inline_for_tty(message: &str) -> String {
    format!("\r{message}\x1b[K")
}

fn prompt_line_for_tty(message: &str) -> String {
    format!("\r{message}\x1b[K\r\n")
}

pub(crate) fn prepare_profile_save_from_patch(
    patch: &profile::Profile,
    cmd_name: &str,
    profile_name: &str,
    compared_profile: Option<&str>,
) -> Result<PreparedProfileSave> {
    let profile_path = profile::resolve_user_profile_path(profile_name)?;

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

    let profile_path = profile::get_user_profile_path(profile_name)?;
    let mut new_profile = patch.clone();
    let extends = compared_profile
        .filter(|name| {
            (profile::is_valid_profile_name(name) || profile::is_registry_ref(name))
                && *name != profile_name
        })
        .map(|name| vec![name.to_string()]);
    let has_base = extends.is_some();
    let suppression_only = patch_is_suppression_only(patch);
    new_profile.extends = extends;
    new_profile.meta = profile::ProfileMeta {
        name: profile_name.to_string(),
        version: "1.0.0".to_string(),
        description: Some(if suppression_only {
            format!(
                "Runtime-discovered save-prompt suppressions for {}",
                cmd_name
            )
        } else if has_base {
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
    sandbox_violations: &[SandboxViolation],
    ignored_denial_paths: &[PathBuf],
) -> Result<Option<profile::Profile>> {
    let mut grants: BTreeMap<PathBuf, PatchGrant> = BTreeMap::new();

    for explanation in policy_explanations {
        add_patch_grant(
            &mut grants,
            &explanation.path,
            explanation.access,
            &explanation.reason,
            ignored_denial_paths,
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
                add_patch_grant(
                    &mut grants,
                    &hint.path,
                    hint.access,
                    &reason,
                    ignored_denial_paths,
                );
            }
            _ => {}
        }
    }

    let unsafe_rules = unsafe_seatbelt_rules_from_sandbox_violations(sandbox_violations);

    if grants.is_empty() && unsafe_rules.is_empty() {
        return Ok(None);
    }

    let mut allow = BTreeSet::new();
    let mut read = BTreeSet::new();
    let mut write = BTreeSet::new();
    let mut allow_file = BTreeSet::new();
    let mut read_file = BTreeSet::new();
    let mut write_file = BTreeSet::new();
    let mut bypass_protection = BTreeSet::new();

    if !grants.is_empty() {
        let home = crate::config::validated_home()?;
        let home_path = Path::new(&home);

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
    }

    let mut patch = profile::Profile::default();
    patch.filesystem.allow = allow.into_iter().collect();
    patch.filesystem.read = read.into_iter().collect();
    patch.filesystem.write = write.into_iter().collect();
    patch.filesystem.allow_file = allow_file.into_iter().collect();
    patch.filesystem.read_file = read_file.into_iter().collect();
    patch.filesystem.write_file = write_file.into_iter().collect();
    patch.filesystem.bypass_protection = bypass_protection.into_iter().collect();
    patch.unsafe_macos_seatbelt_rules = unsafe_rules.into_iter().collect();

    Ok(Some(patch))
}

fn patch_is_suppression_only(patch: &profile::Profile) -> bool {
    !patch.filesystem.suppress_save_prompt.is_empty()
        && patch.filesystem.allow.is_empty()
        && patch.filesystem.read.is_empty()
        && patch.filesystem.write.is_empty()
        && patch.filesystem.allow_file.is_empty()
        && patch.filesystem.read_file.is_empty()
        && patch.filesystem.write_file.is_empty()
        && patch.filesystem.bypass_protection.is_empty()
        && patch.unsafe_macos_seatbelt_rules.is_empty()
}

fn build_suppress_save_prompt_patch(grant_patch: &profile::Profile) -> Option<profile::Profile> {
    let paths = grant_patch_path_suggestions(grant_patch);
    if paths.is_empty() {
        return None;
    }

    let mut patch = profile::Profile::default();
    patch.filesystem.suppress_save_prompt = paths.into_iter().collect();
    Some(patch)
}

fn grant_patch_path_suggestions(patch: &profile::Profile) -> BTreeSet<String> {
    let sections = [
        &patch.filesystem.allow,
        &patch.filesystem.read,
        &patch.filesystem.write,
        &patch.filesystem.allow_file,
        &patch.filesystem.read_file,
        &patch.filesystem.write_file,
    ];

    sections
        .into_iter()
        .flat_map(|paths| paths.iter().cloned())
        .collect()
}

pub(crate) fn has_saveable_system_service_rules(violations: &[SandboxViolation]) -> bool {
    violations
        .iter()
        .any(is_user_preference_read_sandbox_violation)
}

fn unsafe_seatbelt_rules_from_sandbox_violations(
    violations: &[SandboxViolation],
) -> BTreeSet<String> {
    let mut rules = BTreeSet::new();
    if has_saveable_system_service_rules(violations) {
        rules.insert(USER_PREFERENCES_SEATBELT_RULE.to_string());
    }
    rules
}

fn is_user_preference_read_sandbox_violation(violation: &SandboxViolation) -> bool {
    violation.operation == "user-preference-read"
        && violation
            .target
            .as_deref()
            .is_some_and(|target| target.starts_with("kcfpreferences"))
}

fn add_patch_grant(
    grants: &mut BTreeMap<PathBuf, PatchGrant>,
    path: &Path,
    access: AccessMode,
    reason: &str,
    ignored_denial_paths: &[PathBuf],
) {
    let (flag, target) = query_ext::suggested_flag_parts(path, access);
    if !ignored_denial_paths.is_empty()
        && (matches_ignored_denial(path, ignored_denial_paths)
            || (target.as_path() != path && matches_ignored_denial(&target, ignored_denial_paths)))
    {
        return;
    }

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

fn matches_ignored_denial(path: &Path, ignored_denial_paths: &[PathBuf]) -> bool {
    if ignored_denial_paths.is_empty() {
        return false;
    }

    let canonical = nono::try_canonicalize(path);
    ignored_denial_paths
        .iter()
        .any(|ignored| canonical == *ignored || canonical.starts_with(ignored))
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
    profile.filesystem.suppress_save_prompt = profile::dedup_append(
        &profile.filesystem.suppress_save_prompt,
        &patch.filesystem.suppress_save_prompt,
    );
    profile.unsafe_macos_seatbelt_rules = profile::dedup_append(
        &profile.unsafe_macos_seatbelt_rules,
        &patch.unsafe_macos_seatbelt_rules,
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
    use crate::test_env::{ENV_LOCK, EnvVarGuard};
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
        };

        let patch = build_run_profile_patch(
            &[explanation],
            &ErrorObservation::default(),
            &CapabilitySet::new(),
            &[],
            &[],
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
        };
        let write = PolicyExplanation {
            path: target,
            access: AccessMode::Write,
            reason: "insufficient_access".to_string(),
        };

        let patch = build_run_profile_patch(
            &[read, write],
            &ErrorObservation::default(),
            &CapabilitySet::new(),
            &[],
            &[],
        )
        .expect("build patch")
        .expect("patch");

        assert_eq!(patch.filesystem.allow_file, vec!["~/config.json"]);
        assert!(patch.filesystem.read_file.is_empty());
        assert!(patch.filesystem.write_file.is_empty());
    }

    #[test]
    fn build_run_profile_patch_omits_ignored_denials() {
        let _env_lock = ENV_LOCK.lock().expect("env lock");
        let temp_home = TempDir::new().expect("temp home");
        let _env = EnvVarGuard::set_all(&[("HOME", temp_home.path().to_str().expect("home path"))]);

        let ignored = temp_home.path().join(".copilot").join("settings.json");
        let saved = temp_home.path().join(".copilot").join("config.json");
        std::fs::create_dir_all(saved.parent().expect("parent")).expect("mkdir");
        std::fs::write(&ignored, b"{}").expect("write ignored");
        std::fs::write(&saved, b"{}").expect("write saved");

        let ignored_explanation = PolicyExplanation {
            path: ignored.clone(),
            access: AccessMode::Read,
            reason: "path_not_granted".to_string(),
        };
        let saved_explanation = PolicyExplanation {
            path: saved,
            access: AccessMode::Read,
            reason: "path_not_granted".to_string(),
        };

        let patch = build_run_profile_patch(
            &[ignored_explanation, saved_explanation],
            &ErrorObservation::default(),
            &CapabilitySet::new(),
            &[],
            &[nono::try_canonicalize(&ignored)],
        )
        .expect("build patch")
        .expect("patch");

        assert_eq!(patch.filesystem.read_file, vec!["~/.copilot/config.json"]);
    }

    #[test]
    fn build_run_profile_patch_returns_none_when_all_denials_are_ignored() {
        let _env_lock = ENV_LOCK.lock().expect("env lock");
        let temp_home = TempDir::new().expect("temp home");
        let _env = EnvVarGuard::set_all(&[("HOME", temp_home.path().to_str().expect("home path"))]);

        let target = temp_home.path().join(".copilot").join("settings.json");
        std::fs::create_dir_all(target.parent().expect("parent")).expect("mkdir");
        std::fs::write(&target, b"{}").expect("write");

        let explanation = PolicyExplanation {
            path: target.clone(),
            access: AccessMode::Read,
            reason: "path_not_granted".to_string(),
        };

        let patch = build_run_profile_patch(
            &[explanation],
            &ErrorObservation::default(),
            &CapabilitySet::new(),
            &[],
            &[nono::try_canonicalize(&target)],
        )
        .expect("build patch");

        assert!(patch.is_none());
    }

    #[test]
    fn build_suppress_save_prompt_patch_collects_all_grant_paths() {
        let grant_patch = profile::Profile {
            filesystem: profile::FilesystemConfig {
                read: vec!["~/workspace".to_string()],
                read_file: vec!["~/.copilot/settings.json".to_string()],
                allow_file: vec!["~/.copilot/config.json".to_string()],
                bypass_protection: vec!["~/.copilot/settings.json".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        let suppress_patch =
            build_suppress_save_prompt_patch(&grant_patch).expect("suppression patch");

        assert_eq!(
            suppress_patch.filesystem.suppress_save_prompt,
            vec![
                "~/.copilot/config.json".to_string(),
                "~/.copilot/settings.json".to_string(),
                "~/workspace".to_string(),
            ]
        );
        assert!(suppress_patch.filesystem.read.is_empty());
        assert!(suppress_patch.filesystem.read_file.is_empty());
        assert!(suppress_patch.filesystem.bypass_protection.is_empty());
    }

    #[test]
    fn build_suppress_save_prompt_patch_ignores_unsafe_only_patch() {
        let grant_patch = profile::Profile {
            unsafe_macos_seatbelt_rules: vec![USER_PREFERENCES_SEATBELT_RULE.to_string()],
            ..Default::default()
        };

        assert!(build_suppress_save_prompt_patch(&grant_patch).is_none());
    }

    #[test]
    fn parse_profile_save_choice_supports_grant_suppress_and_skip() {
        assert_eq!(
            parse_profile_save_choice("g", true),
            Some(ProfileSaveChoice::Grant)
        );
        assert_eq!(
            parse_profile_save_choice("yes", true),
            Some(ProfileSaveChoice::Grant)
        );
        assert_eq!(
            parse_profile_save_choice("s", true),
            Some(ProfileSaveChoice::Suppress)
        );
        assert_eq!(
            parse_profile_save_choice("no-nag", true),
            Some(ProfileSaveChoice::Suppress)
        );
        assert_eq!(
            parse_profile_save_choice("", true),
            Some(ProfileSaveChoice::Skip)
        );
        assert_eq!(
            parse_profile_save_choice("no", true),
            Some(ProfileSaveChoice::Skip)
        );
        assert_eq!(parse_profile_save_choice("s", false), None);
    }

    #[test]
    fn build_run_profile_patch_adds_unsafe_rule_for_user_preferences_violation() {
        let violations = vec![SandboxViolation {
            operation: "user-preference-read".to_string(),
            target: Some("kcfpreferencesanyapplication".to_string()),
        }];

        let patch = build_run_profile_patch(
            &[],
            &ErrorObservation::default(),
            &CapabilitySet::new(),
            &violations,
            &[],
        )
        .expect("build patch")
        .expect("patch");

        assert_eq!(
            patch.unsafe_macos_seatbelt_rules,
            vec![USER_PREFERENCES_SEATBELT_RULE.to_string()]
        );
        assert!(patch.filesystem.allow.is_empty());
        assert!(patch.filesystem.read.is_empty());
        assert!(patch.filesystem.write.is_empty());
    }

    #[test]
    fn unsafe_macos_seatbelt_rules_count_as_policy_overrides() {
        let mut patch = profile::Profile::default();
        assert!(!patch_has_policy_overrides(&patch));

        patch.unsafe_macos_seatbelt_rules = vec![USER_PREFERENCES_SEATBELT_RULE.to_string()];

        assert!(patch_has_policy_overrides(&patch));
    }

    #[test]
    fn nested_unsafe_macos_seatbelt_rules_in_command_sandbox_count_as_policy_overrides() {
        use crate::command_policy::{
            CommandPoliciesConfig, CommandPolicyConfig, CommandSandboxConfig,
        };

        let patch = profile::Profile::default();
        assert!(!patch_has_policy_overrides(&patch));

        let mut policies = CommandPoliciesConfig::default();
        policies.commands.insert(
            "git".to_string(),
            CommandPolicyConfig {
                sandbox: Some(CommandSandboxConfig {
                    unsafe_macos_seatbelt_rules: vec!["(allow iokit-open)".to_string()],
                    ..CommandSandboxConfig::default()
                }),
                ..CommandPolicyConfig::default()
            },
        );
        let patch = profile::Profile {
            command_policies: Some(policies),
            ..patch
        };

        assert!(patch_has_policy_overrides(&patch));
    }

    #[test]
    fn nested_unsafe_macos_seatbelt_rules_in_intercept_sandbox_count_as_policy_overrides() {
        use crate::command_policy::{
            CommandPoliciesConfig, CommandPolicyConfig, CommandSandboxConfig,
            InterceptActionConfig, InterceptRuleConfig,
        };

        let mut policies = CommandPoliciesConfig::default();
        policies.commands.insert(
            "git".to_string(),
            CommandPolicyConfig {
                intercept: vec![InterceptRuleConfig {
                    args: vec!["push".to_string()],
                    action: InterceptActionConfig::Passthrough,
                    sandbox: Some(CommandSandboxConfig {
                        unsafe_macos_seatbelt_rules: vec!["(allow iokit-open)".to_string()],
                        ..CommandSandboxConfig::default()
                    }),
                }],
                ..CommandPolicyConfig::default()
            },
        );
        let patch = profile::Profile {
            command_policies: Some(policies),
            ..profile::Profile::default()
        };

        assert!(patch_has_policy_overrides(&patch));
    }

    #[test]
    fn suggested_run_profile_name_uses_compared_profile_when_available() {
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

        assert_eq!(
            suggested_run_profile_name(Some("claude-code"), "copilot"),
            Some("claude-code-local".to_string())
        );
    }

    #[test]
    fn suggested_run_profile_name_falls_back_to_command_name() {
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

        assert_eq!(
            suggested_run_profile_name(None, "copilot"),
            Some("copilot".to_string())
        );
        assert_eq!(
            suggested_run_profile_name(None, "GitHub.Copilot"),
            Some("github-copilot".to_string())
        );
    }

    #[test]
    fn suggested_run_profile_name_avoids_shadowing_builtin() {
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

        assert_eq!(suggested_run_profile_name(None, "openclaw"), None);
    }

    #[test]
    fn suggested_run_profile_name_allows_short_name_matching_pack_install_as() {
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

        // Set up a fake pack store with a profile named "hermes".
        let pack_dir = temp_config
            .path()
            .join("nono")
            .join("packages")
            .join("test-ns")
            .join("test-pack");
        std::fs::create_dir_all(pack_dir.join("profiles")).expect("mkdir pack");
        let manifest = r#"{
            "schema_version": 1,
            "name": "test-pack",
            "artifacts": [
                {"type": "profile", "path": "profiles/hermes.json", "install_as": "hermes"}
            ]
        }"#;
        std::fs::write(pack_dir.join("package.json"), manifest).expect("write manifest");
        std::fs::write(
            pack_dir.join("profiles").join("hermes.json"),
            "{\"meta\":{\"name\":\"hermes\",\"version\":\"1.0.0\"}}\n",
        )
        .expect("write pack profile");

        // "hermes" matches a pack install_as but is not a built-in, so
        // suggesting it directly as a profile name is valid.
        assert_eq!(
            suggested_run_profile_name(None, "hermes"),
            Some("hermes".to_string())
        );
    }

    #[test]
    fn prompt_line_uses_crlf_for_terminal_layout() {
        assert_eq!(
            prompt_line("[nono] Paths to be saved as grants:"),
            "[nono] Paths to be saved as grants:\r\n"
        );
        assert_eq!(prompt_line(""), "\r\n");
    }

    #[test]
    fn prompt_tty_rendering_clears_line_tails() {
        assert_eq!(
            prompt_line_for_tty("[nono] Paths to be saved as grants:"),
            "\r[nono] Paths to be saved as grants:\u{1b}[K\r\n"
        );
        assert_eq!(
            prompt_inline_for_tty("Update profile? [Y/n] "),
            "\rUpdate profile? [Y/n] \u{1b}[K"
        );
    }

    #[test]
    fn denial_selector_visible_range_keeps_short_lists_unscrolled() {
        assert_eq!(
            denial_selector_visible_range(10, 9, DENIAL_SELECTOR_MAX_VISIBLE_ITEMS),
            (0, 10)
        );
    }

    #[test]
    fn denial_selector_visible_range_centers_cursor_when_possible() {
        assert_eq!(
            denial_selector_visible_range(50, 25, DENIAL_SELECTOR_MAX_VISIBLE_ITEMS),
            (18, 33)
        );
    }

    #[test]
    fn denial_selector_visible_range_pins_to_top_and_bottom_edges() {
        assert_eq!(
            denial_selector_visible_range(50, 0, DENIAL_SELECTOR_MAX_VISIBLE_ITEMS),
            (0, 15)
        );
        assert_eq!(
            denial_selector_visible_range(50, 49, DENIAL_SELECTOR_MAX_VISIBLE_ITEMS),
            (35, 50)
        );
    }

    #[test]
    fn denial_selector_visible_range_handles_empty_lists() {
        assert_eq!(
            denial_selector_visible_range(0, 0, DENIAL_SELECTOR_MAX_VISIBLE_ITEMS),
            (0, 0)
        );
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
        patch.unsafe_macos_seatbelt_rules = vec![USER_PREFERENCES_SEATBELT_RULE.to_string()];

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
        assert_eq!(
            prepared.profile.unsafe_macos_seatbelt_rules,
            vec![USER_PREFERENCES_SEATBELT_RULE.to_string()]
        );
    }

    #[test]
    fn prepare_profile_save_from_suppression_patch_uses_suppression_description() {
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

        let patch = profile::Profile {
            filesystem: profile::FilesystemConfig {
                suppress_save_prompt: vec!["~/.copilot/settings.json".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        let prepared =
            prepare_profile_save_from_patch(&patch, "claude", "claude-local", Some("claude-code"))
                .expect("prepare");

        assert!(matches!(prepared.action, SaveAction::Created));
        assert_eq!(
            prepared.profile.extends,
            Some(vec!["claude-code".to_string()])
        );
        assert_eq!(
            prepared.profile.meta.description.as_deref(),
            Some("Runtime-discovered save-prompt suppressions for claude")
        );
        assert_eq!(
            prepared.profile.filesystem.suppress_save_prompt,
            vec!["~/.copilot/settings.json"]
        );
        assert!(prepared.profile.filesystem.read_file.is_empty());
    }

    #[test]
    fn prepare_profile_save_from_patch_preserves_registry_ref_as_extends() {
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

        let patch = profile::Profile {
            filesystem: profile::FilesystemConfig {
                suppress_save_prompt: vec!["~/.copilot/settings.json".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        let prepared = prepare_profile_save_from_patch(
            &patch,
            "claude",
            "claude-test",
            Some("always-further/claude"),
        )
        .expect("prepare");

        assert!(matches!(prepared.action, SaveAction::Created));
        assert_eq!(
            prepared.profile.extends,
            Some(vec!["always-further/claude".to_string()])
        );
    }

    #[test]
    fn prepare_profile_save_from_patch_preserves_versioned_registry_ref() {
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

        let mut patch = profile::Profile::default();
        patch.filesystem.read = vec!["~/workspace".to_string()];

        let prepared = prepare_profile_save_from_patch(
            &patch,
            "claude",
            "claude-test",
            Some("always-further/claude@1.2.0"),
        )
        .expect("prepare");

        assert_eq!(
            prepared.profile.extends,
            Some(vec!["always-further/claude@1.2.0".to_string()])
        );
    }

    #[test]
    fn prepare_profile_save_from_patch_still_avoids_self_reference() {
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

        let mut patch = profile::Profile::default();
        patch.filesystem.read = vec!["~/workspace".to_string()];

        let prepared =
            prepare_profile_save_from_patch(&patch, "claude", "my-profile", Some("my-profile"))
                .expect("prepare");

        assert!(prepared.profile.extends.is_none());
    }

    #[test]
    fn would_shadow_existing_profile_flags_known_builtin_names() {
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

        // `openclaw` is a known built-in; writing to that user path would shadow it.
        assert!(would_shadow_existing_profile("openclaw"));
        // Names that don't exist as built-ins or pack profiles are fine.
        assert!(!would_shadow_existing_profile("my-unique-saved-profile"));
    }

    #[test]
    fn would_shadow_existing_profile_allows_short_name_matching_pack_install_as() {
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

        // Set up a fake pack store: $XDG_CONFIG_HOME/nono/packages/test-ns/test-pack/
        let pack_dir = temp_config
            .path()
            .join("nono")
            .join("packages")
            .join("test-ns")
            .join("test-pack");
        std::fs::create_dir_all(pack_dir.join("profiles")).expect("mkdir pack");

        let manifest = r#"{
            "schema_version": 1,
            "name": "test-pack",
            "artifacts": [
                {"type": "profile", "path": "profiles/hermes.json", "install_as": "hermes"}
            ]
        }"#;
        std::fs::write(pack_dir.join("package.json"), manifest).expect("write manifest");
        std::fs::write(
            pack_dir.join("profiles").join("hermes.json"),
            "{\"meta\":{\"name\":\"hermes\",\"version\":\"1.0.0\"}}\n",
        )
        .expect("write pack profile");

        // Pack profiles are referenced by `org/name` (an invalid profile name),
        // so a user profile named "hermes" does not shadow the pack.
        assert!(!would_shadow_existing_profile("hermes"));
        assert!(!would_shadow_existing_profile("my-unique-saved-profile"));
    }

    #[test]
    fn would_shadow_existing_profile_allows_update_of_existing_user_override() {
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
        let path = profile::get_user_profile_path("openclaw").expect("profile path");
        std::fs::create_dir_all(path.parent().expect("dir")).expect("mkdir");
        std::fs::write(
            &path,
            "{\"meta\":{\"name\":\"openclaw\",\"version\":\"1.0.0\"}}\n",
        )
        .expect("write");

        assert!(!would_shadow_existing_profile("openclaw"));
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
