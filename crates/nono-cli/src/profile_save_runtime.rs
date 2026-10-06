use crate::command_display::format_command_line;
use crate::diagnostic::{ErrorObservation, PolicyExplanation};
use crate::exec_strategy::ProfileSaveOffer;
use crate::theme;
use crate::{profile, protected_paths, query_ext};
use colored::Colorize;
use nono::SandboxViolation;
use nono::{AccessMode, CapabilitySet, NonoError, Result, UrlDenialReason, UrlDenialRecord};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

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
    pub(crate) patch: profile::Profile,
}

/// Where a save prompt writes its rules.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SaveTarget {
    /// An existing profile file the session ran with.
    File(PathBuf),
    /// A user profile the user names at the prompt.
    NewUserProfile,
}

/// Save targets in precedence order. A new user profile is offered only when
/// the session ran with no writable profile file.
fn save_targets(save_files: &[profile::ProfileSourceFile]) -> Vec<SaveTarget> {
    if save_files.is_empty() {
        return vec![SaveTarget::NewUserProfile];
    }
    save_files
        .iter()
        .map(|file| SaveTarget::File(file.path.clone()))
        .collect()
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UrlItemKind {
    Origin,
    Localhost,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UrlItemAction {
    Grant,
    Skip,
}

impl UrlItemAction {
    fn cycle(self) -> Self {
        match self {
            Self::Grant => Self::Skip,
            Self::Skip => Self::Grant,
        }
    }

    fn padded_label(self) -> &'static str {
        match self {
            Self::Grant => "grant   ",
            Self::Skip => "skip    ",
        }
    }
}

#[derive(Clone, Debug)]
enum DenialItem {
    Fs {
        path: String,
        section: ProfileSection,
        is_bypass: bool,
        action: ItemAction,
    },
    Url {
        origin: String,
        kind: UrlItemKind,
        action: UrlItemAction,
    },
}

const DENIAL_SELECTOR_MAX_VISIBLE_ITEMS: usize = 15;
const DENIAL_SELECTOR_INPUT_DELAY: Duration = Duration::from_secs(1);

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
    let protected_roots = protected_paths::ProtectedRoots::from_defaults().ok();

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
            let is_file = matches!(
                section,
                ProfileSection::AllowFile | ProfileSection::ReadFile | ProfileSection::WriteFile
            );
            let overlaps_protected_root = protected_roots.as_ref().is_none_or(|roots| {
                profile::expand_vars(path, Path::new("."))
                    .ok()
                    .is_none_or(|expanded| {
                        protected_paths::profile_save_target_overlaps_protected_root(
                            &expanded,
                            is_file,
                            roots.as_paths(),
                        )
                    })
            });
            if overlaps_protected_root {
                continue;
            }
            let is_bypass = fs.bypass_protection.contains(path);
            items.push(DenialItem::Fs {
                path: path.clone(),
                section: *section,
                is_bypass,
                action: ItemAction::Grant,
            });
        }
    }

    for rule in &patch.unsafe_macos_seatbelt_rules {
        items.push(DenialItem::Fs {
            path: rule.clone(),
            section: ProfileSection::UnsafeSeatbelt,
            is_bypass: false,
            action: ItemAction::Grant,
        });
    }

    // URL items from open_urls patch
    if let Some(ref open_urls) = patch.open_urls {
        if open_urls.allow_localhost {
            items.push(DenialItem::Url {
                origin: String::new(),
                kind: UrlItemKind::Localhost,
                action: UrlItemAction::Grant,
            });
        }
        for origin in &open_urls.allow_origins {
            items.push(DenialItem::Url {
                origin: origin.clone(),
                kind: UrlItemKind::Origin,
                action: UrlItemAction::Grant,
            });
        }
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
    // stdin/stderr being a tty doesn't mean we have a controlling terminal
    // (e.g. a new session can inherit a tty stdin with none). Check /dev/tty
    // directly, in the same read+write mode the prompt itself needs, so we
    // don't promise a prompt we can't open later.
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .is_ok()
}

pub(crate) fn offer_save_run_profile(offer: &ProfileSaveOffer<'_>) -> Result<()> {
    if !terminal_prompts_available() {
        return Ok(());
    }

    let Some(mut patch) = build_run_profile_patch(
        offer.policy_explanations,
        offer.error_observation,
        offer.caps,
        offer.sandbox_violations,
        offer.ignored_denial_paths,
    )?
    else {
        // No filesystem patch — but we may still have URL denials
        return offer_url_only_save(offer);
    };

    // Merge URL grants into the filesystem patch profile so extract_denial_items
    // picks them up alongside filesystem items. The URL patch only sets
    // open_urls, so merging touches nothing else in the filesystem patch.
    if let Some(url_patch) = build_url_patch(offer.url_denials) {
        merge_profile_patch(&mut patch, &url_patch);
    }

    let Some(cmd_name) = offer_command_name(offer.command) else {
        return Ok(());
    };

    // Try the interactive selector first; fall back to the text prompt when
    // raw mode is unavailable (e.g. a dumb terminal or a redirected TTY).
    match interactive_denial_selector(&patch)? {
        Some(items) => {
            let Some(combined_patch) = build_combined_patch_from_items(&items) else {
                return Ok(());
            };
            offer_save_with_patch(&combined_patch, &cmd_name, offer)
        }
        None => offer_save_text_prompt(&patch, &cmd_name, offer),
    }
}

/// Offer profile save when only URL denials exist (no filesystem patch).
fn offer_url_only_save(offer: &ProfileSaveOffer<'_>) -> Result<()> {
    if offer.url_denials.is_empty() {
        return Ok(());
    }

    let Some(url_patch) = build_url_patch(offer.url_denials) else {
        return Ok(());
    };

    let Some(cmd_name) = offer_command_name(offer.command) else {
        return Ok(());
    };

    match interactive_denial_selector(&url_patch)? {
        Some(items) => {
            let Some(combined_patch) = build_combined_patch_from_items(&items) else {
                return Ok(());
            };
            offer_save_with_patch(&combined_patch, &cmd_name, offer)
        }
        None => offer_save_text_prompt(&url_patch, &cmd_name, offer),
    }
}

fn offer_save_with_patch(
    patch: &profile::Profile,
    cmd_name: &str,
    offer: &ProfileSaveOffer<'_>,
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

    let Some(target) = choose_save_target(
        save_targets(offer.profile_save_files),
        top_level_profile(offer.profile_save_files),
    )?
    else {
        return Ok(());
    };
    save_patch_to_target(&target, patch, cmd_name, offer)
}

fn offer_save_text_prompt(
    patch: &profile::Profile,
    cmd_name: &str,
    offer: &ProfileSaveOffer<'_>,
) -> Result<()> {
    let has_overrides = patch_has_policy_overrides(patch);
    let suppress_patch = build_suppress_save_prompt_patch(patch);
    let _prompt_terminal = prepare_prompt_terminal();

    prompt_println("");
    print_patch_preview(patch);

    let targets = save_targets(offer.profile_save_files);
    let choice = prompt_profile_save_choice(&targets, suppress_patch.is_some())?;
    let Some(selected_patch) =
        selected_profile_save_patch(choice, patch, suppress_patch.as_ref(), has_overrides)?
    else {
        return Ok(());
    };

    let Some(target) = choose_save_target(targets, top_level_profile(offer.profile_save_files))?
    else {
        return Ok(());
    };
    save_patch_to_target(&target, selected_patch, cmd_name, offer)
}

/// The top-level profile's file, when it is one of the writable save files.
fn top_level_profile(save_files: &[profile::ProfileSourceFile]) -> Option<&Path> {
    save_files
        .iter()
        .find(|file| file.top_level)
        .map(|file| file.path.as_path())
}

/// A lone target is written without asking only when it is the top-level
/// profile; a base reached through `--extends` under a pack or built-in is
/// shared, so the user picks it explicitly.
fn save_target_menu_needed(files: &[PathBuf], top_level: Option<&Path>) -> bool {
    match files {
        [] => false,
        [only] => Some(only.as_path()) != top_level,
        _ => true,
    }
}

/// The target to save to: the top-level profile when it is the only writable
/// file, otherwise the user's menu choice. `None` when the user skips.
fn choose_save_target(
    targets: Vec<SaveTarget>,
    top_level: Option<&Path>,
) -> Result<Option<SaveTarget>> {
    let files: Vec<PathBuf> = targets
        .iter()
        .filter_map(|target| match target {
            SaveTarget::File(path) => Some(path.clone()),
            SaveTarget::NewUserProfile => None,
        })
        .collect();
    if !save_target_menu_needed(&files, top_level) {
        return Ok(targets.into_iter().next());
    }
    Ok(prompt_save_target(&files, top_level)?.map(SaveTarget::File))
}

fn render_save_target_menu(files: &[PathBuf], top_level: Option<&Path>) -> String {
    let paths: Vec<String> = files
        .iter()
        .map(|path| path.display().to_string())
        .collect();
    let width = paths
        .iter()
        .map(|path| path.chars().count())
        .max()
        .unwrap_or(0);
    let mut menu = String::from("Save the selected rules to:\n");
    for (index, (file, path)) in files.iter().zip(&paths).enumerate() {
        let label = if Some(file.as_path()) == top_level {
            "this profile"
        } else {
            "base — applies to every profile that extends it"
        };
        menu.push_str(&format!("  {}) {path:<width$}    ({label})\n", index + 1));
    }
    menu.push_str("Choice [1]: ");
    menu
}

/// `Some(Some(i))` picks file `i`, `Some(None)` skips, `None` is invalid input.
fn parse_save_target_choice(input: &str, count: usize) -> Option<Option<usize>> {
    match input.trim().to_ascii_lowercase().as_str() {
        "" => Some(Some(0)),
        "skip" => Some(None),
        number => number
            .parse::<usize>()
            .ok()
            .filter(|choice| (1..=count).contains(choice))
            .map(|choice| Some(choice - 1)),
    }
}

/// `input` is the raw line read, so an empty string means the input closed
/// (EOF) and cancels, while Enter arrives as a newline and picks file 1.
fn chosen_save_target(files: &[PathBuf], input: &str) -> Option<Option<PathBuf>> {
    if input.is_empty() {
        return Some(None);
    }
    parse_save_target_choice(input, files.len())
        .map(|choice| choice.and_then(|index| files.get(index).cloned()))
}

fn prompt_save_target(files: &[PathBuf], top_level: Option<&Path>) -> Result<Option<PathBuf>> {
    let menu = render_save_target_menu(files, top_level);
    let (options, choice_prompt) = menu.rsplit_once('\n').unwrap_or(("", menu.as_str()));
    for line in options.lines() {
        prompt_println(line);
    }
    loop {
        prompt_print(choice_prompt, &[]);
        let input = read_input_line()?;
        if let Some(choice) = chosen_save_target(files, &input) {
            return Ok(choice);
        }
        let help = format!(
            "Enter a number from 1 to {}, press Enter for 1, or type skip.",
            files.len()
        );
        prompt_println(&format!("{}", help.red()));
    }
}

/// Write `patch` to `target`, prompting for a name when it is a new user
/// profile, and report the save.
fn save_patch_to_target(
    target: &SaveTarget,
    patch: &profile::Profile,
    cmd_name: &str,
    offer: &ProfileSaveOffer<'_>,
) -> Result<()> {
    let Some(prepared) = prepare_save_to_target(target, patch, cmd_name, offer.compared_profile)?
    else {
        return Ok(());
    };
    write_profile(&prepared)?;
    print_profile_save(&prepared, offer.command);
    print_suppression_save_note(patch);
    Ok(())
}

/// Prepare the save of `patch` to `target`. `None` when the user cancels the
/// new-profile name prompt.
fn prepare_save_to_target(
    target: &SaveTarget,
    patch: &profile::Profile,
    cmd_name: &str,
    compared_profile: Option<&str>,
) -> Result<Option<PreparedProfileSave>> {
    match target {
        SaveTarget::File(path) => {
            let path_text = path.display().to_string();
            let run_with = compared_profile.unwrap_or(&path_text);
            prepare_profile_save_to_file(patch, path, run_with).map(Some)
        }
        SaveTarget::NewUserProfile => {
            let suggested = suggested_run_profile_name(compared_profile, cmd_name);
            let Some(profile_name) = prompt_profile_name(suggested.as_deref())? else {
                return Ok(None);
            };
            prepare_profile_save_from_patch(patch, cmd_name, &profile_name, compared_profile)
                .map(Some)
        }
    }
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

/// The save question names the file only when it is the sole target; with
/// several, the menu that follows picks the file.
fn profile_save_question(targets: &[SaveTarget], can_suppress: bool) -> String {
    if targets.len() > 1 {
        return if can_suppress {
            "Save suggestions to a profile? [g] grant / [s] suppress / [Enter] skip: ".to_string()
        } else {
            "Save the shown rules to a profile? [g] save / [Enter] skip: ".to_string()
        };
    }
    let existing_profile = match targets.first() {
        Some(SaveTarget::File(path)) => Some(path.as_path()),
        Some(SaveTarget::NewUserProfile) | None => None,
    };
    match (existing_profile, can_suppress) {
        (Some(path), true) => format!(
            "Update profile '{}' with suggestions? [g] grant / [s] suppress / [Enter] skip: ",
            path.display()
        ),
        (Some(path), false) => format!(
            "Update existing profile '{}' with the shown rules? [g] save / [Enter] skip: ",
            path.display()
        ),
        (None, true) => {
            "Save suggestions to a user profile? [g] grant / [s] suppress / [Enter] skip: "
                .to_string()
        }
        (None, false) => {
            "Save the shown rules in a user profile? [g] save / [Enter] skip: ".to_string()
        }
    }
}

fn prompt_profile_save_choice(
    targets: &[SaveTarget],
    can_suppress: bool,
) -> Result<ProfileSaveChoice> {
    let prompt = profile_save_question(targets, can_suppress);
    loop {
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

fn command_name<S: AsRef<std::ffi::OsStr>>(command: &[S]) -> Result<String> {
    command
        .first()
        .and_then(|command| std::path::Path::new(command.as_ref()).file_name())
        .and_then(|name| name.to_str())
        .map(ToOwned::to_owned)
        .ok_or_else(|| NonoError::LearnError("Cannot derive profile name from command".to_string()))
}

/// Derive the profile name for a save *offer*, warning and returning `None`
/// when it cannot be derived.
///
/// Every caller runs after the traced or sandboxed child has already finished,
/// so an undeliverable offer must not become the run's result: propagating here
/// would replace the child's exit status with an error about profile naming.
pub(crate) fn offer_command_name<S: AsRef<std::ffi::OsStr>>(command: &[S]) -> Option<String> {
    match command_name(command) {
        Ok(name) => Some(name),
        Err(_) => {
            crate::output::print_warning(
                "Skipping profile save: cannot derive a profile name from the command \
                 (a profile name must be valid UTF-8).",
            );
            None
        }
    }
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
    // referenced by their full `org/name` key (e.g. `nolabs-ai/hermes`),
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

    let contents = match prepared.action {
        SaveAction::Created => {
            let profile_json = serde_json::to_string_pretty(&prepared.profile).map_err(|e| {
                NonoError::LearnError(format!("Failed to serialize profile: {}", e))
            })?;
            format!("{profile_json}\n")
        }
        SaveAction::Updated => updated_profile_text(&prepared.profile_path, &prepared.patch)?,
    };
    atomic_write(&prepared.profile_path, contents.as_bytes())
}

/// Apply `patch` to the profile file's current text, keeping its comments.
/// The result must still parse as a profile; otherwise the file is left as is.
fn updated_profile_text(profile_path: &Path, patch: &profile::Profile) -> Result<String> {
    let original = std::fs::read_to_string(profile_path).map_err(|e| {
        NonoError::LearnError(format!(
            "Failed to read profile {}: {}",
            profile_path.display(),
            e
        ))
    })?;
    let updated = crate::profile_file_edit::apply_patch_to_profile_text(&original, patch).map_err(
        |e| match e {
            NonoError::LearnError(message) => NonoError::LearnError(format!(
                "Failed to update profile {}: {}",
                profile_path.display(),
                message
            )),
            other => other,
        },
    )?;
    profile::parse_profile_bytes(updated.as_bytes()).map_err(|e| {
        NonoError::LearnError(format!(
            "Updated profile {} would be invalid: {}",
            profile_path.display(),
            e
        ))
    })?;
    Ok(updated)
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

    let write_err = |stage: &str, e: std::io::Error| {
        NonoError::LearnError(format!(
            "Failed to {} profile {}: {}",
            stage,
            path.display(),
            e
        ))
    };

    // The directory may be writable by the sandboxed agent, so the temp file
    // gets a random name and is created exclusively (O_EXCL): a name the agent
    // planted, such as a symlink to a shell rc file, is never opened. A sibling
    // keeps the final rename same-filesystem and therefore atomic on POSIX.
    let mut prefix = std::ffi::OsString::from(".");
    prefix.push(file_name);
    prefix.push(".");
    let mut builder = tempfile::Builder::new();
    builder.prefix(&prefix).suffix(".tmp");
    // Match a plain create: mode 0666 filtered by the umask.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o666));
    }
    let mut file = builder
        .tempfile_in(dir)
        .map_err(|e| write_err("open temp file for", e))?;
    // Dropping `file` on an early return removes the temp file.
    file.write_all(contents)
        .map_err(|e| write_err("write", e))?;
    file.as_file()
        .sync_all()
        .map_err(|e| write_err("sync", e))?;
    file.persist(path)
        .map_err(|e| write_err("rename into place", e.error))?;
    Ok(())
}

pub(crate) fn print_profile_save(prepared: &PreparedProfileSave, command: &[std::ffi::OsString]) {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Key {
    Up,
    Down,
    Space,
    Enter,
    CtrlC,
    CtrlD,
    Esc,
    Char(char),
    /// An input sequence the selector does not act on (left/right arrows,
    /// Home/End, function keys, Alt-modified keys, mouse reports).
    Unknown,
}

fn decode_plain_byte(byte: u8) -> Key {
    match byte {
        b' ' => Key::Space,
        b'\r' | b'\n' => Key::Enter,
        0x03 => Key::CtrlC,
        0x04 => Key::CtrlD,
        c => Key::Char(c as char),
    }
}

/// Decode an escape sequence after its leading `ESC` byte.
///
/// `reader` must be in a short-timeout mode, where a zero-byte read means
/// nothing more arrived; that is what distinguishes a bare Esc keypress from
/// the start of a sequence.
fn decode_escape_sequence<R: std::io::Read>(reader: &mut R) -> Key {
    let Some(second) = read_one(reader) else {
        // Nothing followed: a bare Esc.
        return Key::Esc;
    };

    match second {
        // CSI and SS3 introducers.
        b'[' | b'O' => match read_csi_final_byte(reader) {
            Some(b'A') => Key::Up,
            Some(b'B') => Key::Down,
            _ => Key::Unknown,
        },
        // `ESC <char>` is Alt+<char>.
        _ => Key::Unknown,
    }
}

/// Consume a CSI/SS3 body and return its final byte, skipping parameter and
/// intermediate bytes so sequences like `ESC [ 1 ; 5 C` are swallowed whole
/// rather than leaving a tail to be misread as further keypresses.
fn read_csi_final_byte<R: std::io::Read>(reader: &mut R) -> Option<u8> {
    // Bounded so a malformed sequence cannot spin forever.
    const MAX_SEQUENCE_BYTES: usize = 32;
    for _ in 0..MAX_SEQUENCE_BYTES {
        let byte = read_one(reader)?;
        if (0x40..=0x7e).contains(&byte) {
            return Some(byte);
        }
    }
    None
}

/// Read one byte, treating a timeout, EOF, or error as "no byte".
fn read_one<R: std::io::Read>(reader: &mut R) -> Option<u8> {
    let mut buf = [0u8; 1];
    match reader.read(&mut buf) {
        Ok(1) => Some(buf[0]),
        _ => None,
    }
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
        if buf[0] != 0x1b {
            return Ok(decode_plain_byte(buf[0]));
        }
        // Short-timeout non-blocking, so a bare Esc is distinguishable from
        // the start of an escape sequence.
        self.set_vmin_vtime(0, 1)?;
        let key = decode_escape_sequence(&mut self.tty);
        let _ = self.set_vmin_vtime(1, 0);
        Ok(key)
    }

    /// Wait for the selector's input guard, then discard any type-ahead that
    /// arrived before the operator had time to read the prompt.
    fn arm_input_after(&self, delay: Duration) -> Result<()> {
        std::thread::sleep(delay);
        nix::sys::termios::tcflush(&self.tty, nix::sys::termios::FlushArg::TCIFLUSH)
            .map_err(|e| NonoError::LearnError(format!("tcflush: {e}")))
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
    input_armed: bool,
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
    if input_armed {
        tty_ln!(
            "  {}",
            "↑/↓ move  ·  Space cycle  ·  a grant-all  ·  d deny-all  ·  Enter confirm  ·  Esc cancel"
                .dimmed()
        );
    } else {
        tty_ln!(
            "  {}",
            "Input enables in 1 second · early keys ignored".dimmed()
        );
    }
    tty_ln!("");

    for (offset, item) in items[start..end].iter().enumerate() {
        let i = start + offset;
        let selected = i == cursor;

        let cursor_glyph = if selected {
            format!("{}", theme::fg("▶", t.brand))
        } else {
            " ".to_string()
        };

        match item {
            DenialItem::Fs {
                path,
                section,
                is_bypass,
                action,
            } => {
                let action_str = match action {
                    ItemAction::Grant => {
                        format!("{}", theme::fg(action.padded_label(), t.green).bold())
                    }
                    ItemAction::Suppress => {
                        format!("{}", theme::fg(action.padded_label(), t.yellow))
                    }
                    ItemAction::Skip => {
                        format!("{}", theme::fg(action.padded_label(), t.overlay))
                    }
                };

                let bypass_prefix = if *is_bypass {
                    format!("{} ", "⚠".red())
                } else {
                    String::new()
                };

                let path_str = if selected {
                    format!("{}", theme::fg(path, t.text).bold())
                } else {
                    format!("{}", theme::fg(path, t.subtext))
                };

                let label_str = format!("  ({})", theme::fg(section.display_label(), t.overlay));

                tty_ln!(
                    "  {}  {}  {}{}{}",
                    cursor_glyph,
                    action_str,
                    bypass_prefix,
                    path_str,
                    label_str
                );
            }
            DenialItem::Url {
                origin,
                kind,
                action,
            } => {
                let action_str = match action {
                    UrlItemAction::Grant => {
                        format!("{}", theme::fg(action.padded_label(), t.green).bold())
                    }
                    UrlItemAction::Skip => {
                        format!("{}", theme::fg(action.padded_label(), t.overlay))
                    }
                };

                let (display_origin, label_str) = match kind {
                    UrlItemKind::Origin => {
                        let origin_display = if selected {
                            format!("{}", theme::fg(origin, t.text).bold())
                        } else {
                            format!("{}", theme::fg(origin, t.subtext))
                        };
                        (
                            origin_display,
                            format!("  ({})", theme::fg("open-url origin", t.overlay)),
                        )
                    }
                    UrlItemKind::Localhost => (
                        String::new(),
                        format!("  ({})", theme::fg("allow-localhost", t.overlay)),
                    ),
                };

                tty_ln!(
                    "  {}  {}  {}{}",
                    cursor_glyph,
                    action_str,
                    display_origin,
                    label_str
                );
            }
        }
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
    let mut cancelled = false;

    render_denial_selector(&mut raw.tty, &items, cursor, &mut line_count, true, false)?;
    raw.arm_input_after(DENIAL_SELECTOR_INPUT_DELAY)?;

    loop {
        render_denial_selector(&mut raw.tty, &items, cursor, &mut line_count, false, true)?;

        match raw.read_key()? {
            Key::Up => {
                cursor = cursor.saturating_sub(1);
            }
            Key::Down => {
                if cursor + 1 < items.len() {
                    cursor += 1;
                }
            }
            Key::Space => match &mut items[cursor] {
                DenialItem::Fs {
                    action, section, ..
                } => {
                    let mut next = action.cycle();
                    if *section == ProfileSection::UnsafeSeatbelt && next == ItemAction::Suppress {
                        next = next.cycle();
                    }
                    *action = next;
                }
                DenialItem::Url { action, .. } => {
                    *action = action.cycle();
                }
            },
            Key::Char('a') => {
                for item in &mut items {
                    match item {
                        DenialItem::Fs { action, .. } => *action = ItemAction::Grant,
                        DenialItem::Url { action, .. } => *action = UrlItemAction::Grant,
                    }
                }
            }
            Key::Char('d') => {
                for item in &mut items {
                    match item {
                        DenialItem::Fs {
                            action, section, ..
                        } => {
                            *action = if *section == ProfileSection::UnsafeSeatbelt {
                                ItemAction::Skip
                            } else {
                                ItemAction::Suppress
                            };
                        }
                        // URL items are not suppressible; deny-all skips them
                        // so Enter cannot accidentally grant the default Grant.
                        DenialItem::Url { action, .. } => *action = UrlItemAction::Skip,
                    }
                }
            }
            Key::Enter => break,
            Key::CtrlC | Key::CtrlD | Key::Esc => {
                for item in &mut items {
                    match item {
                        DenialItem::Fs { action, .. } => *action = ItemAction::Skip,
                        DenialItem::Url { action, .. } => *action = UrlItemAction::Skip,
                    }
                }
                cancelled = true;
                break;
            }
            // Ignored, so a stray keypress cannot discard the review.
            Key::Char(_) | Key::Unknown => {}
        }
    }

    erase_selector(&mut raw.tty, line_count)?;
    if cancelled {
        print_selector_cancelled_hint(&mut raw.tty);
    }
    Ok(Some(items))
}

/// Report that nothing was saved and how to bring the review back. Written to
/// the selector's tty, so the hint survives stdout or stderr redirection.
fn print_selector_cancelled_hint(tty: &mut std::fs::File) {
    let t = theme::current();
    let _ = writeln!(
        tty,
        "\r{} {}",
        theme::fg(" [nono]", t.brand).bold(),
        "Review cancelled - no profile changes were saved.".dimmed()
    );
    let _ = writeln!(
        tty,
        "\r        {}",
        "Re-run the same command to review the denied paths again.".dimmed()
    );
    let _ = tty.flush();
}

// ─── Build patch from per-item decisions ──────────────────────────────────

fn build_combined_patch_from_items(items: &[DenialItem]) -> Option<profile::Profile> {
    let has_grants = items.iter().any(|i| match i {
        DenialItem::Fs { action, .. } => *action == ItemAction::Grant,
        DenialItem::Url { action, .. } => *action == UrlItemAction::Grant,
    });
    let has_suppresses = items.iter().any(|i| {
        matches!(i, DenialItem::Fs { action: ItemAction::Suppress, section, .. } if *section != ProfileSection::UnsafeSeatbelt)
    });

    if !has_grants && !has_suppresses {
        return None;
    }

    let mut patch = profile::Profile::default();
    let mut origin_grants: Vec<String> = Vec::new();
    let mut localhost_grant = false;

    for item in items {
        match item {
            DenialItem::Fs {
                path,
                section,
                is_bypass,
                action,
            } => match action {
                ItemAction::Grant => {
                    match section {
                        ProfileSection::Allow => patch.filesystem.allow.push(path.clone()),
                        ProfileSection::Read => patch.filesystem.read.push(path.clone()),
                        ProfileSection::Write => patch.filesystem.write.push(path.clone()),
                        ProfileSection::AllowFile => patch.filesystem.allow_file.push(path.clone()),
                        ProfileSection::ReadFile => patch.filesystem.read_file.push(path.clone()),
                        ProfileSection::WriteFile => patch.filesystem.write_file.push(path.clone()),
                        ProfileSection::UnsafeSeatbelt => {
                            patch.unsafe_macos_seatbelt_rules.push(path.clone())
                        }
                    }
                    if *is_bypass && !patch.filesystem.bypass_protection.contains(path) {
                        patch.filesystem.bypass_protection.push(path.clone());
                    }
                }
                ItemAction::Suppress => {
                    if *section != ProfileSection::UnsafeSeatbelt {
                        patch.filesystem.suppress_save_prompt.push(path.clone());
                    }
                }
                ItemAction::Skip => {}
            },
            DenialItem::Url {
                origin,
                kind,
                action,
            } => {
                if *action == UrlItemAction::Grant {
                    match kind {
                        UrlItemKind::Origin => {
                            if !origin.is_empty() && !origin_grants.contains(origin) {
                                origin_grants.push(origin.clone());
                            }
                        }
                        UrlItemKind::Localhost => {
                            localhost_grant = true;
                        }
                    }
                }
            }
        }
    }

    if !origin_grants.is_empty() || localhost_grant {
        patch.open_urls = Some(profile::OpenUrlConfig {
            allow_origins: origin_grants,
            allow_localhost: localhost_grant,
        });
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

/// Prepare an update of the existing profile file at `path`. `run_with` is the
/// `--profile` value shown in the "Run with:" hint.
pub(crate) fn prepare_profile_save_to_file(
    patch: &profile::Profile,
    path: &Path,
    run_with: &str,
) -> Result<PreparedProfileSave> {
    let path = writable_profile_path(path)?;
    let mut existing = profile::load_raw_profile_from_path(&path)?;
    merge_profile_patch(&mut existing, patch);
    Ok(PreparedProfileSave {
        action: SaveAction::Updated,
        profile_name: run_with.to_string(),
        profile_path: path,
        profile: existing,
        patch: patch.clone(),
    })
}

/// Re-check a save target just before writing to it. `path` is the canonical
/// path recorded when the profile loaded, but the sandboxed agent may since
/// have swapped it, or a parent directory, for a symlink to another file (a
/// user profile, the pack store), or for a FIFO that would hang the read.
fn writable_profile_path(path: &Path) -> Result<PathBuf> {
    let canonical = std::fs::canonicalize(path).map_err(|e| {
        NonoError::LearnError(format!(
            "Cannot resolve profile file {}: {e}",
            path.display()
        ))
    })?;
    if canonical != path {
        return Err(NonoError::LearnError(format!(
            "Refusing to save to {}: it now resolves to {}",
            path.display(),
            canonical.display()
        )));
    }
    let is_file = std::fs::metadata(&canonical)
        .map_err(|e| {
            NonoError::LearnError(format!("Cannot read profile file {}: {e}", path.display()))
        })?
        .is_file();
    if !is_file {
        return Err(NonoError::LearnError(format!(
            "Refusing to save to {}: it is not a regular file",
            path.display()
        )));
    }
    Ok(canonical)
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
            patch: patch.clone(),
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
        patch: patch.clone(),
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
    let protected_roots = protected_paths::ProtectedRoots::from_defaults()?;

    for explanation in policy_explanations {
        add_patch_grant(
            &mut grants,
            &explanation.path,
            explanation.access,
            &explanation.reason,
            ignored_denial_paths,
            protected_roots.as_paths(),
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
                    protected_roots.as_paths(),
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
        && patch.open_urls.is_none()
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
    protected_roots: &[PathBuf],
) {
    let (flag, target) = query_ext::suggested_flag_parts(path, access);
    if !ignored_denial_paths.is_empty()
        && (matches_ignored_denial(path, ignored_denial_paths)
            || (target.as_path() != path && matches_ignored_denial(&target, ignored_denial_paths)))
    {
        return;
    }

    let is_file = matches!(flag, "--read-file" | "--write-file" | "--allow-file");
    if protected_paths::profile_save_target_overlaps_protected_root(
        &target,
        is_file,
        protected_roots,
    ) {
        return;
    }

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

/// Keep the merged fields in step with `PATCHED_LISTS` in `profile_file_edit`,
/// which applies the same patch to profile text when updating a file.
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

    // Merge open_urls: origins are dedup-appended, allow_localhost is monotonic (false -> true only)
    if let Some(ref patch_urls) = patch.open_urls
        && (patch_urls.allow_localhost || !patch_urls.allow_origins.is_empty())
    {
        let urls = profile
            .open_urls
            .get_or_insert_with(|| profile::OpenUrlConfig {
                allow_origins: Vec::new(),
                allow_localhost: false,
            });
        urls.allow_origins = profile::dedup_append(&urls.allow_origins, &patch_urls.allow_origins);
        // Monotonic: only flip false -> true, never true -> false
        if patch_urls.allow_localhost {
            urls.allow_localhost = true;
        }
    }
}

/// Build a profile patch containing only open_urls fields from URL denial records.
///
/// The resulting profile is merged into the filesystem profile patch before
/// `extract_denial_items`, so URL items appear in the same selector alongside
/// filesystem items without changing any existing function signatures.
pub(crate) fn build_url_patch(url_denials: &[UrlDenialRecord]) -> Option<profile::Profile> {
    let mut origin_grants: Vec<String> = Vec::new();
    let mut localhost_grant = false;

    for record in url_denials {
        match record.reason {
            UrlDenialReason::OriginNotAllowed
                if !record.origin.is_empty() && !origin_grants.contains(&record.origin) =>
            {
                origin_grants.push(record.origin.clone());
            }
            UrlDenialReason::LocalhostNotAllowed => {
                localhost_grant = true;
            }
            _ => {}
        }
    }

    if origin_grants.is_empty() && !localhost_grant {
        return None;
    }

    let patch = profile::Profile {
        open_urls: Some(profile::OpenUrlConfig {
            allow_origins: origin_grants,
            allow_localhost: localhost_grant,
        }),
        ..Default::default()
    };
    Some(patch)
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
    fn build_run_profile_patch_omits_protected_root_denial() {
        let _env_lock = ENV_LOCK.lock().expect("env lock");
        let temp_home = TempDir::new().expect("temp home");
        let state_home = temp_home.path().join("state");
        let _env = EnvVarGuard::set_all(&[
            ("HOME", temp_home.path().to_str().expect("home path")),
            ("XDG_STATE_HOME", state_home.to_str().expect("state path")),
        ]);

        let protected = temp_home.path().join(".nono");
        std::fs::create_dir_all(&protected).expect("mkdir");
        let explanation = PolicyExplanation {
            path: protected,
            access: AccessMode::Read,
            reason: "path_not_granted".to_string(),
        };

        let patch = build_run_profile_patch(
            &[explanation],
            &ErrorObservation::default(),
            &CapabilitySet::new(),
            &[],
            &[],
        )
        .expect("build patch");

        assert!(patch.is_none());
    }

    #[test]
    fn build_run_profile_patch_omits_xdg_protected_root_denial() {
        let _env_lock = ENV_LOCK.lock().expect("env lock");
        let temp_home = TempDir::new().expect("temp home");
        let state_home = temp_home.path().join("state");
        let _env = EnvVarGuard::set_all(&[
            ("HOME", temp_home.path().to_str().expect("home path")),
            ("XDG_STATE_HOME", state_home.to_str().expect("state path")),
        ]);

        let protected = state_home.join("nono");
        std::fs::create_dir_all(&protected).expect("mkdir");
        let explanation = PolicyExplanation {
            path: protected,
            access: AccessMode::Read,
            reason: "path_not_granted".to_string(),
        };

        let patch = build_run_profile_patch(
            &[explanation],
            &ErrorObservation::default(),
            &CapabilitySet::new(),
            &[],
            &[],
        )
        .expect("build patch");

        assert!(patch.is_none());
    }

    #[test]
    fn build_run_profile_patch_omits_protected_root_ancestor_but_keeps_valid_denial() {
        let _env_lock = ENV_LOCK.lock().expect("env lock");
        let temp_home = TempDir::new().expect("temp home");
        let state_home = temp_home.path().join("state");
        let _env = EnvVarGuard::set_all(&[
            ("HOME", temp_home.path().to_str().expect("home path")),
            ("XDG_STATE_HOME", state_home.to_str().expect("state path")),
        ]);

        let valid = temp_home.path().join("project");
        std::fs::create_dir_all(&valid).expect("mkdir");
        let denials = vec![
            PolicyExplanation {
                path: temp_home.path().to_path_buf(),
                access: AccessMode::Read,
                reason: "path_not_granted".to_string(),
            },
            PolicyExplanation {
                path: valid,
                access: AccessMode::Read,
                reason: "path_not_granted".to_string(),
            },
        ];

        let patch = build_run_profile_patch(
            &denials,
            &ErrorObservation::default(),
            &CapabilitySet::new(),
            &[],
            &[],
        )
        .expect("build patch")
        .expect("valid denial remains");

        assert_eq!(patch.filesystem.read, vec!["~/project"]);
        assert!(patch.filesystem.bypass_protection.is_empty());
        assert!(patch.filesystem.suppress_save_prompt.is_empty());
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
                    args: Some(vec!["push".to_string()]),
                    match_config: None,
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

    /// Issue #1504: a profile name becomes a filename and a JSON key, so a
    /// non-UTF-8 program name cannot yield one. The offer is skipped rather than
    /// failed, because the child whose exit status we still owe has already run.
    #[test]
    fn offer_command_name_skips_non_utf8_program_without_erroring() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStrExt;

        assert_eq!(
            offer_command_name(&[OsString::from("/usr/bin/claude")]),
            Some("claude".to_string())
        );
        assert_eq!(
            offer_command_name(
                &[std::ffi::OsStr::from_bytes(b"/usr/bin/cl\xffude").to_os_string()]
            ),
            None
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

        assert_eq!(suggested_run_profile_name(None, "linux-host-compat"), None);
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

    fn project_source_file(path: &str) -> profile::ProfileSourceFile {
        profile::ProfileSourceFile {
            path: PathBuf::from(path),
            kind: profile::ProfileSourceKind::Project,
            top_level: false,
        }
    }

    #[test]
    fn save_targets_empty_is_new_user_profile() {
        assert_eq!(save_targets(&[]), vec![SaveTarget::NewUserProfile]);
    }

    #[test]
    fn save_targets_files_never_include_new_user_profile() {
        let files = [
            project_source_file("/work/proj/agent.json"),
            project_source_file("/work/shared/base.json"),
        ];

        assert_eq!(
            save_targets(&files),
            vec![
                SaveTarget::File(PathBuf::from("/work/proj/agent.json")),
                SaveTarget::File(PathBuf::from("/work/shared/base.json")),
            ]
        );
    }

    #[test]
    fn prepare_profile_save_to_file_updates_path_profile() {
        let dir = TempDir::new().expect("tempdir");
        let profile_dir = dir.path().join("proj/.nono");
        std::fs::create_dir_all(&profile_dir).expect("mkdir");
        let profile_path = profile_dir.join("agent.json");
        std::fs::write(
            &profile_path,
            r#"{ "meta": { "name": "agent" }, "filesystem": { "read": ["/old"] } }"#,
        )
        .expect("write profile");

        let mut patch = profile::Profile::default();
        patch.filesystem.read = vec!["/new".to_string()];

        let prepared = prepare_profile_save_to_file(
            &patch,
            &profile_path.canonicalize().expect("canonicalize"),
            "./proj/.nono/agent.json",
        )
        .expect("prepare");

        assert!(matches!(prepared.action, SaveAction::Updated));
        assert_eq!(
            prepared.profile_path,
            profile_path.canonicalize().expect("canonicalize")
        );
        assert_eq!(prepared.profile_name, "./proj/.nono/agent.json");
        assert_eq!(
            prepared.profile.filesystem.read,
            vec!["/old".to_string(), "/new".to_string()]
        );
        assert_eq!(prepared.patch.filesystem.read, vec!["/new".to_string()]);
    }

    #[cfg(unix)]
    #[test]
    fn path_profile_symlinked_into_pack_store_not_offered() {
        let (source_files, writable) = crate::test_env::with_isolated_config_home(|config| {
            let install_dir = crate::test_env::write_fake_pack(
                config,
                "acme",
                "packy",
                "packy",
                r#"{ "meta": { "name": "packy" } }"#,
                &[],
                None,
            );
            let dir = TempDir::new().expect("tempdir");
            let link = dir.path().join("agent.json");
            std::os::unix::fs::symlink(install_dir.join("profiles/packy.json"), &link)
                .expect("symlink");

            let loaded = profile::load_profile_from_path(&link).expect("load via symlink");
            (loaded.source_files.clone(), loaded.writable_source_files())
        });

        assert_eq!(source_files.len(), 1);
        assert_eq!(source_files[0].kind, profile::ProfileSourceKind::Pack);
        assert!(writable.is_empty(), "got {writable:?}");
        assert_eq!(save_targets(&writable), vec![SaveTarget::NewUserProfile]);
    }

    #[test]
    fn render_menu_labels_top_and_bases() {
        let files = [
            PathBuf::from("/work/proj/.nono/agent.json"),
            PathBuf::from("/work/shared/base.json"),
        ];

        let menu = render_save_target_menu(&files, Some(files[0].as_path()));
        let lines: Vec<&str> = menu.split('\n').collect();

        assert_eq!(lines.len(), 4, "{menu}");
        assert_eq!(lines[0], "Save the selected rules to:");
        assert_eq!(
            lines[1],
            "  1) /work/proj/.nono/agent.json    (this profile)"
        );
        assert!(
            lines[2].starts_with("  2) /work/shared/base.json "),
            "{menu}"
        );
        assert!(
            lines[2].ends_with("(base — applies to every profile that extends it)"),
            "{menu}"
        );
        assert_eq!(lines[1].find('('), lines[2].find('('), "{menu}");
        assert_eq!(lines[3], "Choice [1]: ");
    }

    #[test]
    fn render_menu_labels_only_the_top_level_profile_as_this_profile() {
        let files = [PathBuf::from("/work/extra.json")];

        let menu = render_save_target_menu(&files, Some(Path::new("/work/agent.json")));
        assert!(
            menu.contains("(base — applies to every profile that extends it)"),
            "{menu}"
        );
        assert!(!menu.contains("this profile"), "{menu}");

        let menu = render_save_target_menu(&files, None);
        assert!(!menu.contains("this profile"), "{menu}");
    }

    #[test]
    fn save_target_menu_shown_unless_the_only_target_is_the_top_level_profile() {
        let top = PathBuf::from("/work/agent.json");
        let extra = PathBuf::from("/work/extra.json");

        assert!(!save_target_menu_needed(
            &[top.clone()],
            Some(top.as_path())
        ));
        assert!(save_target_menu_needed(
            &[extra.clone()],
            Some(top.as_path())
        ));
        assert!(save_target_menu_needed(&[extra.clone()], None));
        assert!(save_target_menu_needed(
            &[top.clone(), extra],
            Some(top.as_path())
        ));
        assert!(!save_target_menu_needed(&[], None));
    }

    #[test]
    fn prepare_save_to_file_target_runs_with_full_path_and_writes_patch() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir
            .path()
            .canonicalize()
            .expect("canonicalize")
            .join("agent.json");
        std::fs::write(&path, r#"{ "meta": { "name": "agent" } }"#).expect("write agent");
        let mut patch = profile::Profile::default();
        patch.filesystem.read = vec!["/new".to_string()];

        let prepared =
            prepare_save_to_target(&SaveTarget::File(path.clone()), &patch, "claude", None)
                .expect("prepare")
                .expect("file target never cancels");
        write_profile(&prepared).expect("write");

        assert_eq!(prepared.profile_path, path);
        assert_eq!(prepared.profile_name, path.display().to_string());
        let written = std::fs::read_to_string(&path).expect("read agent");
        let reparsed = profile::parse_profile_bytes(written.as_bytes()).expect("reparse");
        assert_eq!(reparsed.filesystem.read, vec!["/new"]);
    }

    #[test]
    fn parse_choice_enter_is_first() {
        assert_eq!(parse_save_target_choice("", 2), Some(Some(0)));
        assert_eq!(parse_save_target_choice("2", 2), Some(Some(1)));
        assert_eq!(parse_save_target_choice(" skip ", 2), Some(None));
        assert_eq!(parse_save_target_choice("3", 2), None);
        assert_eq!(parse_save_target_choice("0", 2), None);
        assert_eq!(parse_save_target_choice("x", 2), None);
    }

    #[test]
    fn menu_choice_two_writes_base_only() {
        let dir = TempDir::new().expect("tempdir");
        let root = dir.path().canonicalize().expect("canonicalize");
        let top = root.join("top.json");
        let base = root.join("base.json");
        let top_text = "{ \"meta\": { \"name\": \"top\" }, \"extends\": [\"./base.json\"] }\n";
        std::fs::write(&top, top_text).expect("write top");
        std::fs::write(
            &base,
            "{\n  // shared rules\n  \"meta\": { \"name\": \"base\" }\n}\n",
        )
        .expect("write base");
        let files = vec![top.clone(), base.clone()];

        assert_eq!(chosen_save_target(&files, "2"), Some(Some(base.clone())));
        let mut patch = profile::Profile::default();
        patch.filesystem.read = vec!["/new".to_string()];
        let prepared = prepare_profile_save_to_file(&patch, &base, "./top.json").expect("prepare");
        write_profile(&prepared).expect("write base");

        let written = std::fs::read_to_string(&base).expect("read base");
        assert!(written.contains("// shared rules"), "{written}");
        let reparsed = profile::parse_profile_bytes(written.as_bytes()).expect("reparse");
        assert_eq!(reparsed.filesystem.read, vec!["/new"]);
        assert_eq!(std::fs::read_to_string(&top).expect("read top"), top_text);
    }

    #[test]
    fn menu_choice_skip_and_invalid() {
        let files = vec![PathBuf::from("/a.json"), PathBuf::from("/b.json")];

        assert_eq!(
            chosen_save_target(&files, "\n"),
            Some(Some(PathBuf::from("/a.json")))
        );
        assert_eq!(chosen_save_target(&files, "skip\n"), Some(None));
        assert_eq!(chosen_save_target(&files, "9"), None);
    }

    #[test]
    fn menu_choice_closed_input_cancels() {
        let files = vec![PathBuf::from("/a.json"), PathBuf::from("/b.json")];

        assert_eq!(chosen_save_target(&files, ""), Some(None));
    }

    #[test]
    fn save_question_names_file_only_for_single_target() {
        let one = [SaveTarget::File(PathBuf::from("/work/agent.json"))];
        let two = [
            SaveTarget::File(PathBuf::from("/work/agent.json")),
            SaveTarget::File(PathBuf::from("/work/base.json")),
        ];

        assert_eq!(
            profile_save_question(&one, true),
            "Update profile '/work/agent.json' with suggestions? [g] grant / [s] suppress / [Enter] skip: "
        );
        assert_eq!(
            profile_save_question(&two, true),
            "Save suggestions to a profile? [g] grant / [s] suppress / [Enter] skip: "
        );
        assert_eq!(
            profile_save_question(&two, false),
            "Save the shown rules to a profile? [g] save / [Enter] skip: "
        );
        assert_eq!(
            profile_save_question(&[SaveTarget::NewUserProfile], true),
            "Save suggestions to a user profile? [g] grant / [s] suppress / [Enter] skip: "
        );
    }

    #[cfg(unix)]
    #[test]
    fn save_refuses_target_dir_swapped_into_pack_store() {
        crate::test_env::with_isolated_config_home(|config| {
            let install_dir = crate::test_env::write_fake_pack(
                config,
                "acme",
                "packy",
                "agent",
                r#"{ "meta": { "name": "packy" } }"#,
                &[],
                None,
            );
            let pack_file = install_dir.join("profiles/agent.json");
            let pack_before = std::fs::read(&pack_file).expect("read pack profile");

            let project = TempDir::new().expect("tempdir");
            let nono_dir = project.path().join(".nono");
            std::fs::create_dir_all(&nono_dir).expect("mkdir");
            let agent = nono_dir.join("agent.json");
            std::fs::write(&agent, r#"{ "meta": { "name": "agent" } }"#).expect("write agent");
            let files = [profile::ProfileSourceFile::new(
                agent.canonicalize().expect("canonicalize"),
            )];
            let targets = save_targets(&files);
            let SaveTarget::File(path) = &targets[0] else {
                panic!("expected a file target, got {targets:?}");
            };

            std::fs::remove_dir_all(&nono_dir).expect("remove .nono");
            std::os::unix::fs::symlink(install_dir.join("profiles"), &nono_dir)
                .expect("symlink .nono into pack store");

            let mut patch = profile::Profile::default();
            patch.filesystem.read = vec!["/new".to_string()];
            let result = prepare_profile_save_to_file(&patch, path, "./.nono/agent.json")
                .and_then(|prepared| write_profile(&prepared));

            assert!(
                matches!(result, Err(NonoError::LearnError(_))),
                "expected LearnError, got {result:?}"
            );
            assert_eq!(
                std::fs::read(&pack_file).expect("read pack profile"),
                pack_before
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn save_refuses_target_swapped_for_symlink_to_another_profile() {
        let project = TempDir::new().expect("tempdir");
        let root = project.path().canonicalize().expect("canonicalize");
        let agent = root.join("agent.json");
        std::fs::write(&agent, r#"{ "meta": { "name": "agent" } }"#).expect("write agent");
        let other = root.join("other.json");
        let other_text = r#"{ "meta": { "name": "other" } }"#;
        std::fs::write(&other, other_text).expect("write other");

        std::fs::remove_file(&agent).expect("remove agent");
        std::os::unix::fs::symlink(&other, &agent).expect("symlink agent to other");

        let mut patch = profile::Profile::default();
        patch.filesystem.read = vec!["/new".to_string()];
        let result = prepare_profile_save_to_file(&patch, &agent, "./agent.json")
            .and_then(|prepared| write_profile(&prepared));

        match result {
            Err(NonoError::LearnError(msg)) => {
                assert!(msg.contains(&agent.display().to_string()), "{msg}")
            }
            other => panic!("expected LearnError, got {other:?}"),
        }
        assert_eq!(
            std::fs::read_to_string(&other).expect("read other"),
            other_text
        );
    }

    #[cfg(unix)]
    #[test]
    fn save_refuses_non_regular_target() {
        let project = TempDir::new().expect("tempdir");
        let fifo = project
            .path()
            .canonicalize()
            .expect("canonicalize")
            .join("agent.json");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRWXU).expect("mkfifo");

        let patch = profile::Profile::default();
        let result = prepare_profile_save_to_file(&patch, &fifo, "./agent.json");

        match result {
            Err(NonoError::LearnError(msg)) => {
                assert!(msg.contains(&fifo.display().to_string()), "{msg}")
            }
            other => panic!("expected LearnError, got {:?}", other.map(|_| ())),
        }
    }

    fn write_jsonc_user_profile(name: &str, contents: &str) -> PathBuf {
        let dir = profile::user_profile_dir().expect("profile dir");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join(format!("{name}.jsonc"));
        std::fs::write(&path, contents).expect("write profile");
        path
    }

    #[test]
    fn write_profile_update_keeps_jsonc_comments() {
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

        let path = write_jsonc_user_profile(
            "commented",
            "{\n  // why this profile exists\n  \"meta\": { \"name\": \"commented\", \"version\": \"1.0.0\" },\n  \"filesystem\": {\n    // project data\n    \"read\": [\"/old\"]\n  }\n}\n",
        );
        let mut patch = profile::Profile::default();
        patch.filesystem.read = vec!["/new".to_string()];

        let prepared =
            prepare_profile_save_from_patch(&patch, "claude", "commented", None).expect("prepare");
        assert!(matches!(prepared.action, SaveAction::Updated));
        write_profile(&prepared).expect("write profile");

        let written = std::fs::read_to_string(&path).expect("read profile");
        assert!(written.contains("// why this profile exists"), "{written}");
        assert!(written.contains("// project data"), "{written}");
        let reparsed = profile::parse_profile_bytes(written.as_bytes()).expect("reparse");
        assert_eq!(reparsed.filesystem.read, vec!["/old", "/new"]);
    }

    #[test]
    fn write_profile_update_invalid_file_left_unchanged() {
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

        let path = write_jsonc_user_profile(
            "broken",
            "{ \"meta\": { \"name\": \"broken\", \"version\": \"1.0.0\" } }\n",
        );
        let mut patch = profile::Profile::default();
        patch.filesystem.read = vec!["/new".to_string()];
        let prepared =
            prepare_profile_save_from_patch(&patch, "claude", "broken", None).expect("prepare");

        std::fs::write(&path, "{ invalid").expect("corrupt profile");
        let result = write_profile(&prepared);

        assert!(result.is_err(), "expected error, got {:?}", result.err());
        assert_eq!(std::fs::read(&path).expect("read profile"), b"{ invalid");
    }

    #[test]
    fn write_profile_update_edit_error_names_file() {
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

        let path = write_jsonc_user_profile(
            "array-section",
            "{ \"meta\": { \"name\": \"array-section\", \"version\": \"1.0.0\" } }\n",
        );
        let mut patch = profile::Profile::default();
        patch.filesystem.read = vec!["/new".to_string()];
        let prepared = prepare_profile_save_from_patch(&patch, "claude", "array-section", None)
            .expect("prepare");

        let array_section = "{ \"meta\": { \"name\": \"array-section\", \"version\": \"1.0.0\" }, \"filesystem\": [] }\n";
        std::fs::write(&path, array_section).expect("rewrite profile");
        let message = write_profile(&prepared)
            .expect_err("non-object section")
            .to_string();

        assert!(
            message.contains(&path.display().to_string()),
            "message: {message}"
        );
        assert_eq!(
            message.matches("Profile save error:").count(),
            1,
            "message: {message}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("read profile"),
            array_section
        );
    }

    #[test]
    fn write_profile_update_rejects_invalid_profile_left_unchanged() {
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

        let path = write_jsonc_user_profile(
            "unknown-field",
            "{ \"meta\": { \"name\": \"unknown-field\", \"version\": \"1.0.0\" } }\n",
        );
        let mut patch = profile::Profile::default();
        patch.filesystem.read = vec!["/new".to_string()];
        let prepared = prepare_profile_save_from_patch(&patch, "claude", "unknown-field", None)
            .expect("prepare");

        let unknown_field = "{ \"meta\": { \"name\": \"unknown-field\", \"version\": \"1.0.0\" }, \"bogus_field\": 1 }\n";
        std::fs::write(&path, unknown_field).expect("rewrite profile");
        let result = write_profile(&prepared);

        assert!(result.is_err(), "expected error, got {:?}", result.err());
        assert_eq!(
            std::fs::read_to_string(&path).expect("read profile"),
            unknown_field
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
            Some("nolabs-ai/claude"),
        )
        .expect("prepare");

        assert!(matches!(prepared.action, SaveAction::Created));
        assert_eq!(
            prepared.profile.extends,
            Some(vec!["nolabs-ai/claude".to_string()])
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
            Some("nolabs-ai/claude@1.2.0"),
        )
        .expect("prepare");

        assert_eq!(
            prepared.profile.extends,
            Some(vec!["nolabs-ai/claude@1.2.0".to_string()])
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

        // `linux-host-compat` is a known built-in; writing to that user path would shadow it.
        assert!(would_shadow_existing_profile("linux-host-compat"));
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
        let path = profile::get_user_profile_path("linux-host-compat").expect("profile path");
        std::fs::create_dir_all(path.parent().expect("dir")).expect("mkdir");
        std::fs::write(
            &path,
            "{\"meta\":{\"name\":\"linux-host-compat\",\"version\":\"1.0.0\"}}\n",
        )
        .expect("write");

        assert!(!would_shadow_existing_profile("linux-host-compat"));
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
                    .starts_with(".profile.json.")
            });
        assert!(!leftover, "temp file should be renamed into place");
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_does_not_follow_a_planted_temp_symlink() {
        let dir = TempDir::new().expect("temp dir");
        let target = dir.path().join("agent.json");
        std::fs::write(&target, b"original\n").expect("seed");
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"victim\n").expect("seed victim");
        let planted = dir
            .path()
            .join(format!(".agent.json.tmp.{}", std::process::id()));
        std::os::unix::fs::symlink(&victim, &planted).expect("plant symlink");

        atomic_write(&target, b"updated\n").expect("atomic write");

        assert_eq!(std::fs::read(&victim).expect("read victim"), b"victim\n");
        assert_eq!(std::fs::read(&target).expect("read target"), b"updated\n");
    }

    // ─── URL denial patch tests ───────────────────────────────────────────

    fn url_record(origin: &str, reason: UrlDenialReason) -> UrlDenialRecord {
        UrlDenialRecord {
            origin: origin.to_string(),
            reason,
        }
    }

    #[test]
    fn build_url_patch_returns_none_for_empty_input() {
        // Non-fixable denials never become records, so an empty slice models a
        // run where only non-fixable URL opens were rejected: no patch.
        assert!(build_url_patch(&[]).is_none());
    }

    #[test]
    fn build_url_patch_collects_origin_grants_deduplicated() {
        let denials = vec![
            url_record(
                "https://accounts.google.com",
                UrlDenialReason::OriginNotAllowed,
            ),
            url_record(
                "https://accounts.google.com",
                UrlDenialReason::OriginNotAllowed,
            ),
            url_record("https://github.com", UrlDenialReason::OriginNotAllowed),
        ];
        let patch = build_url_patch(&denials).expect("patch for origin denials");
        let urls = patch.open_urls.expect("open_urls set");
        assert_eq!(
            urls.allow_origins,
            vec!["https://accounts.google.com", "https://github.com"]
        );
        assert!(!urls.allow_localhost);
    }

    #[test]
    fn build_url_patch_enables_localhost_for_localhost_denial() {
        let denials = vec![
            // Localhost record carries empty origin.
            url_record("", UrlDenialReason::LocalhostNotAllowed),
            url_record("", UrlDenialReason::LocalhostNotAllowed),
        ];
        let patch = build_url_patch(&denials).expect("patch for localhost denial");
        let urls = patch.open_urls.expect("open_urls set");
        assert!(urls.allow_origins.is_empty());
        assert!(urls.allow_localhost);
    }

    #[test]
    fn build_url_patch_combines_origins_and_localhost() {
        let denials = vec![
            url_record(
                "https://oauth.example.com",
                UrlDenialReason::OriginNotAllowed,
            ),
            url_record("", UrlDenialReason::LocalhostNotAllowed),
        ];
        let patch = build_url_patch(&denials).expect("combined patch");
        let urls = patch.open_urls.expect("open_urls set");
        assert_eq!(urls.allow_origins, vec!["https://oauth.example.com"]);
        assert!(urls.allow_localhost);
    }

    #[test]
    fn build_combined_patch_from_items_routes_url_origin_grants() {
        let items = vec![
            DenialItem::Url {
                origin: "https://accounts.google.com".to_string(),
                kind: UrlItemKind::Origin,
                action: UrlItemAction::Grant,
            },
            DenialItem::Url {
                origin: "https://github.com".to_string(),
                kind: UrlItemKind::Origin,
                action: UrlItemAction::Skip,
            },
        ];
        let patch = build_combined_patch_from_items(&items).expect("patch from granted items");
        let urls = patch.open_urls.expect("open_urls set");
        // Skipped origin must NOT appear; granted origin must.
        assert_eq!(urls.allow_origins, vec!["https://accounts.google.com"]);
        assert!(!urls.allow_localhost);
    }

    #[test]
    fn build_combined_patch_from_items_routes_localhost_grant() {
        let items = vec![DenialItem::Url {
            origin: String::new(),
            kind: UrlItemKind::Localhost,
            action: UrlItemAction::Grant,
        }];
        let patch = build_combined_patch_from_items(&items).expect("patch from localhost grant");
        let urls = patch.open_urls.expect("open_urls set");
        assert!(urls.allow_origins.is_empty());
        assert!(urls.allow_localhost);
    }

    #[test]
    fn build_combined_patch_from_items_returns_none_when_all_urls_skipped() {
        let items = vec![DenialItem::Url {
            origin: "https://accounts.google.com".to_string(),
            kind: UrlItemKind::Origin,
            action: UrlItemAction::Skip,
        }];
        assert!(build_combined_patch_from_items(&items).is_none());
    }

    #[test]
    fn build_combined_patch_from_items_dedupes_origin_grants() {
        let items = vec![
            DenialItem::Url {
                origin: "https://dup.example.com".to_string(),
                kind: UrlItemKind::Origin,
                action: UrlItemAction::Grant,
            },
            DenialItem::Url {
                origin: "https://dup.example.com".to_string(),
                kind: UrlItemKind::Origin,
                action: UrlItemAction::Grant,
            },
        ];
        let patch = build_combined_patch_from_items(&items).expect("patch");
        let urls = patch.open_urls.expect("open_urls set");
        assert_eq!(urls.allow_origins, vec!["https://dup.example.com"]);
    }

    #[test]
    fn merge_profile_patch_appends_origins_deduplicated() {
        let mut base = profile::Profile {
            open_urls: Some(profile::OpenUrlConfig {
                allow_origins: vec!["https://existing.example.com".to_string()],
                allow_localhost: false,
            }),
            ..Default::default()
        };
        let patch = profile::Profile {
            open_urls: Some(profile::OpenUrlConfig {
                allow_origins: vec![
                    "https://existing.example.com".to_string(),
                    "https://new.example.com".to_string(),
                ],
                allow_localhost: false,
            }),
            ..Default::default()
        };
        merge_profile_patch(&mut base, &patch);
        let urls = base.open_urls.expect("open_urls present");
        assert_eq!(
            urls.allow_origins,
            vec!["https://existing.example.com", "https://new.example.com"]
        );
    }

    #[test]
    fn merge_profile_patch_localhost_is_monotonic_true_stays_true() {
        // Base already allows localhost; patch without localhost must not disable it.
        let mut base = profile::Profile {
            open_urls: Some(profile::OpenUrlConfig {
                allow_origins: vec![],
                allow_localhost: true,
            }),
            ..Default::default()
        };
        let patch = profile::Profile {
            open_urls: Some(profile::OpenUrlConfig {
                allow_origins: vec!["https://only-in-patch.example.com".to_string()],
                allow_localhost: false,
            }),
            ..Default::default()
        };
        merge_profile_patch(&mut base, &patch);
        let urls = base.open_urls.expect("open_urls present");
        assert!(
            urls.allow_localhost,
            "localhost must remain true (monotonic)"
        );
        assert_eq!(
            urls.allow_origins,
            vec!["https://only-in-patch.example.com"]
        );
    }

    #[test]
    fn merge_profile_patch_localhost_flips_false_to_true() {
        let mut base = profile::Profile {
            open_urls: Some(profile::OpenUrlConfig {
                allow_origins: vec![],
                allow_localhost: false,
            }),
            ..Default::default()
        };
        let patch = profile::Profile {
            open_urls: Some(profile::OpenUrlConfig {
                allow_origins: vec![],
                allow_localhost: true,
            }),
            ..Default::default()
        };
        merge_profile_patch(&mut base, &patch);
        let urls = base.open_urls.expect("open_urls present");
        assert!(urls.allow_localhost, "localhost must flip to true");
    }

    #[test]
    fn merge_profile_patch_creates_open_urls_when_base_has_none() {
        let mut base = profile::Profile::default();
        let patch = profile::Profile {
            open_urls: Some(profile::OpenUrlConfig {
                allow_origins: vec!["https://brand-new.example.com".to_string()],
                allow_localhost: true,
            }),
            ..Default::default()
        };
        merge_profile_patch(&mut base, &patch);
        let urls = base.open_urls.expect("open_urls created");
        assert_eq!(urls.allow_origins, vec!["https://brand-new.example.com"]);
        assert!(urls.allow_localhost);
    }

    #[test]
    fn merge_profile_patch_skips_open_urls_when_patch_has_none() {
        let mut base = profile::Profile {
            open_urls: Some(profile::OpenUrlConfig {
                allow_origins: vec!["https://keep.example.com".to_string()],
                allow_localhost: true,
            }),
            ..Default::default()
        };
        let patch = profile::Profile::default();
        merge_profile_patch(&mut base, &patch);
        let urls = base.open_urls.expect("open_urls preserved");
        assert_eq!(urls.allow_origins, vec!["https://keep.example.com"]);
        assert!(urls.allow_localhost);
    }

    // ─── Interactive selector key decoding ────────────────────────────────

    /// Decode a byte sequence the way `read_key` does. An exhausted buffer
    /// stands in for the tty's VTIME timeout.
    fn decode(bytes: &[u8]) -> Key {
        let (first, rest) = bytes.split_first().expect("non-empty input");
        if *first == 0x1b {
            decode_escape_sequence(&mut std::io::Cursor::new(rest))
        } else {
            decode_plain_byte(*first)
        }
    }

    #[test]
    fn bare_esc_decodes_as_cancel() {
        assert_eq!(decode(b"\x1b"), Key::Esc);
    }

    #[test]
    fn up_and_down_arrows_still_decode() {
        assert_eq!(decode(b"\x1b[A"), Key::Up);
        assert_eq!(decode(b"\x1b[B"), Key::Down);
        // SS3 form emitted by some terminals in application cursor mode.
        assert_eq!(decode(b"\x1bOA"), Key::Up);
        assert_eq!(decode(b"\x1bOB"), Key::Down);
    }

    #[test]
    fn unhandled_escape_sequences_are_not_cancel() {
        // Issue #1845: right arrow used to decode as Esc and close the menu.
        for seq in [
            &b"\x1b[C"[..],    // right arrow
            &b"\x1b[D"[..],    // left arrow
            &b"\x1b[H"[..],    // home
            &b"\x1b[F"[..],    // end
            &b"\x1b[5~"[..],   // page up
            &b"\x1b[6~"[..],   // page down
            &b"\x1b[1;5C"[..], // ctrl+right
            &b"\x1b[200~"[..], // bracketed paste start
            &b"\x1bOP"[..],    // F1 (SS3)
            &b"\x1bx"[..],     // alt+x
        ] {
            assert_eq!(
                decode(seq),
                Key::Unknown,
                "sequence {seq:?} must be ignored"
            );
        }
    }

    #[test]
    fn multi_byte_sequence_is_consumed_whole() {
        // Ctrl+Right then Enter: only the Enter may be left to read.
        let mut input = std::io::Cursor::new(&b"[1;5C\r"[..]);
        assert_eq!(decode_escape_sequence(&mut input), Key::Unknown);

        let mut remaining = Vec::new();
        std::io::Read::read_to_end(&mut input, &mut remaining).expect("read remainder");
        assert_eq!(remaining, b"\r");
    }

    #[test]
    fn malformed_escape_sequence_terminates() {
        // No final byte ever arrives; the scan must stop.
        let mut input = std::io::Cursor::new(vec![b';'; 4096]);
        assert_eq!(
            decode_escape_sequence_with_introducer(&mut input),
            Key::Unknown
        );
    }

    fn decode_escape_sequence_with_introducer<R: std::io::Read>(reader: &mut R) -> Key {
        decode_escape_sequence(&mut std::io::Read::chain(&b"["[..], reader))
    }

    #[test]
    fn control_keys_decode_as_cancel_or_confirm() {
        assert_eq!(decode(b"\x03"), Key::CtrlC);
        assert_eq!(decode(b"\x04"), Key::CtrlD);
        assert_eq!(decode(b"\r"), Key::Enter);
        assert_eq!(decode(b"\n"), Key::Enter);
        assert_eq!(decode(b" "), Key::Space);
        assert_eq!(decode(b"a"), Key::Char('a'));
    }

    #[test]
    fn input_guard_discards_queued_keys_before_arming() {
        use nix::pty::{OpenptyResult, openpty};

        let OpenptyResult { master, slave } = openpty(None, None).expect("openpty");
        let saved = nix::sys::termios::tcgetattr(&slave).expect("tcgetattr");
        let mut raw_termios = saved.clone();
        configure_raw_termios(&mut raw_termios);
        nix::sys::termios::tcsetattr(&slave, nix::sys::termios::SetArg::TCSANOW, &raw_termios)
            .expect("tcsetattr");

        nix::unistd::write(&master, b"\r").expect("queue early Enter");
        let mut guard = RawTtyGuard {
            tty: std::fs::File::from(slave),
            saved,
        };
        guard
            .arm_input_after(Duration::ZERO)
            .expect("arm selector input");

        nix::unistd::write(&master, b"d").expect("write key after arming");
        assert_eq!(guard.read_key().expect("read key"), Key::Char('d'));
    }
}
