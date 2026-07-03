//! One-shot cleanup of pre-0.43 inbuilt Claude Code integration.
//!
//! Pre-0.43 installs wrote `~/.claude/hooks/nono-hook.sh` and patched
//! `~/.claude/settings.json::hooks` with one matching command entry.
//! Post-0.43 the integration ships as a registry pack
//! (`nolabs-ai/claude`) with its own marketplace-based plugin
//! install. If the legacy state isn't removed, Claude Code runs both —
//! duplicate hook execution at best, broken behaviour if the legacy
//! `nono-hook.sh` references binaries the current nono no longer ships.
//!
//! Flow: scan for legacy artifacts → if any found, prompt the user with
//! a per-item summary → on accept, strip matching `settings.json` hook
//! entries via `serde_json` (atomic write-back, all unrelated keys
//! preserved), rename the hook file to `.legacy-bak` so any hand-edits
//! survive → print a summary of what changed.
//!
//! Idempotent: re-running on an already-clean install is a silent no-op
//! (no prompt, no work).
//!
//! Why rename rather than delete the hook file: the binary no longer
//! embeds the canonical `nono-hook.sh`, so we can't SHA-match against a
//! known-good copy to decide "definitely safe to delete". A `.legacy-bak`
//! preserves any user customisation; the user can `rm` the backup.

use colored::Colorize;
use nono::{NonoError, Result};
use serde_json::Value;
use std::fs;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

const LEGACY_HOOK_SCRIPT_REL: &str = ".claude/hooks/nono-hook.sh";
const LEGACY_HOOK_COMMAND_TEMPLATE: &str = "$HOME/.claude/hooks/nono-hook.sh";
const LEGACY_BAK_SUFFIX: &str = ".legacy-bak";
const LEGACY_PLUGIN_KEY: &str = "nono@always-further";

/// What `scan` found on disk. Empty = nothing to do.
#[derive(Debug, Default, Clone)]
pub struct LegacyArtifacts {
    /// Path to `~/.claude/hooks/nono-hook.sh` if it exists.
    pub files: Vec<PathBuf>,
    /// Hook entries inside `~/.claude/settings.json` that reference the
    /// legacy script. Stored as `(event, command)` for display.
    pub settings_entries: Vec<(String, String)>,
    /// Whether `enabledPlugins["nono@always-further"]` is present in
    /// `~/.claude/settings.json`. The new pack writes `nono@nolabs-ai`;
    /// leaving both in place causes Claude Code to see two `nono` plugins
    /// from different marketplaces and silently fail one or both.
    pub legacy_plugin_key: bool,
    /// Resolved path to `~/.claude/settings.json` (only set when at
    /// least one matching entry was found).
    settings_path: Option<PathBuf>,
}

impl LegacyArtifacts {
    pub fn is_empty(&self) -> bool {
        self.files.is_empty() && self.settings_entries.is_empty() && !self.legacy_plugin_key
    }
}

/// What `apply` actually did.
#[derive(Debug, Default)]
pub struct LegacyCleanupReport {
    pub renamed_files: Vec<(PathBuf, PathBuf)>,
    pub removed_settings_entries: Vec<(String, String)>,
    pub removed_plugin_key: bool,
    pub settings_path: Option<PathBuf>,
}

impl LegacyCleanupReport {
    fn is_empty(&self) -> bool {
        self.renamed_files.is_empty()
            && self.removed_settings_entries.is_empty()
            && !self.removed_plugin_key
    }
}

/// Public entry point. Scans for legacy state; if any is present, asks
/// the user before touching anything. Returns Ok(()) on clean install,
/// successful cleanup, or declined prompt — the caller doesn't branch on
/// the outcome. A serialise / atomic-write failure during apply is the
/// only error returned; pre-pull state is left untouched on Err.
pub fn check_and_offer_cleanup() -> Result<()> {
    let Some(home) = xdg_home::home_dir() else {
        return Ok(());
    };
    let artifacts = scan(&home);
    if artifacts.is_empty() {
        return Ok(());
    }

    if !confirm(&artifacts) {
        emit_declined_hint();
        return Ok(());
    }

    let report = apply(&artifacts, &home)?;
    if !report.is_empty() {
        emit_summary(&report);
    }
    Ok(())
}

fn scan(home: &Path) -> LegacyArtifacts {
    let mut artifacts = LegacyArtifacts::default();

    let script = home.join(LEGACY_HOOK_SCRIPT_REL);
    if script.exists() {
        artifacts.files.push(script);
    }

    let settings_path = home.join(".claude").join("settings.json");
    if let Some((entries, has_plugin_key)) = scan_settings(&settings_path, home) {
        if !entries.is_empty() {
            artifacts.settings_entries = entries;
        }
        if has_plugin_key {
            artifacts.legacy_plugin_key = true;
        }
        if !artifacts.settings_entries.is_empty() || artifacts.legacy_plugin_key {
            artifacts.settings_path = Some(settings_path);
        }
    }

    artifacts
}

/// Walk `settings.json` looking for legacy artifacts. Returns `None` if
/// the file is missing or unparseable (treated as "nothing to clean").
/// Returns `Some((hook_entries, has_legacy_plugin_key))`. Pure inspection
/// — no mutation.
fn scan_settings(path: &Path, home: &Path) -> Option<(Vec<(String, String)>, bool)> {
    if !path.exists() {
        return None;
    }
    let content = fs::read_to_string(path).ok()?;
    let settings: Value = serde_json::from_str(&content).ok()?;

    let has_plugin_key = settings
        .get("enabledPlugins")
        .and_then(Value::as_object)
        .map_or(false, |p| p.contains_key(LEGACY_PLUGIN_KEY));

    let mut found = Vec::new();
    if let Some(hooks) = settings.get("hooks").and_then(Value::as_object) {
        for (event, matchers) in hooks {
            let Some(matchers) = matchers.as_array() else {
                continue;
            };
            for matcher in matchers {
                let Some(inner) = matcher.get("hooks").and_then(Value::as_array) else {
                    continue;
                };
                for entry in inner {
                    let Some(cmd) = entry.get("command").and_then(Value::as_str) else {
                        continue;
                    };
                    if matches_legacy_command(cmd, home) {
                        found.push((event.clone(), cmd.to_string()));
                    }
                }
            }
        }
    }
    Some((found, has_plugin_key))
}

fn matches_legacy_command(cmd: &str, home: &Path) -> bool {
    if cmd == LEGACY_HOOK_COMMAND_TEMPLATE {
        return true;
    }
    let expanded = LEGACY_HOOK_COMMAND_TEMPLATE.replace("$HOME", &home.to_string_lossy());
    cmd == expanded
}

fn confirm(artifacts: &LegacyArtifacts) -> bool {
    let mut err = io::stderr().lock();
    let _ = writeln!(err);
    let _ = writeln!(
        err,
        "  {}  Legacy nono integration detected in ~/.claude.",
        "⚠".yellow(),
    );
    let _ = writeln!(err);
    let _ = writeln!(
        err,
        "     Pre-0.43 installs wrote a hook script and a matching settings.json"
    );
    let _ = writeln!(
        err,
        "     entry that the registry pack does not manage. If left in place,"
    );
    let _ = writeln!(
        err,
        "     Claude Code will run both the legacy hook and the new pack hooks."
    );
    let _ = writeln!(err);

    if !artifacts.files.is_empty() {
        let _ = writeln!(err, "     {}:", "Files to rename".dimmed());
        for path in &artifacts.files {
            let _ = writeln!(
                err,
                "       {} → {}{}",
                path.display(),
                path.display(),
                LEGACY_BAK_SUFFIX
            );
        }
        let _ = writeln!(err);
    }
    if !artifacts.settings_entries.is_empty() {
        let _ = writeln!(
            err,
            "     {} (~/.claude/settings.json):",
            "Hook entries to remove".dimmed()
        );
        for (event, cmd) in &artifacts.settings_entries {
            let _ = writeln!(err, "       [{event}]  {cmd}");
        }
        let _ = writeln!(err);
    }
    if artifacts.legacy_plugin_key {
        let _ = writeln!(
            err,
            "     {} (~/.claude/settings.json):",
            "Plugin key to remove".dimmed()
        );
        let _ = writeln!(
            err,
            "       enabledPlugins[\"{LEGACY_PLUGIN_KEY}\"] — replaced by nono@nolabs-ai"
        );
        let _ = writeln!(err);
    }

    let interactive = io::stdin().is_terminal() && io::stderr().is_terminal();
    if !interactive {
        let _ = writeln!(
            err,
            "  no TTY available — skipping cleanup. Re-run interactively to apply."
        );
        let _ = writeln!(err);
        return false;
    }

    let _ = write!(err, "  Apply cleanup? [Y/n] ");
    let _ = err.flush();
    drop(err);

    let mut line = String::new();
    if io::stdin().lock().read_line(&mut line).is_err() {
        return false;
    }
    let answer = line.trim().to_ascii_lowercase();
    answer.is_empty() || answer == "y" || answer == "yes"
}

fn apply(artifacts: &LegacyArtifacts, home: &Path) -> Result<LegacyCleanupReport> {
    let mut report = LegacyCleanupReport::default();

    if let Some(path) = &artifacts.settings_path {
        let (removed_entries, removed_plugin_key) =
            strip_settings_entries(path, home, artifacts.legacy_plugin_key)?;
        if !removed_entries.is_empty() {
            report.removed_settings_entries = removed_entries;
            report.settings_path = Some(path.clone());
        }
        if removed_plugin_key {
            report.removed_plugin_key = true;
            report.settings_path.get_or_insert_with(|| path.clone());
        }
    }

    for path in &artifacts.files {
        let backup = backup_path_for(path);
        // If a prior aborted run already produced a `.legacy-bak`, leave
        // it alone and just remove the source — preserves the earliest
        // backup (most likely to be the user's hand edit).
        if backup.exists() {
            fs::remove_file(path).map_err(NonoError::Io)?;
        } else {
            fs::rename(path, &backup).map_err(NonoError::Io)?;
            report.renamed_files.push((path.clone(), backup));
        }
    }

    Ok(report)
}

/// Mutate the on-disk settings.json in one atomic write: drop hook
/// entries whose `command` is a legacy reference (pruning empty matchers
/// and event arrays), and optionally remove `enabledPlugins["nono@always-further"]`.
/// All other keys are preserved. Returns `(removed_hook_entries, plugin_key_removed)`.
fn strip_settings_entries(
    path: &Path,
    home: &Path,
    remove_plugin_key: bool,
) -> Result<(Vec<(String, String)>, bool)> {
    let content = fs::read_to_string(path).map_err(NonoError::Io)?;
    let mut settings: Value = serde_json::from_str(&content)
        .map_err(|e| NonoError::HookInstall(format!("parse {}: {e}", path.display())))?;

    let Some(obj) = settings.as_object_mut() else {
        return Ok((Vec::new(), false));
    };

    let mut removed: Vec<(String, String)> = Vec::new();
    if let Some(hooks) = obj.get_mut("hooks").and_then(Value::as_object_mut) {
        let event_keys: Vec<String> = hooks.keys().cloned().collect();
        for event in event_keys {
            let drop_event = {
                let Some(matchers) = hooks.get_mut(&event).and_then(Value::as_array_mut) else {
                    continue;
                };
                matchers.retain_mut(|matcher| {
                    let Some(inner) = matcher.get_mut("hooks").and_then(Value::as_array_mut)
                    else {
                        return true;
                    };
                    inner.retain(|h| {
                        let Some(cmd) = h.get("command").and_then(Value::as_str) else {
                            return true;
                        };
                        if matches_legacy_command(cmd, home) {
                            removed.push((event.clone(), cmd.to_string()));
                            return false;
                        }
                        true
                    });
                    !inner.is_empty()
                });
                matchers.is_empty()
            };
            if drop_event {
                hooks.remove(&event);
            }
        }
    }

    let mut plugin_key_removed = false;
    if remove_plugin_key {
        if let Some(plugins) = obj.get_mut("enabledPlugins").and_then(Value::as_object_mut) {
            plugin_key_removed = plugins.remove(LEGACY_PLUGIN_KEY).is_some();
        }
    }

    if removed.is_empty() && !plugin_key_removed {
        return Ok((removed, false));
    }

    let serialized = serde_json::to_string_pretty(&settings)
        .map_err(|e| NonoError::HookInstall(format!("serialize {}: {e}", path.display())))?;
    let tmp = path.with_extension("json.nono-tmp");
    fs::write(&tmp, format!("{serialized}\n")).map_err(NonoError::Io)?;
    fs::rename(&tmp, path).map_err(NonoError::Io)?;

    Ok((removed, plugin_key_removed))
}

fn backup_path_for(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("legacy");
    path.with_file_name(format!("{file_name}{LEGACY_BAK_SUFFIX}"))
}

fn emit_summary(report: &LegacyCleanupReport) {
    let mut err = io::stderr().lock();
    let _ = writeln!(err);
    let _ = writeln!(err, "  {}  Legacy cleanup complete.", "✓".green());
    if !report.renamed_files.is_empty() {
        let _ = writeln!(err, "     {}:", "Renamed".dimmed());
        for (from, to) in &report.renamed_files {
            let _ = writeln!(err, "       {} → {}", from.display(), to.display());
        }
    }
    if !report.removed_settings_entries.is_empty() {
        if let Some(path) = &report.settings_path {
            let _ = writeln!(
                err,
                "     {} ({}):",
                "Removed hook entries".dimmed(),
                path.display()
            );
        } else {
            let _ = writeln!(err, "     {}:", "Removed hook entries".dimmed());
        }
        for (event, cmd) in &report.removed_settings_entries {
            let _ = writeln!(err, "       [{event}]  {cmd}");
        }
    }
    if report.removed_plugin_key {
        let _ = writeln!(err, "     {}:", "Removed plugin key".dimmed());
        let _ = writeln!(err, "       enabledPlugins[\"{LEGACY_PLUGIN_KEY}\"]");
    }
    let _ = writeln!(err);
}

fn emit_declined_hint() {
    let mut err = io::stderr().lock();
    let _ = writeln!(err, "  cleanup skipped — legacy hooks left in place.");
    let _ = writeln!(
        err,
        "  to apply later, re-run with the same profile and accept the prompt."
    );
    let _ = writeln!(err);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    fn fake_home_with(settings: Option<Value>, files: &[&str]) -> TempDir {
        let dir = TempDir::new().expect("tempdir");
        let claude = dir.path().join(".claude");
        let hooks = claude.join("hooks");
        fs::create_dir_all(&hooks).expect("mkdir hooks");
        for f in files {
            fs::write(claude.join(f), b"# legacy\n").expect("write legacy file");
        }
        if let Some(value) = settings {
            fs::write(
                claude.join("settings.json"),
                serde_json::to_string_pretty(&value).expect("ser"),
            )
            .expect("write settings");
        }
        dir
    }

    #[test]
    fn scan_clean_install_returns_empty() {
        let dir = TempDir::new().expect("tempdir");
        let artifacts = scan(dir.path());
        assert!(artifacts.is_empty());
    }

    #[test]
    fn scan_finds_legacy_hook_script() {
        let dir = fake_home_with(None, &["hooks/nono-hook.sh"]);
        let artifacts = scan(dir.path());
        assert_eq!(artifacts.files.len(), 1);
        assert!(artifacts.files[0].ends_with("nono-hook.sh"));
        assert!(artifacts.settings_entries.is_empty());
    }

    #[test]
    fn scan_finds_legacy_settings_entries() {
        let home = TempDir::new().expect("tempdir");
        let claude = home.path().join(".claude");
        fs::create_dir_all(&claude).expect("mkdir");
        let expanded_cmd = format!("{}/.claude/hooks/nono-hook.sh", home.path().display());
        let settings = json!({
            "theme": "light",
            "hooks": {
                "PreToolUse": [
                    { "matcher": "*", "hooks": [
                        { "type": "command", "command": "$HOME/.claude/hooks/nono-hook.sh" }
                    ]}
                ],
                "PostToolUse": [
                    { "matcher": "Bash", "hooks": [
                        { "type": "command", "command": expanded_cmd },
                        { "type": "command", "command": "/usr/local/bin/user-hook" }
                    ]}
                ]
            }
        });
        fs::write(
            claude.join("settings.json"),
            serde_json::to_string_pretty(&settings).expect("ser"),
        )
        .expect("write");

        let artifacts = scan(home.path());
        assert!(artifacts.files.is_empty());
        assert_eq!(artifacts.settings_entries.len(), 2);
        assert_eq!(artifacts.settings_entries[0].0, "PreToolUse");
        assert_eq!(artifacts.settings_entries[1].0, "PostToolUse");
    }

    #[test]
    fn apply_renames_legacy_hook_script() {
        let dir = fake_home_with(None, &["hooks/nono-hook.sh"]);
        let artifacts = scan(dir.path());
        let report = apply(&artifacts, dir.path()).expect("apply");
        assert_eq!(report.renamed_files.len(), 1);
        let (from, to) = &report.renamed_files[0];
        assert!(!from.exists(), "source should be gone");
        assert!(to.exists(), "backup should exist");
        assert!(to.to_string_lossy().ends_with(LEGACY_BAK_SUFFIX));
    }

    #[test]
    fn apply_strips_legacy_hook_entries_preserving_user_hooks() {
        let home = TempDir::new().expect("tempdir");
        let claude = home.path().join(".claude");
        fs::create_dir_all(&claude).expect("mkdir");
        let expanded_cmd = format!("{}/.claude/hooks/nono-hook.sh", home.path().display());
        let settings = json!({
            "theme": "light",
            "enabledPlugins": { "nono@nolabs-ai": true },
            "hooks": {
                "PreToolUse": [
                    { "matcher": "*", "hooks": [
                        { "type": "command", "command": "$HOME/.claude/hooks/nono-hook.sh" }
                    ]}
                ],
                "PostToolUse": [
                    { "matcher": "Bash", "hooks": [
                        { "type": "command", "command": expanded_cmd },
                        { "type": "command", "command": "/usr/local/bin/user-hook" }
                    ]}
                ]
            }
        });
        let settings_path = claude.join("settings.json");
        fs::write(
            &settings_path,
            serde_json::to_string_pretty(&settings).expect("ser"),
        )
        .expect("write");

        let artifacts = scan(home.path());
        let report = apply(&artifacts, home.path()).expect("apply");
        assert_eq!(report.removed_settings_entries.len(), 2);

        let after: Value = serde_json::from_str(&fs::read_to_string(&settings_path).expect("read"))
            .expect("parse");

        assert_eq!(after["theme"], "light", "unrelated keys preserved");
        assert_eq!(
            after["enabledPlugins"]["nono@nolabs-ai"], true,
            "plugin entries preserved"
        );
        assert!(
            after["hooks"].get("PreToolUse").is_none(),
            "empty event dropped"
        );
        let post = after["hooks"]["PostToolUse"]
            .as_array()
            .expect("post array");
        assert_eq!(post.len(), 1, "matcher preserved");
        let inner = post[0]["hooks"].as_array().expect("inner array");
        assert_eq!(inner.len(), 1, "user hook preserved");
        assert_eq!(inner[0]["command"], "/usr/local/bin/user-hook");
    }

    #[test]
    fn scan_detects_legacy_plugin_key() {
        let home = TempDir::new().expect("tempdir");
        let claude = home.path().join(".claude");
        fs::create_dir_all(&claude).expect("mkdir");
        let settings = json!({
            "enabledPlugins": { "nono@always-further": true, "other-plugin@somewhere": true }
        });
        fs::write(
            claude.join("settings.json"),
            serde_json::to_string_pretty(&settings).expect("ser"),
        )
        .expect("write");

        let artifacts = scan(home.path());
        assert!(artifacts.legacy_plugin_key, "should detect legacy plugin key");
        assert!(artifacts.settings_entries.is_empty());
        assert!(!artifacts.is_empty());
    }

    #[test]
    fn apply_removes_legacy_plugin_key_preserving_other_plugins() {
        let home = TempDir::new().expect("tempdir");
        let claude = home.path().join(".claude");
        fs::create_dir_all(&claude).expect("mkdir");
        let settings = json!({
            "theme": "dark",
            "enabledPlugins": {
                "nono@always-further": true,
                "nono@nolabs-ai": true,
                "other-plugin@somewhere": true
            }
        });
        let settings_path = claude.join("settings.json");
        fs::write(
            &settings_path,
            serde_json::to_string_pretty(&settings).expect("ser"),
        )
        .expect("write");

        let artifacts = scan(home.path());
        assert!(artifacts.legacy_plugin_key);
        let report = apply(&artifacts, home.path()).expect("apply");
        assert!(report.removed_plugin_key);

        let after: Value =
            serde_json::from_str(&fs::read_to_string(&settings_path).expect("read"))
                .expect("parse");

        assert_eq!(after["theme"], "dark", "unrelated keys preserved");
        assert!(
            after["enabledPlugins"].get("nono@always-further").is_none(),
            "legacy plugin key removed"
        );
        assert_eq!(
            after["enabledPlugins"]["nono@nolabs-ai"], true,
            "new plugin key preserved"
        );
        assert_eq!(
            after["enabledPlugins"]["other-plugin@somewhere"], true,
            "unrelated plugin preserved"
        );
    }

    #[test]
    fn apply_is_idempotent_on_clean_settings() {
        let dir = TempDir::new().expect("tempdir");
        let claude = dir.path().join(".claude");
        fs::create_dir_all(&claude).expect("mkdir");
        let settings = json!({
            "hooks": {
                "PreToolUse": [
                    { "matcher": "*", "hooks": [
                        { "type": "command", "command": "/usr/local/bin/user-hook" }
                    ]}
                ]
            }
        });
        let settings_path = claude.join("settings.json");
        fs::write(
            &settings_path,
            serde_json::to_string_pretty(&settings).expect("ser"),
        )
        .expect("write");

        let artifacts = scan(dir.path());
        assert!(artifacts.is_empty());
    }

    #[test]
    fn apply_skips_rename_if_backup_already_exists() {
        let dir = TempDir::new().expect("tempdir");
        let hooks = dir.path().join(".claude").join("hooks");
        fs::create_dir_all(&hooks).expect("mkdir");
        fs::write(hooks.join("nono-hook.sh"), b"# fresh\n").expect("write source");
        fs::write(
            hooks.join(format!("nono-hook.sh{LEGACY_BAK_SUFFIX}")),
            b"# old hand edit\n",
        )
        .expect("write existing backup");

        let artifacts = scan(dir.path());
        let report = apply(&artifacts, dir.path()).expect("apply");

        assert!(
            report.renamed_files.is_empty(),
            "no new rename when backup already present"
        );
        assert!(!hooks.join("nono-hook.sh").exists(), "source removed");
        let preserved = fs::read_to_string(hooks.join(format!("nono-hook.sh{LEGACY_BAK_SUFFIX}")))
            .expect("read backup");
        assert!(
            preserved.contains("old hand edit"),
            "earliest backup preserved"
        );
    }

    #[test]
    fn matches_legacy_command_recognises_template_and_expanded_forms() {
        let home = PathBuf::from("/Users/alice");
        assert!(matches_legacy_command(
            "$HOME/.claude/hooks/nono-hook.sh",
            &home
        ));
        assert!(matches_legacy_command(
            "/Users/alice/.claude/hooks/nono-hook.sh",
            &home
        ));
        assert!(!matches_legacy_command("/usr/local/bin/user-hook", &home));
        // A different user's expanded path must not match — guards
        // against accidentally stripping someone else's hook entry that
        // happens to mention `nono-hook.sh` under a different home.
        assert!(!matches_legacy_command(
            "/Users/bob/.claude/hooks/nono-hook.sh",
            &home
        ));
    }
}
