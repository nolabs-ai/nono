//! User configuration loading
//!
//! Loads user-level configuration from `$XDG_CONFIG_HOME/nono/config.toml`
//! (default `~/.config/nono/config.toml`).

#![allow(dead_code)]

use nono::{NonoError, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

/// User configuration file name
const USER_CONFIG_FILE: &str = "config.toml";

/// Root structure for user config
#[derive(Debug, Default, Deserialize)]
pub struct UserConfig {
    #[serde(default)]
    pub meta: UserConfigMeta,
    #[serde(default)]
    pub overrides: UserOverrides,
    #[serde(default)]
    pub extensions: UserExtensions,
    #[serde(default)]
    pub trusted_keys: HashMap<String, TrustedKeyInfo>,
    /// ALIAS(canonical="rollback", introduced="v0.0.0", remove_by="indefinite", issue="#124")
    #[serde(default, alias = "undo")]
    pub rollback: RollbackSettings,
    #[serde(default)]
    pub updates: UpdateSettings,
    #[serde(default)]
    pub registry: RegistrySettings,
    #[serde(default)]
    pub ui: UiSettings,
    #[serde(default)]
    pub redaction: RedactionSettings,
}

/// UI display settings
#[derive(Debug, Default, Clone, Deserialize)]
pub struct UiSettings {
    /// Color theme name (mocha, latte, frappe, macchiato, tokyo-night, minimal)
    #[serde(default)]
    pub theme: Option<String>,
    /// In-band PTY detach sequence, e.g. "ctrl-] d"
    #[serde(default)]
    pub detach_sequence: Option<DetachSequence>,
}

/// Output redaction settings for command context persisted in sessions and audit logs.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct RedactionSettings {
    /// Additional command flags whose following value, or `--flag=value` value,
    /// should be redacted.
    #[serde(default)]
    pub extra_flags: Vec<String>,
    /// Additional HTTP header names whose value should be redacted.
    #[serde(default)]
    pub extra_headers: Vec<String>,
    /// Additional URL query parameter names whose value should be redacted.
    #[serde(default)]
    pub extra_query_keys: Vec<String>,
    /// Additional environment variable names whose value should be redacted.
    #[serde(default)]
    pub extra_env_vars: Vec<String>,
    /// Required before any secure default redaction names can be removed.
    #[serde(default)]
    pub unsafe_redaction_overrides: bool,
    /// Secure default names to stop redacting for unsafe debugging sessions.
    #[serde(default)]
    pub allow_unredacted_defaults: Vec<String>,
}

impl RedactionSettings {
    pub fn to_scrub_policy(&self) -> Result<nono::ScrubPolicy> {
        if !self.unsafe_redaction_overrides && !self.allow_unredacted_defaults.is_empty() {
            return Err(NonoError::ConfigParse(
                "[redaction].allow_unredacted_defaults requires \
                 unsafe_redaction_overrides = true"
                    .to_string(),
            ));
        }

        let mut redactions = nono::ScrubPolicy::secure_default();
        for flag in &self.extra_flags {
            redactions.add_flag(flag);
        }
        for header in &self.extra_headers {
            redactions.add_header(header);
        }
        for key in &self.extra_query_keys {
            redactions.add_query_key(key);
        }
        for name in &self.extra_env_vars {
            redactions.add_env_var(name);
        }

        if self.unsafe_redaction_overrides {
            for name in &self.allow_unredacted_defaults {
                redactions.remove_flag(name);
                redactions.remove_header(name);
                redactions.remove_query_key(name);
                redactions.remove_env_var(name);
            }
        }

        Ok(redactions)
    }
}

/// Parsed in-band PTY detach sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetachSequence(Vec<u8>);

impl DetachSequence {
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for DetachSequence {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        parse_detach_sequence(&raw).map_err(serde::de::Error::custom)
    }
}

fn parse_detach_sequence(raw: &str) -> std::result::Result<DetachSequence, String> {
    let mut bytes = Vec::new();
    for token in raw.split_whitespace() {
        let token_bytes = parse_detach_sequence_token(token)?;
        bytes.extend(token_bytes);
    }

    if bytes.len() < 2 {
        return Err(
            "detach sequence must contain at least two key presses (for example: \"ctrl-] d\")"
                .to_string(),
        );
    }

    Ok(DetachSequence(bytes))
}

fn parse_detach_sequence_token(token: &str) -> std::result::Result<Vec<u8>, String> {
    let normalized = token.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err("detach sequence contains an empty token".to_string());
    }

    if let Some(ctrl_suffix) = normalized.strip_prefix("ctrl-") {
        let control = parse_control_token(ctrl_suffix)?;
        return Ok(vec![control]);
    }

    match normalized.as_str() {
        "esc" | "escape" => Ok(vec![0x1b]),
        "tab" => Ok(vec![b'\t']),
        "enter" | "return" => Ok(vec![b'\r']),
        "space" => Ok(vec![b' ']),
        _ => parse_literal_token(&normalized),
    }
}

fn parse_control_token(token: &str) -> std::result::Result<u8, String> {
    if token.len() != 1 {
        return Err(format!(
            "unsupported control key token \"ctrl-{token}\"; use ctrl-<single-char>"
        ));
    }

    let byte = token.as_bytes()[0];
    if !(0x40..=0x5f).contains(&byte.to_ascii_uppercase()) {
        return Err(format!("unsupported control key token \"ctrl-{token}\""));
    }

    Ok(byte.to_ascii_uppercase() & 0x1f)
}

fn parse_literal_token(token: &str) -> std::result::Result<Vec<u8>, String> {
    if token.len() == 1 {
        return Ok(vec![token.as_bytes()[0]]);
    }

    Err(format!(
        "unsupported detach key token \"{token}\"; use a single character or ctrl-<char>"
    ))
}

/// Metadata for user config
#[derive(Debug, Default, Deserialize)]
pub struct UserConfigMeta {
    #[serde(default)]
    pub version: u64,
}

/// User overrides (exceptions to default blocking)
#[derive(Debug, Default, Deserialize)]
pub struct UserOverrides {
    /// Overrides for sensitive paths
    /// Format: path = { reason = "...", acknowledged = "YYYY-MM-DD", access = "read" }
    #[serde(default)]
    pub sensitive_paths: HashMap<String, PathOverrideInfo>,

    /// Overrides for dangerous commands
    /// Format: command = { reason = "...", acknowledged = "YYYY-MM-DD" }
    #[serde(default)]
    pub commands: HashMap<String, CommandOverrideInfo>,
}

/// Override information for a sensitive path
#[derive(Debug, Clone, Deserialize)]
pub struct PathOverrideInfo {
    /// User-provided reason for the override
    pub reason: String,
    /// Date when user acknowledged the risk (required for override to be active)
    pub acknowledged: Option<String>,
    /// Access level: "read", "write", or "both" (default: "both")
    #[serde(default)]
    pub access: Option<String>,
}

/// Override information for a dangerous command
#[derive(Debug, Clone, Deserialize)]
pub struct CommandOverrideInfo {
    /// User-provided reason for the override
    pub reason: String,
    /// Date when user acknowledged the risk (required for override to be active)
    pub acknowledged: Option<String>,
}

/// User extensions (additions to blocklists)
#[derive(Debug, Default, Deserialize)]
pub struct UserExtensions {
    /// Additional sensitive paths to block
    #[serde(default)]
    pub sensitive_paths: HashMap<String, Vec<String>>,

    /// Additional dangerous commands to block
    #[serde(default)]
    pub dangerous_commands: HashMap<String, Vec<String>>,
}

/// Information about a trusted third-party signing key
#[derive(Debug, Clone, Deserialize)]
pub struct TrustedKeyInfo {
    /// Human-readable name for the key owner
    pub name: String,
    /// Key fingerprint for verification
    #[serde(default)]
    pub fingerprint: Option<String>,
}

/// Rollback system settings
#[derive(Debug, Clone, Deserialize)]
pub struct RollbackSettings {
    /// Maximum number of sessions to retain
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
    /// Maximum total storage in gigabytes
    #[serde(default = "default_max_storage_gb")]
    pub max_storage_gb: f64,
    /// Maximum snapshots per session
    #[serde(default = "default_max_snapshots")]
    pub max_snapshots: u32,
    /// Hours to keep stale sessions (ended is None, PID dead) before cleanup
    #[serde(default = "default_stale_grace_hours")]
    pub stale_grace_hours: u64,
}

/// Update check settings
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateSettings {
    /// Whether to check for CLI updates (default: true)
    #[serde(default = "default_true")]
    pub check: bool,
}

fn default_true() -> bool {
    true
}

impl Default for UpdateSettings {
    fn default() -> Self {
        Self {
            check: default_true(),
        }
    }
}

/// Pack registry settings.
///
/// Lets a fleet point `nono pull`/`nono update` at an internal registry and
/// (for air-gapped, internal-trust deployments) disable Sigstore signature
/// verification via a single MDM-managed `config.toml`. `verify` defaults to
/// `true` (fail-secure): signature checks stay on unless explicitly disabled.
/// Disabling `verify` turns off signature verification only — it does NOT
/// disable TLS host verification.
#[derive(Debug, Clone, Deserialize)]
pub struct RegistrySettings {
    /// Default registry base URL. Lower precedence than `--registry` and the
    /// `NONO_REGISTRY` env var; higher than the compiled-in default.
    #[serde(default)]
    pub url: Option<String>,
    /// Whether to verify pack signatures (default: true).
    #[serde(default = "default_true")]
    pub verify: bool,
}

impl Default for RegistrySettings {
    fn default() -> Self {
        Self {
            url: None,
            verify: default_true(),
        }
    }
}

fn default_max_sessions() -> usize {
    10
}
fn default_max_storage_gb() -> f64 {
    5.0
}
fn default_max_snapshots() -> u32 {
    100
}
fn default_stale_grace_hours() -> u64 {
    24
}

impl Default for RollbackSettings {
    fn default() -> Self {
        Self {
            max_sessions: default_max_sessions(),
            max_storage_gb: default_max_storage_gb(),
            max_snapshots: default_max_snapshots(),
            stale_grace_hours: default_stale_grace_hours(),
        }
    }
}

/// Load user configuration from `$XDG_CONFIG_HOME/nono/config.toml`
/// (default `~/.config/nono/config.toml`).
///
/// Returns None if the config file doesn't exist.
/// Returns Err if the file exists but is malformed.
pub fn load_user_config() -> Result<Option<UserConfig>> {
    let config_path = user_config_path()?;

    if !config_path.exists() {
        return Ok(None);
    }

    let content = fs::read_to_string(&config_path).map_err(|e| NonoError::ConfigRead {
        path: config_path.clone(),
        source: e,
    })?;

    let config: UserConfig = toml::from_str(&content)
        .map_err(|e| NonoError::ConfigParse(format!("Failed to parse user config: {}", e)))?;

    Ok(Some(config))
}

/// Get the path to user config file
pub fn user_config_path() -> Result<PathBuf> {
    let config_dir = super::user_config_dir().ok_or_else(|| {
        NonoError::ConfigParse("Could not determine user config directory".to_string())
    })?;

    Ok(config_dir.join(USER_CONFIG_FILE))
}

/// Get the path to user profiles directory
pub fn user_profiles_dir() -> Result<PathBuf> {
    let config_dir = super::user_config_dir().ok_or_else(|| {
        NonoError::ConfigParse("Could not determine user config directory".to_string())
    })?;

    Ok(config_dir.join("profiles"))
}

/// Get the path to user trusted keys directory
pub fn user_trusted_keys_dir() -> Result<PathBuf> {
    let config_dir = super::user_config_dir().ok_or_else(|| {
        NonoError::ConfigParse("Could not determine user config directory".to_string())
    })?;

    Ok(config_dir.join("trusted-keys"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_user_config() {
        let toml = r#"
[meta]
version = 1

[overrides.sensitive_paths]
"~/.ssh/id_rsa.pub" = { reason = "Public key for git", acknowledged = "2025-01-15", access = "read" }

[overrides.commands]
pip = { reason = "Python development", acknowledged = "2025-01-15" }

[extensions.sensitive_paths]
custom = ["~/work/secrets"]

[extensions.dangerous_commands]
custom = ["my-dangerous-tool"]

[trusted_keys]
alice = { name = "Alice", fingerprint = "abc123" }
"#;

        let config: UserConfig = toml::from_str(toml).expect("Failed to parse");

        assert_eq!(config.meta.version, 1);

        // Check overrides
        assert!(
            config
                .overrides
                .sensitive_paths
                .contains_key("~/.ssh/id_rsa.pub")
        );
        let ssh_override = &config.overrides.sensitive_paths["~/.ssh/id_rsa.pub"];
        assert_eq!(ssh_override.reason, "Public key for git");
        assert_eq!(ssh_override.access.as_deref(), Some("read"));

        assert!(config.overrides.commands.contains_key("pip"));

        // Check extensions
        assert!(config.extensions.sensitive_paths.contains_key("custom"));
        assert!(config.extensions.dangerous_commands.contains_key("custom"));

        // Check trusted keys
        assert!(config.trusted_keys.contains_key("alice"));
    }

    #[test]
    fn test_empty_user_config() {
        let toml = "";
        let config: UserConfig = toml::from_str(toml).expect("Failed to parse empty config");

        assert!(config.overrides.sensitive_paths.is_empty());
        assert!(config.overrides.commands.is_empty());
        assert!(config.ui.detach_sequence.is_none());
        assert!(config.redaction.extra_flags.is_empty());
        assert!(config.redaction.extra_env_vars.is_empty());
    }

    #[test]
    fn test_redaction_settings_add_extra_patterns() {
        let toml = r#"
[redaction]
extra_flags = ["--private-token"]
extra_headers = ["Private-Token"]
extra_query_keys = ["signature"]
extra_env_vars = ["CONFIGURED_ENV"]
"#;
        let config: UserConfig = toml::from_str(toml).expect("Failed to parse");
        let policy = config
            .redaction
            .to_scrub_policy()
            .expect("Failed to build policy");

        let diff = policy.diff_from_secure_default();
        assert_eq!(diff.added_flags, vec!["--private-token".to_string()]);
        assert_eq!(diff.added_headers, vec!["private-token".to_string()]);
        assert_eq!(diff.added_query_keys, vec!["signature".to_string()]);
        assert_eq!(diff.added_env_vars, vec!["configured_env".to_string()]);
    }

    #[test]
    fn test_redaction_settings_require_unsafe_override_for_removals() {
        let toml = r#"
[redaction]
allow_unredacted_defaults = ["state"]
"#;
        let config: UserConfig = toml::from_str(toml).expect("Failed to parse");
        let err = config
            .redaction
            .to_scrub_policy()
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(err.contains("unsafe_redaction_overrides = true"));
    }

    #[test]
    fn test_redaction_settings_can_remove_defaults_when_unsafe_enabled() {
        let toml = r#"
[redaction]
unsafe_redaction_overrides = true
allow_unredacted_defaults = ["state"]
"#;
        let config: UserConfig = toml::from_str(toml).expect("Failed to parse");
        let policy = config
            .redaction
            .to_scrub_policy()
            .expect("Failed to build policy");

        let diff = policy.diff_from_secure_default();
        assert_eq!(diff.removed_query_keys, vec!["state".to_string()]);
    }

    #[test]
    fn test_rollback_settings_defaults() {
        let toml = "";
        let config: UserConfig = toml::from_str(toml).expect("Failed to parse");
        assert_eq!(config.rollback.max_sessions, 10);
        assert!((config.rollback.max_storage_gb - 5.0).abs() < f64::EPSILON);
        assert_eq!(config.rollback.max_snapshots, 100);
        assert_eq!(config.rollback.stale_grace_hours, 24);
    }

    #[test]
    fn test_rollback_settings_custom() {
        let toml = r#"
[rollback]
max_sessions = 20
max_storage_gb = 10.0
max_snapshots = 50
stale_grace_hours = 48
"#;
        let config: UserConfig = toml::from_str(toml).expect("Failed to parse");
        assert_eq!(config.rollback.max_sessions, 20);
        assert!((config.rollback.max_storage_gb - 10.0).abs() < f64::EPSILON);
        assert_eq!(config.rollback.max_snapshots, 50);
        assert_eq!(config.rollback.stale_grace_hours, 48);
    }

    #[test]
    fn test_ui_detach_sequence_parses_control_prefix() {
        let toml = r#"
[ui]
detach_sequence = "ctrl-] d"
"#;

        let config: UserConfig = toml::from_str(toml).expect("Failed to parse");
        let detach_sequence = config
            .ui
            .detach_sequence
            .as_ref()
            .map(DetachSequence::bytes)
            .unwrap_or(&[]);
        assert_eq!(detach_sequence, &[0x1d, b'd']);
    }

    #[test]
    fn test_ui_detach_sequence_rejects_single_key() {
        let toml = r#"
[ui]
detach_sequence = "ctrl-]"
"#;

        let err = toml::from_str::<UserConfig>(toml)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(err.contains("detach sequence must contain at least two key presses"));
    }
}
