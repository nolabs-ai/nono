//! Deprecated profile schema compatibility layer.
//!
//! DEPRECATED: delete this file when v1.0.0 deprecations are removed.
//! Removal steps:
//!   1. Delete this file.
//!   2. Delete `mod deprecated_schema;` in `main.rs`.
//!   3. In `cli.rs`: remove `alias = "override-deny"` from the two clap
//!      flag defs and delete the `warn_for_deprecated_flags()` call in
//!      `main()`.
//!   4. In `profile/mod.rs`: delete the `legacy_policy` and legacy security
//!      fields from `ProfileDeserialize`; narrow `security` back to the
//!      canonical `SecurityConfig`.
//!   5. Delete `crates/nono-cli/tests/fixtures/legacy_profiles/`.
//!   6. Delete `crates/nono-cli/tests/deprecated_schema.rs`.
//!   7. Run `scripts/test-list-aliases.sh` — inventory should be empty.
//!   8. `make ci` must pass.
//!
//! Only the drain/warn FUNCTIONS in this module are restricted in where they
//! may be called from:
//!   - `warn_for_deprecated_flags` — called only from `main()`.
//!   - `drain_legacy_policy_into_canonical` — called only from
//!     `impl From<ProfileDeserialize> for Profile`.
//!   - `drain_legacy_security_into_canonical` — called only from
//!     `impl From<ProfileDeserialize> for Profile`.
//!
//! Any other function caller is a policy violation and must be caught by
//! `scripts/test-list-aliases.sh`.
//!
//! Legacy capture structs (`LegacyPolicyPatch`, future `RawSecurityConfig`)
//! are naturally referenced by `Profile`/`ProfileDeserialize` — that is
//! expected and not a policy violation.

// This module drains legacy keys into the deprecated canonical fields
// `commands.{allow,deny}`, so it deliberately writes to them.
#![allow(deprecated)]

use std::io::Write;

// ---------------------------------------------------------------------------
// Per-thread counter and suppression machinery
// ---------------------------------------------------------------------------
//
// The `WarningCounterGuard` and `WarningSuppressionGuard` types — and the
// thread-local cells they drive — moved to `crate::deprecation_warnings`
// so callers (e.g. `cmd_validate`, `load_profile_extends`) don't have to
// import from this deprecated module just to wrap a parse. The `note_*`
// and `is_suppressed` helpers are crate-private over there and we use
// them below from `emit_deprecation_warning`.

/// Captures a security config that may carry both canonical and legacy keys
/// during deserialization. The canonical subset is now narrow (process-level
/// knobs only) so we use `#[serde(flatten)]` over the canonical struct and
/// keep the two legacy keys as renamed siblings.
///
/// **Note on `deny_unknown_fields`** — the design doc (lines 132-133)
/// said this struct should NOT carry `deny_unknown_fields` because the
/// legacy keys had to slip through. With the canonical `SecurityConfig`
/// flattened in (and itself `deny_unknown_fields`), and the only legacy
/// fields being explicit `legacy_groups` / `legacy_allowed_commands`,
/// every accepted key is now named on this struct — so we can re-enable
/// the strict guard. A typo in any `security.*` key (legacy or
/// canonical) is rejected at parse time instead of being silently
/// dropped. Intentional deviation from the design.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawSecurityConfig {
    /// Canonical fields are flattened in; `SecurityConfig` no longer has
    /// `groups` or `allowed_commands`, so there is no JSON-name collision
    /// with the legacy fields below.
    #[serde(flatten)]
    pub canonical: crate::profile::SecurityConfig,

    // === Legacy fields (drained in `drain_legacy_security_into_canonical`) ===
    /// ALIAS(canonical="groups.include", introduced="v0.41.0", remove_by="v1.0.0", issue="#594")
    #[serde(default, rename = "groups")]
    pub legacy_groups: Vec<String>,
    /// ALIAS(canonical="commands.allow", introduced="v0.41.0", remove_by="v1.0.0", issue="#594")
    #[serde(default, rename = "allowed_commands")]
    pub legacy_allowed_commands: Vec<String>,
}

impl From<&RawSecurityConfig> for crate::profile::SecurityConfig {
    fn from(raw: &RawSecurityConfig) -> Self {
        // SecurityConfig is now narrow: just process-level knobs. The legacy
        // `groups` / `allowed_commands` no longer have canonical destinations
        // inside SecurityConfig — they are drained into `Profile.groups.include`
        // and `Profile.commands.allow` by `drain_legacy_security_into_canonical`.
        raw.canonical.clone()
    }
}

/// Drain legacy security fields into canonical `Profile` sections, emitting
/// one deprecation warning per populated legacy field. Mirrors
/// `drain_legacy_policy_into_canonical` structurally: explicit if-blocks,
/// one warning per populated key, extend (not overwrite).
pub(crate) fn drain_legacy_security_into_canonical(
    raw: &RawSecurityConfig,
    profile: &mut crate::profile::Profile,
) {
    if !raw.legacy_groups.is_empty() {
        emit_deprecation_warning("security.groups", "groups.include", "v1.0.0", "#594");
        profile
            .groups
            .include
            .extend(raw.legacy_groups.iter().cloned());
    }
    if !raw.legacy_allowed_commands.is_empty() {
        emit_deprecation_warning(
            "security.allowed_commands",
            "commands.allow",
            "v1.0.0",
            "#594",
        );
        profile
            .commands
            .allow
            .extend(raw.legacy_allowed_commands.iter().cloned());
    }
}

/// Captures the deprecated top-level `"policy"` key. Drained to canonical
/// sections by `drain_legacy_policy_into_canonical` (implemented in B3).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LegacyPolicyPatch {
    /// ALIAS(canonical="groups.exclude", introduced="v0.41.0", remove_by="v1.0.0", issue="#594")
    #[serde(default)]
    pub exclude_groups: Vec<String>,
    /// ALIAS(canonical="filesystem.read", introduced="v0.41.0", remove_by="v1.0.0", issue="#594")
    #[serde(default)]
    pub add_allow_read: Vec<String>,
    /// ALIAS(canonical="filesystem.write", introduced="v0.41.0", remove_by="v1.0.0", issue="#594")
    #[serde(default)]
    pub add_allow_write: Vec<String>,
    /// ALIAS(canonical="filesystem.allow", introduced="v0.41.0", remove_by="v1.0.0", issue="#594")
    #[serde(default)]
    pub add_allow_readwrite: Vec<String>,
    /// ALIAS(canonical="filesystem.deny", introduced="v0.41.0", remove_by="v1.0.0", issue="#594")
    #[serde(default)]
    pub add_deny_access: Vec<String>,
    /// ALIAS(canonical="commands.deny", introduced="v0.41.0", remove_by="v1.0.0", issue="#594")
    #[serde(default)]
    pub add_deny_commands: Vec<String>,
    /// ALIAS(canonical="filesystem.bypass_protection", introduced="v0.41.0", remove_by="v1.0.0", issue="#594")
    #[serde(default)]
    pub override_deny: Vec<String>,
}

/// Emit a single deprecation warning line to stderr. Also bumps the
/// per-thread deprecation counter if a `WarningCounterGuard` is active
/// (see `cmd_validate`). No-op while a `WarningSuppressionGuard` is
/// active on this thread — used by preview-parse paths that re-parse the
/// same file later (e.g. `load_profile_extends` followed by `load_profile`
/// in `cmd_show`).
pub(crate) fn emit_deprecation_warning(
    legacy: &str,
    canonical: &str,
    remove_by: &str,
    issue: &str,
) {
    if crate::deprecation_warnings::is_suppressed() {
        return;
    }
    crate::deprecation_warnings::note_deprecation();
    let _ = writeln!(
        std::io::stderr(),
        "{}",
        format_deprecation_warning(legacy, canonical, remove_by, issue)
    );
}

/// Scan raw command-line arguments for deprecated long flags. Returns the
/// canonical legacy flag spellings (one occurrence per distinct flag) so the
/// caller can emit exactly one warning per kind regardless of how many times
/// the user passed it.
///
/// DEPRECATED: delete when all long-flag aliases in this module are removed
/// in v1.0.0. See module-level removal steps.
pub(crate) fn detect_deprecated_flags(args: &[std::ffi::OsString]) -> Vec<&'static str> {
    let mut hits: Vec<&'static str> = Vec::new();
    for a in args {
        let s = a.to_string_lossy();
        let is_override_deny = s == "--override-deny" || s.starts_with("--override-deny=");
        if is_override_deny && !hits.contains(&"--override-deny") {
            hits.push("--override-deny");
        }
    }
    hits
}

/// Emit a deprecation warning on stderr for each deprecated long flag present
/// in `args`. Called exactly once from `main()` before `Cli::parse()`.
///
/// DEPRECATED: delete when all long-flag aliases in this module are removed
/// in v1.0.0. See module-level removal steps.
pub fn warn_for_deprecated_flags(args: &[std::ffi::OsString]) {
    for flag in detect_deprecated_flags(args) {
        let canonical = match flag {
            "--override-deny" => "--bypass-protection",
            _ => continue,
        };
        emit_deprecation_warning(flag, canonical, "v1.0.0", "#594");
    }
}

/// Drain a `LegacyPolicyPatch` into canonical `Profile` sections, emitting
/// one deprecation warning per populated legacy field. Canonical values are
/// preserved; legacy values are appended.
pub(crate) fn drain_legacy_policy_into_canonical(
    legacy: &LegacyPolicyPatch,
    profile: &mut crate::profile::Profile,
) {
    if !legacy.exclude_groups.is_empty() {
        emit_deprecation_warning("policy.exclude_groups", "groups.exclude", "v1.0.0", "#594");
        profile
            .groups
            .exclude
            .extend(legacy.exclude_groups.iter().cloned());
    }
    if !legacy.add_allow_read.is_empty() {
        emit_deprecation_warning("policy.add_allow_read", "filesystem.read", "v1.0.0", "#594");
        profile
            .filesystem
            .read
            .extend(legacy.add_allow_read.iter().cloned());
    }
    if !legacy.add_allow_write.is_empty() {
        emit_deprecation_warning(
            "policy.add_allow_write",
            "filesystem.write",
            "v1.0.0",
            "#594",
        );
        profile
            .filesystem
            .write
            .extend(legacy.add_allow_write.iter().cloned());
    }
    if !legacy.add_allow_readwrite.is_empty() {
        emit_deprecation_warning(
            "policy.add_allow_readwrite",
            "filesystem.allow",
            "v1.0.0",
            "#594",
        );
        profile
            .filesystem
            .allow
            .extend(legacy.add_allow_readwrite.iter().cloned());
    }
    if !legacy.add_deny_access.is_empty() {
        emit_deprecation_warning(
            "policy.add_deny_access",
            "filesystem.deny",
            "v1.0.0",
            "#594",
        );
        profile
            .filesystem
            .deny
            .extend(legacy.add_deny_access.iter().cloned());
    }
    if !legacy.add_deny_commands.is_empty() {
        emit_deprecation_warning(
            "policy.add_deny_commands",
            "commands.deny",
            "v1.0.0",
            "#594",
        );
        profile
            .commands
            .deny
            .extend(legacy.add_deny_commands.iter().cloned());
    }
    if !legacy.override_deny.is_empty() {
        emit_deprecation_warning(
            "policy.override_deny",
            "filesystem.bypass_protection",
            "v1.0.0",
            "#594",
        );
        profile
            .filesystem
            .bypass_protection
            .extend(legacy.override_deny.iter().cloned());
    }
}

/// Format the warning string (for testability and reuse).
pub(crate) fn format_deprecation_warning(
    legacy: &str,
    canonical: &str,
    remove_by: &str,
    issue: &str,
) -> String {
    format!(
        "warning: deprecated key '{legacy}' — use '{canonical}' instead (will be removed in {remove_by}, {issue})"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deprecation_warnings::{WarningCounterGuard, WarningSuppressionGuard};

    fn canonical_empty_profile() -> crate::profile::Profile {
        crate::profile::Profile::default()
    }

    #[test]
    fn test_drain_exclude_groups_goes_to_groups_exclude() {
        let mut profile = canonical_empty_profile();
        let legacy = LegacyPolicyPatch {
            exclude_groups: vec!["x".into()],
            ..Default::default()
        };
        drain_legacy_policy_into_canonical(&legacy, &mut profile);
        assert_eq!(profile.groups.exclude, vec!["x"]);
    }

    #[test]
    fn test_drain_add_allow_read_goes_to_filesystem_read() {
        let mut profile = canonical_empty_profile();
        let legacy = LegacyPolicyPatch {
            add_allow_read: vec!["/r".into()],
            ..Default::default()
        };
        drain_legacy_policy_into_canonical(&legacy, &mut profile);
        assert_eq!(profile.filesystem.read, vec!["/r"]);
    }

    #[test]
    fn test_drain_add_allow_write_goes_to_filesystem_write() {
        let mut profile = canonical_empty_profile();
        let legacy = LegacyPolicyPatch {
            add_allow_write: vec!["/w".into()],
            ..Default::default()
        };
        drain_legacy_policy_into_canonical(&legacy, &mut profile);
        assert_eq!(profile.filesystem.write, vec!["/w"]);
    }

    #[test]
    fn test_drain_add_allow_readwrite_goes_to_filesystem_allow() {
        let mut profile = canonical_empty_profile();
        let legacy = LegacyPolicyPatch {
            add_allow_readwrite: vec!["/rw".into()],
            ..Default::default()
        };
        drain_legacy_policy_into_canonical(&legacy, &mut profile);
        assert_eq!(profile.filesystem.allow, vec!["/rw"]);
    }

    #[test]
    fn test_drain_add_deny_access_goes_to_filesystem_deny() {
        let mut profile = canonical_empty_profile();
        let legacy = LegacyPolicyPatch {
            add_deny_access: vec!["/d".into()],
            ..Default::default()
        };
        drain_legacy_policy_into_canonical(&legacy, &mut profile);
        assert_eq!(profile.filesystem.deny, vec!["/d"]);
    }

    #[test]
    fn test_drain_add_deny_commands_goes_to_commands_deny() {
        let mut profile = canonical_empty_profile();
        let legacy = LegacyPolicyPatch {
            add_deny_commands: vec!["cmd".into()],
            ..Default::default()
        };
        drain_legacy_policy_into_canonical(&legacy, &mut profile);
        assert_eq!(profile.commands.deny, vec!["cmd"]);
    }

    #[test]
    fn test_drain_override_deny_goes_to_filesystem_bypass_protection() {
        let mut profile = canonical_empty_profile();
        let legacy = LegacyPolicyPatch {
            override_deny: vec!["/o".into()],
            ..Default::default()
        };
        drain_legacy_policy_into_canonical(&legacy, &mut profile);
        assert_eq!(profile.filesystem.bypass_protection, vec!["/o"]);
    }

    #[test]
    fn test_drain_preserves_existing_canonical_values() {
        let mut profile = canonical_empty_profile();
        profile.filesystem.read.push("/existing".into());
        let legacy = LegacyPolicyPatch {
            add_allow_read: vec!["/from_legacy".into()],
            ..Default::default()
        };
        drain_legacy_policy_into_canonical(&legacy, &mut profile);
        assert_eq!(profile.filesystem.read, vec!["/existing", "/from_legacy"]);
    }

    #[test]
    fn test_drain_empty_legacy_is_noop() {
        let mut profile = canonical_empty_profile();
        let legacy = LegacyPolicyPatch::default();
        drain_legacy_policy_into_canonical(&legacy, &mut profile);
        assert!(profile.groups.exclude.is_empty());
        assert!(profile.filesystem.read.is_empty());
        assert!(profile.filesystem.write.is_empty());
        assert!(profile.filesystem.allow.is_empty());
        assert!(profile.filesystem.deny.is_empty());
        assert!(profile.commands.deny.is_empty());
        assert!(profile.filesystem.bypass_protection.is_empty());
    }

    #[test]
    fn test_format_deprecation_warning_includes_all_fields() {
        let s = format_deprecation_warning(
            "policy.add_allow_read",
            "filesystem.read",
            "v1.0.0",
            "#594",
        );
        assert!(s.contains("policy.add_allow_read"));
        assert!(s.contains("filesystem.read"));
        assert!(s.contains("v1.0.0"));
        assert!(s.contains("#594"));
    }

    #[test]
    fn test_raw_security_accepts_legacy_groups_and_allowed_commands() {
        let json = r#"{
            "groups": ["node_runtime"],
            "allowed_commands": ["pip"],
            "signal_mode": "isolated"
        }"#;
        let raw: RawSecurityConfig = serde_json::from_str(json).expect("parse");
        assert_eq!(raw.legacy_groups, vec!["node_runtime"]);
        assert_eq!(raw.legacy_allowed_commands, vec!["pip"]);
        assert!(raw.canonical.signal_mode.is_some()); // canonical field preserved
    }

    #[test]
    fn test_raw_security_accepts_canonical_only() {
        let json = r#"{"signal_mode": "isolated"}"#;
        let raw: RawSecurityConfig = serde_json::from_str(json).expect("parse");
        assert!(raw.legacy_groups.is_empty());
        assert!(raw.legacy_allowed_commands.is_empty());
        assert!(raw.canonical.signal_mode.is_some());
    }

    #[test]
    fn test_drain_legacy_groups_goes_to_groups_include() {
        let mut profile = crate::profile::Profile::default();
        let raw = RawSecurityConfig {
            legacy_groups: vec!["g1".into()],
            ..Default::default()
        };
        drain_legacy_security_into_canonical(&raw, &mut profile);
        assert_eq!(profile.groups.include, vec!["g1"]);
    }

    #[test]
    fn test_drain_legacy_allowed_commands_goes_to_commands_allow() {
        let mut profile = crate::profile::Profile::default();
        let raw = RawSecurityConfig {
            legacy_allowed_commands: vec!["c1".into()],
            ..Default::default()
        };
        drain_legacy_security_into_canonical(&raw, &mut profile);
        assert_eq!(profile.commands.allow, vec!["c1"]);
    }

    #[test]
    fn test_drain_legacy_security_empty_is_noop() {
        let mut profile = crate::profile::Profile::default();
        let raw = RawSecurityConfig::default();
        drain_legacy_security_into_canonical(&raw, &mut profile);
        assert!(profile.groups.include.is_empty());
        assert!(profile.commands.allow.is_empty());
    }

    #[test]
    fn test_drain_preserves_existing_canonical_security_values() {
        let mut profile = crate::profile::Profile::default();
        profile.groups.include.push("existing".into());
        let raw = RawSecurityConfig {
            legacy_groups: vec!["from_legacy".into()],
            ..Default::default()
        };
        drain_legacy_security_into_canonical(&raw, &mut profile);
        assert_eq!(profile.groups.include, vec!["existing", "from_legacy"]);
    }

    #[test]
    fn test_raw_security_to_canonical_carries_all_process_fields() {
        // Confirms From<&RawSecurityConfig> for SecurityConfig propagates every
        // canonical field we care about.
        let json = r#"{"signal_mode": "isolated", "ipc_mode": "full"}"#;
        let raw: RawSecurityConfig = serde_json::from_str(json).expect("parse");
        let canonical = crate::profile::SecurityConfig::from(&raw);
        assert!(canonical.signal_mode.is_some());
        assert!(canonical.ipc_mode.is_some());
    }

    #[test]
    fn test_raw_security_accepts_both_legacy_and_canonical_together() {
        let json = r#"{
            "groups": ["g"],
            "signal_mode": "isolated",
            "ipc_mode": "full"
        }"#;
        let raw: RawSecurityConfig = serde_json::from_str(json).expect("parse");
        assert_eq!(raw.legacy_groups, vec!["g"]);
        assert!(raw.canonical.signal_mode.is_some());
        assert!(raw.canonical.ipc_mode.is_some());

        // Narrowed SecurityConfig no longer holds `groups`; the legacy key
        // now only surfaces via the drain path into `Profile.groups.include`.
        let canonical = crate::profile::SecurityConfig::from(&raw);
        assert!(canonical.signal_mode.is_some());
        assert!(canonical.ipc_mode.is_some());
    }

    #[test]
    fn test_raw_security_from_impl_copies_all_five_canonical_fields() {
        let json = r#"{
            "signal_mode": "isolated",
            "process_info_mode": "isolated",
            "ipc_mode": "full",
            "capability_elevation": true,
            "wsl2_proxy_policy": "error"
        }"#;
        let raw: RawSecurityConfig = serde_json::from_str(json).expect("parse");
        let canonical = crate::profile::SecurityConfig::from(&raw);
        assert!(canonical.signal_mode.is_some());
        assert!(canonical.process_info_mode.is_some());
        assert!(canonical.ipc_mode.is_some());
        assert_eq!(canonical.capability_elevation, Some(true));
        assert!(canonical.wsl2_proxy_policy.is_some());
    }

    /// Lock down the `#[serde(flatten)]` + `#[serde(deny_unknown_fields)]`
    /// interaction. Serde has a known gotcha where flatten can weaken the
    /// strict guard; we deliberately deviate from the design (which said
    /// `RawSecurityConfig` should NOT use `deny_unknown_fields`) to keep
    /// the strict-on-typo behavior. If a future serde upgrade or a
    /// `flatten` reorganization regresses this, these tests fail loudly
    /// instead of silently accepting the typo and dropping the value.
    #[test]
    fn test_raw_security_rejects_typoed_canonical_field() {
        // `signal_modee` (typo of canonical `signal_mode`).
        let json = r#"{
            "signal_modee": "isolated"
        }"#;
        let result: Result<RawSecurityConfig, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "typoed canonical key 'signal_modee' must be rejected, not silently dropped"
        );
    }

    #[test]
    fn test_raw_security_rejects_typoed_legacy_field() {
        // `groupz` (typo of legacy `groups`).
        let json = r#"{
            "groupz": ["x"]
        }"#;
        let result: Result<RawSecurityConfig, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "typoed legacy key 'groupz' must be rejected, not silently dropped"
        );
    }

    #[test]
    fn test_raw_security_rejects_unknown_sibling() {
        // Wholly unrelated key — neither canonical nor legacy.
        let json = r#"{
            "random_unknown_key": "x"
        }"#;
        let result: Result<RawSecurityConfig, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "unknown sibling key must be rejected; flatten + deny_unknown_fields \
             must remain strict"
        );
    }

    #[test]
    fn test_raw_security_rejects_typo_alongside_valid_fields() {
        // Mix of valid and typo'd — must still reject.
        let json = r#"{
            "signal_mode": "isolated",
            "groups": ["g1"],
            "ipc_mod": "full"
        }"#;
        let result: Result<RawSecurityConfig, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "typo 'ipc_mod' alongside valid fields must still cause rejection"
        );
    }

    #[test]
    fn test_warn_for_deprecated_flags_detects_override_deny() {
        use std::ffi::OsString;
        let args: Vec<OsString> = ["nono", "run", "--override-deny", "/x"]
            .iter()
            .map(OsString::from)
            .collect();
        let detected = detect_deprecated_flags(&args);
        assert_eq!(detected, vec!["--override-deny"]);
    }

    #[test]
    fn test_warn_for_deprecated_flags_detects_override_deny_equals_form() {
        use std::ffi::OsString;
        let args: Vec<OsString> = ["nono", "run", "--override-deny=/x"]
            .iter()
            .map(OsString::from)
            .collect();
        let detected = detect_deprecated_flags(&args);
        assert_eq!(detected, vec!["--override-deny"]);
    }

    #[test]
    fn test_detect_deprecated_flags_deduplicates_repeated_occurrences() {
        use std::ffi::OsString;
        let args: Vec<OsString> = [
            "nono",
            "run",
            "--override-deny",
            "/a",
            "--override-deny",
            "/b",
        ]
        .iter()
        .map(OsString::from)
        .collect();
        let detected = detect_deprecated_flags(&args);
        assert_eq!(detected, vec!["--override-deny"]);
    }

    #[test]
    fn test_detect_deprecated_flags_returns_empty_when_no_legacy_flags() {
        use std::ffi::OsString;
        let args: Vec<OsString> = ["nono", "run", "--bypass-protection", "/x"]
            .iter()
            .map(OsString::from)
            .collect();
        let detected = detect_deprecated_flags(&args);
        assert!(detected.is_empty());
    }

    #[test]
    fn test_legacy_policy_patch_deserializes_all_fields() {
        let json = r#"{
            "exclude_groups": ["x"],
            "add_allow_read": ["/r"],
            "add_allow_write": ["/w"],
            "add_allow_readwrite": ["/rw"],
            "add_deny_access": ["/d"],
            "add_deny_commands": ["cmd"],
            "override_deny": ["/o"]
        }"#;
        let patch: LegacyPolicyPatch = serde_json::from_str(json).expect("parse");
        assert_eq!(patch.exclude_groups, vec!["x"]);
        assert_eq!(patch.add_allow_read, vec!["/r"]);
        assert_eq!(patch.add_allow_write, vec!["/w"]);
        assert_eq!(patch.add_allow_readwrite, vec!["/rw"]);
        assert_eq!(patch.add_deny_access, vec!["/d"]);
        assert_eq!(patch.add_deny_commands, vec!["cmd"]);
        assert_eq!(patch.override_deny, vec!["/o"]);
    }

    #[test]
    fn test_warning_counter_guard_counts_within_scope() {
        let guard = WarningCounterGuard::begin();
        // Any drain call inside the scope bumps the counter. Use the drain
        // path directly so the test does not depend on serde internals.
        let mut profile = crate::profile::Profile::default();
        let legacy = LegacyPolicyPatch {
            exclude_groups: vec!["x".into()],
            add_allow_read: vec!["/r".into()],
            ..Default::default()
        };
        drain_legacy_policy_into_canonical(&legacy, &mut profile);
        let n = guard.finish();
        assert_eq!(n, 2, "expected 2 warnings (one per populated legacy key)");
    }

    #[test]
    fn test_warning_counter_guard_is_noop_outside_scope() {
        // Calling `emit_deprecation_warning` without a guard must not panic
        // and must not leave state around that a later guard could pick up.
        emit_deprecation_warning("legacy", "canonical", "v1.0.0", "#594");
        let guard = WarningCounterGuard::begin();
        let n = guard.finish();
        assert_eq!(
            n, 0,
            "counter outside-scope emissions must not leak into next scope"
        );
    }

    #[test]
    fn test_warning_counter_guard_cleared_on_early_drop() {
        // Simulate an early-return path that drops the guard without calling
        // `finish()` — a subsequent guard on the same thread must start at 0.
        {
            let _guard = WarningCounterGuard::begin();
            emit_deprecation_warning("legacy", "canonical", "v1.0.0", "#594");
            // `_guard` drops here without finish() → counter cleared.
        }
        let guard = WarningCounterGuard::begin();
        emit_deprecation_warning("legacy2", "canonical2", "v1.0.0", "#594");
        let n = guard.finish();
        assert_eq!(n, 1, "second scope must start fresh at 0");
    }

    #[test]
    fn test_warning_suppression_guard_blocks_emit_and_count() {
        let counter = WarningCounterGuard::begin();
        {
            let _suppress = WarningSuppressionGuard::begin();
            // While suppressed, neither stderr nor counter is touched.
            emit_deprecation_warning("legacy", "canonical", "v1.0.0", "#594");
        }
        // After suppress drops, normal emit resumes.
        emit_deprecation_warning("legacy2", "canonical2", "v1.0.0", "#594");
        let n = counter.finish();
        assert_eq!(n, 1, "only the post-suppression emit should count; got {n}");
    }

    #[test]
    fn test_warning_suppression_guard_nests_correctly() {
        let counter = WarningCounterGuard::begin();
        {
            let _outer = WarningSuppressionGuard::begin();
            {
                let _inner = WarningSuppressionGuard::begin();
                emit_deprecation_warning("a", "A", "v1.0.0", "#594");
            }
            // Inner dropped but outer still active — emit still suppressed.
            emit_deprecation_warning("b", "B", "v1.0.0", "#594");
        }
        // Both dropped — emit normally.
        emit_deprecation_warning("c", "C", "v1.0.0", "#594");
        let n = counter.finish();
        assert_eq!(n, 1, "only post-suppression emit counts");
    }

    // -----------------------------------------------------------------
    // Drain integration: full `Profile` deserialization round-trip
    // -----------------------------------------------------------------
    //
    // These tests live here (rather than `profile/mod.rs`) so the legacy
    // JSON literals stay confined to a file `lint-docs.sh` already
    // allowlists. They exercise the same `serde_json::from_str::<Profile>`
    // path used by `parse_profile_file`.

    #[test]
    fn legacy_policy_keys_drain_into_canonical_via_full_profile_parse() {
        let json = r#"{
            "meta": {"name": "drain-test"},
            "security": {"groups": ["g1"], "allowed_commands": ["c1"]},
            "policy": {
                "exclude_groups": ["g2"],
                "add_allow_read": ["/r"],
                "add_allow_write": ["/w"],
                "add_allow_readwrite": ["/rw"],
                "add_deny_access": ["/d"],
                "add_deny_commands": ["c2"],
                "override_deny": ["/o"]
            }
        }"#;
        let _suppress = WarningSuppressionGuard::begin(); // keep stderr clean
        let profile: crate::profile::Profile =
            serde_json::from_str(json).expect("parse legacy profile");
        assert_eq!(profile.groups.include, vec!["g1"]);
        assert_eq!(profile.groups.exclude, vec!["g2"]);
        assert_eq!(profile.commands.allow, vec!["c1"]);
        assert_eq!(profile.commands.deny, vec!["c2"]);
        assert_eq!(profile.filesystem.read, vec!["/r"]);
        assert_eq!(profile.filesystem.write, vec!["/w"]);
        assert_eq!(profile.filesystem.allow, vec!["/rw"]);
        assert_eq!(profile.filesystem.deny, vec!["/d"]);
        assert_eq!(profile.filesystem.bypass_protection, vec!["/o"]);
    }

    #[test]
    fn legacy_security_allowed_commands_drains_to_canonical_commands_allow() {
        let json = r#"{
            "meta": { "name": "rm-test" },
            "filesystem": { "allow": ["/tmp"] },
            "security": { "allowed_commands": ["rm", "dd"] }
        }"#;
        let _suppress = WarningSuppressionGuard::begin();
        let profile: crate::profile::Profile =
            serde_json::from_str(json).expect("parse legacy profile");
        assert_eq!(profile.commands.allow, vec!["rm", "dd"]);
    }

    #[test]
    fn legacy_policy_patch_drains_full_set_via_full_profile_parse() {
        let json = r#"{
            "meta": { "name": "patchy" },
            "policy": {
                "exclude_groups": ["deny_shell_configs"],
                "add_allow_read": ["/tmp/read"],
                "add_allow_write": ["/tmp/write"],
                "add_allow_readwrite": ["/tmp/rw"],
                "add_deny_access": ["/tmp/deny"],
                "override_deny": ["~/.docker"]
            }
        }"#;
        let _suppress = WarningSuppressionGuard::begin();
        let profile: crate::profile::Profile =
            serde_json::from_str(json).expect("parse legacy profile");
        assert_eq!(profile.groups.exclude, vec!["deny_shell_configs"]);
        assert_eq!(profile.filesystem.read, vec!["/tmp/read"]);
        assert_eq!(profile.filesystem.write, vec!["/tmp/write"]);
        assert_eq!(profile.filesystem.allow, vec!["/tmp/rw"]);
        assert_eq!(profile.filesystem.deny, vec!["/tmp/deny"]);
        assert_eq!(profile.filesystem.bypass_protection, vec!["~/.docker"]);
    }
}
