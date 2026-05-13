//! Profile system for pre-configured capability sets
//!
//! Profiles provide named configurations for common applications like
//! claude-code, openclaw, and opencode. They can be built-in (compiled
//! into the binary) or user-defined (in ~/.config/nono/profiles/).

pub(crate) mod builtin;

use nono::{NonoError, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

// ============================================================================
// Plan 36-01a: upstream f0abd413 deprecated_schema module port
// ============================================================================
//
// Plan 34-04b (2026-05-11) shipped a pragmatic Option C:
//   - serde alias `bypass_protection` on `PolicyPatchConfig::override_deny`
//   - clap `alias = "bypass-protection"` on the CLI flag
//   - single per-process AtomicBool emitting one stderr WARN when the
//     legacy `override_deny` key was encountered
//
// Plan 36-01a (D-20 manual-replay of upstream f0abd413 v0.47.0) replaces
// the above with the full upstream surface:
//   - `deprecated_schema::LegacyPolicyPatch` rewriter (serde-driven,
//     deny_unknown_fields, rewrite() → CanonicalPolicy)
//   - `deprecated_schema::DeprecationCounter` per-key OnceLock<HashMap<...>>
//   - `nono profile validate --strict` fail-closed lever
//
// Plan 36-01a Task 2 retired the single-key AtomicBool seed and the
// one-shot-emit helper that were present in Plan 34-04b. The warning-emission
// concern now lives in deprecated_schema.rs::DeprecationCounter per D-36-B1.
//
// Tombstone (Plan 36-01a): emit_legacy_override_deny_warning_once +
// single-key AtomicBool retired; now lives in
// crates/nono-cli/src/deprecated_schema.rs::DeprecationCounter per D-36-B1
// (upstream f0abd413).

/// Returns `true` if the raw JSON contains a legacy `override_deny` key.
///
/// Pure function — no side effects, no global state. The production path
/// passes the result to `detect_legacy_override_deny_key` which calls
/// `GLOBAL_DEPRECATION_COUNTER.emit_once(...)`. Tests call this directly
/// to verify detection logic without side effects on global counter state
/// (which is shared per-process and would race in parallel test runs).
fn raw_profile_has_legacy_override_deny_key(raw: &str) -> bool {
    let value: serde_json::Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return false, // main parser will surface the real error
    };
    json_value_has_key(&value, "override_deny")
}

/// Scan a raw JSON profile string for the legacy `override_deny` key and
/// emit the one-time deprecation warning when found.
///
/// Implemented as a coarse `serde_json::Value` walk rather than a structural
/// AST traversal to keep the detection surface tiny and the code path
/// orthogonal to the main `Profile` deserialize. False positives (e.g. a
/// custom JSON string literal containing the substring `"override_deny"`)
/// are accepted as the lesser cost vs. mis-detecting a real legacy key.
///
/// Plan 36-01a: delegates to `deprecated_schema::GLOBAL_DEPRECATION_COUNTER`
/// for per-key one-shot emission semantics.
fn detect_legacy_override_deny_key(raw: &str) {
    if raw_profile_has_legacy_override_deny_key(raw) {
        crate::deprecated_schema::GLOBAL_DEPRECATION_COUNTER
            .emit_once("override_deny", "bypass_protection");
    }
}

/// Recursive walk: returns `true` if any object in `v` contains `target` as
/// a key. Visits arrays and nested objects.
fn json_value_has_key(v: &serde_json::Value, target: &str) -> bool {
    match v {
        serde_json::Value::Object(map) => {
            if map.contains_key(target) {
                return true;
            }
            map.values().any(|inner| json_value_has_key(inner, target))
        }
        serde_json::Value::Array(items) => {
            items.iter().any(|inner| json_value_has_key(inner, target))
        }
        _ => false,
    }
}

#[cfg(test)]
mod canonical_schema_rename_tests {
    use super::*;

    // NB: these tests avoid touching the global GLOBAL_DEPRECATION_COUNTER
    // (process-wide state) because Rust test runners parallelize within the
    // same process and a previous test may have already triggered an emission.
    // We instead test the pure detection helper
    // `raw_profile_has_legacy_override_deny_key` which has no side effects.
    // (Plan 36-01a: the single-key AtomicBool global was retired in Task 2.)

    #[test]
    fn legacy_override_deny_key_detected() {
        let raw = r#"{"meta":{"name":"t"},"policy":{"override_deny":["/etc/hosts"]}}"#;
        assert!(
            raw_profile_has_legacy_override_deny_key(raw),
            "legacy override_deny key should be detected in raw JSON"
        );
    }

    #[test]
    fn canonical_bypass_protection_key_does_not_match_legacy_detector() {
        let raw = r#"{"meta":{"name":"t"},"policy":{"bypass_protection":["/etc/hosts"]}}"#;
        assert!(
            !raw_profile_has_legacy_override_deny_key(raw),
            "canonical bypass_protection key must NOT trigger the legacy detector"
        );
    }

    #[test]
    fn bypass_protection_alias_deserializes_into_override_deny_field() {
        // Verifies the #[serde(alias = "bypass_protection")] attribute on
        // PolicyPatchConfig::override_deny. A profile using the canonical
        // bypass_protection key must populate the existing override_deny
        // Vec so downstream consumers (210 callsites) remain untouched.
        let raw = r#"{"bypass_protection":["/etc/hosts"]}"#;
        let cfg: PolicyPatchConfig =
            serde_json::from_str(raw).expect("bypass_protection must deserialize via serde alias");
        assert_eq!(cfg.override_deny, vec!["/etc/hosts".to_string()]);
    }

    #[test]
    fn legacy_override_deny_key_still_deserializes() {
        let raw = r#"{"override_deny":["/etc/hosts"]}"#;
        let cfg: PolicyPatchConfig =
            serde_json::from_str(raw).expect("legacy override_deny must continue to deserialize");
        assert_eq!(cfg.override_deny, vec!["/etc/hosts".to_string()]);
    }

    #[test]
    fn json_value_has_key_walks_nested_objects() {
        let raw = r#"{"a":{"b":{"override_deny":[]}}}"#;
        assert!(raw_profile_has_legacy_override_deny_key(raw));
    }

    #[test]
    fn json_value_has_key_handles_arrays() {
        let raw = r#"{"items":[{"override_deny":[]}]}"#;
        assert!(raw_profile_has_legacy_override_deny_key(raw));
    }

    #[test]
    fn malformed_json_returns_false_silently() {
        // Detector must not panic on malformed input; the main parser
        // will surface the real error path.
        assert!(!raw_profile_has_legacy_override_deny_key("not json"));
        assert!(!raw_profile_has_legacy_override_deny_key("{"));
    }

    // ----------------------------------------------------------------
    // Plan 36-01b: canonical section sub-struct serde invariants
    // Tests reference FilesystemConfig (extended) + CommandsConfig (new)
    // ----------------------------------------------------------------

    /// T-36-01b-1: legacy `override_deny` JSON key must deserialize into
    /// `FilesystemConfig::bypass_protection` via the serde alias (D-36-B3).
    #[test]
    fn filesystem_legacy_override_deny_alias_to_bypass_protection() {
        let json = r#"{"override_deny":["/var/log"]}"#;
        let cfg: FilesystemConfig =
            serde_json::from_str(json).expect("legacy alias must deserialize");
        assert_eq!(
            cfg.bypass_protection,
            vec!["/var/log".to_string()],
            "override_deny must populate bypass_protection via serde alias"
        );
    }

    /// T-36-01b-2: canonical JSON with both new fields must deserialize cleanly.
    #[test]
    fn filesystem_canonical_deny_and_bypass_protection_deserializes() {
        let json = r#"{"deny":["/etc"],"bypass_protection":["/var/log"]}"#;
        let cfg: FilesystemConfig =
            serde_json::from_str(json).expect("canonical fields must deserialize");
        assert_eq!(cfg.deny, vec!["/etc".to_string()]);
        assert_eq!(cfg.bypass_protection, vec!["/var/log".to_string()]);
    }

    /// T-36-01b-3: empty filesystem block must default both new fields to vec![].
    #[test]
    fn filesystem_empty_block_defaults_new_fields_to_empty() {
        let json = r#"{}"#;
        let cfg: FilesystemConfig =
            serde_json::from_str(json).expect("empty block must deserialize");
        assert!(cfg.deny.is_empty(), "deny must default to empty vec");
        assert!(
            cfg.bypass_protection.is_empty(),
            "bypass_protection must default to empty vec"
        );
    }

    /// T-36-01b-4: CommandsConfig must deserialize both allow and deny fields.
    #[test]
    fn commands_config_allow_and_deny_deserializes() {
        let json = r#"{"allow":["git"],"deny":["rm"]}"#;
        let cfg: CommandsConfig =
            serde_json::from_str(json).expect("CommandsConfig must deserialize");
        assert_eq!(cfg.allow, vec!["git".to_string()]);
        assert_eq!(cfg.deny, vec!["rm".to_string()]);
    }

    /// T-36-01b-5: CommandsConfig must reject unknown fields
    /// (#[serde(deny_unknown_fields)] invariant per D-36-B1 threat model).
    #[test]
    fn commands_config_rejects_unknown_fields() {
        let json = r#"{"unknown_key":[]}"#;
        let result: std::result::Result<CommandsConfig, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "CommandsConfig must reject unknown fields via deny_unknown_fields"
        );
    }

    // ----------------------------------------------------------------
    // Plan 36-01b Task 2: Profile / From<ProfileDeserialize> wiring tests
    // ----------------------------------------------------------------

    /// T-36-01b-6: canonical Profile JSON with commands + filesystem.deny
    /// round-trips through From<ProfileDeserialize> without field loss.
    #[test]
    fn profile_round_trip_with_canonical_sections() {
        let json = r#"{
            "meta": {"name": "test"},
            "filesystem": {"deny": ["/etc"]},
            "commands": {"allow": ["git"]}
        }"#;
        let profile: Profile =
            serde_json::from_str(json).expect("canonical Profile must deserialize");
        assert_eq!(
            profile.filesystem.deny,
            vec!["/etc".to_string()],
            "filesystem.deny must survive From<ProfileDeserialize>"
        );
        assert_eq!(
            profile.commands.allow,
            vec!["git".to_string()],
            "commands.allow must survive From<ProfileDeserialize>"
        );
    }

    /// T-36-01b-7: legacy filesystem.override_deny key normalizes to
    /// Profile::filesystem.bypass_protection via serde alias (D-36-B3).
    #[test]
    fn legacy_filesystem_override_deny_normalizes_to_bypass_protection() {
        let json = r#"{"filesystem": {"override_deny": ["/var/log"]}}"#;
        let profile: Profile =
            serde_json::from_str(json).expect("legacy alias must deserialize into Profile");
        assert_eq!(
            profile.filesystem.bypass_protection,
            vec!["/var/log".to_string()],
            "legacy override_deny must populate filesystem.bypass_protection via serde alias"
        );
    }

    /// T-36-01b-8: Profile with canonical commands + filesystem sections
    /// re-serializes with both keys present at expected nesting depth.
    /// Verifies Phase 35 Plan 35-03 Map-insertion JSON shape composes
    /// cleanly with the new canonical fields (T-36-01-MAP-SHAPE-REGRESS).
    #[test]
    fn profile_canonical_sections_serialize_at_correct_nesting() {
        let json = r#"{
            "meta": {"name": "nest-test"},
            "filesystem": {"deny": ["/proc"], "bypass_protection": ["/tmp/safe"]},
            "commands": {"deny": ["rm"]}
        }"#;
        let profile: Profile =
            serde_json::from_str(json).expect("Profile must deserialize");
        let serialized = serde_json::to_value(&profile)
            .expect("Profile must serialize to JSON value");
        // commands must be a top-level key with a deny sub-key
        assert!(
            serialized["commands"]["deny"].as_array().is_some(),
            "commands.deny must appear at top-level nesting in serialized JSON"
        );
        // filesystem.deny must still exist
        assert!(
            serialized["filesystem"]["deny"].as_array().is_some(),
            "filesystem.deny must appear in serialized JSON"
        );
        // filesystem.bypass_protection must still exist
        assert!(
            serialized["filesystem"]["bypass_protection"].as_array().is_some(),
            "filesystem.bypass_protection must appear in serialized JSON"
        );
    }

    /// T-36-01b-9: empty commands block defaults both allow and deny to vec![].
    #[test]
    fn profile_empty_commands_block_defaults_correctly() {
        let json = r#"{"commands": {}}"#;
        let profile: Profile =
            serde_json::from_str(json).expect("empty commands block must deserialize");
        assert!(
            profile.commands.allow.is_empty(),
            "commands.allow must default to empty vec"
        );
        assert!(
            profile.commands.deny.is_empty(),
            "commands.deny must default to empty vec"
        );
    }
}

// Re-export InjectMode and OAuth2Config from nono-proxy for use in profiles
pub use nono_proxy::config::{InjectMode, OAuth2Config};

/// Profile metadata
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct ProfileMeta {
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub author: Option<String>,
}

/// Filesystem configuration in a profile
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemConfig {
    /// Directories with read+write access
    #[serde(default)]
    pub allow: Vec<String>,
    /// Directories with read-only access
    #[serde(default)]
    pub read: Vec<String>,
    /// Directories with write-only access
    #[serde(default)]
    pub write: Vec<String>,
    /// Single files with read+write access
    #[serde(default)]
    pub allow_file: Vec<String>,
    /// Single files with read-only access
    #[serde(default)]
    pub read_file: Vec<String>,
    /// Single files with write-only access
    #[serde(default)]
    pub write_file: Vec<String>,
    /// Directories explicitly denied for the sandboxed child.
    ///
    /// Canonical section per upstream f0abd413 (v0.47.0). Paths here
    /// activate the platform deny mechanism (macOS Seatbelt `(deny
    /// file-read*)`, Linux Landlock restricted ruleset) even if the
    /// path would otherwise be accessible by default. Applied AFTER
    /// `filesystem.allow` grants so that deny takes precedence.
    #[serde(default)]
    pub deny: Vec<String>,
    /// Paths that bypass deny rules when paired with an explicit
    /// user-intent grant (e.g. `filesystem.allow` or `--allow`).
    ///
    /// Canonical key per upstream f0abd413 (v0.47.0 / PR #594).
    /// The legacy `override_deny` JSON key is accepted indefinitely
    /// via the serde alias below per D-36-B3 (no hard-deprecation date).
    /// Callers referencing `policy.override_deny` are the canonical
    /// runtime consumers; Plan 36-01c will atomically rename those
    /// callsites to `policy.bypass_protection` — this field is the
    /// `filesystem`-section counterpart introduced here so the canonical
    /// JSON shape is accepted end-to-end before the callsite rename lands.
    #[serde(default, alias = "override_deny")]
    pub bypass_protection: Vec<String>,
}

/// Commands configuration in a profile — canonical section per upstream
/// f0abd413 (v0.47.0).
///
/// Mirrors the shape precedent of `CapabilitiesConfig` (lines below):
/// `#[derive(...)] #[serde(deny_unknown_fields)]` with `#[serde(default)]`
/// fields. Unknown keys in the JSON `commands` block are rejected at
/// parse time (fail-closed per CLAUDE.md § Fail Secure).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandsConfig {
    /// Commands explicitly allowed for the sandboxed child even when a
    /// deny-group would block them (e.g. `["git", "cargo"]`).
    #[serde(default)]
    pub allow: Vec<String>,
    /// Commands explicitly denied for the sandboxed child, extending the
    /// deny-group command list (e.g. `["rm", "mv"]`).
    #[serde(default)]
    pub deny: Vec<String>,
}

/// AIPC-01 (Phase 18) per-handle-type access widening.
///
/// Widening only — never narrows the hard-coded default-deny. See
/// `nono::supervisor::policy` for the hard-coded defaults that this config
/// extends. Unknown tokens are rejected at parse time via the per-type
/// `from_token` parsers (see `socket_role_from_token`,
/// `pipe_direction_from_token`, `job_object_mask_from_token`,
/// `event_mask_from_token`, `mutex_mask_from_token` below).
///
/// SECURITY NOTE: enabling `terminate` for `job_object` grants the child the
/// ability to terminate process trees IT owns (separate Job Objects the child
/// created or was assigned to). The supervisor's OWN containment Job is
/// REFUSED by a structural runtime guard (`CompareObjectHandles` in
/// `handle_job_object_request`) regardless of this widening — but `terminate`
/// on other Job Objects is accepted as part of the profile author's contract.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AipcConfig {
    /// Socket role tokens to widen the default Connect-only allowlist.
    /// Valid: "connect", "bind", "listen".
    #[serde(default)]
    pub socket: Vec<String>,
    /// Pipe direction tokens to widen the default read-OR-write allowlist.
    /// Valid: "read", "write", "read+write".
    #[serde(default)]
    pub pipe: Vec<String>,
    /// Job Object access tokens to widen the default JOB_OBJECT_QUERY mask.
    /// Valid: "query", "set_attributes", "terminate".
    /// WARNING: see SECURITY NOTE on `AipcConfig`.
    #[serde(default)]
    pub job_object: Vec<String>,
    /// Event access tokens to widen the default SYNCHRONIZE | EVENT_MODIFY_STATE
    /// mask. Valid: "wait", "signal", "both".
    #[serde(default)]
    pub event: Vec<String>,
    /// Mutex access tokens to widen the default SYNCHRONIZE | MUTEX_MODIFY_STATE
    /// mask. Valid: "wait", "release", "both".
    #[serde(default)]
    pub mutex: Vec<String>,
}

/// Wrapper for the `capabilities` block on a `Profile`. Currently carries one
/// optional sub-block (`aipc`); future capability families would land as
/// sibling fields here.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitiesConfig {
    /// AIPC-01 (Phase 18) per-handle-type access widening. Absent block
    /// (`None`) means the hard-coded defaults from `nono::supervisor::policy`
    /// apply unchanged.
    #[serde(default)]
    pub aipc: Option<AipcConfig>,
}

/// Pre-resolved per-handle-type allowlist (hard-coded default ∪ profile
/// widening). Cheap to clone; passed through to the capability pipe thread
/// via `Arc` per RESEARCH Open Question #3 — pre-resolve to keep the hot
/// dispatcher path branch-free.
///
/// Default values match the D-05 hard-coded defaults: Connect-only socket,
/// read-OR-write pipe (NOT ReadWrite), `JOB_OBJECT_QUERY` only,
/// `SYNCHRONIZE | EVENT_MODIFY_STATE` event, `SYNCHRONIZE |
/// MUTEX_MODIFY_STATE` mutex.
#[derive(Debug, Clone)]
pub struct AipcResolvedAllowlist {
    /// Socket roles allowed for HandleKind::Socket requests.
    pub socket_roles: Vec<nono::supervisor::SocketRole>,
    /// Pipe directions allowed for HandleKind::Pipe requests.
    pub pipe_directions: Vec<nono::supervisor::PipeDirection>,
    /// Resolved access mask for HandleKind::JobObject requests.
    pub job_object_mask: u32,
    /// Resolved access mask for HandleKind::Event requests.
    pub event_mask: u32,
    /// Resolved access mask for HandleKind::Mutex requests.
    pub mutex_mask: u32,
}

impl Default for AipcResolvedAllowlist {
    fn default() -> Self {
        use nono::supervisor::policy;
        Self {
            socket_roles: vec![nono::supervisor::SocketRole::Connect],
            pipe_directions: vec![
                nono::supervisor::PipeDirection::Read,
                nono::supervisor::PipeDirection::Write,
            ],
            job_object_mask: policy::JOB_OBJECT_DEFAULT_MASK,
            event_mask: policy::EVENT_DEFAULT_MASK,
            mutex_mask: policy::MUTEX_DEFAULT_MASK,
        }
    }
}

fn socket_role_from_token(profile_name: &str, tok: &str) -> Result<nono::supervisor::SocketRole> {
    match tok {
        "connect" => Ok(nono::supervisor::SocketRole::Connect),
        "bind" => Ok(nono::supervisor::SocketRole::Bind),
        "listen" => Ok(nono::supervisor::SocketRole::Listen),
        _ => Err(NonoError::ProfileParse(format!(
            "profile '{profile_name}' capabilities.aipc.socket: \
             unknown role token '{tok}' (valid: connect, bind, listen)"
        ))),
    }
}

fn pipe_direction_from_token(
    profile_name: &str,
    tok: &str,
) -> Result<nono::supervisor::PipeDirection> {
    match tok {
        "read" => Ok(nono::supervisor::PipeDirection::Read),
        "write" => Ok(nono::supervisor::PipeDirection::Write),
        "read+write" => Ok(nono::supervisor::PipeDirection::ReadWrite),
        _ => Err(NonoError::ProfileParse(format!(
            "profile '{profile_name}' capabilities.aipc.pipe: \
             unknown direction token '{tok}' (valid: read, write, read+write)"
        ))),
    }
}

fn job_object_mask_from_token(profile_name: &str, tok: &str) -> Result<u32> {
    use nono::supervisor::policy;
    match tok {
        "query" => Ok(policy::JOB_OBJECT_QUERY),
        "set_attributes" => Ok(policy::JOB_OBJECT_SET_ATTRIBUTES),
        "terminate" => Ok(policy::JOB_OBJECT_TERMINATE),
        _ => Err(NonoError::ProfileParse(format!(
            "profile '{profile_name}' capabilities.aipc.job_object: \
             unknown access token '{tok}' (valid: query, set_attributes, terminate). \
             WARNING: 'terminate' on the supervisor's own containment Job is REFUSED \
             by a structural runtime guard — but enabling it for OTHER Job Objects \
             grants the child the ability to terminate process trees it owns."
        ))),
    }
}

fn event_mask_from_token(profile_name: &str, tok: &str) -> Result<u32> {
    use nono::supervisor::policy;
    match tok {
        "wait" => Ok(policy::SYNCHRONIZE),
        "signal" => Ok(policy::EVENT_MODIFY_STATE),
        "both" => Ok(policy::SYNCHRONIZE | policy::EVENT_MODIFY_STATE),
        _ => Err(NonoError::ProfileParse(format!(
            "profile '{profile_name}' capabilities.aipc.event: \
             unknown access token '{tok}' (valid: wait, signal, both)"
        ))),
    }
}

fn mutex_mask_from_token(profile_name: &str, tok: &str) -> Result<u32> {
    use nono::supervisor::policy;
    match tok {
        "wait" => Ok(policy::SYNCHRONIZE),
        // MUTEX_MODIFY_STATE is documented "Reserved for future use" by
        // Microsoft; ReleaseMutex works against SYNCHRONIZE alone today.
        // We include the bit for forward-compat symmetry with EVENT_MODIFY_STATE
        // (see nono::supervisor::policy::MUTEX_MODIFY_STATE doc).
        "release" => Ok(policy::MUTEX_MODIFY_STATE),
        "both" => Ok(policy::SYNCHRONIZE | policy::MUTEX_MODIFY_STATE),
        _ => Err(NonoError::ProfileParse(format!(
            "profile '{profile_name}' capabilities.aipc.mutex: \
             unknown access token '{tok}' (valid: wait, release, both)"
        ))),
    }
}

/// Policy patch configuration in a profile.
///
/// These fields provide explicit subtractive/additive composition on top of
/// inherited groups and existing filesystem configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPatchConfig {
    /// Group names to remove from the resolved group set.
    #[serde(default)]
    pub exclude_groups: Vec<String>,
    /// Additional read-only directories to allow.
    #[serde(default)]
    pub add_allow_read: Vec<String>,
    /// Additional write-only directories to allow.
    #[serde(default)]
    pub add_allow_write: Vec<String>,
    /// Additional read-write directories to allow.
    #[serde(default)]
    pub add_allow_readwrite: Vec<String>,
    /// Additional deny.access paths to apply.
    #[serde(default)]
    pub add_deny_access: Vec<String>,
    /// Additional commands to block, extending deny.commands from groups.
    /// Useful for blocking specific binaries (e.g. "docker", "kubectl") without
    /// requiring changes to policy.json.
    #[serde(default)]
    pub add_deny_commands: Vec<String>,
    /// Paths to exempt from deny groups.
    /// Each path must also be explicitly granted via `filesystem` or `policy.add_allow_*`.
    /// Does not implicitly grant access; only removes the deny rule.
    ///
    /// **Upstream rename (v0.47.0 / #594):** the canonical JSON key is now
    /// `bypass_protection`. The legacy `override_deny` key continues to
    /// deserialize via the `#[serde(alias = "bypass_protection")]` attribute
    /// for v2.3 backwards-compat, and `Profile::load_from_path` emits a
    /// one-time stderr deprecation warning when the legacy key is observed.
    /// The internal Rust identifier intentionally remains `override_deny` to
    /// avoid a 210-callsite flag-day rename across capability_ext.rs,
    /// policy.rs, policy_cmd.rs, command_runtime.rs, execution_runtime.rs,
    /// launch_runtime.rs, sandbox_prepare.rs, etc. — that internal rename
    /// is tracked as a deferred follow-up to Plan 34-04b (P34-DEFER-04b).
    /// Option C (per Plan 34-04b Task 2 disposition): backwards-compat
    /// deserialize plus deprecation warning runway. Full Option C
    /// (upstream's 824-line `deprecated_schema` module, `LegacyPolicyPatch`
    /// rewriter, and canonical sections `groups`/`commands`/`filesystem`)
    /// is the follow-up surface; this commit lands only the
    /// rename-acceptance contract.
    #[serde(default, alias = "bypass_protection")]
    pub override_deny: Vec<String>,
}

/// Custom credential route definition for reverse proxy.
///
/// Allows users to define their own credential services in profiles,
/// enabling `--proxy-credential` to work with any API without requiring
/// changes to the built-in `network-policy.json`.
///
/// Supports multiple injection modes:
/// - `header`: Inject into HTTP header with format string (default)
/// - `url_path`: Replace pattern in URL path (e.g., Telegram Bot API `/bot{}/`)
/// - `query_param`: Add/replace query parameter (e.g., `?api_key=...`)
/// - `basic_auth`: HTTP Basic Authentication (credential as `username:password`)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomCredentialDef {
    /// Upstream URL to proxy requests to (e.g., "https://api.telegram.org")
    pub upstream: String,
    /// Keystore account name for the credential (e.g., "telegram_bot_token").
    /// PROF-03 (Phase 22): now Optional — `auth` is the alternative for
    /// OAuth2 client_credentials flows. credential_key and auth are mutually
    /// exclusive (validated at profile-load time).
    #[serde(default)]
    pub credential_key: Option<String>,
    /// PROF-03 (Phase 22): Optional OAuth2 client_credentials configuration.
    /// When present, the proxy handles token exchange automatically instead
    /// of using a static credential from the keystore. Mutually exclusive
    /// with `credential_key` — use one or the other.
    ///
    /// Validation at profile-load time:
    /// - `token_url` must be HTTPS (http only for loopback) — fail-closed
    ///   via `NonoError::ProfileParse` per CLAUDE.md "Fail Secure".
    /// - `client_id` and `client_secret` must not be empty.
    /// - `client_secret` may be a `keyring://`, `env://`, `file://`, or
    ///   `op://` URI; resolution happens at proxy startup via
    ///   `nono::keystore::load_secret`.
    ///
    /// The actual OAuth2 token-exchange client lands in Plan 22-04 (OAUTH).
    #[serde(default)]
    pub auth: Option<OAuth2Config>,
    /// Injection mode (default: "header")
    #[serde(default)]
    pub inject_mode: InjectMode,

    // --- Header mode fields ---
    /// HTTP header to inject the credential into (default: "Authorization")
    /// Only used when inject_mode is "header".
    #[serde(default = "default_inject_header")]
    pub inject_header: String,
    /// Format string for the credential value (default: "Bearer {}")
    /// Use {} as placeholder for the credential value.
    /// Only used when inject_mode is "header".
    #[serde(default = "default_credential_format")]
    pub credential_format: String,

    // --- URL path mode fields ---
    /// Pattern to match in incoming URL path. Use {} as placeholder for phantom token.
    /// Example: "/bot{}/" matches "/bot<token>/getMe"
    /// Only used when inject_mode is "url_path".
    #[serde(default)]
    pub path_pattern: Option<String>,
    /// Pattern for outgoing URL path. Use {} as placeholder for real credential.
    /// Defaults to same as path_pattern if not specified.
    /// Only used when inject_mode is "url_path".
    #[serde(default)]
    pub path_replacement: Option<String>,

    // --- Query param mode fields ---
    /// Name of the query parameter to add/replace with the credential.
    /// Only used when inject_mode is "query_param".
    #[serde(default)]
    pub query_param_name: Option<String>,

    /// Explicit environment variable name for the phantom token (e.g., "OPENAI_API_KEY").
    ///
    /// When set, the proxy uses this as the SDK API key env var instead of
    /// deriving it from `credential_key.to_uppercase()`. Required when
    /// `credential_key` is a URI manager reference (`op://`,
    /// `apple-password://`, or `file://`).
    #[serde(default)]
    pub env_var: Option<String>,

    /// Optional L7 endpoint rules for method+path filtering.
    /// When non-empty, only matching method+path combinations are allowed.
    #[serde(default)]
    pub endpoint_rules: Vec<nono_proxy::config::EndpointRule>,

    /// Optional path to a PEM-encoded CA certificate file for upstream TLS.
    ///
    /// When set, the proxy trusts this CA in addition to the system roots
    /// when connecting to the upstream for this route. Required for upstreams
    /// with self-signed or private CA certificates (e.g., Kubernetes API servers).
    ///
    /// Supports absolute paths and tilde (`~/…`) expansion. Relative paths
    /// resolve against the working directory; prefer absolute paths to avoid
    /// ambiguity.
    #[serde(default)]
    pub tls_ca: Option<String>,
}

fn default_inject_header() -> String {
    "Authorization".to_string()
}

fn default_credential_format() -> String {
    "Bearer {}".to_string()
}

/// Check if a character is a valid HTTP token character per RFC 7230.
fn is_http_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '!' | '#'
                | '$'
                | '%'
                | '&'
                | '\''
                | '*'
                | '+'
                | '-'
                | '.'
                | '^'
                | '_'
                | '`'
                | '|'
                | '~'
        )
}

/// Validate a credential key.
///
/// Accepts either:
/// - A bare keyring account name (alphanumeric + underscores only)
/// - A 1Password `op://` URI (validated by `nono::keystore::validate_op_uri`)
/// - An Apple Passwords `apple-password://` URI
/// - A `file://` URI pointing to an absolute path (validated by `nono::keystore::validate_file_uri`)
/// - An `env://` URI referencing a host environment variable (validated by `nono::keystore::validate_env_uri`)
fn validate_credential_key(context_name: &str, key: &str) -> Result<()> {
    if key.is_empty() {
        return Err(NonoError::ProfileParse(format!(
            "credential_key for custom credential '{}' cannot be empty",
            context_name
        )));
    }

    if nono::keystore::is_op_uri(key) {
        nono::keystore::validate_op_uri(key).map_err(|e| {
            NonoError::ProfileParse(format!(
                "invalid 1Password URI for custom credential '{}': {}",
                context_name, e
            ))
        })
    } else if nono::keystore::is_apple_password_uri(key) {
        nono::keystore::validate_apple_password_uri(key).map_err(|e| {
            NonoError::ProfileParse(format!(
                "invalid Apple Passwords URI for custom credential '{}': {}",
                context_name, e
            ))
        })
    } else if nono::keystore::is_file_uri(key) {
        nono::keystore::validate_file_uri(key).map_err(|e| {
            NonoError::ProfileParse(format!(
                "invalid file:// URI for custom credential '{}': {}",
                context_name, e
            ))
        })
    } else if nono::keystore::is_env_uri(key) {
        nono::keystore::validate_env_uri(key).map_err(|e| {
            NonoError::ProfileParse(format!(
                "invalid env:// URI for custom credential '{}': {}",
                context_name, e
            ))
        })
    } else {
        if !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(NonoError::ProfileParse(format!(
                "credential_key '{}' for custom credential '{}' must contain only \
                 alphanumeric characters and underscores (or use op:// / apple-password:// / file:// / env:// URI)",
                key, context_name
            )));
        }
        Ok(())
    }
}

/// Validate a custom credential definition for security issues.
///
/// Checks:
/// - `credential_key` must be alphanumeric + underscores only, or a valid
///   `op://` / `apple-password://` / `file://` / `env://` URI
/// - `upstream` must be HTTPS (or HTTP for loopback only)
/// - Mode-specific validation:
///   - `header`: inject_header must be valid HTTP token, credential_format no CRLF
///   - `url_path`: path_pattern required, no CRLF in patterns
///   - `query_param`: query_param_name required, valid query param name
///   - `basic_auth`: no additional required fields
fn validate_custom_credential(name: &str, cred: &CustomCredentialDef) -> Result<()> {
    // PROF-03 (Phase 22): Mutual exclusion of credential_key and auth.
    if cred.credential_key.is_some() && cred.auth.is_some() {
        return Err(NonoError::ProfileParse(format!(
            "custom credential '{}' has both 'credential_key' and 'auth' set; \
             these are mutually exclusive — use one or the other",
            name
        )));
    }

    // PROF-03 (Phase 22): At least one of credential_key or auth must be set.
    if cred.credential_key.is_none() && cred.auth.is_none() {
        return Err(NonoError::ProfileParse(format!(
            "custom credential '{}' must have either 'credential_key' or 'auth' set",
            name
        )));
    }

    // PROF-03 (Phase 22): Validate OAuth2 auth if present. token_url HTTPS-only
    // (loopback exception) is the fail-closed mechanism per CLAUDE.md
    // "Fail Secure" / threat T-22-01-02.
    if let Some(ref auth) = cred.auth {
        validate_oauth2_auth(name, auth)?;
    }

    // Validate credential_key only when set (Optional from PROF-03 onward).
    if let Some(ref key) = cred.credential_key {
        validate_credential_key(name, key)?;

        // URI manager references (except env://) cannot be meaningfully
        // uppercased into an env var name, so env_var is required for them.
        // env:// is exempt: the var name is derived from the URI itself.
        if (nono::keystore::is_op_uri(key)
            || nono::keystore::is_apple_password_uri(key)
            || nono::keystore::is_file_uri(key))
            && cred.env_var.is_none()
        {
            return Err(NonoError::ProfileParse(format!(
                "env_var is required for custom credential '{}' when credential_key is a URI \
                 manager reference (op://, apple-password://, or file://); \
                 set it to the SDK API key env var name (e.g., \"OPENAI_API_KEY\")",
                name
            )));
        }
    }

    // Validate env_var format if specified
    if let Some(ref ev) = cred.env_var {
        if ev.is_empty() {
            return Err(NonoError::ProfileParse(format!(
                "env_var for custom credential '{}' cannot be empty",
                name
            )));
        }
        if !ev.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(NonoError::ProfileParse(format!(
                "env_var '{}' for custom credential '{}' must contain only \
                 alphanumeric characters and underscores",
                ev, name
            )));
        }
    }

    // Validate upstream URL (HTTPS required, HTTP only for loopback)
    validate_upstream_url(&cred.upstream, name)?;

    // Mode-specific validation only applies to credential_key-based routes.
    // OAuth2 routes always inject as Bearer header (no per-mode validation).
    if cred.credential_key.is_some() {
        match cred.inject_mode {
            InjectMode::Header => {
                validate_header_mode(name, cred)?;
            }
            InjectMode::UrlPath => {
                validate_url_path_mode(name, cred)?;
            }
            InjectMode::QueryParam => {
                validate_query_param_mode(name, cred)?;
            }
            InjectMode::BasicAuth => {
                // No additional required fields for basic_auth mode
                // Credential value is expected to be "username:password" format
            }
        }
    }

    Ok(())
}

/// Validate OAuth2 client_credentials auth configuration.
///
/// PROF-03 (Phase 22) — fail-closed checks at profile load time:
/// - `token_url` must be HTTPS (http only for loopback addresses) per
///   CLAUDE.md "Fail Secure" + threat T-22-01-02 (BLOCKING). Reuses the
///   existing `validate_upstream_url` mechanism for semantic equivalence.
/// - `client_id` must not be empty.
/// - `client_secret` must not be empty. Plain values, `keyring://`, `env://`,
///   `file://`, and `op://` URIs are all accepted at this layer; the actual
///   secret resolution happens at proxy startup (Plan 22-04 OAUTH scope).
fn validate_oauth2_auth(name: &str, auth: &OAuth2Config) -> Result<()> {
    // token_url: HTTPS or loopback HTTP (fail-closed against MITM downgrade).
    validate_upstream_url(&auth.token_url, &format!("{}/auth.token_url", name))?;

    if auth.client_id.is_empty() {
        return Err(NonoError::ProfileParse(format!(
            "auth.client_id for custom credential '{}' cannot be empty",
            name
        )));
    }

    if auth.client_secret.is_empty() {
        return Err(NonoError::ProfileParse(format!(
            "auth.client_secret for custom credential '{}' cannot be empty",
            name
        )));
    }

    // CL-03-M (Phase 22 review): warn (don't fail) when client_secret looks
    // like a literal value rather than a credential URI. The schema documents
    // `keyring://`, `env://`, `file://`, and `op://` as the recommended
    // patterns; a plain literal is accepted but is a leak vector if the
    // profile JSON is committed or shared. Emit a soft warning so the user
    // sees it without breaking valid (but inadvisable) configurations.
    if !auth.client_secret.contains("://") {
        tracing::warn!(
            "custom credential '{}' has a literal auth.client_secret value (no URI scheme). \
             Prefer keyring://, env://, file://, or op:// URIs to avoid committing secrets to disk.",
            name
        );
    }

    Ok(())
}

/// Validate header injection mode fields.
fn validate_header_mode(name: &str, cred: &CustomCredentialDef) -> Result<()> {
    // Validate inject_header (RFC 7230 token)
    if cred.inject_header.is_empty() {
        return Err(NonoError::ProfileParse(format!(
            "inject_header for custom credential '{}' cannot be empty",
            name
        )));
    }
    if !cred.inject_header.chars().all(is_http_token_char) {
        return Err(NonoError::ProfileParse(format!(
            "inject_header '{}' for custom credential '{}' contains invalid characters; \
             header names must be valid HTTP tokens (alphanumeric and !#$%&'*+-.^_`|~)",
            cred.inject_header, name
        )));
    }

    // Validate credential_format (no CRLF injection)
    if cred.credential_format.contains('\r') || cred.credential_format.contains('\n') {
        return Err(NonoError::ProfileParse(format!(
            "credential_format for custom credential '{}' contains invalid CRLF characters; \
             this could enable header injection attacks",
            name
        )));
    }

    Ok(())
}

/// Validate URL path injection mode fields.
fn validate_url_path_mode(name: &str, cred: &CustomCredentialDef) -> Result<()> {
    // path_pattern is required for url_path mode
    let pattern = cred.path_pattern.as_ref().ok_or_else(|| {
        NonoError::ProfileParse(format!(
            "path_pattern is required for custom credential '{}' with inject_mode 'url_path'",
            name
        ))
    })?;

    // Pattern must contain {} placeholder
    if !pattern.contains("{}") {
        return Err(NonoError::ProfileParse(format!(
            "path_pattern '{}' for custom credential '{}' must contain {{}} placeholder for the token",
            pattern, name
        )));
    }

    // No CRLF in pattern
    if pattern.contains('\r') || pattern.contains('\n') {
        return Err(NonoError::ProfileParse(format!(
            "path_pattern for custom credential '{}' contains invalid CRLF characters",
            name
        )));
    }

    // Validate path_replacement if specified
    if let Some(replacement) = &cred.path_replacement {
        if !replacement.contains("{}") {
            return Err(NonoError::ProfileParse(format!(
                "path_replacement '{}' for custom credential '{}' must contain {{}} placeholder",
                replacement, name
            )));
        }
        if replacement.contains('\r') || replacement.contains('\n') {
            return Err(NonoError::ProfileParse(format!(
                "path_replacement for custom credential '{}' contains invalid CRLF characters",
                name
            )));
        }
    }

    Ok(())
}

/// Validate query parameter injection mode fields.
fn validate_query_param_mode(name: &str, cred: &CustomCredentialDef) -> Result<()> {
    // query_param_name is required for query_param mode
    let param_name = cred.query_param_name.as_ref().ok_or_else(|| {
        NonoError::ProfileParse(format!(
            "query_param_name is required for custom credential '{}' with inject_mode 'query_param'",
            name
        ))
    })?;

    // Validate query param name (alphanumeric + underscore + hyphen)
    if param_name.is_empty() {
        return Err(NonoError::ProfileParse(format!(
            "query_param_name for custom credential '{}' cannot be empty",
            name
        )));
    }
    if !param_name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(NonoError::ProfileParse(format!(
            "query_param_name '{}' for custom credential '{}' must contain only \
             alphanumeric characters, underscores, and hyphens",
            param_name, name
        )));
    }

    Ok(())
}

/// Validate an upstream URL for security.
///
/// HTTP is only allowed for loopback addresses:
/// - `localhost` (hostname)
/// - `127.0.0.0/8` (IPv4 loopback range)
/// - `::1` (IPv6 loopback)
/// - `0.0.0.0` (unspecified IPv4, binds to all interfaces)
/// - `::` (unspecified IPv6)
fn validate_upstream_url(url: &str, service_name: &str) -> Result<()> {
    let parsed = url::Url::parse(url).map_err(|e| {
        NonoError::ProfileParse(format!(
            "Invalid upstream URL for custom credential '{}': {}",
            service_name, e
        ))
    })?;

    match parsed.scheme() {
        "https" => Ok(()),
        "http" => {
            // OAUTH-02 security tightening (Plan 22-04, ports semantic of
            // upstream 0c990116): HTTP upstreams are permitted ONLY for
            // explicit loopback addresses (127.0.0.0/8, ::1, "localhost").
            // Unspecified addresses (0.0.0.0, ::) are REJECTED — binding
            // an insecure http upstream to all interfaces would expose it
            // to the local network. Per CLAUDE.md "Fail Secure".
            //
            // For IPv6 addresses, url::Url returns the address in host()
            // but host_str() may include brackets. We need to handle both cases.
            let is_loopback = match parsed.host() {
                Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
                Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
                Some(url::Host::Domain(domain)) => domain == "localhost",
                None => false,
            };

            if is_loopback {
                Ok(())
            } else {
                Err(NonoError::ProfileParse(format!(
                    "Upstream URL for custom credential '{}' must use HTTPS \
                     (HTTP only allowed for loopback addresses, not unspecified \
                     addresses like 0.0.0.0 or ::): {}",
                    service_name, url
                )))
            }
        }
        scheme => Err(NonoError::ProfileParse(format!(
            "Upstream URL for custom credential '{}' must use HTTPS, got scheme '{}': {}",
            service_name, scheme, url
        ))),
    }
}

/// Validate all custom credentials in a profile.
fn validate_profile_custom_credentials(profile: &Profile) -> Result<()> {
    for (name, cred) in &profile.network.custom_credentials {
        validate_custom_credential(name, cred)?;
    }
    Ok(())
}

/// Validate env_credentials keys in a profile.
///
/// Keys can be keyring account names, `op://` URIs, `apple-password://` URIs,
/// `env://` URIs, or `file://` URIs.
/// Keyring account names are validated at load time by the keyring crate itself,
/// but URI entries need structural validation upfront.
fn validate_env_credential_keys(profile: &Profile) -> Result<()> {
    for (key, value) in &profile.env_credentials.mappings {
        if nono::keystore::is_op_uri(key) {
            nono::keystore::validate_op_uri(key).map_err(|e| {
                NonoError::ProfileParse(format!("invalid 1Password URI in env_credentials: {}", e))
            })?;
        } else if nono::keystore::is_apple_password_uri(key) {
            nono::keystore::validate_apple_password_uri(key).map_err(|e| {
                NonoError::ProfileParse(format!(
                    "invalid Apple Passwords URI in env_credentials: {}",
                    e
                ))
            })?;
        } else if nono::keystore::is_env_uri(key) {
            nono::keystore::validate_env_uri(key).map_err(|e| {
                NonoError::ProfileParse(format!("invalid env:// URI in env_credentials: {}", e))
            })?;
        } else if nono::keystore::is_file_uri(key) {
            nono::keystore::validate_file_uri(key).map_err(|e| {
                NonoError::ProfileParse(format!("invalid file:// URI in env_credentials: {}", e))
            })?;
        }
        // Validate destination env var name against dangerous blocklist
        nono::validate_destination_env_var(value).map_err(|e| {
            NonoError::ProfileParse(format!(
                "invalid destination env var '{}' in env_credentials: {}",
                value, e
            ))
        })?;
    }
    Ok(())
}

/// Parse-time validator for the AIPC-01 (Phase 18) `capabilities.aipc` block.
///
/// Calls `Profile::resolve_aipc_allowlist` and discards the result. The call
/// itself runs the per-type `from_token` parsers, surfacing unknown-token
/// errors with verbose `NonoError::ProfileParse` reasons. Wired into
/// `parse_profile_file` so the rejection happens at profile load time, not
/// at the first capability request.
fn validate_profile_aipc_tokens(profile: &Profile) -> Result<()> {
    let _ = profile.resolve_aipc_allowlist()?;
    Ok(())
}

impl Profile {
    /// Resolve the per-handle-type AIPC allowlist by UNIONing the hard-coded
    /// supervisor defaults (D-05) with the profile widening tokens (D-06).
    ///
    /// **Widening only** (D-06): a profile narrower than the default does NOT
    /// narrow the resolved allowlist; the default-deny still applies via the
    /// hard-coded baseline. Tests `aipc_default_inherits_when_block_absent`
    /// and `resolve_aipc_allowlist_widens_event_mask_with_signal_token` prove
    /// the union semantic.
    ///
    /// Unknown tokens are rejected with `NonoError::ProfileParse`. Pre-validate
    /// at profile load time via `validate_profile_aipc_tokens`.
    pub fn resolve_aipc_allowlist(&self) -> Result<AipcResolvedAllowlist> {
        let mut out = AipcResolvedAllowlist::default();
        let aipc = match self.capabilities.aipc.as_ref() {
            Some(a) => a,
            None => return Ok(out),
        };
        let profile_name: &str = if self.meta.name.is_empty() {
            "<unknown>"
        } else {
            self.meta.name.as_str()
        };

        for tok in &aipc.socket {
            let role = socket_role_from_token(profile_name, tok)?;
            if !out.socket_roles.contains(&role) {
                out.socket_roles.push(role);
            }
        }
        for tok in &aipc.pipe {
            let dir = pipe_direction_from_token(profile_name, tok)?;
            if !out.pipe_directions.contains(&dir) {
                out.pipe_directions.push(dir);
            }
        }
        for tok in &aipc.job_object {
            out.job_object_mask |= job_object_mask_from_token(profile_name, tok)?;
        }
        for tok in &aipc.event {
            out.event_mask |= event_mask_from_token(profile_name, tok)?;
        }
        for tok in &aipc.mutex {
            out.mutex_mask |= mutex_mask_from_token(profile_name, tok)?;
        }
        Ok(out)
    }
}

/// Three-state value used for inheritable profile fields.
///
/// - `Inherit`: field was absent in the child profile, so keep the base value
/// - `Clear`: field was explicitly set to `null`, so remove the base value
/// - `Set(T)`: field was provided with a concrete override value
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum InheritableValue<T> {
    #[default]
    Inherit,
    Clear,
    Set(T),
}

impl<T> InheritableValue<T> {
    fn merge(self, base: Self) -> Self {
        match self {
            Self::Inherit => base,
            Self::Clear => Self::Clear,
            Self::Set(value) => Self::Set(value),
        }
    }

    pub fn as_ref(&self) -> Option<&T> {
        match self {
            Self::Set(value) => Some(value),
            Self::Inherit | Self::Clear => None,
        }
    }

    /// Returns `true` if this value is `Inherit` (absent in the source JSON).
    ///
    /// Used with `#[serde(skip_serializing_if)]` to omit inherited fields
    /// from serialized output, preserving the distinction between absent
    /// (inherit) and explicit null (clear).
    pub fn is_inherit(&self) -> bool {
        matches!(self, Self::Inherit)
    }
}

impl<T> Serialize for InheritableValue<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Set(value) => value.serialize(serializer),
            Self::Clear => serializer.serialize_none(),
            // Inherit should be skipped via skip_serializing_if.
            // If serialize is called anyway, emit null as a safe fallback.
            Self::Inherit => serializer.serialize_none(),
        }
    }
}

impl<'de, T> Deserialize<'de> for InheritableValue<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Option::<T>::deserialize(deserializer)? {
            Some(value) => Ok(Self::Set(value)),
            None => Ok(Self::Clear),
        }
    }
}

/// Network configuration in a profile
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// Block network access (network allowed by default; true = blocked).
    /// Canonical profile key: `block`.
    #[serde(default)]
    pub block: bool,
    /// Network proxy profile name (from network-policy.json).
    /// When set, outbound traffic is filtered through the proxy.
    ///
    /// `null` explicitly clears an inherited profile value, while an absent
    /// field inherits the base profile's value.
    #[serde(default, skip_serializing_if = "InheritableValue::is_inherit")]
    pub network_profile: InheritableValue<String>,
    /// Additional domains to allow through the proxy (on top of profile hosts).
    /// Canonical profile key: `allow_domain` (legacy `proxy_allow` and
    /// `allow_proxy` are also accepted).
    #[serde(
        default,
        rename = "allow_domain",
        alias = "proxy_allow",
        alias = "allow_proxy"
    )]
    pub allow_domain: Vec<String>,
    /// Credential services to enable via reverse proxy.
    /// Canonical profile key: `credentials` (legacy `proxy_credentials` accepted).
    ///
    /// When `None` (absent from profile), inherits parent credentials during merge.
    /// When `Some([])` (explicitly set to empty array), overrides parent to disable
    /// all inherited credential routes.
    #[serde(
        default,
        rename = "credentials",
        alias = "proxy_credentials",
        skip_serializing_if = "Option::is_none"
    )]
    pub credentials: Option<Vec<String>>,
    /// Localhost TCP ports to allow bidirectional IPC (connect + bind).
    /// Equivalent to `--open-port` CLI flag.
    /// Canonical profile key: `open_port` (legacy `port_allow` and `allow_port`
    /// are also accepted).
    #[serde(
        default,
        rename = "open_port",
        alias = "port_allow",
        alias = "allow_port"
    )]
    pub open_port: Vec<u16>,
    /// TCP ports the sandboxed child may listen on.
    /// Equivalent to `--listen-port` CLI flag.
    #[serde(default)]
    pub listen_port: Vec<u16>,
    /// Outbound TCP connect ports (allowlist). Linux Landlock V4+ only.
    /// Equivalent to `--allow-connect-port` CLI flag.
    #[serde(default)]
    pub connect_port: Vec<u16>,
    /// Custom credential definitions for services not in network-policy.json.
    /// Keys are service names (used with `--credential`), values define
    /// how to route and inject credentials for that service.
    #[serde(default)]
    pub custom_credentials: HashMap<String, CustomCredentialDef>,
    /// Upstream proxy address (host:port) for enterprise proxy passthrough.
    /// Canonical profile key: `upstream_proxy` (legacy `external_proxy`
    /// accepted).
    #[serde(default, rename = "upstream_proxy", alias = "external_proxy")]
    pub upstream_proxy: Option<String>,
    /// Hosts to bypass the upstream proxy and route directly.
    /// Canonical profile key: `upstream_bypass` (legacy
    /// `external_proxy_bypass` accepted).
    #[serde(default, rename = "upstream_bypass", alias = "external_proxy_bypass")]
    pub upstream_bypass: Vec<String>,
}

impl NetworkConfig {
    pub fn resolved_network_profile(&self) -> Option<&str> {
        self.network_profile.as_ref().map(String::as_str)
    }

    /// Returns the resolved credentials list, defaulting to empty if unset.
    pub fn resolved_credentials(&self) -> &[String] {
        self.credentials.as_deref().unwrap_or(&[])
    }

    /// Whether any profile setting requires proxy mode activation.
    pub fn has_proxy_flags(&self) -> bool {
        self.resolved_network_profile().is_some()
            || !self.allow_domain.is_empty()
            || !self.resolved_credentials().is_empty()
            || self.upstream_proxy.is_some()
    }
}

/// Secrets configuration in a profile
///
/// Maps keystore account names to environment variable names.
/// Secrets are loaded from the system keystore (macOS Keychain / Linux Secret Service)
/// under the service name "nono".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretsConfig {
    /// Map of keystore account name -> environment variable name
    /// Example: { "openai_api_key" = "OPENAI_API_KEY" }
    #[serde(flatten)]
    pub mappings: HashMap<String, String>,
}

/// Hook configuration for an agent
///
/// Defines hooks that nono will install for the target application.
/// For example, Claude Code hooks are installed to ~/.claude/hooks/
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookConfig {
    /// Event that triggers the hook (e.g., "PostToolUseFailure")
    pub event: String,
    /// Regex pattern to match tool names (e.g., "Read|Write|Edit|Bash")
    pub matcher: String,
    /// Script filename from data/hooks/ to install
    pub script: String,
}

/// Hooks configuration in a profile
///
/// Maps target application names to their hook configurations.
/// Example: [hooks.claude-code] for Claude Code hooks
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HooksConfig {
    /// Map of target application -> hook configuration
    #[serde(flatten)]
    pub hooks: HashMap<String, HookConfig>,
}

/// Working directory access level for profiles
///
/// Controls whether and how the current working directory is automatically
/// shared with the sandboxed process. This is profile-driven so each
/// application can declare its own CWD requirements.
/// Signal isolation mode as specified in a profile.
///
/// Maps to `nono::SignalMode` when building the `CapabilitySet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileSignalMode {
    /// Signals restricted to the current process only
    Isolated,
    /// Signals allowed to child processes in the same sandbox only
    AllowSameSandbox,
    /// Signals allowed to any process
    AllowAll,
}

impl From<ProfileSignalMode> for nono::SignalMode {
    fn from(val: ProfileSignalMode) -> Self {
        match val {
            ProfileSignalMode::Isolated => nono::SignalMode::Isolated,
            ProfileSignalMode::AllowSameSandbox => nono::SignalMode::AllowSameSandbox,
            ProfileSignalMode::AllowAll => nono::SignalMode::AllowAll,
        }
    }
}

/// Process inspection mode as specified in a profile.
///
/// Maps to `nono::ProcessInfoMode` when building the `CapabilitySet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileProcessInfoMode {
    /// Inspection restricted to self only (default)
    Isolated,
    /// Inspection allowed for same-sandbox children
    AllowSameSandbox,
    /// Inspection allowed for any process
    AllowAll,
}

impl From<ProfileProcessInfoMode> for nono::ProcessInfoMode {
    fn from(val: ProfileProcessInfoMode) -> Self {
        match val {
            ProfileProcessInfoMode::Isolated => nono::ProcessInfoMode::Isolated,
            ProfileProcessInfoMode::AllowSameSandbox => nono::ProcessInfoMode::AllowSameSandbox,
            ProfileProcessInfoMode::AllowAll => nono::ProcessInfoMode::AllowAll,
        }
    }
}

/// IPC mode as specified in a profile.
///
/// Maps to `nono::IpcMode` when building the `CapabilitySet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileIpcMode {
    /// POSIX shared memory only (default). Semaphores denied.
    SharedMemoryOnly,
    /// Full POSIX IPC: shared memory + semaphores.
    Full,
}

impl From<ProfileIpcMode> for nono::IpcMode {
    fn from(val: ProfileIpcMode) -> Self {
        match val {
            ProfileIpcMode::SharedMemoryOnly => nono::IpcMode::SharedMemoryOnly,
            ProfileIpcMode::Full => nono::IpcMode::Full,
        }
    }
}

/// WSL2 proxy fallback policy.
///
/// Controls what happens when `NetworkMode::ProxyOnly` is requested on WSL2
/// where the seccomp-notify fallback cannot be used (EBUSY). On native Linux
/// (including pre-V4 kernels), the seccomp fallback enforces proxy-only
/// networking. On WSL2, that enforcement is unavailable.
///
/// Default: `Error` — refuse to run rather than silently losing enforcement.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Wsl2ProxyPolicy {
    /// Refuse to run if ProxyOnly cannot be kernel-enforced on WSL2.
    /// This is the secure default.
    #[default]
    Error,
    /// Allow degraded execution: credential proxy runs and env vars are
    /// injected, but the child is NOT prevented from bypassing the proxy
    /// and opening arbitrary outbound connections directly.
    /// Use only when credential injection is more important than network
    /// lockdown (e.g., development workflows where the agent is trusted).
    InsecureProxy,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkdirAccess {
    /// No automatic CWD access
    #[default]
    None,
    /// Read-only access to CWD
    Read,
    /// Write-only access to CWD
    Write,
    /// Full read+write access to CWD
    ReadWrite,
}

/// Working directory configuration in a profile
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkdirConfig {
    /// Access level for the current working directory
    #[serde(default)]
    pub access: WorkdirAccess,
}

/// Security configuration referencing policy.json groups
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    /// Policy group names to resolve (from policy.json)
    #[serde(default)]
    pub groups: Vec<String>,
    /// Commands to allow even when blocked by default policy (e.g. `["rm"]`).
    /// Applied before CLI `--allow-command` overrides.
    #[serde(default)]
    pub allowed_commands: Vec<String>,
    /// Signal isolation mode. Controls whether the sandboxed process can signal
    /// other processes. When `None`, inherits from the base profile during merge
    /// (defaults to `Isolated` if no base sets it).
    #[serde(default)]
    pub signal_mode: Option<ProfileSignalMode>,
    /// Process inspection mode. Controls whether the sandboxed process can read
    /// process info (ps, proc_pidinfo) for other processes. When `None`, defaults
    /// to `Isolated`.
    #[serde(default)]
    pub process_info_mode: Option<ProfileProcessInfoMode>,
    /// IPC mode. Controls whether the sandboxed process can use POSIX semaphores
    /// (needed for multiprocessing). When `None`, defaults to `SharedMemoryOnly`.
    #[serde(default)]
    pub ipc_mode: Option<ProfileIpcMode>,
    /// Enable runtime capability elevation via seccomp-notify (Linux).
    /// When true, the supervisor intercepts file opens and can grant access
    /// to paths not in the initial capability set. When false (default),
    /// the sandbox is static — no seccomp interception, no PTY mux, no prompts.
    #[serde(default)]
    pub capability_elevation: Option<bool>,
    /// WSL2 proxy fallback policy. Controls behavior when ProxyOnly network
    /// mode cannot be kernel-enforced on WSL2 (seccomp notify returns EBUSY).
    /// Default: `error` — refuse to run. Set to `insecure_proxy` to allow
    /// degraded execution where the credential proxy runs but the child is
    /// not prevented from bypassing it.
    #[serde(default)]
    pub wsl2_proxy_policy: Option<Wsl2ProxyPolicy>,
}

/// Rollback snapshot configuration in a profile
///
/// Controls which files are excluded from rollback snapshots. Patterns are
/// matched against path components (exact match) or, if they contain `/`,
/// as substrings of the full path. Glob patterns are matched against
/// the filename (last path component).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackConfig {
    /// Patterns to exclude from rollback snapshots.
    /// Added on top of the CLI's base exclusion list.
    #[serde(default)]
    pub exclude_patterns: Vec<String>,
    /// Glob patterns to exclude from rollback snapshots.
    /// Matched against the filename using standard glob syntax.
    #[serde(default)]
    pub exclude_globs: Vec<String>,
}

/// Controls which environment variables are passed to the sandboxed process.
///
/// By default, all environment variables are inherited from the parent process.
/// When `allow_vars` is set, only the listed variables (and nono-injected
/// credentials) are passed through. Supports exact names (`"PATH"`) and
/// prefix patterns (`"AWS_*"`).
///
/// Precedence (highest to lowest):
/// 1. Hardcoded `is_dangerous_env_var` — always stripped, cannot be re-allowed.
/// 2. `deny_vars` — stripped even if matched by `allow_vars`.
/// 3. `allow_vars` — if non-empty, only matching vars pass; if empty, all (except 1+2) pass.
///
/// Ported from upstream v0.37.0 `1b412a7` per Plan 34-08a Task 3 (D-20 manual
/// replay). Phase 20-03 commit `b4762e63` ported only the CLI flag-parsing
/// slice; this is part of the deferred surface. `deny_vars` added per
/// upstream v0.52.0 `3657c935` (Plan 34-08a Task 4).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentConfig {
    /// Allow-list of environment variable names passed to the sandboxed process.
    ///
    /// Supports exact names (`"PATH"`) and prefix patterns ending with `*`
    /// (`"AWS_*"` matches `AWS_REGION`, `AWS_SECRET_ACCESS_KEY`, etc.).
    /// When empty, all variables are allowed (default).
    /// Nono-injected credentials always bypass this list.
    #[serde(default)]
    pub allow_vars: Vec<String>,

    /// Deny-list of environment variable names stripped from the sandboxed process.
    ///
    /// Supports exact names (`"GH_TOKEN"`) and prefix patterns ending with `*`
    /// (`"GITHUB_*"` strips all vars starting with `GITHUB_`).
    /// Denied vars are stripped even if they also appear in `allow_vars`.
    /// Use this to strip specific secrets while keeping everything else inherited.
    #[serde(default)]
    pub deny_vars: Vec<String>,
}

/// Configuration for supervisor-delegated URL opening.
///
/// Controls which URLs the sandboxed child can request the supervisor to
/// open in the user's browser. Used for OAuth2 login flows and similar
/// operations where the sandboxed process cannot launch a browser directly.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenUrlConfig {
    /// Allowed URL origins (scheme + host, e.g., "https://console.anthropic.com").
    /// The supervisor validates each URL open request against this list.
    /// An empty list means no URLs are allowed.
    #[serde(default)]
    pub allow_origins: Vec<String>,
    /// Allow opening http://localhost and http://127.0.0.1 URLs (for OAuth2 callbacks).
    #[serde(default)]
    pub allow_localhost: bool,
}

/// Deserialize the `extends` field from either a single string or an array of strings.
///
/// Accepts:
/// - `"extends": "base"` → `Some(vec!["base"])`
/// - `"extends": ["a", "b"]` → `Some(vec!["a", "b"])`
/// - absent / null → `None`
fn deserialize_extends<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum ExtendsValue {
        Single(String),
        Multiple(Vec<String>),
    }

    let value: Option<ExtendsValue> = Option::deserialize(deserializer)?;
    Ok(match value {
        Some(ExtendsValue::Single(s)) => Some(vec![s]),
        Some(ExtendsValue::Multiple(v)) => {
            if v.is_empty() {
                None
            } else {
                Some(v)
            }
        }
        None => None,
    })
}

/// A complete profile definition
#[derive(Debug, Clone, Default, Serialize)]
pub struct Profile {
    /// Optional base profile(s) to inherit from (by name).
    /// Accepts either a single string `"extends": "base"` or an array
    /// `"extends": ["base-a", "base-b"]`. Multiple bases are merged
    /// left-to-right before the child overrides.
    #[serde(default, deserialize_with = "deserialize_extends")]
    pub extends: Option<Vec<String>>,
    #[serde(default)]
    pub meta: ProfileMeta,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub filesystem: FilesystemConfig,
    #[serde(default)]
    pub policy: PolicyPatchConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default, alias = "secrets")]
    pub env_credentials: SecretsConfig,
    /// Environment variable allow-list (ported from upstream v0.37.0 `1b412a7`).
    /// When `None` (absent from JSON), all parent env vars are inherited (default).
    /// When `Some(EnvironmentConfig { allow_vars: [...] })`, only matching vars
    /// pass through. Nono-injected credentials always bypass.
    #[serde(default)]
    pub environment: Option<EnvironmentConfig>,
    #[serde(default)]
    pub workdir: WorkdirConfig,
    #[serde(default)]
    pub hooks: HooksConfig,
    #[serde(default, alias = "undo")]
    pub rollback: RollbackConfig,
    /// Supervisor-delegated URL opening (e.g., for OAuth2 login flows).
    /// When `None` (absent from JSON), inherits from the base profile.
    /// When `Some`, replaces the base profile's config entirely, allowing
    /// derived profiles to narrow permissions.
    #[serde(default)]
    pub open_urls: Option<OpenUrlConfig>,
    /// Opt-in gate for temporary direct LaunchServices opens on macOS.
    /// Must be paired with the CLI flag `--allow-launch-services`.
    /// When `None`, inherits from the base profile.
    #[serde(default)]
    pub allow_launch_services: Option<bool>,
    /// Deprecated: Parsed for backward compatibility but ignored.
    /// Supervised mode preserves TTY by default, making this unnecessary.
    #[serde(default)]
    pub interactive: bool,
    /// Directory names to skip during trust scanning and rollback preflight.
    /// Treated like built-in heavy directories (for example `target`).
    #[serde(default)]
    pub skipdirs: Vec<String>,
    /// AIPC-01 (Phase 18) capability widening. Absent block (`Default`)
    /// means the hard-coded supervisor defaults apply unchanged.
    #[serde(default)]
    pub capabilities: CapabilitiesConfig,
    /// PROF-02 (Phase 22): pack dependencies verified at launch before
    /// sandbox is applied. Each entry is a `<namespace>/<name>` reference
    /// to an installed pack. On Windows the registry-pack resolution short-
    /// circuits when the registry client is unavailable (Plan 22-03 lands
    /// the actual resolution surface). Field deserializes on every platform.
    #[serde(default)]
    pub packs: Vec<String>,
    /// PROF-02 (Phase 22): extra arguments appended to the child command
    /// at launch. Supports variable expansion (e.g. `$NONO_PACKAGES` —
    /// expansion lands with the rest of the package machinery in Plan
    /// 22-03). Field deserializes on every platform.
    #[serde(default)]
    pub command_args: Vec<String>,
    /// Raw macOS-only Seatbelt S-expression rules applied verbatim to the sandbox policy.
    ///
    /// Expert escape hatch for capability gaps. Each entry must be a valid Seatbelt
    /// S-expression such as `(allow iokit-open)`. Rules are validated at load time
    /// and rejected if malformed. Ignored on Linux and Windows (deserialize-only;
    /// runtime application is macOS-only by design per REQ-PROF-01). Prominently
    /// surfaced in `nono profile show` output when present so it is obvious a
    /// profile uses raw platform rules.
    ///
    /// This field is intentionally named `unsafe_*` — it bypasses nono's capability
    /// model. If a rule pattern becomes common, prefer promoting it to a typed
    /// first-class capability.
    #[serde(default)]
    pub unsafe_macos_seatbelt_rules: Vec<String>,
    /// Commands configuration — canonical section per upstream f0abd413 (v0.47.0).
    ///
    /// Provides structured allow/deny command lists at the profile level. These
    /// compose with the group-based command policy from `security.groups` and
    /// the CLI `--allow-command` / add_deny_commands flags. Plan 36-01c follows
    /// with the callsite rename that wires this field into the capability
    /// construction path; this field is the canonical target shape.
    #[serde(default)]
    pub commands: CommandsConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileDeserialize {
    /// Optional JSON Schema URI for editor tooling. Parsed and ignored.
    #[serde(rename = "$schema", default)]
    _schema: Option<String>,
    #[serde(default, deserialize_with = "deserialize_extends")]
    extends: Option<Vec<String>>,
    #[serde(default)]
    meta: ProfileMeta,
    #[serde(default)]
    security: SecurityConfig,
    #[serde(default)]
    filesystem: FilesystemConfig,
    #[serde(default)]
    policy: PolicyPatchConfig,
    #[serde(default)]
    network: NetworkConfig,
    #[serde(default, alias = "secrets")]
    env_credentials: SecretsConfig,
    #[serde(default)]
    environment: Option<EnvironmentConfig>,
    #[serde(default)]
    workdir: WorkdirConfig,
    #[serde(default)]
    hooks: HooksConfig,
    #[serde(default, alias = "undo")]
    rollback: RollbackConfig,
    #[serde(default)]
    open_urls: Option<OpenUrlConfig>,
    #[serde(default)]
    allow_launch_services: Option<bool>,
    #[serde(default)]
    interactive: bool,
    #[serde(default)]
    skipdirs: Vec<String>,
    #[serde(default)]
    capabilities: CapabilitiesConfig,
    #[serde(default)]
    unsafe_macos_seatbelt_rules: Vec<String>,
    #[serde(default)]
    packs: Vec<String>,
    #[serde(default)]
    #[serde(alias = "brokered_commands")]
    command_args: Vec<String>,
    #[serde(default)]
    commands: CommandsConfig,
}

impl From<ProfileDeserialize> for Profile {
    fn from(raw: ProfileDeserialize) -> Self {
        Self {
            extends: raw.extends,
            meta: raw.meta,
            security: raw.security,
            filesystem: raw.filesystem,
            policy: raw.policy,
            network: raw.network,
            env_credentials: raw.env_credentials,
            environment: raw.environment,
            workdir: raw.workdir,
            hooks: raw.hooks,
            rollback: raw.rollback,
            open_urls: raw.open_urls,
            allow_launch_services: raw.allow_launch_services,
            interactive: raw.interactive,
            skipdirs: raw.skipdirs,
            capabilities: raw.capabilities,
            unsafe_macos_seatbelt_rules: raw.unsafe_macos_seatbelt_rules,
            packs: raw.packs,
            command_args: raw.command_args,
            // Plan 36-01b: canonical section per upstream f0abd413 (v0.47.0).
            // Exhaustively enumerated here so rustc's struct-literal completeness
            // check (T-36-01-CANONICAL) catches any future field additions.
            commands: raw.commands,
        }
    }
}

impl<'de> Deserialize<'de> for Profile {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = ProfileDeserialize::deserialize(deserializer)?;
        Ok(raw.into())
    }
}

/// Check whether a profile name is loaded from a user file rather than the built-in set.
///
/// Returns `true` when a user profile file exists at `~/.config/nono/profiles/<name>.json`,
/// which means the user has overridden or shadowed any built-in profile of the same name.
pub fn is_user_override(name: &str) -> bool {
    if !is_valid_profile_name(name) {
        return false;
    }
    get_user_profile_path(name)
        .map(|p| p.exists())
        .unwrap_or(false)
}

/// Return the package directory that owns a profile symlink, if any.
///
/// A package-managed profile appears in `~/.config/nono/profiles/` (or the
/// platform equivalent) as a symlink into the package store. This helper
/// resolves that relationship so package hooks and other assets can be
/// located relative to the installed package.
pub fn get_package_for_profile(name: &str) -> Option<PathBuf> {
    if !is_valid_profile_name(name) {
        return None;
    }

    crate::package::is_profile_symlink_into_package_store(name)
}

/// Load a profile's raw (unresolved) extends target names.
///
/// Returns `Some(base_names)` if the profile declares `extends`, `None` otherwise.
/// This reads the raw profile definition before inheritance resolution clears the field.
pub fn load_profile_extends(name_or_path: &str) -> Option<Vec<String>> {
    // Direct file path
    if name_or_path.contains('/') || name_or_path.ends_with(".json") {
        return parse_profile_file(Path::new(name_or_path))
            .ok()
            .and_then(|p| p.extends);
    }

    if !is_valid_profile_name(name_or_path) {
        return None;
    }

    // User profile
    if let Ok(profile_path) = get_user_profile_path(name_or_path) {
        if profile_path.exists() {
            return parse_profile_file(&profile_path)
                .ok()
                .and_then(|p| p.extends);
        }
    }

    // Built-in profile
    if let Ok(policy) = crate::policy::load_embedded_policy() {
        if let Some(def) = policy.profiles.get(name_or_path) {
            return def.extends.as_ref().map(|s| vec![s.clone()]);
        }
    }

    None
}

/// Load a profile by name or file path
///
/// If `name_or_path` contains a path separator or ends with `.json`, it is
/// treated as a direct file path. Otherwise it is resolved as a profile name.
///
/// Name loading precedence:
/// 1. User profiles from ~/.config/nono/profiles/<name>.json (allows customization)
/// 2. Built-in profiles (compiled into binary, fallback)
pub fn load_profile(name_or_path: &str) -> Result<Profile> {
    // Registry reference (namespace/name) — detect before the file path check
    // since the `/` would otherwise be treated as a path separator.
    if is_registry_ref(name_or_path) {
        return load_registry_profile(name_or_path);
    }

    // Direct file path: contains separator or ends with .json
    if name_or_path.contains('/') || name_or_path.ends_with(".json") {
        return load_profile_from_path(Path::new(name_or_path));
    }

    // Validate profile name (alphanumeric + hyphen only)
    if !is_valid_profile_name(name_or_path) {
        return Err(NonoError::ProfileParse(format!(
            "Invalid profile name '{}': must be alphanumeric with hyphens only",
            name_or_path
        )));
    }

    // 1. Check user profiles first (allows overriding built-ins)
    let profile_path = get_user_profile_path(name_or_path)?;
    if profile_path.exists() {
        tracing::info!("Loading user profile from: {}", profile_path.display());
        return finalize_profile(load_from_file(&profile_path)?);
    }

    // 2. Fall back to built-in profiles
    if let Some(profile) = builtin::get_builtin(name_or_path) {
        tracing::info!("Using built-in profile: {}", name_or_path);
        return Ok(profile);
    }

    Err(NonoError::ProfileNotFound(name_or_path.to_string()))
}

/// Returns true if the string looks like a registry package reference
/// (`namespace/name` or `namespace/name@version`) rather than a filesystem path.
fn is_registry_ref(s: &str) -> bool {
    // Strip optional @version suffix for the path check
    let path_part = s.split_once('@').map_or(s, |(p, _)| p);
    let parts: Vec<&str> = path_part.split('/').collect();
    parts.len() == 2
        && !s.starts_with('.')
        && !s.starts_with('~')
        && !s.starts_with('/')
        && !s.ends_with(".json")
        && parts.iter().all(|p| !p.is_empty())
}

/// Load a profile from a registry pack. If the pack isn't installed locally,
/// pull it first (Docker-style auto-pull with Sigstore verification).
fn load_registry_profile(name_or_path: &str) -> Result<Profile> {
    let package_ref = crate::package::parse_package_ref(name_or_path)?;
    let install_dir =
        crate::package::package_install_dir(&package_ref.namespace, &package_ref.name)?;

    // Check if pack is already installed
    if !install_dir.join("package.json").exists() {
        eprintln!("Profile '{}' not found locally.", package_ref.key());

        // Auto-pull from registry
        crate::package_cmd::run_pull(crate::cli::PullArgs {
            package_ref: name_or_path.to_string(),
            registry: None,
            force: false,
            init: false,
            help: None,
        })?;
    }

    // Read manifest to check pack type and find profile artifacts
    let manifest_path = install_dir.join("package.json");
    if !manifest_path.exists() {
        return Err(NonoError::ProfileNotFound(format!(
            "pack '{}' failed to install",
            package_ref.key()
        )));
    }

    let manifest_json = std::fs::read_to_string(&manifest_path).map_err(NonoError::Io)?;
    let manifest: crate::package::PackageManifest =
        serde_json::from_str(&manifest_json).map_err(|e| {
            NonoError::ProfileParse(format!(
                "invalid package.json in '{}': {e}",
                package_ref.key()
            ))
        })?;

    if manifest.pack_type != crate::package::PackType::Policy {
        return Err(NonoError::ProfileParse(format!(
            "'{}' is a {} — only policy packs can be used with --profile.\n\
             Use 'nono pull {}' to install it instead.",
            package_ref.key(),
            manifest.pack_type.label(),
            package_ref.key()
        )));
    }

    // Find the profile JSON in the installed pack
    for artifact in &manifest.artifacts {
        if artifact.artifact_type == crate::package::ArtifactType::Profile {
            let install_name = artifact.install_as.as_deref().unwrap_or(&artifact.path);
            let profile_path = install_dir
                .join("profiles")
                .join(format!("{install_name}.json"));
            if profile_path.exists() {
                tracing::info!("Loading registry profile from: {}", profile_path.display());
                return finalize_profile(load_from_file(&profile_path)?);
            }
        }
    }

    Err(NonoError::ProfileParse(format!(
        "no profile found in pack '{}'",
        package_ref.key()
    )))
}

/// Load a profile from a direct file path.
///
/// The path must exist and point to a valid JSON profile file.
/// Base groups are merged automatically.
pub fn load_profile_from_path(path: &Path) -> Result<Profile> {
    if !path.exists() {
        return Err(NonoError::ProfileRead {
            path: path.to_path_buf(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "profile file not found"),
        });
    }

    tracing::info!("Loading profile from path: {}", path.display());
    finalize_profile(load_from_file(path)?)
}

/// Load a raw profile from a direct file path without resolving inheritance.
#[cfg(not(target_os = "windows"))]
pub(crate) fn load_raw_profile_from_path(path: &Path) -> Result<Profile> {
    if !path.exists() {
        return Err(NonoError::ProfileRead {
            path: path.to_path_buf(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "profile file not found"),
        });
    }

    tracing::info!("Loading raw profile from path: {}", path.display());
    parse_profile_file(path)
}

/// Resolve inheritance and apply implicit default-group merging for a raw profile.
pub(crate) fn finalize_profile(mut profile: Profile) -> Result<Profile> {
    merge_implicit_default_groups(&mut profile)?;
    Ok(profile)
}

/// Resolve inheritance and apply implicit default-group merging for a raw profile.
pub(crate) fn resolve_and_finalize_profile(profile: Profile) -> Result<Profile> {
    finalize_profile(resolve_extends(profile, &mut Vec::new(), 0, None, None)?)
}

/// Get the implicit default groups for a finalized profile.
///
/// The built-in `default` profile is now the canonical source of implicit
/// groups. The `default` profile itself does not inherit any additional groups.
fn implicit_default_groups(profile: &Profile) -> Result<Vec<String>> {
    if profile.meta.name == "default" {
        return Ok(Vec::new());
    }

    let default = crate::policy::get_policy_profile("default")?
        .ok_or_else(|| NonoError::ProfileNotFound("default".to_string()))?;
    Ok(default.security.groups)
}

/// Merge the implicit default profile groups into a finalized profile.
///
/// User profiles loaded from file only declare their own groups in
/// `security.groups`. Built-in profiles also resolve through the same raw
/// profile pipeline before implicit default groups are merged.
/// This function applies:
/// `((implicit_default_groups + profile.groups) - profile.policy.exclude_groups)`.
///
/// This means exclusions win even if the same group is also added explicitly in
/// `security.groups`.
fn merge_implicit_default_groups(profile: &mut Profile) -> Result<()> {
    let policy = crate::policy::load_embedded_policy()?;
    let exclusions = &profile.policy.exclude_groups;
    crate::policy::validate_group_exclusions(&policy, exclusions)?;

    let mut merged = implicit_default_groups(profile)?;
    // Append profile-specific groups (avoiding duplicates)
    let mut seen: std::collections::HashSet<String> = merged.iter().cloned().collect();
    for g in &profile.security.groups {
        if seen.insert(g.clone()) {
            merged.push(g.clone());
        }
    }
    if !exclusions.is_empty() {
        let exclude_set: std::collections::HashSet<&String> = exclusions.iter().collect();
        merged.retain(|g| !exclude_set.contains(g));
    }
    profile.security.groups = merged;
    Ok(())
}

/// Parse a profile JSON file without resolving inheritance.
///
/// Returns the raw deserialized `Profile` with `extends` still set.
/// Used during inheritance resolution to load base profiles without
/// triggering infinite recursion.
fn parse_profile_file(path: &Path) -> Result<Profile> {
    let content = fs::read_to_string(path).map_err(|e| NonoError::ProfileRead {
        path: path.to_path_buf(),
        source: e,
    })?;

    // Plan 34-04b Option C: emit a one-time deprecation warning if this
    // profile uses the legacy `override_deny` JSON key (upstream f0abd413
    // renamed it to `bypass_protection`; both continue to deserialize for
    // v2.3 backwards-compat via the serde alias on PolicyPatchConfig).
    detect_legacy_override_deny_key(&content);

    let profile: Profile =
        serde_json::from_str(&content).map_err(|e| NonoError::ProfileParse(e.to_string()))?;

    // Validate custom credentials for security issues
    validate_profile_custom_credentials(&profile)?;

    // Validate env_credentials keys (URI entries need structural validation)
    validate_env_credential_keys(&profile)?;

    // Validate AIPC-01 (Phase 18) capability widening tokens at parse time so
    // unknown tokens fail loudly here rather than at the first capability
    // request. Reuses Profile::resolve_aipc_allowlist's per-type from_token
    // parsers.
    validate_profile_aipc_tokens(&profile)?;

    Ok(profile)
}

/// Load a profile from a JSON file, resolving inheritance. The parent
/// directory is passed as context so `extends` can resolve sibling profiles.
fn load_from_file(path: &Path) -> Result<Profile> {
    let profile = parse_profile_file(path)?;
    let context_dir = path.parent();
    resolve_extends(profile, &mut Vec::new(), 0, context_dir, Some(path))
}

// ============================================================================
// Profile inheritance (extends)
// ============================================================================

/// Maximum depth for profile inheritance chains.
const MAX_INHERITANCE_DEPTH: usize = 10;

/// Resolve the `extends` chain for a profile.
///
/// If the profile declares `extends` (one or more base names), each base is
/// loaded and resolved recursively, then they are fold-merged left-to-right.
/// The accumulated base is finally merged with the child. When `context_dir`
/// is set, sibling `<name>.json` files are checked first so project-local
/// profiles can reference each other by name. `source_file` is the path of
/// the file whose extends are being resolved so sibling lookup can skip
/// self-references (e.g. `.nono/codex.json` extending `"codex"` should not
/// resolve to itself). The `visited` vec tracks profile names already in the
/// chain to detect circular dependencies.
///
/// Shared transitive bases are handled naturally: `visited` tracks only the
/// current ancestor chain (push before recurse, pop after). When two siblings
/// share a transitive base, it is resolved once per sibling; because
/// `merge_profiles` is idempotent, the result is correct. Only true cycles
/// (a profile extending one of its own ancestors) are rejected.
fn resolve_extends(
    child: Profile,
    visited: &mut Vec<String>,
    depth: usize,
    context_dir: Option<&Path>,
    source_file: Option<&Path>,
) -> Result<Profile> {
    let base_names = match child.extends {
        Some(ref names) => names.clone(),
        None => return Ok(child),
    };

    if depth >= MAX_INHERITANCE_DEPTH {
        return Err(NonoError::ProfileInheritance(format!(
            "inheritance chain too deep (max {}): {}",
            MAX_INHERITANCE_DEPTH,
            visited.join(" -> ")
        )));
    }

    // Resolve each base and fold-merge them left-to-right
    let mut accumulated_base: Option<Profile> = None;
    for base_name in &base_names {
        if visited.contains(base_name) {
            return Err(NonoError::ProfileInheritance(format!(
                "circular dependency detected: {} -> {}",
                visited.join(" -> "),
                base_name
            )));
        }

        visited.push(base_name.clone());

        let resolved = load_base_profile_raw(base_name, context_dir, source_file)?;
        let (base, next_context, next_source) = match resolved {
            ResolvedBase::Sibling(p, path) => (p, context_dir, Some(path)),
            ResolvedBase::Global(p) => (p, None, None),
        };
        let resolved_base = resolve_extends(
            base,
            visited,
            depth + 1,
            next_context,
            next_source.as_deref(),
        )?;
        // Pop to restore the stack to the pre-base state. On the error path
        // above (? propagation), visited is abandoned so the missing pop is harmless.
        visited.pop();

        accumulated_base = Some(match accumulated_base {
            Some(acc) => merge_profiles(acc, resolved_base),
            None => resolved_base,
        });
    }

    match accumulated_base {
        Some(base) => Ok(merge_profiles(base, child)),
        None => Ok(child),
    }
}

/// Distinguishes where a base profile was resolved from so `resolve_extends`
/// can propagate `context_dir` only for sibling-resolved profiles. Global
/// sources (user dir, pack-store, built-in) clear the context to prevent
/// project-local files from hijacking built-in inheritance chains. `Sibling`
/// carries the file path so the next recursion level can skip self-references.
enum ResolvedBase {
    Sibling(Profile, PathBuf),
    Global(Profile),
}

/// Load a base profile by name WITHOUT applying implicit default-group merging.
///
/// Checks sibling profiles in `context_dir` first (so project-local profiles
/// can reference each other by name), then user profiles, and built-in
/// profiles. Built-in profiles are loaded as raw profile definitions so
/// inheritance can resolve before implicit default groups are merged.
///
/// `source_file` is the path to the child profile that initiated the
/// extends-resolution; when set, the sibling-directory probe skips the file
/// matching that path to prevent self-references (e.g. `.nono/codex.json`
/// extending `"codex"`).
///
/// Fork-divergence note: upstream's commit `bc443928` adds two additional
/// resolver branches — pack-store lookup (`find_pack_store_profile`) and
/// pack-provided rescue (`crate::migration::check_and_run`). The fork does
/// not have the pack-store subsystem or `migration::check_and_run` in the
/// same shape; those branches are omitted here and remain out of scope for
/// Plan 34-04 (C7 cluster). The sibling-resolution behavior (the actual
/// "fix" in the commit subject) is adopted in full.
fn load_base_profile_raw(
    name: &str,
    context_dir: Option<&Path>,
    source_file: Option<&Path>,
) -> Result<ResolvedBase> {
    if !is_valid_profile_name(name) {
        return Err(NonoError::ProfileInheritance(format!(
            "invalid base profile name '{}'",
            name
        )));
    }

    // 0. Sibling in the same directory as the child profile.
    //    Skip if the sibling path is the source file itself to avoid
    //    self-references (e.g. `.nono/codex.json` extending "codex").
    if let Some(dir) = context_dir {
        let sibling_path = dir.join(format!("{name}.json"));
        let is_self = source_file.is_some_and(|src| sibling_path == src);
        if !is_self && sibling_path.is_file() {
            tracing::debug!(
                "Resolved '{}' from sibling: {}",
                name,
                sibling_path.display()
            );
            return Ok(ResolvedBase::Sibling(
                parse_profile_file(&sibling_path)?,
                sibling_path,
            ));
        }
    }

    // 1. User profiles take precedence.
    let profile_path = get_user_profile_path(name)?;
    if profile_path.exists() {
        return Ok(ResolvedBase::Global(parse_profile_file(&profile_path)?));
    }

    // 2. Built-in profile from embedded policy.
    let policy = crate::policy::load_embedded_policy()?;
    if let Some(def) = policy.profiles.get(name) {
        return Ok(ResolvedBase::Global(def.to_raw_profile()));
    }

    Err(NonoError::ProfileInheritance(format!(
        "base profile '{}' not found",
        name
    )))
}

/// Merge a resolved base profile with a child profile.
///
/// The child's values take precedence for scalar fields. Collection fields
/// are appended and deduplicated. The `extends` field is consumed (set to `None`).
fn merge_profiles(base: Profile, child: Profile) -> Profile {
    Profile {
        extends: None,
        meta: child.meta,
        security: SecurityConfig {
            groups: dedup_append(&base.security.groups, &child.security.groups),
            allowed_commands: dedup_append(
                &base.security.allowed_commands,
                &child.security.allowed_commands,
            ),
            signal_mode: child.security.signal_mode.or(base.security.signal_mode),
            process_info_mode: child
                .security
                .process_info_mode
                .or(base.security.process_info_mode),
            ipc_mode: child.security.ipc_mode.or(base.security.ipc_mode),
            capability_elevation: child
                .security
                .capability_elevation
                .or(base.security.capability_elevation),
            wsl2_proxy_policy: child
                .security
                .wsl2_proxy_policy
                .or(base.security.wsl2_proxy_policy),
        },
        filesystem: FilesystemConfig {
            allow: dedup_append(&base.filesystem.allow, &child.filesystem.allow),
            read: dedup_append(&base.filesystem.read, &child.filesystem.read),
            write: dedup_append(&base.filesystem.write, &child.filesystem.write),
            allow_file: dedup_append(&base.filesystem.allow_file, &child.filesystem.allow_file),
            read_file: dedup_append(&base.filesystem.read_file, &child.filesystem.read_file),
            write_file: dedup_append(&base.filesystem.write_file, &child.filesystem.write_file),
            deny: dedup_append(&base.filesystem.deny, &child.filesystem.deny),
            bypass_protection: dedup_append(
                &base.filesystem.bypass_protection,
                &child.filesystem.bypass_protection,
            ),
        },
        policy: PolicyPatchConfig {
            exclude_groups: dedup_append(&base.policy.exclude_groups, &child.policy.exclude_groups),
            add_allow_read: dedup_append(&base.policy.add_allow_read, &child.policy.add_allow_read),
            add_allow_write: dedup_append(
                &base.policy.add_allow_write,
                &child.policy.add_allow_write,
            ),
            add_allow_readwrite: dedup_append(
                &base.policy.add_allow_readwrite,
                &child.policy.add_allow_readwrite,
            ),
            add_deny_access: dedup_append(
                &base.policy.add_deny_access,
                &child.policy.add_deny_access,
            ),
            add_deny_commands: dedup_append(
                &base.policy.add_deny_commands,
                &child.policy.add_deny_commands,
            ),
            override_deny: dedup_append(&base.policy.override_deny, &child.policy.override_deny),
        },
        network: NetworkConfig {
            block: base.network.block || child.network.block,
            network_profile: child
                .network
                .network_profile
                .merge(base.network.network_profile),
            allow_domain: dedup_append(&base.network.allow_domain, &child.network.allow_domain),
            open_port: dedup_append(&base.network.open_port, &child.network.open_port),
            listen_port: dedup_append(&base.network.listen_port, &child.network.listen_port),
            connect_port: dedup_append(&base.network.connect_port, &child.network.connect_port),
            // Child `Some([])` overrides parent credentials to empty (disables proxy).
            // Child `None` inherits parent credentials. Child `Some([...])` merges with parent.
            credentials: match child.network.credentials {
                Some(ref child_creds) => {
                    if child_creds.is_empty() {
                        // Explicitly empty — override parent, disable inherited credentials
                        Some(Vec::new())
                    } else {
                        // Child has credentials — merge with parent
                        Some(dedup_append(
                            base.network.credentials.as_deref().unwrap_or(&[]),
                            child_creds,
                        ))
                    }
                }
                None => base.network.credentials,
            },
            custom_credentials: {
                let mut merged = base.network.custom_credentials;
                merged.extend(child.network.custom_credentials);
                merged
            },
            // Child overrides base upstream proxy; if child has None, inherit base
            upstream_proxy: child.network.upstream_proxy.or(base.network.upstream_proxy),
            upstream_bypass: dedup_append(
                &base.network.upstream_bypass,
                &child.network.upstream_bypass,
            ),
        },
        env_credentials: SecretsConfig {
            mappings: {
                let mut merged = base.env_credentials.mappings;
                merged.extend(child.env_credentials.mappings);
                merged
            },
        },
        environment: match (&base.environment, &child.environment) {
            (None, None) => None,
            (Some(base_env), None) => Some(base_env.clone()),
            (None, Some(child_env)) => Some(child_env.clone()),
            (Some(base_env), Some(child_env)) => Some(EnvironmentConfig {
                allow_vars: dedup_append(&base_env.allow_vars, &child_env.allow_vars),
                // Plan 34-08a Task 4 (D-20 replay of v0.52.0 `3657c935`):
                // deny_vars merges identically to allow_vars.
                deny_vars: dedup_append(&base_env.deny_vars, &child_env.deny_vars),
            }),
        },
        // NOTE: WorkdirAccess::None serves as both "not specified" and "explicitly no access".
        // A child cannot override a base's workdir grant to None. This is a v1 limitation;
        // fixing it requires wrapping in Option<WorkdirAccess> and updating all consumers.
        workdir: if child.workdir.access != WorkdirAccess::None {
            child.workdir
        } else {
            base.workdir
        },
        hooks: HooksConfig {
            hooks: {
                let mut merged = base.hooks.hooks;
                merged.extend(child.hooks.hooks);
                merged
            },
        },
        rollback: RollbackConfig {
            exclude_patterns: dedup_append(
                &base.rollback.exclude_patterns,
                &child.rollback.exclude_patterns,
            ),
            exclude_globs: dedup_append(
                &base.rollback.exclude_globs,
                &child.rollback.exclude_globs,
            ),
        },
        open_urls: match child.open_urls {
            Some(child_urls) => Some(child_urls),
            None => base.open_urls,
        },
        allow_launch_services: child.allow_launch_services.or(base.allow_launch_services),
        interactive: base.interactive || child.interactive,
        skipdirs: dedup_append(&base.skipdirs, &child.skipdirs),
        // Phase 18 Plan 18-03 (D-06): widening only — UNION the per-key
        // string-token arrays from base + child so a child profile can ADD
        // tokens to its base's `capabilities.aipc` block without losing the
        // base's allowlist. The default-deny baseline still applies via
        // `Profile::resolve_aipc_allowlist` (hard-coded supervisor defaults
        // are unioned at allowlist-resolution time).
        capabilities: CapabilitiesConfig {
            aipc: match (base.capabilities.aipc, child.capabilities.aipc) {
                (None, None) => None,
                (Some(b), None) => Some(b),
                (None, Some(c)) => Some(c),
                (Some(b), Some(c)) => Some(AipcConfig {
                    socket: dedup_append(&b.socket, &c.socket),
                    pipe: dedup_append(&b.pipe, &c.pipe),
                    job_object: dedup_append(&b.job_object, &c.job_object),
                    event: dedup_append(&b.event, &c.event),
                    mutex: dedup_append(&b.mutex, &c.mutex),
                }),
            },
        },
        unsafe_macos_seatbelt_rules: dedup_append(
            &base.unsafe_macos_seatbelt_rules,
            &child.unsafe_macos_seatbelt_rules,
        ),
        packs: dedup_append(&base.packs, &child.packs),
        command_args: dedup_append(&base.command_args, &child.command_args),
        // Plan 36-01b: merge canonical commands sections — union allow + deny lists.
        commands: CommandsConfig {
            allow: dedup_append(&base.commands.allow, &child.commands.allow),
            deny: dedup_append(&base.commands.deny, &child.commands.deny),
        },
    }
}

/// Append child items after base items, deduplicating while preserving order.
pub(crate) fn dedup_append<T: Eq + std::hash::Hash + Clone>(base: &[T], child: &[T]) -> Vec<T> {
    let mut seen = std::collections::HashSet::with_capacity(base.len() + child.len());
    let mut result = Vec::with_capacity(base.len() + child.len());
    for item in base.iter().chain(child.iter()) {
        if seen.insert(item) {
            result.push(item.clone());
        }
    }
    result
}

/// Get the path to a user profile
pub(crate) fn get_user_profile_path(name: &str) -> Result<PathBuf> {
    let config_dir = resolve_user_config_dir()?;

    Ok(config_dir
        .join("nono")
        .join("profiles")
        .join(format!("{}.json", name)))
}

/// Resolve the user config directory with secure validation.
///
/// Security behavior:
/// - If `XDG_CONFIG_HOME` is set, it must be absolute.
/// - If absolute, we canonicalize it to avoid path confusion through symlinks.
/// - If invalid (relative or cannot be canonicalized), we fall back to `$HOME/.config`.
pub(crate) fn resolve_user_config_dir() -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    if let Ok(raw) = std::env::var("APPDATA") {
        let path = PathBuf::from(&raw);
        if path.is_absolute() {
            match path.canonicalize() {
                Ok(canonical) => return Ok(canonical),
                Err(_) => return Ok(path),
            }
        }
    }

    if let Ok(raw) = std::env::var("XDG_CONFIG_HOME") {
        let path = PathBuf::from(&raw);
        if path.is_absolute() {
            match path.canonicalize() {
                Ok(canonical) => return Ok(canonical),
                Err(e) => {
                    tracing::warn!(
                        "Ignoring invalid XDG_CONFIG_HOME='{}' (canonicalize failed: {}), falling back to $HOME/.config",
                        raw,
                        e
                    );
                }
            }
        } else {
            tracing::warn!(
                "Ignoring invalid XDG_CONFIG_HOME='{}' (must be absolute), falling back to $HOME/.config",
                raw
            );
        }
    }

    // Fallback: use HOME/.config. Canonicalize HOME when possible, but do not
    // fail hard if HOME currently points to a non-existent path.
    let home = home_dir()?;
    let home_base = match home.canonicalize() {
        Ok(canonical) => canonical,
        Err(e) => {
            tracing::warn!(
                "Failed to canonicalize HOME='{}' ({}), using raw HOME path for fallback",
                home.display(),
                e
            );
            home
        }
    };
    Ok(home_base.join(".config"))
}

/// Get home directory path. Honors `NONO_TEST_HOME` via the central
/// `crate::config::nono_home_dir()` helper (Phase 27.1 D-27.1-03).
fn home_dir() -> Result<PathBuf> {
    crate::config::nono_home_dir()
}

/// Validate profile name (alphanumeric + hyphen only, no path traversal)
pub(crate) fn is_valid_profile_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && !name.starts_with('-')
        && !name.ends_with('-')
}

/// Expand environment variables in a path string
///
/// Supported variables:
/// - $WORKDIR: Working directory (--workdir or cwd)
/// - $HOME: User's home directory
/// - $XDG_CONFIG_HOME: XDG config directory
/// - $XDG_DATA_HOME: XDG data directory
/// - $XDG_STATE_HOME: XDG state directory
/// - $XDG_CACHE_HOME: XDG cache directory
/// - $XDG_RUNTIME_DIR: XDG runtime directory (no default; left unexpanded when unset)
/// - $TMPDIR: System temporary directory
/// - $UID: Current user ID
///
/// If $HOME cannot be determined and the path uses $HOME or XDG variables,
/// the unexpanded variable is left in place (which will cause the path to not exist).
pub fn expand_vars(path: &str, workdir: &Path) -> Result<PathBuf> {
    use crate::config;

    let home = config::validated_home()?;

    // Expand ~/... to $HOME/... before other substitutions
    let path = if let Some(rest) = path.strip_prefix("~/") {
        format!("{}/{}", home, rest)
    } else if path == "~" {
        home.clone()
    } else {
        path.to_string()
    };

    let expanded = path.replace("$WORKDIR", &workdir.to_string_lossy());

    // Expand $TMPDIR and $UID
    let tmpdir = config::validated_tmpdir()?;
    let uid = current_uid_string();
    let expanded = expanded
        .replace("$TMPDIR", tmpdir.trim_end_matches('/'))
        .replace("$UID", &uid);

    let xdg_config = std::env::var("XDG_CONFIG_HOME").unwrap_or_else(|_| {
        #[cfg(target_os = "windows")]
        {
            std::env::var("APPDATA")
                .unwrap_or_else(|_| format!("{}", PathBuf::from(&home).join(".config").display()))
        }
        #[cfg(not(target_os = "windows"))]
        {
            format!("{}", PathBuf::from(&home).join(".config").display())
        }
    });
    let xdg_data = std::env::var("XDG_DATA_HOME").unwrap_or_else(|_| {
        #[cfg(target_os = "windows")]
        {
            std::env::var("APPDATA").unwrap_or_else(|_| {
                format!(
                    "{}",
                    PathBuf::from(&home).join(".local").join("share").display()
                )
            })
        }
        #[cfg(not(target_os = "windows"))]
        {
            format!(
                "{}",
                PathBuf::from(&home).join(".local").join("share").display()
            )
        }
    });
    let xdg_state = std::env::var("XDG_STATE_HOME").unwrap_or_else(|_| {
        format!(
            "{}",
            PathBuf::from(&home).join(".local").join("state").display()
        )
    });
    let xdg_cache = std::env::var("XDG_CACHE_HOME")
        .unwrap_or_else(|_| format!("{}", PathBuf::from(&home).join(".cache").display()));

    // $XDG_RUNTIME_DIR has no default per the XDG Base Directory spec.
    // When unset, leave the variable unexpanded so the path won't resolve.
    let xdg_runtime = std::env::var("XDG_RUNTIME_DIR").ok();

    // Validate XDG paths are absolute
    let mut xdg_vars: Vec<(&str, &str)> = vec![
        ("XDG_CONFIG_HOME", &xdg_config),
        ("XDG_DATA_HOME", &xdg_data),
        ("XDG_STATE_HOME", &xdg_state),
        ("XDG_CACHE_HOME", &xdg_cache),
    ];
    if let Some(ref rt) = xdg_runtime {
        xdg_vars.push(("XDG_RUNTIME_DIR", rt));
    }
    for (var, val) in &xdg_vars {
        if !Path::new(val).is_absolute() {
            return Err(NonoError::EnvVarValidation {
                var: var.to_string(),
                reason: format!("must be an absolute path, got: {}", val),
            });
        }
    }

    let mut expanded = expanded
        .replace("$HOME", &home)
        .replace("$XDG_CONFIG_HOME", &xdg_config)
        .replace("$XDG_STATE_HOME", &xdg_state)
        .replace("$XDG_CACHE_HOME", &xdg_cache)
        .replace("$XDG_DATA_HOME", &xdg_data);

    // Only expand $XDG_RUNTIME_DIR when set; leave literal otherwise
    if let Some(ref rt) = xdg_runtime {
        expanded = expanded.replace("$XDG_RUNTIME_DIR", rt);
    }

    Ok(PathBuf::from(expanded))
}

#[cfg(unix)]
fn current_uid_string() -> String {
    nix::unistd::getuid().to_string()
}

#[cfg(not(unix))]
fn current_uid_string() -> String {
    "0".to_string()
}

/// List available profiles (built-in + user)
pub fn list_profiles() -> Vec<String> {
    let mut profiles = builtin::list_builtin();

    // Add user profiles (if home directory is available)
    if let Ok(profile_path) = get_user_profile_path("") {
        if let Some(dir) = profile_path.parent() {
            if dir.exists() {
                if let Ok(entries) = fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        if let Some(name) = entry.path().file_stem() {
                            let name_str = name.to_string_lossy().to_string();
                            if !profiles.contains(&name_str) {
                                profiles.push(name_str);
                            }
                        }
                    }
                }
            }
        }
    }

    profiles.sort();
    profiles
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::test_env::EnvVarGuard;
    use std::sync::MutexGuard;
    use tempfile::tempdir;

    #[cfg(target_os = "windows")]
    fn test_home() -> &'static str {
        r"C:\Users\tester"
    }

    #[cfg(not(target_os = "windows"))]
    fn test_home() -> &'static str {
        "/home/user"
    }

    #[cfg(target_os = "windows")]
    fn test_xdg_state_home() -> &'static str {
        r"C:\Users\tester\AppData\Local\state"
    }

    #[cfg(not(target_os = "windows"))]
    fn test_xdg_state_home() -> &'static str {
        "/custom/state"
    }

    #[cfg(target_os = "windows")]
    fn test_xdg_cache_home() -> &'static str {
        r"C:\Users\tester\AppData\Local\cache"
    }

    #[cfg(not(target_os = "windows"))]
    fn test_xdg_cache_home() -> &'static str {
        "/custom/cache"
    }

    #[cfg(target_os = "windows")]
    fn test_xdg_runtime_dir() -> &'static str {
        r"C:\Users\tester\AppData\Local\Temp\runtime"
    }

    #[cfg(not(target_os = "windows"))]
    fn test_xdg_runtime_dir() -> &'static str {
        "/run/user/1000"
    }

    fn env_lock() -> MutexGuard<'static, ()> {
        crate::test_env::lock_env()
    }

    #[test]
    fn test_valid_profile_names() {
        assert!(is_valid_profile_name("claude-code"));
        assert!(is_valid_profile_name("openclaw"));
        assert!(is_valid_profile_name("my-app-2"));
        assert!(!is_valid_profile_name(""));
        assert!(!is_valid_profile_name("-invalid"));
        assert!(!is_valid_profile_name("invalid-"));
        assert!(!is_valid_profile_name("../escape"));
        assert!(!is_valid_profile_name("path/traversal"));
    }

    #[test]
    fn test_expand_vars() {
        let _guard = env_lock();
        let _env = EnvVarGuard::set_all(&[("HOME", test_home())]);

        let workdir = PathBuf::from("/projects/myapp");

        let expanded = expand_vars("$WORKDIR/src", &workdir).expect("valid env");
        assert_eq!(expanded, PathBuf::from("/projects/myapp/src"));

        let expanded = expand_vars("$HOME/.config", &workdir).expect("valid env");
        assert_eq!(expanded, PathBuf::from(test_home()).join(".config"));
    }

    #[test]
    fn test_expand_vars_xdg_state_home() {
        let _guard = env_lock();
        // $XDG_STATE_HOME must be expanded so that profiles and deny rules
        // can reference it portably. Without this, users cannot write
        // add_deny_access: ["$XDG_STATE_HOME"] and the variable is treated
        // as a literal string that matches nothing.
        let _env = EnvVarGuard::set_all(&[
            ("HOME", test_home()),
            ("XDG_STATE_HOME", test_xdg_state_home()),
        ]);

        let workdir = PathBuf::from("/projects/myapp");
        let expanded = expand_vars("$XDG_STATE_HOME/history", &workdir).expect("valid env");
        assert_eq!(
            expanded,
            PathBuf::from(test_xdg_state_home()).join("history")
        );

        // Fallback when env var is unset
        _env.remove("XDG_STATE_HOME");
        let expanded = expand_vars("$XDG_STATE_HOME/history", &workdir).expect("valid env");
        assert_eq!(
            expanded,
            PathBuf::from(test_home())
                .join(".local")
                .join("state")
                .join("history")
        );
    }

    #[test]
    fn test_expand_vars_xdg_cache_home() {
        let _guard = env_lock();
        let _env = EnvVarGuard::set_all(&[
            ("HOME", test_home()),
            ("XDG_CACHE_HOME", test_xdg_cache_home()),
        ]);

        let workdir = PathBuf::from("/projects/myapp");
        let expanded = expand_vars("$XDG_CACHE_HOME/pip", &workdir).expect("valid env");
        assert_eq!(expanded, PathBuf::from(test_xdg_cache_home()).join("pip"));

        // Fallback when env var is unset
        _env.remove("XDG_CACHE_HOME");
        let expanded = expand_vars("$XDG_CACHE_HOME/pip", &workdir).expect("valid env");
        assert_eq!(
            expanded,
            PathBuf::from(test_home()).join(".cache").join("pip")
        );
    }

    #[test]
    fn test_expand_vars_xdg_runtime_dir() {
        let _guard = env_lock();
        let _env = EnvVarGuard::set_all(&[("XDG_RUNTIME_DIR", test_xdg_runtime_dir())]);

        let workdir = PathBuf::from("/projects/myapp");
        let expanded = expand_vars("$XDG_RUNTIME_DIR/pulse", &workdir).expect("valid env");
        assert_eq!(
            expanded,
            PathBuf::from(test_xdg_runtime_dir()).join("pulse")
        );

        // When unset, $XDG_RUNTIME_DIR has no default per the spec — the
        // variable should be left unexpanded so the path won't resolve.
        _env.remove("XDG_RUNTIME_DIR");
        let expanded = expand_vars("$XDG_RUNTIME_DIR/pulse", &workdir).expect("valid env");
        assert_eq!(
            expanded,
            PathBuf::from("$XDG_RUNTIME_DIR/pulse"),
            "unset XDG_RUNTIME_DIR should leave variable unexpanded"
        );
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_resolve_user_config_dir_uses_valid_absolute_xdg() {
        let _guard = env_lock();
        let tmp = tempdir().expect("tmpdir");
        let _env =
            EnvVarGuard::set_all(&[("XDG_CONFIG_HOME", tmp.path().to_str().expect("utf8 path"))]);
        let resolved = resolve_user_config_dir().expect("resolve user config dir");
        assert_eq!(
            resolved,
            tmp.path().canonicalize().expect("canonicalize tmp")
        );
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_resolve_user_config_dir_falls_back_on_relative_xdg() {
        let _guard = env_lock();
        let expected_home = home_dir().expect("home dir");
        let _env = EnvVarGuard::set_all(&[("XDG_CONFIG_HOME", "relative/path")]);

        let resolved = resolve_user_config_dir().expect("resolve with fallback");
        assert_eq!(resolved, expected_home.join(".config"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_resolve_user_config_dir_uses_appdata() {
        let _guard = crate::config::test_env_lock()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let tmp = tempdir().expect("tmpdir");
        let _env = EnvVarGuard::set_all(&[
            ("APPDATA", tmp.path().to_str().expect("utf8 path")),
            ("XDG_CONFIG_HOME", "placeholder"),
        ]);
        _env.remove("XDG_CONFIG_HOME");

        let resolved = resolve_user_config_dir().expect("resolve with APPDATA");
        assert_eq!(
            resolved,
            tmp.path().canonicalize().expect("canonicalize tmp")
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_expand_vars_uses_windows_home_and_appdata() {
        let _guard = crate::config::test_env_lock()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let _env = EnvVarGuard::set_all(&[
            ("HOME", "placeholder"),
            ("USERPROFILE", r"C:\Users\tester"),
            ("APPDATA", r"C:\Users\tester\AppData\Roaming"),
        ]);
        _env.remove("HOME");

        let workdir = PathBuf::from(r"C:\work\repo");

        let expanded = expand_vars("$HOME\\.config", &workdir).expect("expand HOME on Windows");
        assert_eq!(expanded, PathBuf::from(r"C:\Users\tester\.config"));

        let config = expand_vars("$XDG_CONFIG_HOME\\nono", &workdir).expect("expand config dir");
        assert_eq!(
            config,
            PathBuf::from(r"C:\Users\tester\AppData\Roaming\nono")
        );
    }

    #[test]
    fn test_load_builtin_profile() {
        let profile = load_profile("claude-code").expect("Failed to load profile");
        assert_eq!(profile.meta.name, "claude-code");
        assert!(!profile.network.block); // network allowed by default
    }

    #[test]
    fn test_load_nonexistent_profile() {
        let result = load_profile("nonexistent-profile-12345");
        assert!(matches!(result, Err(NonoError::ProfileNotFound(_))));
    }

    #[test]
    fn test_load_profile_from_file_path() {
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("custom.json");
        std::fs::write(
            &profile_path,
            r#"{
                "meta": { "name": "custom-test" },
                "security": { "groups": ["node_runtime"] },
                "network": { "block": true }
            }"#,
        )
        .expect("write profile");

        let profile =
            load_profile(profile_path.to_str().expect("valid utf8")).expect("load from path");
        assert_eq!(profile.meta.name, "custom-test");
        assert!(profile.network.block);
        // implicit default profile groups should be merged in
        assert!(profile
            .security
            .groups
            .contains(&"deny_credentials".to_string()));
        assert!(profile
            .security
            .groups
            .contains(&"node_runtime".to_string()));
    }

    #[test]
    fn test_load_profile_from_nonexistent_path() {
        let result = load_profile("/tmp/does-not-exist-nono-test.json");
        assert!(result.is_err());
    }

    #[test]
    fn test_list_profiles() {
        let profiles = list_profiles();
        assert!(profiles.contains(&"claude-code".to_string()));
        assert!(profiles.contains(&"codex".to_string()));
        assert!(profiles.contains(&"openclaw".to_string()));
        assert!(profiles.contains(&"opencode".to_string()));
    }

    #[test]
    fn test_env_credentials_config_parsing() {
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "env_credentials": {
                "openai_api_key": "OPENAI_API_KEY",
                "anthropic_api_key": "ANTHROPIC_API_KEY"
            }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        assert_eq!(profile.env_credentials.mappings.len(), 2);
        assert_eq!(
            profile.env_credentials.mappings.get("openai_api_key"),
            Some(&"OPENAI_API_KEY".to_string())
        );
        assert_eq!(
            profile.env_credentials.mappings.get("anthropic_api_key"),
            Some(&"ANTHROPIC_API_KEY".to_string())
        );
    }

    // ============================================================================
    // EnvironmentConfig — ported from upstream v0.37.0 `1b412a7`
    // (Plan 34-08a Task 3, D-20 manual replay)
    // ============================================================================

    #[test]
    fn test_environment_config_default() {
        let json_str = r#"{
            "meta": { "name": "test-profile" }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        assert!(profile.environment.is_none());
    }

    #[test]
    fn test_environment_config_with_allow_vars() {
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "environment": {
                "allow_vars": ["PATH", "HOME", "AWS_*"]
            }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        assert_eq!(
            profile
                .environment
                .as_ref()
                .expect("environment")
                .allow_vars,
            vec!["PATH", "HOME", "AWS_*"]
        );
    }

    #[test]
    fn test_environment_config_deny_unknown_fields() {
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "environment": {
                "allow_vars": ["PATH"],
                "unknown_field": true
            }
        }"#;

        let result = serde_json::from_str::<Profile>(json_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_environment_config_empty_allow_vars() {
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "environment": {
                "allow_vars": []
            }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        let env_config = profile
            .environment
            .as_ref()
            .expect("environment should be Some");
        assert!(env_config.allow_vars.is_empty());
    }

    // ============================================================================
    // deny_vars — ported from upstream v0.52.0 `3657c935`
    // (Plan 34-08a Task 4, D-20 manual-replay-by-escalation)
    // ============================================================================

    #[test]
    fn test_environment_config_with_deny_vars() {
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "environment": {
                "deny_vars": ["GH_TOKEN", "GITHUB_*", "ANTHROPIC_API_KEY"]
            }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        let env_config = profile
            .environment
            .as_ref()
            .expect("environment should be Some");
        assert_eq!(
            env_config.deny_vars,
            vec!["GH_TOKEN", "GITHUB_*", "ANTHROPIC_API_KEY"]
        );
        assert!(env_config.allow_vars.is_empty());
    }

    #[test]
    fn test_environment_config_allow_and_deny_vars_together() {
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "environment": {
                "allow_vars": ["PATH", "HOME", "AWS_*"],
                "deny_vars": ["AWS_SECRET_ACCESS_KEY"]
            }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        let env_config = profile
            .environment
            .as_ref()
            .expect("environment should be Some");
        assert_eq!(env_config.allow_vars, vec!["PATH", "HOME", "AWS_*"]);
        assert_eq!(env_config.deny_vars, vec!["AWS_SECRET_ACCESS_KEY"]);
    }

    #[test]
    fn test_environment_config_deny_vars_merge() {
        let base = Profile {
            environment: Some(EnvironmentConfig {
                allow_vars: vec![],
                deny_vars: vec!["GH_TOKEN".into()],
            }),
            ..Default::default()
        };
        let child = Profile {
            environment: Some(EnvironmentConfig {
                allow_vars: vec![],
                deny_vars: vec!["ANTHROPIC_API_KEY".into()],
            }),
            ..Default::default()
        };
        let merged = merge_profiles(base, child);
        let env_config = merged
            .environment
            .expect("merged environment should be Some");
        assert_eq!(env_config.deny_vars, vec!["GH_TOKEN", "ANTHROPIC_API_KEY"]);
    }

    #[test]
    fn test_environment_config_deny_vars_merge_deduplicates() {
        let base = Profile {
            environment: Some(EnvironmentConfig {
                allow_vars: vec![],
                deny_vars: vec!["GH_TOKEN".into(), "ANTHROPIC_API_KEY".into()],
            }),
            ..Default::default()
        };
        let child = Profile {
            environment: Some(EnvironmentConfig {
                allow_vars: vec![],
                deny_vars: vec!["ANTHROPIC_API_KEY".into()],
            }),
            ..Default::default()
        };
        let merged = merge_profiles(base, child);
        let env_config = merged
            .environment
            .expect("merged environment should be Some");
        assert_eq!(env_config.deny_vars, vec!["GH_TOKEN", "ANTHROPIC_API_KEY"]);
    }

    #[test]
    fn test_validate_env_credentials_accepts_apple_password_uri() {
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "env_credentials": {
                "apple-password://github.com/alice@example.com": "GITHUB_PASSWORD"
            }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        assert!(validate_env_credential_keys(&profile).is_ok());
    }

    #[test]
    fn test_validate_env_credentials_rejects_invalid_apple_password_uri() {
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "env_credentials": {
                "apple-password://github.com": "GITHUB_PASSWORD"
            }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        let err = validate_env_credential_keys(&profile).expect_err("should reject");
        assert!(err.to_string().contains("Apple Passwords URI"));
    }

    #[test]
    fn test_secrets_alias_backward_compat() {
        // "secrets" should still work as an alias for "env_credentials"
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "secrets": {
                "openai_api_key": "OPENAI_API_KEY"
            }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        assert_eq!(profile.env_credentials.mappings.len(), 1);
        assert_eq!(
            profile.env_credentials.mappings.get("openai_api_key"),
            Some(&"OPENAI_API_KEY".to_string())
        );
    }

    #[test]
    fn test_empty_env_credentials_config() {
        let json_str = r#"{ "meta": { "name": "test-profile" } }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        assert!(profile.env_credentials.mappings.is_empty());
    }

    #[test]
    fn test_merge_implicit_default_groups_into_user_profile() {
        let mut profile = Profile {
            security: SecurityConfig {
                groups: vec!["node_runtime".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        merge_implicit_default_groups(&mut profile).expect("merge should succeed");

        // Should contain base groups
        assert!(
            profile
                .security
                .groups
                .contains(&"deny_credentials".to_string()),
            "Expected base group 'deny_credentials'"
        );
        assert!(
            profile
                .security
                .groups
                .contains(&"system_read_macos".to_string())
                || profile
                    .security
                    .groups
                    .contains(&"system_read_linux_core".to_string())
                || profile
                    .security
                    .groups
                    .contains(&"system_read_windows".to_string()),
            "Expected platform system_read group"
        );

        // Should still contain the profile's own group
        assert!(
            profile
                .security
                .groups
                .contains(&"node_runtime".to_string()),
            "Expected profile group 'node_runtime'"
        );

        // No duplicates
        let unique: std::collections::HashSet<_> = profile.security.groups.iter().collect();
        assert_eq!(
            unique.len(),
            profile.security.groups.len(),
            "Groups should have no duplicates"
        );
    }

    #[test]
    fn test_merge_implicit_default_groups_respects_policy_exclude_groups() {
        let mut profile = Profile {
            security: SecurityConfig {
                groups: vec!["node_runtime".to_string()],
                ..Default::default()
            },
            policy: PolicyPatchConfig {
                exclude_groups: vec!["dangerous_commands".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        merge_implicit_default_groups(&mut profile).expect("merge should succeed");

        assert!(
            !profile
                .security
                .groups
                .contains(&"dangerous_commands".to_string()),
            "excluded group 'dangerous_commands' should be removed"
        );
    }

    #[test]
    fn test_load_profile_extends_default_respects_excluded_groups() {
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("no-dangerous-commands.json");
        std::fs::write(
            &profile_path,
            r#"{
                "meta": { "name": "no-dangerous-commands", "version": "1.0.0" },
                "extends": "default",
                "policy": {
                    "exclude_groups": [
                        "dangerous_commands",
                        "dangerous_commands_linux",
                        "dangerous_commands_macos"
                    ]
                },
                "workdir": { "access": "readwrite" }
            }"#,
        )
        .expect("write profile");

        let profile = load_profile_from_path(&profile_path).expect("load profile");

        assert!(
            !profile
                .security
                .groups
                .contains(&"dangerous_commands".to_string()),
            "excluded dangerous_commands should not be present in finalized groups"
        );
        assert!(
            !profile
                .security
                .groups
                .contains(&"dangerous_commands_macos".to_string()),
            "excluded dangerous_commands_macos should not be present in finalized groups"
        );
    }

    #[test]
    fn test_workdir_config_readwrite() {
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "workdir": { "access": "readwrite" }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        assert_eq!(profile.workdir.access, WorkdirAccess::ReadWrite);
    }

    #[test]
    fn test_workdir_config_read() {
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "workdir": { "access": "read" }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        assert_eq!(profile.workdir.access, WorkdirAccess::Read);
    }

    #[test]
    fn test_workdir_config_none() {
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "workdir": { "access": "none" }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        assert_eq!(profile.workdir.access, WorkdirAccess::None);
    }

    #[test]
    fn test_workdir_config_default() {
        let json_str = r#"{ "meta": { "name": "test-profile" } }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        assert_eq!(profile.workdir.access, WorkdirAccess::None);
    }

    // ============================================================================
    // is_http_token_char tests (RFC 7230)
    // ============================================================================

    #[test]
    fn test_http_token_char_alphanumeric() {
        assert!(is_http_token_char('a'));
        assert!(is_http_token_char('Z'));
        assert!(is_http_token_char('0'));
        assert!(is_http_token_char('9'));
    }

    #[test]
    fn test_http_token_char_special_chars() {
        // RFC 7230 tchar: !#$%&'*+-.^_`|~
        for c in "!#$%&'*+-.^_`|~".chars() {
            assert!(is_http_token_char(c), "Expected '{}' to be valid tchar", c);
        }
    }

    #[test]
    fn test_http_token_char_rejects_invalid() {
        // Control chars, space, colon, parentheses should be rejected
        assert!(!is_http_token_char(' '));
        assert!(!is_http_token_char(':'));
        assert!(!is_http_token_char('('));
        assert!(!is_http_token_char(')'));
        assert!(!is_http_token_char('\r'));
        assert!(!is_http_token_char('\n'));
    }

    // ============================================================================
    // Custom credential validation integration tests
    //
    // These test the full validation chain including:
    // - inject_header (RFC 7230 token validation)
    // - credential_format (CRLF injection prevention)
    // - credential_key (alphanumeric + underscore)
    // - upstream URL (HTTPS required, HTTP only for loopback)
    // ============================================================================

    fn header_cred_builder() -> CustomCredentialDef {
        CustomCredentialDef {
            upstream: "https://api.example.com".to_string(),
            credential_key: Some("api_key".to_string()),
            auth: None,
            inject_mode: InjectMode::Header,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            env_var: None,
            endpoint_rules: vec![],
            tls_ca: None,
        }
    }

    #[test]
    fn test_validate_custom_credential_valid() {
        let cred = header_cred_builder();
        assert!(validate_custom_credential("test", &cred).is_ok());
    }

    #[test]
    fn test_validate_custom_credential_http_loopback_allowed() {
        let mut cred = header_cred_builder();
        cred.upstream = "http://127.0.0.1:8080/api".to_string();
        cred.credential_key = Some("local_key".to_string());
        assert!(validate_custom_credential("local", &cred).is_ok());
    }

    #[test]
    fn test_validate_custom_credential_http_remote_rejected() {
        let mut cred = header_cred_builder();
        cred.upstream = "http://api.example.com".to_string();
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("HTTP to remote should be rejected");
        assert!(err.to_string().contains("HTTPS"));
    }

    #[test]
    fn test_validate_custom_credential_invalid_header_rejected() {
        let mut cred = header_cred_builder();
        cred.inject_header = "X-Header\r\nEvil: injected".to_string();
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("CRLF in header should be rejected");
        assert!(err.to_string().contains("invalid characters"));
    }

    #[test]
    fn test_validate_custom_credential_invalid_format_rejected() {
        let mut cred = header_cred_builder();
        cred.credential_format = "Bearer {}\r\nEvil: header".to_string();
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("CRLF in format should be rejected");
        assert!(err.to_string().contains("CRLF"));
    }

    #[test]
    fn test_validate_custom_credential_invalid_key_rejected() {
        let mut cred = header_cred_builder();
        cred.credential_key = Some("api-key".to_string()); // hyphens not allowed
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("hyphen in key should be rejected");
        assert!(err.to_string().contains("alphanumeric"));
    }

    #[test]
    fn test_validate_custom_credential_empty_header_rejected() {
        let mut cred = header_cred_builder();
        cred.inject_header = "".to_string();
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("empty header should be rejected");
        assert!(err.to_string().contains("cannot be empty"));
    }

    #[test]
    fn test_validate_custom_credential_header_with_space_rejected() {
        let mut cred = header_cred_builder();
        cred.inject_header = "X Header".to_string();
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("space in header should be rejected");
        assert!(err.to_string().contains("invalid characters"));
    }

    #[test]
    fn test_validate_custom_credential_header_with_colon_rejected() {
        let mut cred = header_cred_builder();
        cred.inject_header = "X-Header:".to_string();
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("colon in header should be rejected");
        assert!(err.to_string().contains("invalid characters"));
    }

    #[test]
    fn test_validate_custom_credential_valid_special_header_chars() {
        let mut cred = header_cred_builder();
        cred.inject_header = "X-Header!".to_string(); // ! is valid tchar
        assert!(validate_custom_credential("test", &cred).is_ok());
    }

    #[test]
    fn test_validate_custom_credential_format_with_cr_rejected() {
        let mut cred = header_cred_builder();
        cred.credential_format = "Bearer {}\rEvil: header".to_string();
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("CR in format should be rejected");
        assert!(err.to_string().contains("CRLF"));
    }

    #[test]
    fn test_validate_custom_credential_format_with_lf_rejected() {
        let mut cred = header_cred_builder();
        cred.credential_format = "Bearer {}\nEvil: header".to_string();
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("LF in format should be rejected");
        assert!(err.to_string().contains("CRLF"));
    }

    #[test]
    fn test_validate_custom_credential_various_valid_formats() {
        for format in ["Bearer {}", "Token {}", "{}", "Basic {}", "ApiKey={}"] {
            let mut cred = header_cred_builder();
            cred.credential_format = format.to_string();
            assert!(
                validate_custom_credential("test", &cred).is_ok(),
                "Expected format '{}' to be valid",
                format
            );
        }
    }

    #[test]
    fn test_validate_custom_credential_http_localhost_allowed() {
        let mut cred = header_cred_builder();
        cred.upstream = "http://localhost:3000/api".to_string();
        cred.credential_key = Some("local_key".to_string());
        assert!(validate_custom_credential("local", &cred).is_ok());
    }

    #[test]
    fn test_validate_custom_credential_http_ipv6_loopback_allowed() {
        let mut cred = header_cred_builder();
        cred.upstream = "http://[::1]:8080/api".to_string();
        cred.credential_key = Some("local_key".to_string());
        assert!(validate_custom_credential("local", &cred).is_ok());
    }

    #[test]
    fn test_validate_custom_credential_http_0_0_0_0_rejected() {
        // OAUTH-02 security tightening (ports upstream 0c990116):
        // unspecified addresses (0.0.0.0, ::) are REJECTED for http://
        // upstreams — only explicit loopback (127.0.0.0/8, ::1) is allowed.
        let mut cred = header_cred_builder();
        cred.upstream = "http://0.0.0.0:3000/api".to_string();
        cred.credential_key = Some("local_key".to_string());
        let result = validate_custom_credential("local", &cred);
        let err = result.expect_err("HTTP to 0.0.0.0 should be rejected");
        assert!(err.to_string().contains("loopback"));
    }

    #[test]
    fn test_validate_custom_credential_http_ipv6_unspecified_rejected() {
        // OAUTH-02: IPv6 unspecified (::) also rejected.
        let mut cred = header_cred_builder();
        cred.upstream = "http://[::]:3000/api".to_string();
        cred.credential_key = Some("local_key".to_string());
        let result = validate_custom_credential("local", &cred);
        let err = result.expect_err("HTTP to :: should be rejected");
        assert!(err.to_string().contains("loopback"));
    }

    // ============================================================================
    // Injection Mode Validation Tests
    // ============================================================================

    #[test]
    fn test_validate_url_path_mode_valid() {
        let cred = CustomCredentialDef {
            upstream: "https://api.telegram.org".to_string(),
            credential_key: Some("telegram_token".to_string()),
            auth: None,
            inject_mode: InjectMode::UrlPath,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: Some("/bot{}/".to_string()),
            path_replacement: None,
            query_param_name: None,
            env_var: None,
            endpoint_rules: vec![],
            tls_ca: None,
        };
        assert!(validate_custom_credential("telegram", &cred).is_ok());
    }

    #[test]
    fn test_validate_url_path_mode_missing_pattern() {
        let cred = CustomCredentialDef {
            upstream: "https://api.telegram.org".to_string(),
            credential_key: Some("telegram_token".to_string()),
            auth: None,
            inject_mode: InjectMode::UrlPath,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: None, // Missing required field
            path_replacement: None,
            query_param_name: None,
            env_var: None,
            endpoint_rules: vec![],
            tls_ca: None,
        };
        let result = validate_custom_credential("telegram", &cred);
        let err = result.expect_err("missing path_pattern should be rejected");
        assert!(err.to_string().contains("path_pattern is required"));
    }

    #[test]
    fn test_validate_url_path_mode_pattern_without_placeholder() {
        let cred = CustomCredentialDef {
            upstream: "https://api.telegram.org".to_string(),
            credential_key: Some("telegram_token".to_string()),
            auth: None,
            inject_mode: InjectMode::UrlPath,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: Some("/bot/token/".to_string()), // No {} placeholder
            path_replacement: None,
            query_param_name: None,
            env_var: None,
            endpoint_rules: vec![],
            tls_ca: None,
        };
        let result = validate_custom_credential("telegram", &cred);
        let err = result.expect_err("pattern without {} should be rejected");
        assert!(err.to_string().contains("{}"));
    }

    #[test]
    fn test_validate_url_path_mode_with_replacement() {
        let cred = CustomCredentialDef {
            upstream: "https://api.telegram.org".to_string(),
            credential_key: Some("telegram_token".to_string()),
            auth: None,
            inject_mode: InjectMode::UrlPath,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: Some("/bot{}/".to_string()),
            path_replacement: Some("/v2/bot{}/".to_string()),
            query_param_name: None,
            env_var: None,
            endpoint_rules: vec![],
            tls_ca: None,
        };
        assert!(validate_custom_credential("telegram", &cred).is_ok());
    }

    #[test]
    fn test_validate_url_path_mode_replacement_without_placeholder() {
        let cred = CustomCredentialDef {
            upstream: "https://api.telegram.org".to_string(),
            credential_key: Some("telegram_token".to_string()),
            auth: None,
            inject_mode: InjectMode::UrlPath,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: Some("/bot{}/".to_string()),
            path_replacement: Some("/v2/bot/fixed/".to_string()), // No {} placeholder
            query_param_name: None,
            env_var: None,
            endpoint_rules: vec![],
            tls_ca: None,
        };
        let result = validate_custom_credential("telegram", &cred);
        let err = result.expect_err("replacement without {} should be rejected");
        assert!(err.to_string().contains("{}"));
    }

    #[test]
    fn test_validate_query_param_mode_valid() {
        let cred = CustomCredentialDef {
            upstream: "https://maps.googleapis.com".to_string(),
            credential_key: Some("google_maps_key".to_string()),
            auth: None,
            inject_mode: InjectMode::QueryParam,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: None,
            path_replacement: None,
            query_param_name: Some("key".to_string()),
            env_var: None,
            endpoint_rules: vec![],
            tls_ca: None,
        };
        assert!(validate_custom_credential("google_maps", &cred).is_ok());
    }

    #[test]
    fn test_validate_query_param_mode_missing_param_name() {
        let cred = CustomCredentialDef {
            upstream: "https://maps.googleapis.com".to_string(),
            credential_key: Some("google_maps_key".to_string()),
            auth: None,
            inject_mode: InjectMode::QueryParam,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None, // Missing required field
            env_var: None,
            endpoint_rules: vec![],
            tls_ca: None,
        };
        let result = validate_custom_credential("google_maps", &cred);
        let err = result.expect_err("missing query_param_name should be rejected");
        assert!(err.to_string().contains("query_param_name is required"));
    }

    #[test]
    fn test_validate_query_param_mode_empty_param_name() {
        let cred = CustomCredentialDef {
            upstream: "https://maps.googleapis.com".to_string(),
            credential_key: Some("google_maps_key".to_string()),
            auth: None,
            inject_mode: InjectMode::QueryParam,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: None,
            path_replacement: None,
            query_param_name: Some("".to_string()), // Empty
            env_var: None,
            endpoint_rules: vec![],
            tls_ca: None,
        };
        let result = validate_custom_credential("google_maps", &cred);
        let err = result.expect_err("empty query_param_name should be rejected");
        assert!(err.to_string().contains("cannot be empty"));
    }

    #[test]
    fn test_validate_basic_auth_mode_valid() {
        let cred = CustomCredentialDef {
            upstream: "https://api.example.com".to_string(),
            credential_key: Some("example_basic_auth".to_string()),
            auth: None,
            inject_mode: InjectMode::BasicAuth,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            env_var: None,
            endpoint_rules: vec![],
            tls_ca: None,
        };
        // BasicAuth mode doesn't require additional fields
        // Credential value is expected to be "username:password" format
        assert!(validate_custom_credential("example", &cred).is_ok());
    }

    // ============================================================================
    // env_var validation tests
    // ============================================================================

    #[test]
    fn test_validate_env_var_with_op_uri_requires_env_var() {
        // When credential_key is a URI manager ref, env_var must be set because
        // uppercasing the URI produces a nonsensical env var name.
        let mut cred = header_cred_builder();
        cred.credential_key = Some("op://Development/OpenAI/credential".to_string());
        cred.env_var = None;
        let result = validate_custom_credential("openai", &cred);
        let err = result.expect_err("op:// URI without env_var should be rejected");
        assert!(err.to_string().contains("env_var is required"));
    }

    #[test]
    fn test_validate_env_var_with_op_uri_and_env_var_ok() {
        let mut cred = header_cred_builder();
        cred.credential_key = Some("op://Development/OpenAI/credential".to_string());
        cred.env_var = Some("OPENAI_API_KEY".to_string());
        assert!(validate_custom_credential("openai", &cred).is_ok());
    }

    #[test]
    fn test_validate_env_var_with_apple_password_uri_requires_env_var() {
        let mut cred = header_cred_builder();
        cred.credential_key = Some("apple-password://github.com/alice@example.com".to_string());
        cred.env_var = None;
        let result = validate_custom_credential("github", &cred);
        let err = result.expect_err("apple-password URI without env_var should be rejected");
        assert!(err.to_string().contains("env_var is required"));
    }

    #[test]
    fn test_validate_env_var_with_apple_password_uri_and_env_var_ok() {
        let mut cred = header_cred_builder();
        cred.credential_key = Some("apple-password://github.com/alice@example.com".to_string());
        cred.env_var = Some("GITHUB_PASSWORD".to_string());
        assert!(validate_custom_credential("github", &cred).is_ok());
    }

    #[test]
    fn test_validate_env_var_empty_rejected() {
        let mut cred = header_cred_builder();
        cred.env_var = Some("".to_string());
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("empty env_var should be rejected");
        assert!(err.to_string().contains("cannot be empty"));
    }

    #[test]
    fn test_validate_env_var_invalid_chars_rejected() {
        let mut cred = header_cred_builder();
        cred.env_var = Some("OPEN-AI_KEY".to_string()); // hyphens not allowed
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("env_var with hyphens should be rejected");
        assert!(err.to_string().contains("alphanumeric"));
    }

    #[test]
    fn test_validate_env_var_optional_for_keyring_keys() {
        // When credential_key is a plain keyring name, env_var is optional
        // (backward compat: falls back to cred_key.to_uppercase())
        let mut cred = header_cred_builder();
        cred.env_var = None;
        assert!(validate_custom_credential("test", &cred).is_ok());
    }

    #[test]
    fn test_validate_env_var_with_keyring_key_ok() {
        // Explicit env_var with a keyring key is allowed (overrides default)
        let mut cred = header_cred_builder();
        cred.env_var = Some("MY_CUSTOM_VAR".to_string());
        assert!(validate_custom_credential("test", &cred).is_ok());
    }

    #[test]
    fn test_security_config_allowed_commands_deserializes() {
        let json = r#"{
            "meta": { "name": "rm-test" },
            "filesystem": { "allow": ["/tmp"] },
            "security": { "allowed_commands": ["rm", "dd"] }
        }"#;
        let dir = tempdir().expect("tmpdir");
        let path = dir.path().join("rm-test.json");
        std::fs::write(&path, json).expect("write profile");
        let profile = load_profile_from_path(&path).expect("parse profile");
        assert_eq!(profile.security.allowed_commands, vec!["rm", "dd"]);
    }

    #[test]
    fn test_security_config_allowed_commands_defaults_empty() {
        let json = r#"{
            "meta": { "name": "no-cmds" },
            "filesystem": { "allow": ["/tmp"] }
        }"#;
        let dir = tempdir().expect("tmpdir");
        let path = dir.path().join("no-cmds.json");
        std::fs::write(&path, json).expect("write profile");
        let profile = load_profile_from_path(&path).expect("parse profile");
        assert!(profile.security.allowed_commands.is_empty());
    }
    // ============================================================================
    // Profile inheritance (extends) tests
    // ============================================================================

    /// Helper: build a minimal Profile for merge testing.
    fn base_profile() -> Profile {
        Profile {
            extends: None,
            meta: ProfileMeta {
                name: "base".to_string(),
                version: "1.0".to_string(),
                description: Some("Base profile".to_string()),
                author: None,
            },
            security: SecurityConfig {
                groups: vec!["base_group".to_string()],
                ..Default::default()
            },
            filesystem: FilesystemConfig {
                allow: vec!["/base/rw".to_string()],
                read: vec!["/base/read".to_string()],
                write: vec![],
                allow_file: vec![],
                read_file: vec!["/base/file.txt".to_string()],
                write_file: vec![],
                deny: vec![],
                bypass_protection: vec![],
            },
            policy: PolicyPatchConfig {
                exclude_groups: vec!["base_excluded".to_string()],
                add_allow_read: vec!["/base/policy-read".to_string()],
                add_allow_write: vec![],
                add_allow_readwrite: vec![],
                add_deny_access: vec!["/base/policy-deny".to_string()],
                add_deny_commands: vec![],
                override_deny: vec!["/base/override-deny".to_string()],
            },
            network: NetworkConfig {
                block: false,
                network_profile: InheritableValue::Set("base-net".to_string()),
                allow_domain: vec!["base.example.com".to_string()],
                open_port: vec![3000],
                listen_port: vec![4000],
                connect_port: vec![],
                credentials: Some(vec!["base_cred".to_string()]),
                custom_credentials: HashMap::new(),
                upstream_proxy: None,
                upstream_bypass: Vec::new(),
            },
            env_credentials: SecretsConfig {
                mappings: {
                    let mut m = HashMap::new();
                    m.insert("base_key".to_string(), "BASE_VAR".to_string());
                    m
                },
            },
            environment: None,
            workdir: WorkdirConfig {
                access: WorkdirAccess::ReadWrite,
            },
            hooks: HooksConfig {
                hooks: HashMap::new(),
            },
            rollback: RollbackConfig {
                exclude_patterns: vec!["node_modules".to_string()],
                exclude_globs: vec!["*.pyc".to_string()],
            },
            open_urls: Some(OpenUrlConfig {
                allow_origins: vec!["https://base.example.com".to_string()],
                allow_localhost: false,
            }),
            allow_launch_services: Some(false),
            interactive: false,
            skipdirs: vec!["vendor".to_string()],
            capabilities: CapabilitiesConfig::default(),
            unsafe_macos_seatbelt_rules: Vec::new(),
            packs: Vec::new(),
            command_args: Vec::new(),
            commands: CommandsConfig::default(),
        }
    }

    fn child_profile() -> Profile {
        Profile {
            extends: Some(vec!["base".to_string()]),
            meta: ProfileMeta {
                name: "child".to_string(),
                version: "2.0".to_string(),
                description: Some("Child profile".to_string()),
                author: None,
            },
            security: SecurityConfig {
                groups: vec!["child_group".to_string()],
                ..Default::default()
            },
            filesystem: FilesystemConfig {
                allow: vec!["/child/rw".to_string()],
                read: vec![],
                write: vec![],
                allow_file: vec![],
                read_file: vec![],
                write_file: vec![],
                deny: vec![],
                bypass_protection: vec![],
            },
            policy: PolicyPatchConfig {
                exclude_groups: vec!["child_excluded".to_string()],
                add_allow_read: vec![],
                add_allow_write: vec!["/child/policy-write".to_string()],
                add_allow_readwrite: vec!["/child/policy-rw".to_string()],
                add_deny_access: vec!["/child/policy-deny".to_string()],
                add_deny_commands: vec![],
                override_deny: vec!["/child/override-deny".to_string()],
            },
            network: NetworkConfig {
                block: false,
                network_profile: InheritableValue::Inherit,
                allow_domain: vec!["child.example.com".to_string()],
                open_port: vec![3000, 5000],
                listen_port: vec![4000, 6000],
                connect_port: vec![],
                credentials: None,
                custom_credentials: HashMap::new(),
                upstream_proxy: None,
                upstream_bypass: Vec::new(),
            },
            env_credentials: SecretsConfig {
                mappings: {
                    let mut m = HashMap::new();
                    m.insert("child_key".to_string(), "CHILD_VAR".to_string());
                    m
                },
            },
            environment: None,
            workdir: WorkdirConfig {
                access: WorkdirAccess::None,
            },
            hooks: HooksConfig {
                hooks: HashMap::new(),
            },
            rollback: RollbackConfig {
                exclude_patterns: vec![],
                exclude_globs: vec![],
            },
            open_urls: Some(OpenUrlConfig {
                allow_origins: vec!["https://child.example.com".to_string()],
                allow_localhost: true,
            }),
            allow_launch_services: Some(true),
            interactive: false,
            skipdirs: vec!["dist".to_string()],
            capabilities: CapabilitiesConfig::default(),
            unsafe_macos_seatbelt_rules: Vec::new(),
            packs: Vec::new(),
            command_args: Vec::new(),
            commands: CommandsConfig::default(),
        }
    }

    // --- merge_profiles unit tests ---

    #[test]
    fn test_merge_profiles_appends_filesystem_paths() {
        let merged = merge_profiles(base_profile(), child_profile());
        assert!(merged.filesystem.allow.contains(&"/base/rw".to_string()));
        assert!(merged.filesystem.allow.contains(&"/child/rw".to_string()));
        assert!(merged.filesystem.read.contains(&"/base/read".to_string()));
        assert!(merged
            .filesystem
            .read_file
            .contains(&"/base/file.txt".to_string()));
    }

    #[test]
    fn test_merge_profiles_deduplicates_open_port() {
        let merged = merge_profiles(base_profile(), child_profile());
        // base has [3000], child has [3000, 5000] — merged should dedup to [3000, 5000]
        assert_eq!(merged.network.open_port, vec![3000, 5000]);
    }

    #[test]
    fn test_merge_profiles_appends_security_groups() {
        let merged = merge_profiles(base_profile(), child_profile());
        assert!(merged.security.groups.contains(&"base_group".to_string()));
        assert!(merged.security.groups.contains(&"child_group".to_string()));
    }

    #[test]
    fn test_merge_profiles_deduplicates_vecs() {
        let mut base = base_profile();
        let mut child = child_profile();
        // Both have the same group
        base.security.groups = vec!["shared_group".to_string(), "base_only".to_string()];
        child.security.groups = vec!["shared_group".to_string(), "child_only".to_string()];

        let merged = merge_profiles(base, child);
        assert_eq!(
            merged.security.groups,
            vec![
                "shared_group".to_string(),
                "base_only".to_string(),
                "child_only".to_string()
            ]
        );
    }

    #[test]
    fn test_merge_profiles_replaces_meta() {
        let merged = merge_profiles(base_profile(), child_profile());
        assert_eq!(merged.meta.name, "child");
        assert_eq!(merged.meta.version, "2.0");
    }

    #[test]
    fn test_merge_profiles_merges_custom_credentials() {
        let mut base = base_profile();
        base.network.custom_credentials.insert(
            "svc_a".to_string(),
            CustomCredentialDef {
                upstream: "https://a.example.com".to_string(),
                credential_key: Some("key_a".to_string()),
                auth: None,
                inject_mode: InjectMode::Header,
                inject_header: "Authorization".to_string(),
                credential_format: "Bearer {}".to_string(),
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                env_var: None,
                endpoint_rules: vec![],
                tls_ca: None,
            },
        );

        let mut child = child_profile();
        child.network.custom_credentials.insert(
            "svc_b".to_string(),
            CustomCredentialDef {
                upstream: "https://b.example.com".to_string(),
                credential_key: Some("key_b".to_string()),
                auth: None,
                inject_mode: InjectMode::Header,
                inject_header: "Authorization".to_string(),
                credential_format: "Token {}".to_string(),
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                env_var: None,
                endpoint_rules: vec![],
                tls_ca: None,
            },
        );

        let merged = merge_profiles(base, child);
        assert!(merged.network.custom_credentials.contains_key("svc_a"));
        assert!(merged.network.custom_credentials.contains_key("svc_b"));
    }

    #[test]
    fn test_merge_profiles_network_profile_override() {
        let base = base_profile(); // has network_profile = Set("base-net")
        let child = child_profile(); // has network_profile = Inherit

        // Child Inherit -> inherit base
        let merged = merge_profiles(base.clone(), child);
        assert_eq!(merged.network.resolved_network_profile(), Some("base-net"));

        // Child has explicit value -> override
        let mut overriding_child = child_profile();
        overriding_child.network.network_profile = InheritableValue::Set("child-net".to_string());
        let merged = merge_profiles(base, overriding_child);
        assert_eq!(merged.network.resolved_network_profile(), Some("child-net"));
    }

    #[test]
    fn test_merge_profiles_network_profile_null_clears_base() {
        let base = base_profile();
        let mut child = child_profile();
        child.network.network_profile = InheritableValue::Clear;

        let merged = merge_profiles(base, child);
        assert_eq!(merged.network.resolved_network_profile(), None);
    }

    #[test]
    fn test_merge_profiles_inherits_network_block() {
        let mut base = base_profile();
        base.network.block = true;
        let child = child_profile(); // block = false

        let merged = merge_profiles(base, child);
        assert!(merged.network.block, "base block=true must be inherited");
    }

    #[test]
    fn test_merge_profiles_workdir_inherit_from_base() {
        let base = base_profile(); // ReadWrite
        let child = child_profile(); // None (not specified)

        let merged = merge_profiles(base, child);
        assert_eq!(merged.workdir.access, WorkdirAccess::ReadWrite);
    }

    #[test]
    fn test_merge_profiles_workdir_override() {
        let base = base_profile(); // ReadWrite
        let mut child = child_profile();
        child.workdir.access = WorkdirAccess::Read;

        let merged = merge_profiles(base, child);
        assert_eq!(merged.workdir.access, WorkdirAccess::Read);
    }

    #[test]
    fn test_merge_profiles_merges_hooks() {
        let mut base = base_profile();
        base.hooks.hooks.insert(
            "claude-code".to_string(),
            HookConfig {
                event: "PostToolUseFailure".to_string(),
                matcher: "Bash".to_string(),
                script: "base-hook.sh".to_string(),
            },
        );

        let mut child = child_profile();
        child.hooks.hooks.insert(
            "opencode".to_string(),
            HookConfig {
                event: "PreToolUse".to_string(),
                matcher: "Write".to_string(),
                script: "child-hook.sh".to_string(),
            },
        );

        let merged = merge_profiles(base, child);
        assert!(merged.hooks.hooks.contains_key("claude-code"));
        assert!(merged.hooks.hooks.contains_key("opencode"));

        // Same-key collision: child wins
        let mut base2 = base_profile();
        base2.hooks.hooks.insert(
            "claude-code".to_string(),
            HookConfig {
                event: "PostToolUseFailure".to_string(),
                matcher: "Bash".to_string(),
                script: "base-hook.sh".to_string(),
            },
        );

        let mut child2 = child_profile();
        child2.hooks.hooks.insert(
            "claude-code".to_string(),
            HookConfig {
                event: "PreToolUse".to_string(),
                matcher: "Read".to_string(),
                script: "child-hook.sh".to_string(),
            },
        );

        let merged2 = merge_profiles(base2, child2);
        let hook = &merged2.hooks.hooks["claude-code"];
        assert_eq!(
            hook.script, "child-hook.sh",
            "child should win on collision"
        );
        assert_eq!(hook.event, "PreToolUse");
    }

    #[test]
    fn test_merge_profiles_custom_credentials_child_wins_on_collision() {
        let mut base = base_profile();
        base.network.custom_credentials.insert(
            "svc_shared".to_string(),
            CustomCredentialDef {
                upstream: "https://base.example.com".to_string(),
                credential_key: Some("key_base".to_string()),
                auth: None,
                inject_mode: InjectMode::Header,
                inject_header: "Authorization".to_string(),
                credential_format: "Bearer {}".to_string(),
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                env_var: None,
                endpoint_rules: vec![],
                tls_ca: None,
            },
        );

        let mut child = child_profile();
        child.network.custom_credentials.insert(
            "svc_shared".to_string(),
            CustomCredentialDef {
                upstream: "https://child.example.com".to_string(),
                credential_key: Some("key_child".to_string()),
                auth: None,
                inject_mode: InjectMode::Header,
                inject_header: "Authorization".to_string(),
                credential_format: "Token {}".to_string(),
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                env_var: None,
                endpoint_rules: vec![],
                tls_ca: None,
            },
        );

        let merged = merge_profiles(base, child);
        let cred = &merged.network.custom_credentials["svc_shared"];
        assert_eq!(
            cred.upstream, "https://child.example.com",
            "child should win on same-key collision"
        );
        assert_eq!(cred.credential_key.as_deref(), Some("key_child"));
    }

    // --- Loading pipeline tests ---

    #[test]
    fn test_extends_builtin_profile() {
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("ext.json");
        std::fs::write(
            &profile_path,
            r#"{
                "extends": "claude-code",
                "meta": { "name": "ext-test" },
                "filesystem": { "allow": ["/tmp/ext-test"] }
            }"#,
        )
        .expect("write profile");

        let profile = load_from_file(&profile_path).expect("load extended profile");
        assert_eq!(profile.meta.name, "ext-test");
        // Should inherit claude-code's filesystem paths
        assert!(
            profile.filesystem.allow.len() > 1,
            "Expected inherited paths from claude-code, got: {:?}",
            profile.filesystem.allow
        );
        assert!(profile
            .filesystem
            .allow
            .contains(&"/tmp/ext-test".to_string()));
        // extends should be consumed
        assert!(profile.extends.is_none());
    }

    #[test]
    fn test_extends_user_profile() {
        // Test user-to-user file-based inheritance by parsing two temp files
        // and running resolve_extends + merge_profiles — the same pipeline
        // that load_from_file uses. We avoid setting XDG_CONFIG_HOME because
        // env::set_var is process-global and races with parallel tests.
        let dir = tempdir().expect("tmpdir");

        // Write base profile (no extends)
        let base_path = dir.path().join("base.json");
        std::fs::write(
            &base_path,
            r#"{
                "meta": { "name": "base-user" },
                "filesystem": { "allow": ["/base/path"], "read": ["/base/read"] },
                "network": { "block": true }
            }"#,
        )
        .expect("write base");

        // Write child profile (no extends in file — we set it after parsing)
        let child_path = dir.path().join("child.json");
        std::fs::write(
            &child_path,
            r#"{
                "meta": { "name": "child-user" },
                "filesystem": { "allow": ["/child/path"] }
            }"#,
        )
        .expect("write child");

        // Simulate the load_from_file pipeline: parse both, then merge
        let base = parse_profile_file(&base_path).expect("parse base");
        let child = parse_profile_file(&child_path).expect("parse child");
        let merged = merge_profiles(base, child);

        assert_eq!(merged.meta.name, "child-user");
        assert!(merged.filesystem.allow.contains(&"/base/path".to_string()));
        assert!(merged.filesystem.allow.contains(&"/child/path".to_string()));
        assert!(merged.filesystem.read.contains(&"/base/read".to_string()));
        assert!(merged.network.block, "base block=true must be inherited");
        assert!(merged.extends.is_none());
    }

    #[test]
    fn test_extends_chain_three_levels() {
        // Test A -> B -> claude-code (built-in)
        let dir = tempdir().expect("tmpdir");

        // B extends claude-code
        let b_path = dir.path().join("b.json");
        std::fs::write(
            &b_path,
            r#"{
                "extends": "claude-code",
                "meta": { "name": "b-profile" },
                "filesystem": { "allow": ["/b/path"] }
            }"#,
        )
        .expect("write b");

        // A extends B via direct file load (since B is a temp file,
        // we test the resolve_extends logic directly)
        let b_profile = parse_profile_file(&b_path).expect("parse b");
        let a_profile = Profile {
            extends: None, // We'll manually chain
            meta: ProfileMeta {
                name: "a-profile".to_string(),
                ..Default::default()
            },
            filesystem: FilesystemConfig {
                allow: vec!["/a/path".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        // Resolve B first
        let resolved_b =
            resolve_extends(b_profile, &mut Vec::new(), 0, None, None).expect("resolve b");
        // Then merge A on top
        let merged = merge_profiles(resolved_b, a_profile);

        assert_eq!(merged.meta.name, "a-profile");
        assert!(merged.filesystem.allow.contains(&"/a/path".to_string()));
        assert!(merged.filesystem.allow.contains(&"/b/path".to_string()));
    }

    #[test]
    fn test_extends_missing_base_error() {
        let profile = Profile {
            extends: Some(vec!["nonexistent-profile-xyz".to_string()]),
            ..Default::default()
        };

        let result = resolve_extends(profile, &mut Vec::new(), 0, None, None);
        assert!(result.is_err());
        let err = result.expect_err("missing base should error");
        assert!(
            err.to_string().contains("not found"),
            "Error should mention 'not found': {}",
            err
        );
    }

    #[test]
    fn test_extends_circular_dependency_error() {
        // Simulate: visited already has "b", and we try to extend "b" again
        let profile = Profile {
            extends: Some(vec!["b".to_string()]),
            ..Default::default()
        };

        let mut visited = vec!["a".to_string(), "b".to_string()];
        let result = resolve_extends(profile, &mut visited, 2, None, None);
        assert!(result.is_err());
        let err = result.expect_err("circular dep should error");
        assert!(
            err.to_string().contains("circular"),
            "Error should mention 'circular': {}",
            err
        );
    }

    #[test]
    fn test_extends_self_reference_error() {
        let profile = Profile {
            extends: Some(vec!["self-ref".to_string()]),
            ..Default::default()
        };

        let mut visited = vec!["self-ref".to_string()];
        let result = resolve_extends(profile, &mut visited, 1, None, None);
        assert!(result.is_err());
        let err = result.expect_err("self-reference should error");
        assert!(
            err.to_string().contains("circular"),
            "Error should mention 'circular': {}",
            err
        );
    }

    #[test]
    fn test_extends_depth_limit_error() {
        let profile = Profile {
            extends: Some(vec!["deep".to_string()]),
            ..Default::default()
        };

        let visited: Vec<String> = (0..MAX_INHERITANCE_DEPTH)
            .map(|i| format!("level-{}", i))
            .collect();
        let result = resolve_extends(
            profile,
            &mut visited.clone(),
            MAX_INHERITANCE_DEPTH,
            None,
            None,
        );
        assert!(result.is_err());
        let err = result.expect_err("depth limit should error");
        assert!(
            err.to_string().contains("too deep"),
            "Error should mention 'too deep': {}",
            err
        );
    }

    #[test]
    fn test_extends_empty_child_inherits_all() {
        let base = base_profile();
        let empty_child = Profile {
            extends: Some(vec!["base".to_string()]),
            ..Default::default()
        };

        let merged = merge_profiles(base.clone(), empty_child);
        // Should inherit all base filesystem paths
        assert_eq!(merged.filesystem.allow, base.filesystem.allow);
        assert_eq!(merged.filesystem.read, base.filesystem.read);
        assert_eq!(merged.filesystem.read_file, base.filesystem.read_file);
        // Should inherit base security groups
        assert_eq!(merged.security.groups, base.security.groups);
        // Should inherit base workdir
        assert_eq!(merged.workdir.access, base.workdir.access);
        // Should inherit base network settings
        assert_eq!(
            merged.network.resolved_network_profile(),
            base.network.resolved_network_profile()
        );
        assert_eq!(merged.network.allow_domain, base.network.allow_domain);
        // Should inherit rollback config
        assert_eq!(
            merged.rollback.exclude_patterns,
            base.rollback.exclude_patterns
        );
        assert_eq!(merged.rollback.exclude_globs, base.rollback.exclude_globs);
    }

    #[test]
    fn test_dedup_append_preserves_order() {
        let base = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let child = vec!["b".to_string(), "d".to_string(), "a".to_string()];
        let result = dedup_append(&base, &child);
        assert_eq!(
            result,
            vec![
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
                "d".to_string()
            ]
        );
    }

    #[test]
    fn test_dedup_append_empty_vecs() {
        let empty: Vec<String> = vec![];
        assert!(dedup_append(&empty, &empty).is_empty());

        let items = vec!["x".to_string()];
        assert_eq!(dedup_append(&empty, &items), items);
        assert_eq!(dedup_append(&items, &empty), items);
    }

    #[test]
    fn test_merge_profiles_env_credentials_child_wins() {
        let mut base = base_profile();
        base.env_credentials
            .mappings
            .insert("shared_key".to_string(), "BASE_VALUE".to_string());

        let mut child = child_profile();
        child
            .env_credentials
            .mappings
            .insert("shared_key".to_string(), "CHILD_VALUE".to_string());

        let merged = merge_profiles(base, child);
        assert_eq!(
            merged.env_credentials.mappings.get("shared_key"),
            Some(&"CHILD_VALUE".to_string()),
            "child should win for same key"
        );
        assert!(merged.env_credentials.mappings.contains_key("base_key"));
        assert!(merged.env_credentials.mappings.contains_key("child_key"));
    }

    #[test]
    fn test_merge_profiles_interactive_or_semantics() {
        // base=false, child=false -> false
        let merged = merge_profiles(base_profile(), child_profile());
        assert!(!merged.interactive);

        // base=true, child=false -> true
        let mut base = base_profile();
        base.interactive = true;
        let merged = merge_profiles(base, child_profile());
        assert!(merged.interactive);

        // base=false, child=true -> true
        let mut child = child_profile();
        child.interactive = true;
        let merged = merge_profiles(base_profile(), child);
        assert!(merged.interactive);
    }

    #[test]
    fn test_merge_profiles_extends_consumed() {
        let child = child_profile(); // has extends = Some(vec!["base"])
        let merged = merge_profiles(base_profile(), child);
        assert!(
            merged.extends.is_none(),
            "extends should be consumed after merge"
        );
    }

    #[test]
    fn test_merge_profiles_open_urls_child_replaces_base() {
        // When child has open_urls, it replaces base entirely
        let merged = merge_profiles(base_profile(), child_profile());
        let urls = merged.open_urls.expect("should have open_urls");
        assert_eq!(urls.allow_origins, vec!["https://child.example.com"]);
        assert!(!urls
            .allow_origins
            .contains(&"https://base.example.com".to_string()));
        assert!(urls.allow_localhost);
    }

    #[test]
    fn test_merge_profiles_open_urls_child_absent_inherits_base() {
        // When child has no open_urls, base is inherited
        let mut child = child_profile();
        child.open_urls = None;
        let merged = merge_profiles(base_profile(), child);
        let urls = merged.open_urls.expect("should inherit base open_urls");
        assert_eq!(urls.allow_origins, vec!["https://base.example.com"]);
        assert!(!urls.allow_localhost);
    }

    #[test]
    fn test_merge_profiles_open_urls_child_narrows() {
        // A derived profile can restrict to fewer origins than base
        let mut child = child_profile();
        child.open_urls = Some(OpenUrlConfig {
            allow_origins: vec![],
            allow_localhost: false,
        });
        let merged = merge_profiles(base_profile(), child);
        let urls = merged.open_urls.expect("should have open_urls");
        assert!(urls.allow_origins.is_empty());
        assert!(!urls.allow_localhost);
    }

    #[test]
    fn test_merge_profiles_allow_launch_services_child_overrides_base() {
        let merged = merge_profiles(base_profile(), child_profile());
        assert_eq!(merged.allow_launch_services, Some(true));

        let mut child = child_profile();
        child.allow_launch_services = Some(false);
        let merged = merge_profiles(base_profile(), child);
        assert_eq!(merged.allow_launch_services, Some(false));
    }

    #[test]
    fn test_merge_profiles_merges_policy_patches() {
        let merged = merge_profiles(base_profile(), child_profile());
        assert!(merged
            .policy
            .exclude_groups
            .contains(&"base_excluded".to_string()));
        assert!(merged
            .policy
            .exclude_groups
            .contains(&"child_excluded".to_string()));
        assert!(merged
            .policy
            .add_allow_read
            .contains(&"/base/policy-read".to_string()));
        assert!(merged
            .policy
            .add_allow_write
            .contains(&"/child/policy-write".to_string()));
        assert!(merged
            .policy
            .add_allow_readwrite
            .contains(&"/child/policy-rw".to_string()));
        assert!(merged
            .policy
            .add_deny_access
            .contains(&"/base/policy-deny".to_string()));
        assert!(merged
            .policy
            .add_deny_access
            .contains(&"/child/policy-deny".to_string()));
        assert!(merged
            .policy
            .override_deny
            .contains(&"/base/override-deny".to_string()));
        assert!(merged
            .policy
            .override_deny
            .contains(&"/child/override-deny".to_string()));
    }

    #[test]
    fn test_merge_profiles_credentials_none_inherits_base() {
        let base = base_profile(); // credentials: Some(["base_cred"])
        let child = child_profile(); // credentials: None
        let merged = merge_profiles(base, child);
        // None child inherits base credentials
        assert_eq!(
            merged.network.resolved_credentials(),
            &["base_cred".to_string()]
        );
    }

    #[test]
    fn test_merge_profiles_credentials_empty_overrides_base() {
        let base = base_profile(); // credentials: Some(["base_cred"])
        let mut child = child_profile();
        child.network.credentials = Some(Vec::new()); // Explicitly empty
        let merged = merge_profiles(base, child);
        // Some([]) overrides base — no credentials
        assert!(merged.network.resolved_credentials().is_empty());
        assert_eq!(merged.network.credentials, Some(Vec::new()));
    }

    #[test]
    fn test_merge_profiles_credentials_some_merges_with_base() {
        let base = base_profile(); // credentials: Some(["base_cred"])
        let mut child = child_profile();
        child.network.credentials = Some(vec!["child_cred".to_string()]);
        let merged = merge_profiles(base, child);
        // Some([...]) merges with base
        let creds = merged.network.resolved_credentials();
        assert!(creds.contains(&"base_cred".to_string()));
        assert!(creds.contains(&"child_cred".to_string()));
    }

    #[test]
    fn test_credentials_none_does_not_activate_proxy() {
        let mut config = NetworkConfig::default();
        assert!(!config.has_proxy_flags()); // None = no proxy
        config.credentials = Some(Vec::new());
        assert!(!config.has_proxy_flags()); // Some([]) = no proxy
        config.credentials = Some(vec!["openai".to_string()]);
        assert!(config.has_proxy_flags()); // Some(["openai"]) = proxy
    }

    #[test]
    fn test_credentials_deserialization_absent_vs_empty() {
        // Absent field → None (inherit)
        let json = r#"{ "meta": { "name": "no-creds" }, "network": {} }"#;
        let profile: Profile = serde_json::from_str(json).expect("parse");
        assert!(profile.network.credentials.is_none());

        // Explicit empty array → Some([]) (override to empty)
        let json = r#"{ "meta": { "name": "empty-creds" }, "network": { "credentials": [] } }"#;
        let profile: Profile = serde_json::from_str(json).expect("parse");
        assert_eq!(profile.network.credentials, Some(Vec::<String>::new()));

        // With values → Some(["openai"])
        let json =
            r#"{ "meta": { "name": "has-creds" }, "network": { "credentials": ["openai"] } }"#;
        let profile: Profile = serde_json::from_str(json).expect("parse");
        assert_eq!(
            profile.network.credentials,
            Some(vec!["openai".to_string()])
        );
    }

    #[test]
    fn test_extends_field_deserialization() {
        // Single string form
        let json_str = r#"{
            "extends": "claude-code",
            "meta": { "name": "ext-test" }
        }"#;
        let profile: Profile = serde_json::from_str(json_str).expect("parse single");
        assert_eq!(profile.extends, Some(vec!["claude-code".to_string()]));

        // Array form
        let json_str = r#"{
            "extends": ["claude-code", "opencode"],
            "meta": { "name": "ext-multi" }
        }"#;
        let profile: Profile = serde_json::from_str(json_str).expect("parse array");
        assert_eq!(
            profile.extends,
            Some(vec!["claude-code".to_string(), "opencode".to_string()])
        );

        // Absent field
        let json_str = r#"{ "meta": { "name": "no-ext" } }"#;
        let profile: Profile = serde_json::from_str(json_str).expect("parse absent");
        assert!(profile.extends.is_none());

        // Empty array
        let json_str = r#"{ "extends": [], "meta": { "name": "empty-ext" } }"#;
        let profile: Profile = serde_json::from_str(json_str).expect("parse empty array");
        assert!(
            profile.extends.is_none(),
            "empty array should normalize to None"
        );
    }

    #[test]
    fn test_extends_empty_string_in_array_rejected() {
        // An empty string passes deserialization but is caught by load_base_profile_raw
        let profile = Profile {
            extends: Some(vec!["".to_string()]),
            ..Default::default()
        };

        let result = resolve_extends(profile, &mut Vec::new(), 0, None, None);
        assert!(result.is_err());
        let err = result.expect_err("empty string base should error");
        assert!(
            err.to_string().contains("invalid base profile name"),
            "Error should mention invalid name: {}",
            err
        );
    }

    // --- Multiple extends tests ---

    #[test]
    fn test_extends_multiple_bases() {
        // Child extends ["a", "b"] — gets merged groups/filesystem from both
        let base_a = Profile {
            extends: None,
            meta: ProfileMeta {
                name: "a".to_string(),
                ..Default::default()
            },
            security: SecurityConfig {
                groups: vec!["group_a".to_string()],
                ..Default::default()
            },
            filesystem: FilesystemConfig {
                allow: vec!["/a/path".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        let base_b = Profile {
            extends: None,
            meta: ProfileMeta {
                name: "b".to_string(),
                ..Default::default()
            },
            security: SecurityConfig {
                groups: vec!["group_b".to_string()],
                ..Default::default()
            },
            filesystem: FilesystemConfig {
                allow: vec!["/b/path".to_string()],
                read: vec!["/b/read".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        let child = Profile {
            extends: Some(vec!["a".to_string(), "b".to_string()]),
            meta: ProfileMeta {
                name: "child".to_string(),
                ..Default::default()
            },
            filesystem: FilesystemConfig {
                allow: vec!["/child/path".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        // Simulate what resolve_extends does: merge a + b, then merge with child
        let merged_bases = merge_profiles(base_a, base_b);
        let merged = merge_profiles(merged_bases, child);

        assert_eq!(merged.meta.name, "child");
        assert!(merged.filesystem.allow.contains(&"/a/path".to_string()));
        assert!(merged.filesystem.allow.contains(&"/b/path".to_string()));
        assert!(merged.filesystem.allow.contains(&"/child/path".to_string()));
        assert!(merged.filesystem.read.contains(&"/b/read".to_string()));
        assert!(merged.security.groups.contains(&"group_a".to_string()));
        assert!(merged.security.groups.contains(&"group_b".to_string()));
        assert!(merged.extends.is_none());
    }

    #[test]
    fn test_extends_multiple_ordering() {
        // Later bases override earlier for scalar fields (network_profile, workdir)
        let base_a = Profile {
            extends: None,
            network: NetworkConfig {
                network_profile: InheritableValue::Set("net-a".to_string()),
                ..Default::default()
            },
            workdir: WorkdirConfig {
                access: WorkdirAccess::Read,
            },
            interactive: false,
            ..Default::default()
        };

        let base_b = Profile {
            extends: None,
            network: NetworkConfig {
                network_profile: InheritableValue::Set("net-b".to_string()),
                ..Default::default()
            },
            workdir: WorkdirConfig {
                access: WorkdirAccess::ReadWrite,
            },
            interactive: true,
            ..Default::default()
        };

        // Merge a then b: b should win for scalars
        let merged = merge_profiles(base_a, base_b);
        assert_eq!(
            merged.network.network_profile,
            InheritableValue::Set("net-b".to_string()),
            "later base should override network_profile"
        );
        assert_eq!(
            merged.workdir.access,
            WorkdirAccess::ReadWrite,
            "later base should override workdir"
        );
        assert!(merged.interactive, "interactive should be OR'd");
    }

    #[test]
    fn test_extends_duplicate_base_deduplicates() {
        // extends: ["claude-code", "claude-code"] — duplicate is silently skipped
        let profile = Profile {
            extends: Some(vec!["claude-code".to_string(), "claude-code".to_string()]),
            ..Default::default()
        };

        let result = resolve_extends(profile, &mut Vec::new(), 0, None, None);
        assert!(
            result.is_ok(),
            "duplicate base should be deduplicated, not error: {:?}",
            result
        );
    }

    #[test]
    fn test_extends_multiple_builtin_default() {
        // Test extending a single built-in profile (default) via array syntax
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("multi-ext.json");
        std::fs::write(
            &profile_path,
            r#"{
                "extends": ["default"],
                "meta": { "name": "multi-ext-test" },
                "filesystem": { "allow": ["/tmp/multi-ext"] }
            }"#,
        )
        .expect("write profile");

        let profile = load_from_file(&profile_path).expect("load extended profile");
        assert_eq!(profile.meta.name, "multi-ext-test");
        assert!(profile
            .filesystem
            .allow
            .contains(&"/tmp/multi-ext".to_string()));
        assert!(profile.extends.is_none());
    }

    #[test]
    fn test_extends_multiple_shared_transitive_base_deduplicates() {
        // Two built-in profiles that both extend "default" — shared base is deduplicated
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("shared-base.json");
        std::fs::write(
            &profile_path,
            r#"{
                "extends": ["claude-code", "opencode"],
                "meta": { "name": "shared-base-test" }
            }"#,
        )
        .expect("write profile");

        let result = load_from_file(&profile_path);
        assert!(
            result.is_ok(),
            "shared transitive base should be deduplicated, not error: {:?}",
            result
        );
        let profile = result.expect("shared base profile");
        assert_eq!(profile.meta.name, "shared-base-test");
    }

    #[test]
    fn test_extends_resolves_sibling_in_same_directory() {
        let dir = tempdir().expect("tmpdir");
        std::fs::write(
            dir.path().join("shared.json"),
            r#"{ "meta": { "name": "shared" }, "filesystem": { "allow": ["/tmp/shared"] } }"#,
        )
        .expect("write");
        let child_path = dir.path().join("child.json");
        std::fs::write(
            &child_path,
            r#"{ "extends": "shared", "meta": { "name": "child" } }"#,
        )
        .expect("write");

        let profile = load_from_file(&child_path).expect("resolve");
        assert_eq!(profile.meta.name, "child");
        assert!(profile
            .filesystem
            .allow
            .contains(&"/tmp/shared".to_string()));
    }

    #[test]
    fn test_extends_same_name_as_base_skips_self() {
        // A file named "default.json" extending "default" should resolve to
        // the built-in default profile, not itself (which would be circular).
        let dir = tempdir().expect("tmpdir");
        let self_path = dir.path().join("default.json");
        std::fs::write(
            &self_path,
            r#"{ "extends": "default", "meta": { "name": "my-default" }, "filesystem": { "read": ["/tmp/mine"] } }"#,
        )
        .expect("write");

        let profile = load_from_file(&self_path).expect("should not be circular");
        assert_eq!(profile.meta.name, "my-default");
        assert!(
            !profile.security.groups.is_empty(),
            "should inherit default groups"
        );
        assert!(profile.filesystem.read.contains(&"/tmp/mine".to_string()));
    }

    #[test]
    fn test_extends_same_name_still_resolves_other_siblings() {
        // "default.json" extends ["default", "extra"]. "default" should skip
        // self and resolve globally; "extra" should resolve as a sibling.
        let dir = tempdir().expect("tmpdir");
        std::fs::write(
            dir.path().join("extra.json"),
            r#"{ "meta": { "name": "extra" }, "filesystem": { "allow": ["/tmp/extra"] } }"#,
        )
        .expect("write");
        let self_path = dir.path().join("default.json");
        std::fs::write(
            &self_path,
            r#"{ "extends": ["default", "extra"], "meta": { "name": "my-combo" } }"#,
        )
        .expect("write");

        let profile = load_from_file(&self_path).expect("should resolve both bases");
        assert_eq!(profile.meta.name, "my-combo");
        assert!(
            !profile.security.groups.is_empty(),
            "should inherit default groups"
        );
        assert!(profile.filesystem.allow.contains(&"/tmp/extra".to_string()));
    }

    #[test]
    fn test_network_profile_deserialization_distinguishes_absent_null_and_value() {
        let absent: Profile = serde_json::from_str(r#"{ "meta": { "name": "absent" } }"#)
            .expect("parse absent profile");
        assert_eq!(absent.network.network_profile, InheritableValue::Inherit);

        let cleared: Profile = serde_json::from_str(
            r#"{
                "meta": { "name": "cleared" },
                "network": { "network_profile": null }
            }"#,
        )
        .expect("parse cleared profile");
        assert_eq!(cleared.network.network_profile, InheritableValue::Clear);

        let set: Profile = serde_json::from_str(
            r#"{
                "meta": { "name": "set" },
                "network": { "network_profile": "developer" }
            }"#,
        )
        .expect("parse profile with network profile");
        assert_eq!(
            set.network.network_profile,
            InheritableValue::Set("developer".to_string())
        );
    }

    #[test]
    fn test_top_level_schema_field_allowed_in_profile() {
        let profile: Profile = serde_json::from_str(
            r#"{
                "$schema": "https://nono.dev/schemas/nono-profile.schema.json",
                "meta": { "name": "schema-ok" }
            }"#,
        )
        .expect("top-level $schema must be accepted");

        assert_eq!(profile.meta.name, "schema-ok");
    }

    #[test]
    fn test_unknown_fields_rejected_in_profile() {
        // A typo like "add_deny_acces" (missing 's') must be caught at parse
        // time. For a security tool, silently discarding unknown keys means a
        // single typo can void an entire security policy with no feedback.
        let json = r#"{
            "meta": { "name": "typo-test" },
            "policy": {
                "add_deny_acces": ["~/.local/state"]
            }
        }"#;
        let result: std::result::Result<Profile, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "unknown field 'add_deny_acces' must be rejected, not silently ignored"
        );
    }

    #[test]
    fn test_unknown_fields_rejected_in_top_level_profile() {
        // Unknown top-level keys must also be rejected.
        let json = r#"{
            "meta": { "name": "top-level-typo" },
            "polcy": {
                "add_deny_access": ["~/.local/state"]
            }
        }"#;
        let result: std::result::Result<Profile, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "unknown top-level field 'polcy' must be rejected, not silently ignored"
        );
    }

    #[test]
    fn test_policy_patch_deserialization() {
        let profile: Profile = serde_json::from_str(
            r#"{
                "meta": { "name": "patchy" },
                "policy": {
                    "exclude_groups": ["deny_shell_configs"],
                    "add_allow_read": ["/tmp/read"],
                    "add_allow_write": ["/tmp/write"],
                    "add_allow_readwrite": ["/tmp/rw"],
                    "add_deny_access": ["/tmp/deny"],
                    "override_deny": ["~/.docker"]
                }
            }"#,
        )
        .expect("parse profile with policy patch");

        assert_eq!(profile.policy.exclude_groups, vec!["deny_shell_configs"]);
        assert_eq!(profile.policy.add_allow_read, vec!["/tmp/read"]);
        assert_eq!(profile.policy.add_allow_write, vec!["/tmp/write"]);
        assert_eq!(profile.policy.add_allow_readwrite, vec!["/tmp/rw"]);
        assert_eq!(profile.policy.add_deny_access, vec!["/tmp/deny"]);
        assert_eq!(profile.policy.override_deny, vec!["~/.docker"]);
    }

    #[test]
    fn test_network_config_accepts_verb_noun_collection_aliases() {
        let profile: Profile = serde_json::from_str(
            r#"{
                "meta": { "name": "aliases" },
                "network": {
                    "block": true,
                    "allow_proxy": ["api.openai.com"],
                    "allow_port": [3000],
                    "external_proxy": "squid.corp:3128"
                }
            }"#,
        )
        .expect("parse profile with supported aliases");

        assert!(profile.network.block);
        assert_eq!(profile.network.allow_domain, vec!["api.openai.com"]);
        assert_eq!(profile.network.open_port, vec![3000]);
        assert_eq!(
            profile.network.upstream_proxy.as_deref(),
            Some("squid.corp:3128")
        );
    }

    #[test]
    fn test_network_config_serializes_new_names() {
        let profile: Profile = serde_json::from_str(
            r#"{
                "meta": { "name": "canonical" },
                "network": {
                    "allow_domain": ["api.openai.com"],
                    "credentials": ["openai"],
                    "open_port": [3000],
                    "listen_port": [4000],
                    "upstream_proxy": "squid.corp:3128",
                    "upstream_bypass": ["internal.corp"]
                }
            }"#,
        )
        .expect("parse profile with canonical names");

        let serialized = serde_json::to_value(&profile).expect("serialize profile");
        let network = serialized["network"].as_object().expect("network object");

        assert!(network.contains_key("allow_domain"));
        assert!(network.contains_key("credentials"));
        assert!(network.contains_key("open_port"));
        assert!(network.contains_key("listen_port"));
        assert!(network.contains_key("upstream_proxy"));
        assert!(network.contains_key("upstream_bypass"));
    }

    #[test]
    fn test_extends_can_clear_inherited_network_profile_with_null() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let profile_path = dir.path().join("claude-code-netopen.json");
        std::fs::write(
            &profile_path,
            r#"{
                "meta": { "name": "claude-code-netopen" },
                "extends": "claude-code",
                "network": { "network_profile": null }
            }"#,
        )
        .expect("write profile");

        let profile = load_profile_from_path(&profile_path).expect("load profile");
        assert_eq!(profile.network.resolved_network_profile(), None);
        assert!(!profile.network.has_proxy_flags());
        assert!(
            profile
                .filesystem
                .allow
                .iter()
                .any(|path| path == "$HOME/.claude"),
            "expected filesystem grants from claude-code to still be inherited",
        );
    }

    #[test]
    fn test_signal_mode_allow_same_sandbox_deserializes() {
        let json = r#"{
            "meta": { "name": "sig-test" },
            "filesystem": { "allow": ["/tmp"] },
            "security": { "signal_mode": "allow_same_sandbox" }
        }"#;
        let dir = tempdir().expect("tmpdir");
        let path = dir.path().join("sig-test.json");
        std::fs::write(&path, json).expect("write profile");
        let profile = load_profile_from_path(&path).expect("parse profile");
        assert_eq!(
            profile.security.signal_mode,
            Some(ProfileSignalMode::AllowSameSandbox)
        );
    }

    #[test]
    fn test_security_config_process_info_mode_deserializes() {
        let json = r#"{
            "meta": { "name": "ps-test" },
            "filesystem": { "allow": ["/tmp"] },
            "security": { "process_info_mode": "allow_same_sandbox" }
        }"#;
        let dir = tempdir().expect("tmpdir");
        let path = dir.path().join("ps-test.json");
        std::fs::write(&path, json).expect("write profile");
        let profile = load_profile_from_path(&path).expect("parse profile");
        assert_eq!(
            profile.security.process_info_mode,
            Some(ProfileProcessInfoMode::AllowSameSandbox)
        );
    }

    #[test]
    fn test_security_config_process_info_mode_defaults_none() {
        let json = r#"{ "meta": { "name": "no-pim" }, "filesystem": { "allow": ["/tmp"] } }"#;
        let dir = tempdir().expect("tmpdir");
        let path = dir.path().join("no-pim.json");
        std::fs::write(&path, json).expect("write profile");
        let profile = load_profile_from_path(&path).expect("parse profile");
        assert!(profile.security.process_info_mode.is_none());
    }

    #[test]
    fn test_security_config_process_info_mode_allow_all() {
        let json = r#"{
            "meta": { "name": "pim-alias" },
            "filesystem": { "allow": ["/tmp"] },
            "security": { "process_info_mode": "allow_all" }
        }"#;
        let dir = tempdir().expect("tmpdir");
        let path = dir.path().join("pim-alias.json");
        std::fs::write(&path, json).expect("write profile");
        let profile = load_profile_from_path(&path).expect("parse profile");
        assert_eq!(
            profile.security.process_info_mode,
            Some(ProfileProcessInfoMode::AllowAll)
        );
    }

    #[test]
    fn test_security_config_ipc_mode_full_deserializes() {
        let json = r#"{
            "meta": { "name": "ipc-test" },
            "filesystem": { "allow": ["/tmp"] },
            "security": { "ipc_mode": "full" }
        }"#;
        let dir = tempdir().expect("tmpdir");
        let path = dir.path().join("ipc-test.json");
        std::fs::write(&path, json).expect("write profile");
        let profile = load_profile_from_path(&path).expect("parse profile");
        assert_eq!(profile.security.ipc_mode, Some(ProfileIpcMode::Full));
    }

    #[test]
    fn test_security_config_ipc_mode_defaults_none() {
        let json = r#"{ "meta": { "name": "no-ipc" }, "filesystem": { "allow": ["/tmp"] } }"#;
        let dir = tempdir().expect("tmpdir");
        let path = dir.path().join("no-ipc.json");
        std::fs::write(&path, json).expect("write profile");
        let profile = load_profile_from_path(&path).expect("parse profile");
        assert!(profile.security.ipc_mode.is_none());
    }

    #[test]
    fn test_security_config_ipc_mode_shared_memory_only() {
        let json = r#"{
            "meta": { "name": "ipc-shm" },
            "filesystem": { "allow": ["/tmp"] },
            "security": { "ipc_mode": "shared_memory_only" }
        }"#;
        let dir = tempdir().expect("tmpdir");
        let path = dir.path().join("ipc-shm.json");
        std::fs::write(&path, json).expect("write profile");
        let profile = load_profile_from_path(&path).expect("parse profile");
        assert_eq!(
            profile.security.ipc_mode,
            Some(ProfileIpcMode::SharedMemoryOnly)
        );
    }

    // --- JSON Schema validation tests ---

    /// Helper: validate a JSON string against the embedded profile schema.
    fn validate_against_schema(json_str: &str) -> std::result::Result<(), String> {
        let schema_str = crate::config::embedded::embedded_profile_schema();
        let schema: serde_json::Value =
            serde_json::from_str(schema_str).expect("schema is valid JSON");
        let instance: serde_json::Value =
            serde_json::from_str(json_str).expect("instance is valid JSON");
        let validator = jsonschema::validator_for(&schema).expect("schema compiles");
        let errors: Vec<_> = validator.iter_errors(&instance).collect();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors
                .iter()
                .map(|e| format!("{} at {}", e, e.instance_path()))
                .collect::<Vec<_>>()
                .join("; "))
        }
    }

    #[test]
    fn test_schema_validates_extends_as_string() {
        let json = r#"{
            "extends": "default",
            "meta": { "name": "str-extends" },
            "filesystem": { "allow": ["/tmp/test"] }
        }"#;
        validate_against_schema(json)
            .expect("extends as a single string should pass schema validation");
    }

    #[test]
    fn test_schema_validates_extends_as_array() {
        let json = r#"{
            "extends": ["default", "claude-code"],
            "meta": { "name": "arr-extends" },
            "filesystem": { "allow": ["/tmp/test"] }
        }"#;
        validate_against_schema(json)
            .expect("extends as an array of strings should pass schema validation");
    }

    #[test]
    fn test_schema_validates_extends_single_element_array() {
        let json = r#"{
            "extends": ["default"],
            "meta": { "name": "single-arr" }
        }"#;
        validate_against_schema(json)
            .expect("extends as single-element array should pass schema validation");
    }

    #[test]
    fn test_schema_rejects_extends_empty_array() {
        let json = r#"{
            "extends": [],
            "meta": { "name": "empty-arr" }
        }"#;
        let result = validate_against_schema(json);
        assert!(
            result.is_err(),
            "empty extends array should fail schema validation"
        );
    }

    #[test]
    fn test_schema_rejects_extends_numeric() {
        let json = r#"{
            "extends": 42,
            "meta": { "name": "bad-extends" }
        }"#;
        let result = validate_against_schema(json);
        assert!(
            result.is_err(),
            "numeric extends should fail schema validation"
        );
    }

    #[test]
    fn test_schema_rejects_extends_array_of_non_strings() {
        let json = r#"{
            "extends": [1, 2],
            "meta": { "name": "bad-arr" }
        }"#;
        let result = validate_against_schema(json);
        assert!(
            result.is_err(),
            "array of ints should fail schema validation"
        );
    }

    #[test]
    fn test_schema_validates_absent_extends() {
        let json = r#"{
            "meta": { "name": "no-extends" },
            "filesystem": { "allow": ["/tmp"] }
        }"#;
        validate_against_schema(json).expect("absent extends should pass schema validation");
    }

    #[test]
    fn test_schema_validates_full_profile() {
        let json = r#"{
            "extends": ["default"],
            "meta": {
                "name": "full-test",
                "version": "1.0.0",
                "description": "A test profile",
                "author": "test"
            },
            "security": {
                "groups": ["git_config", "node_runtime"],
                "signal_mode": "isolated",
                "capability_elevation": false
            },
            "filesystem": {
                "allow": ["/tmp/project"],
                "read": ["/etc"],
                "allow_file": ["/tmp/config.json"]
            },
            "policy": {
                "exclude_groups": ["dangerous_commands"],
                "add_allow_read": ["/opt/data"],
                "override_deny": ["/etc/hosts"]
            },
            "network": {
                "block": false,
                "network_profile": "anthropic",
                "proxy_allow": ["extra.example.com"],
                "allow_port": [8080]
            },
            "workdir": { "access": "readwrite" },
            "undo": {
                "exclude_patterns": ["node_modules"],
                "exclude_globs": ["*.tmp"]
            }
        }"#;
        validate_against_schema(json)
            .expect("full profile with array extends should pass schema validation");
    }

    #[test]
    fn test_schema_validates_builtin_profiles_in_policy_json() {
        // Validate that all built-in profiles in policy.json conform to the schema
        let policy_str = include_str!("../../data/policy.json");
        let policy: serde_json::Value =
            serde_json::from_str(policy_str).expect("policy.json is valid JSON");
        let profiles = policy["profiles"]
            .as_object()
            .expect("profiles is an object");

        for (name, profile_value) in profiles {
            let result = validate_against_schema(
                &serde_json::to_string(profile_value).expect("re-serialize"),
            );
            assert!(
                result.is_ok(),
                "built-in profile '{}' should conform to schema: {}",
                name,
                result.expect_err("already checked is_ok")
            );
        }
    }

    // ============================================================================
    // file:// credential key validation tests
    // ============================================================================

    #[test]
    fn test_validate_custom_credential_file_uri_accepted() {
        let cred = CustomCredentialDef {
            upstream: "https://api.example.com".to_string(),
            credential_key: Some("file:///run/secrets/api-token".to_string()),
            auth: None,
            inject_mode: InjectMode::Header,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            endpoint_rules: vec![],
            env_var: Some("EXAMPLE_API_KEY".to_string()),
            tls_ca: None,
        };
        assert!(
            validate_custom_credential("example", &cred).is_ok(),
            "file:// URI with env_var should be accepted"
        );
    }

    #[test]
    fn test_validate_custom_credential_file_uri_requires_env_var() {
        let cred = CustomCredentialDef {
            upstream: "https://api.example.com".to_string(),
            credential_key: Some("file:///run/secrets/api-token".to_string()),
            auth: None,
            inject_mode: InjectMode::Header,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            endpoint_rules: vec![],
            env_var: None,
            tls_ca: None,
        };
        let result = validate_custom_credential("example", &cred);
        let err = result.expect_err("file:// URI without env_var should be rejected");
        assert!(
            err.to_string().contains("env_var is required"),
            "error should mention env_var is required, got: {}",
            err
        );
    }

    #[test]
    fn test_validate_custom_credential_file_uri_invalid_rejected() {
        let cred = CustomCredentialDef {
            upstream: "https://api.example.com".to_string(),
            credential_key: Some("file://relative/path".to_string()),
            auth: None,
            inject_mode: InjectMode::Header,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            endpoint_rules: vec![],
            env_var: Some("EXAMPLE_API_KEY".to_string()),
            tls_ca: None,
        };
        let result = validate_custom_credential("example", &cred);
        let err = result.expect_err("file:// URI with relative path should be rejected");
        assert!(
            err.to_string().contains("file://"),
            "error should mention file://, got: {}",
            err
        );
    }

    #[test]
    fn test_validate_custom_credential_file_uri_traversal_rejected() {
        let cred = CustomCredentialDef {
            upstream: "https://api.example.com".to_string(),
            credential_key: Some("file:///run/secrets/../../../etc/shadow".to_string()),
            auth: None,
            inject_mode: InjectMode::Header,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            endpoint_rules: vec![],
            env_var: Some("EXAMPLE_API_KEY".to_string()),
            tls_ca: None,
        };
        let result = validate_custom_credential("example", &cred);
        assert!(
            result.is_err(),
            "file:// URI with path traversal should be rejected"
        );
    }

    #[test]
    fn test_validate_env_credentials_accepts_file_uri() {
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "env_credentials": {
                "file:///run/secrets/api-token": "API_TOKEN"
            }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        assert!(
            validate_env_credential_keys(&profile).is_ok(),
            "valid file:// URI in env_credentials should be accepted"
        );
    }

    #[test]
    fn test_validate_env_credentials_rejects_invalid_file_uri() {
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "env_credentials": {
                "file://relative/path": "API_TOKEN"
            }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        let err = validate_env_credential_keys(&profile).expect_err("should reject");
        assert!(
            err.to_string().contains("file://"),
            "error should mention file://, got: {}",
            err
        );
    }

    #[test]
    fn test_validate_custom_credential_env_uri_accepted() {
        let cred = CustomCredentialDef {
            upstream: "https://api.example.com".to_string(),
            credential_key: Some("env://MY_API_TOKEN".to_string()),
            auth: None,
            inject_mode: InjectMode::Header,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            endpoint_rules: vec![],
            env_var: None,
            tls_ca: None,
        };
        assert!(validate_custom_credential("example", &cred).is_ok());
    }

    #[test]
    fn test_validate_custom_credential_env_uri_dangerous_var_rejected() {
        let cred = CustomCredentialDef {
            upstream: "https://api.example.com".to_string(),
            credential_key: Some("env://LD_PRELOAD".to_string()),
            auth: None,
            inject_mode: InjectMode::Header,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            endpoint_rules: vec![],
            env_var: None,
            tls_ca: None,
        };
        let result = validate_custom_credential("example", &cred);
        assert!(result.is_err(), "env://LD_PRELOAD should be rejected");
    }

    // End-to-end: parse a profile JSON with a file:// custom credential
    #[test]
    fn test_profile_json_with_file_uri_custom_credential_parses() {
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("file-cred.json");
        std::fs::write(
            &profile_path,
            r#"{
                "meta": { "name": "file-cred-test" },
                "network": {
                    "custom_credentials": {
                        "my_service": {
                            "upstream": "https://api.example.com",
                            "credential_key": "file:///run/secrets/api-token",
                            "env_var": "MY_API_KEY"
                        }
                    }
                }
            }"#,
        )
        .expect("write profile");

        let profile = parse_profile_file(&profile_path).expect("profile should parse");
        let cred = profile
            .network
            .custom_credentials
            .get("my_service")
            .expect("my_service credential should exist");
        assert_eq!(
            cred.credential_key.as_deref(),
            Some("file:///run/secrets/api-token")
        );
        assert_eq!(cred.env_var, Some("MY_API_KEY".to_string()));
    }

    // ========================================================================
    // Phase 18 AIPC-01 Plan 18-03 Task 2 — capabilities.aipc widening tests
    // ========================================================================

    #[test]
    fn aipc_capabilities_block_parses_valid_tokens() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("aipc-valid.json");
        let json = r#"{
          "meta": { "name": "test-aipc-valid" },
          "capabilities": {
            "aipc": {
              "socket": ["connect", "bind"],
              "pipe": ["read", "write"],
              "job_object": ["query"],
              "event": ["wait", "signal"],
              "mutex": ["wait", "release"]
            }
          }
        }"#;
        std::fs::write(&path, json).expect("write profile");
        let profile = parse_profile_file(&path).expect("parse profile");
        let aipc = profile
            .capabilities
            .aipc
            .as_ref()
            .expect("aipc block present");
        assert_eq!(aipc.socket, vec!["connect".to_string(), "bind".to_string()]);
        assert_eq!(aipc.pipe, vec!["read".to_string(), "write".to_string()]);
        assert_eq!(aipc.job_object, vec!["query".to_string()]);
        assert_eq!(aipc.event, vec!["wait".to_string(), "signal".to_string()]);
        assert_eq!(aipc.mutex, vec!["wait".to_string(), "release".to_string()]);
    }

    #[test]
    fn aipc_unknown_token_rejected_at_parse_time() {
        // Parameterized over all 5 from_token parsers — each must reject an
        // unknown token at parse time with NonoError::ProfileParse and a
        // verbose message naming the offending token.
        let cases: &[(&str, &str, &[&str])] = &[
            (
                "socket",
                "bogus_role",
                &["bogus_role", "socket", "connect, bind, listen"],
            ),
            (
                "pipe",
                "duplex",
                &["duplex", "pipe", "read, write, read+write"],
            ),
            (
                "job_object",
                "kill",
                &["kill", "job_object", "query, set_attributes, terminate"],
            ),
            (
                "event",
                "modify",
                &["modify", "event", "wait, signal, both"],
            ),
            (
                "mutex",
                "acquire",
                &["acquire", "mutex", "wait, release, both"],
            ),
        ];
        for (key, bogus, must_contain) in cases {
            let dir = tempdir().expect("tempdir");
            let path = dir.path().join(format!("aipc-bogus-{key}.json"));
            let json = format!(
                r#"{{
                  "meta": {{ "name": "test-aipc-bogus" }},
                  "capabilities": {{
                    "aipc": {{
                      "{key}": ["{bogus}"]
                    }}
                  }}
                }}"#
            );
            std::fs::write(&path, &json).expect("write profile");
            let err = parse_profile_file(&path)
                .expect_err(&format!("expected ProfileParse for {key}/{bogus}"));
            let msg = err.to_string();
            for needle in *must_contain {
                assert!(
                    msg.contains(needle),
                    "kind {key}: expected error to contain '{needle}', got: {msg}"
                );
            }
        }
    }

    #[test]
    fn aipc_default_inherits_when_block_absent() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("no-aipc.json");
        let json = r#"{ "meta": { "name": "no-aipc-block" } }"#;
        std::fs::write(&path, json).expect("write profile");
        let profile = parse_profile_file(&path).expect("parse profile");
        assert!(
            profile.capabilities.aipc.is_none(),
            "absent capabilities.aipc must yield None, got: {:?}",
            profile.capabilities.aipc
        );
        // resolve_aipc_allowlist returns the hard-coded D-05 defaults
        // verbatim when aipc is None.
        let resolved = profile.resolve_aipc_allowlist().expect("resolve");
        let default = AipcResolvedAllowlist::default();
        assert_eq!(resolved.socket_roles, default.socket_roles);
        assert_eq!(resolved.pipe_directions, default.pipe_directions);
        assert_eq!(resolved.job_object_mask, default.job_object_mask);
        assert_eq!(resolved.event_mask, default.event_mask);
        assert_eq!(resolved.mutex_mask, default.mutex_mask);
    }

    #[test]
    fn resolve_aipc_allowlist_widens_event_mask_with_signal_token() {
        // D-06 widening-only semantic: profile UNIONs with hard-coded default,
        // never narrows. event ["wait"] alone (narrower than default which
        // includes signal) MUST still include the default's signal bit
        // because the union semantic preserves the baseline.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("event-wait-only.json");
        let json = r#"{
          "meta": { "name": "event-wait-only" },
          "capabilities": { "aipc": { "event": ["wait"] } }
        }"#;
        std::fs::write(&path, json).expect("write profile");
        let profile = parse_profile_file(&path).expect("parse profile");
        let resolved = profile.resolve_aipc_allowlist().expect("resolve");
        // Default = SYNCHRONIZE | EVENT_MODIFY_STATE; widening with "wait"
        // (= SYNCHRONIZE) is a no-op (subset of default), so the resolved
        // mask EQUALS the default. This is the union semantic.
        assert_eq!(
            resolved.event_mask,
            nono::supervisor::policy::EVENT_DEFAULT_MASK
        );
    }

    #[test]
    fn resolve_aipc_allowlist_widens_socket_role_with_bind_token() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("socket-bind-widened.json");
        let json = r#"{
          "meta": { "name": "socket-bind-widened" },
          "capabilities": { "aipc": { "socket": ["bind", "connect"] } }
        }"#;
        std::fs::write(&path, json).expect("write profile");
        let profile = parse_profile_file(&path).expect("parse profile");
        let resolved = profile.resolve_aipc_allowlist().expect("resolve");
        // Default contains Connect; widening with bind+connect (connect is
        // dedup-skipped) MUST yield [Connect, Bind].
        assert!(resolved
            .socket_roles
            .contains(&nono::supervisor::SocketRole::Connect));
        assert!(resolved
            .socket_roles
            .contains(&nono::supervisor::SocketRole::Bind));
        assert!(!resolved
            .socket_roles
            .contains(&nono::supervisor::SocketRole::Listen));
    }

    #[test]
    fn resolve_aipc_allowlist_widens_pipe_with_readwrite_token() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("pipe-readwrite-widened.json");
        let json = r#"{
          "meta": { "name": "pipe-readwrite-widened" },
          "capabilities": {
            "aipc": { "pipe": ["read", "write", "read+write"] }
          }
        }"#;
        std::fs::write(&path, json).expect("write profile");
        let profile = parse_profile_file(&path).expect("parse profile");
        let resolved = profile.resolve_aipc_allowlist().expect("resolve");
        // Default contains Read + Write; widening adds ReadWrite.
        assert!(resolved
            .pipe_directions
            .contains(&nono::supervisor::PipeDirection::Read));
        assert!(resolved
            .pipe_directions
            .contains(&nono::supervisor::PipeDirection::Write));
        assert!(resolved
            .pipe_directions
            .contains(&nono::supervisor::PipeDirection::ReadWrite));

        // Default-only profile MUST NOT include ReadWrite.
        let default_only = Profile::default();
        let default_resolved = default_only.resolve_aipc_allowlist().expect("resolve");
        assert!(!default_resolved
            .pipe_directions
            .contains(&nono::supervisor::PipeDirection::ReadWrite));
    }

    #[test]
    fn resolve_aipc_allowlist_widens_job_object_with_terminate_token() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("job-terminate-widened.json");
        let json = r#"{
          "meta": { "name": "job-terminate-widened" },
          "capabilities": {
            "aipc": { "job_object": ["query", "terminate"] }
          }
        }"#;
        std::fs::write(&path, json).expect("write profile");
        let profile = parse_profile_file(&path).expect("parse profile");
        let resolved = profile.resolve_aipc_allowlist().expect("resolve");
        let expected = nono::supervisor::policy::JOB_OBJECT_QUERY
            | nono::supervisor::policy::JOB_OBJECT_TERMINATE;
        assert_eq!(
            resolved.job_object_mask, expected,
            "widened mask must include both QUERY and TERMINATE bits"
        );
        // Note: the runtime guard in `handle_job_object_request`
        // (CompareObjectHandles vs containment_job) STILL refuses to broker
        // the supervisor's own containment Job even with this widening —
        // proven end-to-end by
        // handle_denies_job_object_brokering_of_containment_job_even_with_profile_widening.
    }

    #[test]
    fn built_in_profiles_load_with_aipc_block_present() {
        // policy.json is embedded at build time; the 5 named profiles
        // (claude-code, codex, opencode, openclaw, swival) all carry
        // capabilities.aipc per Plan 18-03 Task 2 step 6. Round-trip
        // through serde + the parse-time validator.
        use crate::profile::builtin;
        let names = &["claude-code", "codex", "opencode", "openclaw", "swival"];
        for name in names {
            let profile = builtin::get_builtin(name)
                .unwrap_or_else(|| panic!("built-in profile '{name}' must exist"));
            let aipc = profile.capabilities.aipc.as_ref().unwrap_or_else(|| {
                panic!("built-in profile '{name}' must carry capabilities.aipc")
            });
            // Every shipped profile must have at least a non-empty socket
            // entry (default Connect) — even openclaw's minimal config.
            assert!(
                !aipc.socket.is_empty(),
                "profile '{name}' has empty capabilities.aipc.socket"
            );
            // resolve_aipc_allowlist must not error on any built-in profile.
            let _ = profile
                .resolve_aipc_allowlist()
                .unwrap_or_else(|e| panic!("profile '{name}' resolve failed: {e}"));
        }
    }

    #[test]
    fn policy_json_validates_against_schema() {
        // Both policy.json and the schema are embedded at build time via
        // include_str! in builtin.rs / config/embedded.rs. Run the schema
        // validator across every named profile to catch drift between data
        // and schema.
        use jsonschema::Validator;
        let policy_json: serde_json::Value =
            serde_json::from_str(include_str!("../../data/policy.json"))
                .expect("policy.json must be valid JSON");
        let schema_json: serde_json::Value =
            serde_json::from_str(include_str!("../../data/nono-profile.schema.json"))
                .expect("nono-profile.schema.json must be valid JSON");
        let validator = Validator::new(&schema_json).expect("schema must compile");

        let profiles_obj = policy_json
            .get("profiles")
            .and_then(|p| p.as_object())
            .expect("policy.json must contain a 'profiles' object");
        for (name, profile_json) in profiles_obj {
            // ProfileMeta requires a 'name' field; built-in profiles set
            // meta.name explicitly. Validate the profile body itself.
            let result = validator.validate(profile_json);
            assert!(
                result.is_ok(),
                "profile '{name}' must validate against schema; errors: {:?}",
                result.err().map(|e| format!("{e}"))
            );
        }
    }

    // -------------------------------------------------------------------
    // PROF-01 (Phase 22): unsafe_macos_seatbelt_rules deserialize coverage.
    // VALIDATION 22-01-T1 — runtime application is macOS-only by design;
    // Windows + Linux must deserialize the field cleanly without runtime
    // surface. The platform gating lives in sandbox_prepare.rs.
    // -------------------------------------------------------------------

    #[test]
    fn deserialize_seatbelt_rules_with_field() {
        let json = r#"{
            "meta": { "name": "test", "version": "1.0" },
            "unsafe_macos_seatbelt_rules": [
                "(allow iokit-open)",
                "(allow mach-lookup (global-name \"com.apple.test\"))"
            ]
        }"#;
        let profile: Profile = serde_json::from_str(json).expect("parse profile");
        assert_eq!(profile.unsafe_macos_seatbelt_rules.len(), 2);
        assert_eq!(profile.unsafe_macos_seatbelt_rules[0], "(allow iokit-open)");
        assert_eq!(
            profile.unsafe_macos_seatbelt_rules[1],
            "(allow mach-lookup (global-name \"com.apple.test\"))"
        );
    }

    #[test]
    fn deserialize_seatbelt_rules_default_is_empty() {
        // Field is absent — must default to empty Vec via #[serde(default)].
        let json = r#"{
            "meta": { "name": "test", "version": "1.0" }
        }"#;
        let profile: Profile = serde_json::from_str(json).expect("parse profile");
        assert!(profile.unsafe_macos_seatbelt_rules.is_empty());
    }

    #[test]
    fn merge_profiles_dedup_appends_seatbelt_rules() {
        let mut base = base_profile();
        let mut child = child_profile();
        base.unsafe_macos_seatbelt_rules = vec![
            "(allow iokit-open)".to_string(),
            "(allow mach-lookup)".to_string(),
        ];
        child.unsafe_macos_seatbelt_rules = vec![
            "(allow mach-lookup)".to_string(), // duplicate — must dedup
            "(deny file-read*)".to_string(),
        ];
        let merged = merge_profiles(base, child);
        assert_eq!(
            merged.unsafe_macos_seatbelt_rules,
            vec![
                "(allow iokit-open)".to_string(),
                "(allow mach-lookup)".to_string(),
                "(deny file-read*)".to_string(),
            ]
        );
    }

    // -------------------------------------------------------------------
    // PROF-02 (Phase 22): packs + command_args deserialize coverage.
    // VALIDATION 22-01-T2 — both fields use #[serde(default)] so absent
    // fields produce empty Vecs without erroring; pack resolution is
    // deserialize-only at this point (Plan 22-03 lands the resolver).
    // -------------------------------------------------------------------

    #[test]
    fn deserialize_packs_and_command_args() {
        let json = r#"{
            "meta": { "name": "test", "version": "1.0" },
            "packs": ["acme/devtools", "acme/test-runner"],
            "command_args": ["--verbose", "--target", "$NONO_PACKAGES/acme/devtools/bin"]
        }"#;
        let profile: Profile = serde_json::from_str(json).expect("parse profile");
        assert_eq!(
            profile.packs,
            vec!["acme/devtools".to_string(), "acme/test-runner".to_string()]
        );
        assert_eq!(
            profile.command_args,
            vec![
                "--verbose".to_string(),
                "--target".to_string(),
                "$NONO_PACKAGES/acme/devtools/bin".to_string(),
            ]
        );
    }

    #[test]
    fn deserialize_packs_and_command_args_default_empty() {
        // Both fields absent — must default to empty Vec via #[serde(default)].
        let json = r#"{
            "meta": { "name": "test", "version": "1.0" }
        }"#;
        let profile: Profile = serde_json::from_str(json).expect("parse profile");
        assert!(profile.packs.is_empty());
        assert!(profile.command_args.is_empty());
    }

    #[test]
    fn merge_profiles_dedup_appends_packs_and_command_args() {
        let mut base = base_profile();
        let mut child = child_profile();
        base.packs = vec!["acme/a".to_string(), "acme/shared".to_string()];
        child.packs = vec!["acme/shared".to_string(), "acme/b".to_string()];
        base.command_args = vec!["--base-flag".to_string()];
        child.command_args = vec!["--child-flag".to_string()];
        let merged = merge_profiles(base, child);
        assert_eq!(
            merged.packs,
            vec![
                "acme/a".to_string(),
                "acme/shared".to_string(),
                "acme/b".to_string(),
            ]
        );
        assert_eq!(
            merged.command_args,
            vec!["--base-flag".to_string(), "--child-flag".to_string()]
        );
    }

    // -------------------------------------------------------------------
    // PROF-03 (Phase 22): custom_credentials.auth (OAuth2Config) coverage.
    // VALIDATION 22-01-T3 / threat T-22-01-02 (BLOCKING) — token_url MUST
    // reject http:// fail-closed. CLAUDE.md "Fail Secure" + "Permission
    // Scope: Configuration load failures must be fatal" enforced via
    // validate_oauth2_auth → validate_upstream_url at profile-load time.
    // -------------------------------------------------------------------

    #[test]
    fn deserialize_custom_credentials_oauth2() {
        let json = r#"{
            "meta": { "name": "test", "version": "1.0" },
            "network": {
                "custom_credentials": {
                    "vendor_api": {
                        "upstream": "https://api.vendor.example.com",
                        "auth": {
                            "token_url": "https://auth.vendor.example.com/oauth/token",
                            "client_id": "agent-1",
                            "client_secret": "keyring://nono/oauth2-test",
                            "scope": "api.read"
                        }
                    }
                }
            }
        }"#;
        let profile: Profile = serde_json::from_str(json).expect("parse profile");
        let cred = &profile.network.custom_credentials["vendor_api"];
        assert!(cred.credential_key.is_none());
        let auth = cred.auth.as_ref().expect("auth set");
        assert_eq!(
            auth.token_url,
            "https://auth.vendor.example.com/oauth/token"
        );
        assert_eq!(auth.client_id, "agent-1");
        assert_eq!(auth.client_secret, "keyring://nono/oauth2-test");
        assert_eq!(auth.scope, "api.read");
    }

    #[test]
    fn oauth2_http_token_url_rejected() {
        // T-22-01-02 (BLOCKING): plain http:// token_url for a non-loopback
        // host MUST be rejected fail-closed at profile-load time. Reusing
        // the existing validate_upstream_url HTTPS-or-loopback gate provides
        // semantic equivalence to upstream's PolicyError-style enforcement.
        let auth = OAuth2Config {
            token_url: "http://auth.attacker.example.com/oauth/token".to_string(),
            client_id: "client".to_string(),
            client_secret: "env://SECRET".to_string(),
            scope: String::new(),
        };
        let err = validate_oauth2_auth("vendor", &auth)
            .expect_err("http:// token_url must be rejected fail-closed");
        let msg = err.to_string();
        assert!(
            msg.contains("HTTPS"),
            "error must explain HTTPS requirement: {msg}"
        );
    }

    #[test]
    fn oauth2_http_loopback_token_url_allowed() {
        // Loopback HTTP is the documented exception for local dev/test.
        let auth = OAuth2Config {
            token_url: "http://127.0.0.1:8080/oauth/token".to_string(),
            client_id: "client".to_string(),
            client_secret: "env://SECRET".to_string(),
            scope: String::new(),
        };
        validate_oauth2_auth("local", &auth).expect("loopback http accepted");
    }

    #[test]
    fn oauth2_empty_client_id_rejected() {
        let auth = OAuth2Config {
            token_url: "https://auth.example.com/oauth/token".to_string(),
            client_id: String::new(),
            client_secret: "env://SECRET".to_string(),
            scope: String::new(),
        };
        let err = validate_oauth2_auth("v", &auth).expect_err("empty client_id rejected");
        assert!(err.to_string().contains("client_id"));
    }

    #[test]
    fn oauth2_empty_client_secret_rejected() {
        let auth = OAuth2Config {
            token_url: "https://auth.example.com/oauth/token".to_string(),
            client_id: "id".to_string(),
            client_secret: String::new(),
            scope: String::new(),
        };
        let err = validate_oauth2_auth("v", &auth).expect_err("empty client_secret rejected");
        assert!(err.to_string().contains("client_secret"));
    }

    #[test]
    fn custom_credential_credential_key_and_auth_mutually_exclusive() {
        let cred = CustomCredentialDef {
            upstream: "https://api.example.com".to_string(),
            credential_key: Some("api_key".to_string()),
            auth: Some(OAuth2Config {
                token_url: "https://auth.example.com/oauth/token".to_string(),
                client_id: "id".to_string(),
                client_secret: "env://S".to_string(),
                scope: String::new(),
            }),
            inject_mode: InjectMode::Header,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            env_var: None,
            endpoint_rules: vec![],
            tls_ca: None,
        };
        let err = validate_custom_credential("v", &cred).expect_err("mutual exclusion");
        assert!(err.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn custom_credential_neither_key_nor_auth_rejected() {
        let cred = CustomCredentialDef {
            upstream: "https://api.example.com".to_string(),
            credential_key: None,
            auth: None,
            inject_mode: InjectMode::Header,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            env_var: None,
            endpoint_rules: vec![],
            tls_ca: None,
        };
        let err = validate_custom_credential("v", &cred)
            .expect_err("must require credential_key or auth");
        assert!(
            err.to_string().contains("credential_key") || err.to_string().contains("auth"),
            "{}",
            err
        );
    }

    #[test]
    fn oauth2_keystore_secret_resolves() {
        // Existence check: nono::keystore::load_secret accepts keyring:// URIs
        // (already cross-platform via Phase 20 UPST-03). Verify the URI shape
        // validator accepts the format we expect to accept in profile JSON.
        // Actual secret resolution requires a keystore entry; here we only
        // assert the URI is recognized as a keystore reference at the type
        // level — Plan 22-04 OAUTH does the live resolution.
        let secret_uri = "keyring://nono/oauth2-test";
        assert!(
            nono::keystore::is_keyring_uri(secret_uri),
            "client_secret must accept keyring:// URIs for keystore resolution"
        );
    }
}
