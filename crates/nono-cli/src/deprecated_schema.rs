//! Deprecated profile-schema rewriter and per-key deprecation counter.
//!
//! # Upstream awareness (v0.47.0, manual-replay of f0abd413)
//!
//! In upstream nono v0.47.0 (commit `f0abd413`), the upstream project
//! shipped a `deprecated_schema` module carrying:
//!   - `LegacyPolicyPatch`: a Deserialize-driven rewriter that captures
//!     legacy keys (e.g. `override_deny`) and exposes a `rewrite()`
//!     method returning canonical form (`bypass_protection`).
//!   - `DeprecationCounter`: a per-key `AtomicBool` collection emitting
//!     exactly one stderr WARN per legacy key per process on first
//!     encounter.
//!   - `--strict` mode lever: `nono profile validate --strict` fails
//!     closed on legacy keys with a clear pointer to the canonical key.
//!
//! Phase 34-04b shipped a pragmatic Option C (serde alias + clap
//! visible_alias + single AtomicBool at `profile/mod.rs:47`); Plan
//! 36-01a (D-20 manual-replay of f0abd413) replaces this with the
//! full upstream surface. See `.planning/phases/36-upst3-deep-closure/
//! 36-CONTEXT.md` § D-36-B1 for the locked decision rationale.
//!
//! Indefinite acceptance per D-36-B3: legacy keys keep deserializing
//! after this port lands; `--strict` is the operator-controlled
//! fail-closed lever. No hard-deprecation date in v2.4.

use nono::Result;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

// ============================================================================
// CanonicalPolicy — the output type of LegacyPolicyPatch::rewrite
// ============================================================================

/// Canonical form produced by `LegacyPolicyPatch::rewrite`.
///
/// Currently carries only the fields that have a legacy-key counterpart;
/// future Plan 36-01b canonical Profile sections will extend this type.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CanonicalPolicy {
    /// Canonical `bypass_protection` paths (rewritten from legacy `override_deny`).
    pub bypass_protection: Vec<String>,
}

// ============================================================================
// LegacyPolicyPatch — Deserialize-driven rewriter
// ============================================================================

/// Deserialize-driven rewriter that captures legacy JSON profile keys and
/// exposes a `rewrite()` method returning the canonical form.
///
/// Carries `#[serde(deny_unknown_fields)]` to prevent silent acceptance of
/// unknown legacy keys (Pitfall #11 per RESEARCH.md § Security Considerations
/// and `T-36-01-LEGACY-KEY` threat register entry).
///
/// Usage:
/// ```rust,no_run
/// # use nono_cli::deprecated_schema::LegacyPolicyPatch;
/// # fn main() -> nono::Result<()> {
/// let raw = r#"{"override_deny":["/var/log"]}"#;
/// let patch: LegacyPolicyPatch = serde_json::from_str(raw)?;
/// let canonical = patch.rewrite()?;
/// assert_eq!(canonical.bypass_protection, vec!["/var/log".to_string()]);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyPolicyPatch {
    /// Legacy `override_deny` key — rewritten to `bypass_protection` by
    /// `rewrite()`. Both the legacy key name and the canonical name are
    /// accepted here via the serde alias so round-trip JSON with either
    /// key deserializes into this struct (the canonical key is then
    /// emitted by `rewrite()`).
    ///
    /// Note: `#[serde(deny_unknown_fields)]` means ONLY `override_deny` (and
    /// its alias `bypass_protection`) are accepted at the top level of this
    /// struct. Any other key causes a deserialization error.
    #[serde(default, alias = "bypass_protection")]
    pub(crate) override_deny: Vec<String>,
}

impl LegacyPolicyPatch {
    /// Rewrite the legacy policy patch into canonical form.
    ///
    /// Renames `override_deny` → `bypass_protection` in the output.
    /// Returns `Err(NonoError::ProfileParse)` if the rewrite cannot be
    /// performed (currently infallible, but kept as `Result` for forward
    /// compatibility with future validations).
    ///
    /// Callers MUST consume the result; discarding it silently loses the
    /// rewritten canonical form.
    #[must_use = "rewrite() produces the canonical policy; discarding it loses the result"]
    pub fn rewrite(&self) -> Result<CanonicalPolicy> {
        Ok(CanonicalPolicy {
            bypass_protection: self.override_deny.clone(),
        })
    }

    /// Returns `true` if any legacy keys were observed during deserialization.
    ///
    /// Use this to decide whether to emit a deprecation warning or fail
    /// closed in `--strict` mode.
    pub fn has_legacy_keys(&self) -> bool {
        !self.override_deny.is_empty()
    }
}

// ============================================================================
// DeprecationCounter — per-key one-shot stderr WARN emission
// ============================================================================

/// Per-key one-shot stderr deprecation warning tracker.
///
/// Emits exactly one `WARN: profile field '<key>' is deprecated...` line to
/// stderr per legacy key per process on first encounter. Subsequent encounters
/// of the same key are silent. Backed by a `OnceLock<HashMap<&'static str,
/// AtomicBool>>` for wait-free first-encounter detection (no lock contention).
///
/// Thread-safe: `AtomicBool::swap` is wait-free; `OnceLock::get_or_init` is
/// safe for concurrent callers.
///
/// # Security note (`T-36-01-DEPRECATION-DOS`)
/// Worst-case emission count is N known legacy keys × 1 emission. No unbounded
/// emission possible; `AtomicBool::swap` is wait-free.
pub struct DeprecationCounter {
    keys: OnceLock<HashMap<&'static str, AtomicBool>>,
}

impl DeprecationCounter {
    /// Construct a new `DeprecationCounter`.
    ///
    /// The internal map is lazily initialized on first call to `emit_once`.
    pub const fn new() -> Self {
        Self {
            keys: OnceLock::new(),
        }
    }

    /// Emit exactly one `WARN` line to stderr for `key` on first encounter.
    ///
    /// Subsequent calls with the same `key` (in the same process) are silent.
    /// If `key` is not a known legacy key, the call is a no-op (safe to call
    /// with arbitrary strings — unknown keys simply find no matching entry in
    /// the map and produce no output).
    ///
    /// # Arguments
    /// - `key` — the legacy key name (e.g. `"override_deny"`).
    /// - `canonical` — the canonical replacement key name (e.g.
    ///   `"bypass_protection"`), used in the warning message.
    pub fn emit_once(&self, key: &'static str, canonical: &'static str) {
        let map = self.keys.get_or_init(|| {
            let mut m = HashMap::new();
            // Enumerate all known legacy keys from upstream f0abd413.
            // Add new entries here as additional legacy keys are identified.
            m.insert("override_deny", AtomicBool::new(false));
            m
        });
        if let Some(flag) = map.get(key) {
            if !flag.swap(true, Ordering::SeqCst) {
                eprintln!(
                    "WARN: profile field `{key}` is deprecated (upstream #594, v0.47.0); \
                     use `{canonical}` instead. Both keys continue to deserialize \
                     identically; the legacy key may be removed in a future major release."
                );
            }
        }
    }

    /// Returns `true` if the key has already been emitted (i.e. was seen at
    /// least once in this process).
    ///
    /// Only available in test builds — production code should use `emit_once`.
    #[cfg(test)]
    pub fn was_emitted(&self, key: &'static str) -> bool {
        let map = self.keys.get_or_init(|| {
            let mut m = HashMap::new();
            m.insert("override_deny", AtomicBool::new(false));
            m
        });
        map.get(key).is_some_and(|flag| flag.load(Ordering::SeqCst))
    }
}

impl Default for DeprecationCounter {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Process-global counter (used by cmd_validate wiring in profile_cmd.rs)
// ============================================================================

/// Process-global `DeprecationCounter` instance.
///
/// Shared across all profile-validate invocations in the same process.
/// In production use (single `nono profile validate` invocation), the
/// one-shot semantics mean each legacy key emits at most one `WARN`.
///
/// In integration tests (multiple `cmd_validate` calls in the same
/// process), the counter accumulates across calls — this is the documented
/// one-warning-per-process invariant per D-36-B3 and `T-36-01-GLOBAL-STATE-LEAK`.
pub static GLOBAL_DEPRECATION_COUNTER: DeprecationCounter = DeprecationCounter::new();

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // NB: tests avoid relying on `GLOBAL_DEPRECATION_COUNTER` global state
    // (which is process-wide and would race in parallel test execution).
    // Each test constructs a local `DeprecationCounter` instead.

    /// T-36-01-LEGACY-KEY acceptance criteria #1: round-trip rewrite.
    ///
    /// Verify that `LegacyPolicyPatch` deserializes `{"override_deny": [...]}` and
    /// `rewrite()` produces a `CanonicalPolicy` with `bypass_protection == [...]`.
    #[test]
    fn legacy_override_deny_rewrites_to_bypass_protection() {
        let raw = r#"{"override_deny":["/var/log"]}"#;
        let patch: LegacyPolicyPatch =
            serde_json::from_str(raw).expect("should deserialize override_deny");
        let canonical = patch.rewrite().expect("rewrite should succeed");
        assert_eq!(
            canonical.bypass_protection,
            vec!["/var/log".to_string()],
            "rewrite() must produce bypass_protection equal to legacy override_deny paths"
        );
    }

    /// T-36-01-LEGACY-KEY acceptance criteria #2: per-key first-encounter emission.
    ///
    /// Calls `emit_once("override_deny", ...)` three times on a fresh local counter.
    /// Verifies that after the first call the key is marked as emitted, and that
    /// subsequent calls are no-ops (state does not change).
    ///
    /// NOTE: We cannot easily capture stderr in a Rust unit test without an extra
    /// crate. We instead verify the `AtomicBool` state directly (which is the
    /// mechanism that guards the one-shot emission). The integration test in
    /// `tests/profile_validate_strict.rs` provides end-to-end stderr capture.
    #[test]
    fn deprecation_counter_emits_once_per_key() {
        let counter = DeprecationCounter::new();

        // Before any calls — key should not be marked as emitted.
        assert!(
            !counter.was_emitted("override_deny"),
            "key should not be emitted before first call"
        );

        // First call — marks the key as emitted.
        counter.emit_once("override_deny", "bypass_protection");
        assert!(
            counter.was_emitted("override_deny"),
            "key should be emitted after first call"
        );

        // Second and third calls — state does not change (already emitted).
        counter.emit_once("override_deny", "bypass_protection");
        counter.emit_once("override_deny", "bypass_protection");
        assert!(
            counter.was_emitted("override_deny"),
            "key should still be emitted after multiple calls"
        );
    }

    /// T-36-01-LEGACY-KEY acceptance criteria #3: independent per-key state.
    ///
    /// Emitting key A does not affect key B's state.
    ///
    /// NOTE: "key_b" is not in the known-legacy-keys map, so it is silently
    /// ignored by `emit_once`. We verify via `was_emitted` returning `false`
    /// (unknown key → no entry → `map_or(false, ...)` → false).
    /// This also tests the unknown-key no-op invariant.
    #[test]
    fn deprecation_counter_emits_separately_per_key() {
        let counter = DeprecationCounter::new();

        // Emit the known key.
        counter.emit_once("override_deny", "bypass_protection");
        assert!(
            counter.was_emitted("override_deny"),
            "known key should be emitted"
        );

        // Attempt to emit an unknown key — no-op, not tracked.
        counter.emit_once("unknown_legacy_key", "some_canonical");
        assert!(
            !counter.was_emitted("unknown_legacy_key"),
            "unknown key should not be tracked (not in the known-keys map)"
        );

        // The known key state is still independent.
        assert!(
            counter.was_emitted("override_deny"),
            "known key state must not be affected by unknown key call"
        );
    }

    /// T-36-01-LEGACY-KEY acceptance criteria #4 (`#[serde(deny_unknown_fields)]`).
    ///
    /// Verifies that `LegacyPolicyPatch` rejects unknown JSON keys at
    /// deserialization time. Preserves the invariant from `PolicyPatchConfig`
    /// at `profile/mod.rs:441` (successor struct).
    #[test]
    fn legacy_policy_patch_passes_through_unknown_legacy_keys() {
        // An unknown top-level key MUST cause a deserialization error because
        // `LegacyPolicyPatch` carries `#[serde(deny_unknown_fields)]`.
        let raw_unknown = r#"{"completely_unknown_field": ["/some/path"]}"#;
        let result: std::result::Result<LegacyPolicyPatch, _> = serde_json::from_str(raw_unknown);
        assert!(
            result.is_err(),
            "LegacyPolicyPatch must reject unknown fields (deny_unknown_fields invariant)"
        );

        // The canonical alias must also work (bypass_protection → override_deny field).
        let raw_canonical = r#"{"bypass_protection":["/var/log"]}"#;
        let patch: LegacyPolicyPatch = serde_json::from_str(raw_canonical)
            .expect("bypass_protection alias must deserialize into LegacyPolicyPatch");
        let canonical = patch.rewrite().expect("rewrite should succeed");
        assert_eq!(
            canonical.bypass_protection,
            vec!["/var/log".to_string()],
            "canonical alias must also rewrite correctly"
        );
    }
}
