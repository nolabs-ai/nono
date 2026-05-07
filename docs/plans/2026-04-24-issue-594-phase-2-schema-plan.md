# Issue #594 Phase 2: Profile JSON Schema Restructure — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Restructure the profile JSON schema per issue #594 — `groups.include/exclude`, `commands.allow/deny`, expanded `filesystem`, narrowed `security`, no top-level `policy` key — with backward-compatible legacy parsing, CLI flag rename `--override-deny` → `--bypass-protection`, and enforcement tooling targeting removal in v1.0.0.

**Architecture:** Two-layer parsing: canonical structs keep `#[serde(deny_unknown_fields)]`; transient legacy-capture types (`LegacyPolicyPatch`, `RawSecurityConfig`) accept old keys and drain to canonical inside `From<ProfileDeserialize> for Profile`. All deprecation code lives in one new `crates/nono-cli/src/deprecated_schema.rs` module with a documented removal sequence, mirroring phase 1's `deprecated_policy.rs`. A new `/// ALIAS(...)` comment convention is enforced by `scripts/test-list-aliases.sh` (POSIX `grep`).

**Tech Stack:** Rust, serde (JSON), clap (CLI), `#[serde(alias)]`, POSIX shell for tooling. No new dependencies.

**Design doc:** `docs/plans/2026-04-24-issue-594-phase-2-schema-design.md` (read this first).

---

## Prerequisites

Before writing code, comment on issue #594 stating phase 2 kickoff, approach summary, and `remove_by=v1.0.0`. Per CLAUDE.md agent policy.

---

## Part A — New canonical structs (non-breaking additions)

Each task in Part A adds new schema without removing old. Profiles remain parseable throughout. After Part A the code compiles and all existing tests still pass; the new fields exist but aren't populated yet.

### Task A1: Add `GroupsConfig` struct and `Profile.groups` field

**Files:**
- Modify: `crates/nono-cli/src/profile/mod.rs` (struct defs around line 32; `Profile` struct at line 1177; `ProfileDeserialize` at line 1257; `From` impl at line 1305)

**Step 1: Write failing test** (inline in `#[cfg(test)] mod tests` at line 2103):

```rust
#[test]
fn test_groups_config_deserializes() {
    let json = r#"{
        "meta": {"name": "t"},
        "groups": {"include": ["node_runtime"], "exclude": ["dangerous_commands"]}
    }"#;
    let profile: Profile = serde_json::from_str(json).expect("parse");
    assert_eq!(profile.groups.include, vec!["node_runtime"]);
    assert_eq!(profile.groups.exclude, vec!["dangerous_commands"]);
}
```

**Step 2: Run test to see it fail**

```bash
cargo test -p nono-cli --lib profile::tests::test_groups_config_deserializes 2>&1 | tail -10
```

Expected: FAIL with "unknown field `groups`" (because `deny_unknown_fields`).

**Step 3: Minimal implementation**

Add after `FilesystemConfig`:

```rust
/// Group composition — include/exclude pair for policy groups.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupsConfig {
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}
```

Add `pub groups: GroupsConfig,` to `Profile` (after `extends`), to `ProfileDeserialize`, and to the `From` impl's construction block. Use `#[serde(default)]`.

**Step 4: Run test to see it pass**

```bash
cargo test -p nono-cli --lib profile::tests::test_groups_config_deserializes 2>&1 | tail -10
cargo build -p nono-cli 2>&1 | tail -5
```

Expected: PASS. No warnings.

**Step 5: Commit**

```bash
git add crates/nono-cli/src/profile/mod.rs
git commit -s -m "feat(profile): add GroupsConfig and groups field to Profile

Introduces new canonical section for group include/exclude composition.
Part of #594 phase 2 schema restructure. No legacy draining yet."
```

---

### Task A2: Add `CommandsConfig` struct and `Profile.commands` field

**Files:** same as A1.

**Step 1: Failing test**

```rust
#[test]
fn test_commands_config_deserializes() {
    let json = r#"{
        "meta": {"name": "t"},
        "commands": {"allow": ["pip"], "deny": ["docker"]}
    }"#;
    let profile: Profile = serde_json::from_str(json).expect("parse");
    assert_eq!(profile.commands.allow, vec!["pip"]);
    assert_eq!(profile.commands.deny, vec!["docker"]);
}
```

**Step 2–4:** Same pattern as A1. Struct:

```rust
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandsConfig {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}
```

Wire into `Profile` + `ProfileDeserialize` + `From`.

**Step 5: Commit** — `feat(profile): add CommandsConfig and commands field to Profile`.

---

### Task A3: Expand `FilesystemConfig` with `deny` and `bypass_protection`

**Files:** `crates/nono-cli/src/profile/mod.rs:35` (FilesystemConfig).

**Step 1: Failing test**

```rust
#[test]
fn test_filesystem_config_deny_and_bypass_protection() {
    let json = r#"{
        "meta": {"name": "t"},
        "filesystem": {
            "deny": ["/blocked"],
            "bypass_protection": ["$HOME/.docker"]
        }
    }"#;
    let profile: Profile = serde_json::from_str(json).expect("parse");
    assert_eq!(profile.filesystem.deny, vec!["/blocked"]);
    assert_eq!(profile.filesystem.bypass_protection, vec!["$HOME/.docker"]);
}
```

**Step 2:** Run; expect failure.

**Step 3:** Add to `FilesystemConfig`:

```rust
/// Paths denied filesystem access (was policy.add_deny_access).
#[serde(default)]
pub deny: Vec<String>,
/// Paths exempted from deny groups. Must also appear in allow/read/write.
/// Was policy.override_deny; renamed to convey safety implications.
#[serde(default)]
pub bypass_protection: Vec<String>,
```

**Step 4:** Run test; expect pass.

**Step 5: Commit** — `feat(profile): expand FilesystemConfig with deny and bypass_protection`.

---

## Part B — Legacy capture layer

After Part B, old-schema profiles round-trip through the new fields. Old fields still exist on canonical structs (we remove them in Part C).

### Task B1: Create `deprecated_schema.rs` skeleton with warning helper

**Files:**
- Create: `crates/nono-cli/src/deprecated_schema.rs`
- Modify: `crates/nono-cli/src/main.rs` (add `mod deprecated_schema;` near line 18 alongside `mod deprecated_policy;`)

**Step 1: Failing test** (inline in the new file):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emit_deprecation_warning_format() {
        let captured = capture_warning(|| {
            emit_deprecation_warning(
                "policy.add_allow_read",
                "filesystem.read",
                "v1.0.0",
                "#594",
            );
        });
        assert!(captured.contains("policy.add_allow_read"));
        assert!(captured.contains("filesystem.read"));
        assert!(captured.contains("v1.0.0"));
        assert!(captured.contains("#594"));
    }
}
```

**Step 2:** Run, expect compile error (file doesn't exist).

**Step 3: Create the module.** Contents:

```rust
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
//! Only two callers may import from this module:
//!   - `main()` — `warn_for_deprecated_flags`.
//!   - `impl From<ProfileDeserialize> for Profile` — `drain_legacy_into_canonical`.
//! Any other import is a policy violation and must be caught by
//! `scripts/test-list-aliases.sh`.

use std::io::Write;

/// Emit a single deprecation warning line to stderr.
pub(crate) fn emit_deprecation_warning(
    legacy: &str,
    canonical: &str,
    remove_by: &str,
    issue: &str,
) {
    let _ = writeln!(
        std::io::stderr(),
        "warning: deprecated key '{legacy}' — use '{canonical}' instead (removed in {remove_by}, {issue})"
    );
}

#[cfg(test)]
pub(crate) fn capture_warning<F: FnOnce()>(_f: F) -> String {
    // Minimal capture using gag or a test-only sink; simplest impl:
    // tests use std::process::Command for integration-level capture.
    // For unit tests, expose a format-only helper below.
    format_deprecation_warning(
        "policy.add_allow_read", "filesystem.read", "v1.0.0", "#594",
    )
}

pub(crate) fn format_deprecation_warning(
    legacy: &str, canonical: &str, remove_by: &str, issue: &str,
) -> String {
    format!(
        "warning: deprecated key '{legacy}' — use '{canonical}' instead (removed in {remove_by}, {issue})"
    )
}
```

Rewrite the test to exercise `format_deprecation_warning` directly — keep it a pure unit test.

**Step 4:** `cargo test -p nono-cli --lib deprecated_schema::tests` — expect pass.

**Step 5: Commit** — `feat(deprecated_schema): scaffold module with warning formatter`.

---

### Task B2: Relocate `PolicyPatchConfig` as `LegacyPolicyPatch` in `deprecated_schema.rs`

**Files:**
- Modify: `crates/nono-cli/src/profile/mod.rs` (remove `PolicyPatchConfig` definition at line 62; keep the field on `ProfileDeserialize` but retype it to the new location)
- Modify: `crates/nono-cli/src/deprecated_schema.rs` (add `LegacyPolicyPatch`)

**Step 1: Failing test** (in `deprecated_schema.rs`):

```rust
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
    // ... all seven fields
}
```

**Step 2:** Run, fail.

**Step 3:** In `deprecated_schema.rs`, add `LegacyPolicyPatch` — **identical** layout to the existing `PolicyPatchConfig`, with `/// ALIAS` markers on each field:

```rust
/// Captures the deprecated top-level `"policy"` key. Drained to canonical
/// sections in `drain_legacy_into_canonical`.
#[derive(Debug, Clone, Default, serde::Deserialize)]
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
```

In `profile/mod.rs`:
- Remove the existing `PolicyPatchConfig` struct.
- `ProfileDeserialize.policy` retypes from `PolicyPatchConfig` to `Option<crate::deprecated_schema::LegacyPolicyPatch>` with `#[serde(default)]`.
- **Temporarily** keep `Profile.policy` as `PolicyPatchConfig` by re-aliasing — but cleaner: keep a transitional `PolicyPatchConfig` type alias pointing to `LegacyPolicyPatch` until Part C removes the field. Alternative: leave `Profile.policy: LegacyPolicyPatch` directly (canonical doesn't strictly require distinct names; we're removing the field entirely in Part C).

**Recommended:** Simplest path — `Profile.policy` stays, typed as `LegacyPolicyPatch`. Consumers still compile unchanged because the fields are identical. The `From` impl moves `raw.policy.unwrap_or_default()` into `Profile.policy`.

**Step 4:** Run all profile tests. Expect pass.

**Step 5: Commit** — `refactor(profile): relocate PolicyPatchConfig to deprecated_schema::LegacyPolicyPatch`.

---

### Task B3: Implement `drain_legacy_policy_into_canonical`

**Files:**
- Modify: `crates/nono-cli/src/deprecated_schema.rs`

Drains a `LegacyPolicyPatch` into the new canonical sections of `Profile`, emitting one warning per populated legacy field.

**Step 1: Failing tests** — seven, one per field:

```rust
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
fn test_drain_override_deny_goes_to_filesystem_bypass_protection() { /* ... */ }

// ...five more, one per LegacyPolicyPatch field.
```

Helper `canonical_empty_profile()` builds a minimal default-valued `Profile`.

**Step 2:** Run, fail (function doesn't exist).

**Step 3:** Implement in `deprecated_schema.rs`:

```rust
pub(crate) fn drain_legacy_policy_into_canonical(
    legacy: &LegacyPolicyPatch,
    profile: &mut crate::profile::Profile,
) {
    if !legacy.exclude_groups.is_empty() {
        emit_deprecation_warning("policy.exclude_groups", "groups.exclude", "v1.0.0", "#594");
        profile.groups.exclude.extend(legacy.exclude_groups.iter().cloned());
    }
    if !legacy.add_allow_read.is_empty() {
        emit_deprecation_warning("policy.add_allow_read", "filesystem.read", "v1.0.0", "#594");
        profile.filesystem.read.extend(legacy.add_allow_read.iter().cloned());
    }
    // ... five more, mirror pattern.
}
```

**Step 4:** Run all seven tests; expect pass.

**Step 5: Commit** — `feat(deprecated_schema): drain LegacyPolicyPatch into canonical sections`.

---

### Task B4: `RawSecurityConfig` wrapper for legacy `security.groups` / `security.allowed_commands`

**Files:**
- Modify: `crates/nono-cli/src/deprecated_schema.rs` (add `RawSecurityConfig`, `drain_legacy_security`)
- Modify: `crates/nono-cli/src/profile/mod.rs` (`ProfileDeserialize.security` retypes to `RawSecurityConfig`)

**Step 1: Failing test** in deprecated_schema.rs:

```rust
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
    assert!(raw.canonical.signal_mode.is_some());
}
```

**Step 2:** Run, fail.

**Step 3:** Implement:

```rust
/// Captures both canonical and legacy security keys during deserialization.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawSecurityConfig {
    #[serde(flatten)]
    pub canonical: crate::profile::SecurityConfig,
    /// ALIAS(canonical="groups.include", introduced="v0.41.0", remove_by="v1.0.0", issue="#594")
    #[serde(default, rename = "groups")]
    pub legacy_groups: Vec<String>,
    /// ALIAS(canonical="commands.allow", introduced="v0.41.0", remove_by="v1.0.0", issue="#594")
    #[serde(default, rename = "allowed_commands")]
    pub legacy_allowed_commands: Vec<String>,
}

pub(crate) fn drain_legacy_security_into_canonical(
    raw: &RawSecurityConfig,
    profile: &mut crate::profile::Profile,
) {
    if !raw.legacy_groups.is_empty() {
        emit_deprecation_warning("security.groups", "groups.include", "v1.0.0", "#594");
        profile.groups.include.extend(raw.legacy_groups.iter().cloned());
    }
    if !raw.legacy_allowed_commands.is_empty() {
        emit_deprecation_warning("security.allowed_commands", "commands.allow", "v1.0.0", "#594");
        profile.commands.allow.extend(raw.legacy_allowed_commands.iter().cloned());
    }
}
```

Important: `SecurityConfig` still has `groups` and `allowed_commands` fields at this point (Part C removes them). Using `#[serde(flatten)]` on `canonical` PLUS the legacy fields would cause collision. The clean path: temporarily `#[serde(flatten)]` onto a *narrow* `CanonicalSecurityConfig` shadow type. Simpler: switch `canonical` to explicit field-by-field in `RawSecurityConfig` until Part C narrows `SecurityConfig`.

**Practical interim shape** — until Part C removes `groups`/`allowed_commands` from `SecurityConfig`:

```rust
pub(crate) struct RawSecurityConfig {
    #[serde(default)] pub signal_mode: Option<crate::profile::ProfileSignalMode>,
    #[serde(default)] pub process_info_mode: Option<crate::profile::ProfileProcessInfoMode>,
    #[serde(default)] pub ipc_mode: Option<crate::profile::ProfileIpcMode>,
    #[serde(default)] pub capability_elevation: Option<bool>,
    #[serde(default)] pub wsl2_proxy_policy: Option<crate::profile::Wsl2ProxyPolicy>,
    /// ALIAS...
    #[serde(default, rename = "groups")] pub legacy_groups: Vec<String>,
    /// ALIAS...
    #[serde(default, rename = "allowed_commands")] pub legacy_allowed_commands: Vec<String>,
}

impl From<&RawSecurityConfig> for SecurityConfig { /* copy canonical fields */ }
```

Post-Part C we can switch to the `#[serde(flatten)]` shape once `SecurityConfig` is narrow.

`ProfileDeserialize.security` changes from `SecurityConfig` to `RawSecurityConfig`. The `From<ProfileDeserialize>` converts via `SecurityConfig::from(&raw.security)` and passes `&raw.security` to `drain_legacy_security_into_canonical`.

**Step 4:** All tests pass; `make build` passes.

**Step 5: Commit** — `feat(deprecated_schema): RawSecurityConfig captures legacy security.groups and allowed_commands`.

---

### Task B5: Wire both drains into `From<ProfileDeserialize> for Profile`

**Files:**
- Modify: `crates/nono-cli/src/profile/mod.rs` (`From` impl around line 1305)

**Step 1: Failing test** at workspace level (in `profile/mod.rs` tests):

```rust
#[test]
fn test_legacy_policy_keys_drain_into_new_sections() {
    let json = r#"{
        "meta": {"name": "t"},
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
    let profile: Profile = serde_json::from_str(json).expect("parse");
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
```

**Step 2:** Run, fail.

**Step 3:** Modify `impl From<ProfileDeserialize> for Profile`:

```rust
impl From<ProfileDeserialize> for Profile {
    fn from(raw: ProfileDeserialize) -> Self {
        let mut profile = Self {
            extends: raw.extends,
            meta: raw.meta,
            security: SecurityConfig::from(&raw.security),
            filesystem: raw.filesystem,
            // policy: until Part C, still has a PolicyPatchConfig-shaped field
            policy: raw.policy.clone().unwrap_or_default(),
            groups: raw.groups,
            commands: raw.commands,
            // ... rest unchanged
        };

        // Drain legacy into canonical — emits warnings.
        crate::deprecated_schema::drain_legacy_security_into_canonical(&raw.security, &mut profile);
        if let Some(legacy_policy) = raw.policy.as_ref() {
            crate::deprecated_schema::drain_legacy_policy_into_canonical(legacy_policy, &mut profile);
        }

        profile
    }
}
```

**Step 4:** Run workspace tests.

```bash
cargo test -p nono-cli 2>&1 | tail -20
```

Expect: new test passes; existing tests still pass.

**Step 5: Commit** — `feat(profile): drain legacy security and policy keys into canonical sections`.

---

### Task B6: Integration test — single-key fixtures + byte-equal semantic check

**Files:**
- Create: `crates/nono-cli/tests/fixtures/legacy_profiles/` (nine single-key JSON files + `legacy_all_keys.json` + `canonical_equivalent_of_all_keys.json`)
- Create: `crates/nono-cli/tests/deprecated_schema.rs`

**Step 1: Draft fixtures**

Nine files, one key each. Example `legacy_policy_override_deny.json`:

```json
{
  "meta": {"name": "legacy-test", "version": "0.1.0"},
  "extends": "default",
  "filesystem": {"allow": ["$HOME/.docker"]},
  "policy": {"override_deny": ["$HOME/.docker"]}
}
```

`legacy_all_keys.json` uses every legacy key. `canonical_equivalent_of_all_keys.json` has the semantically identical config in the new schema.

**Step 2: Failing integration test**

```rust
// crates/nono-cli/tests/deprecated_schema.rs
use std::process::Command;

fn bin() -> &'static str { env!("CARGO_BIN_EXE_nono") }

fn show_json(path: &str) -> String {
    let out = Command::new(bin())
        .args(["profile", "show", "--json", path])
        .output()
        .expect("run");
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).expect("utf8")
}

#[test]
fn legacy_all_keys_shows_byte_equal_canonical_equivalent() {
    let legacy = show_json("tests/fixtures/legacy_profiles/legacy_all_keys.json");
    let canonical = show_json("tests/fixtures/legacy_profiles/canonical_equivalent_of_all_keys.json");
    assert_eq!(legacy, canonical);
}

#[test]
fn legacy_all_keys_validate_succeeds_and_emits_nine_warnings() {
    let out = Command::new(bin())
        .args(["profile", "validate", "tests/fixtures/legacy_profiles/legacy_all_keys.json"])
        .output().expect("run");
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(stderr.matches("warning: deprecated key").count(), 9, "stderr: {stderr}");
}

#[test]
fn each_legacy_single_key_fixture_parses_and_warns() {
    for entry in std::fs::read_dir("tests/fixtures/legacy_profiles").unwrap() {
        let p = entry.unwrap().path();
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        if !name.starts_with("legacy_") || name == "legacy_all_keys.json" { continue; }
        let out = Command::new(bin())
            .args(["profile", "validate", p.to_str().unwrap()])
            .output().expect("run");
        assert!(out.status.success(), "{name} failed: {:?}", out);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("warning: deprecated key"),
            "{name} did not emit warning; stderr: {stderr}");
    }
}
```

**Step 3:** Run:

```bash
cargo test -p nono-cli --test deprecated_schema 2>&1 | tail -20
```

Expected: most fail initially (some tests depend on Part D's validate warnings; expected to fail until D3).

**Step 4:** Mark the validate-emission test `#[ignore]` with a note pointing to Task D3. Other tests should pass once fixtures exist. Re-run.

**Step 5: Commit** — `test(deprecated_schema): legacy fixture suite and byte-equal semantic check`.

---

## Part C — Remove old fields from canonical

Now the legacy drain works, we remove `PolicyPatchConfig` from `Profile`, remove `groups` and `allowed_commands` from `SecurityConfig`, and update every consumer. This is the most invasive task but every change is mechanical.

### Task C1: Remove `PolicyPatchConfig` from canonical `Profile`

**Files:**
- Modify: `crates/nono-cli/src/profile/mod.rs` (delete `policy: PolicyPatchConfig` from `Profile` struct at ~line 1192)
- Modify: every consumer of `profile.policy.*` (grep to find them)

**Step 1:** Identify consumers:

```bash
rg -n 'profile\.policy\.|\.policy\.add_|\.policy\.override_deny|\.policy\.exclude_groups' crates/ tests/ 2>&1 | tee /tmp/p2-c1-sites.txt
```

Expect: dozens of hits. Each must rewrite to the canonical equivalent:
- `profile.policy.add_allow_read` → `profile.filesystem.read`
- `profile.policy.add_allow_write` → `profile.filesystem.write`
- `profile.policy.add_allow_readwrite` → `profile.filesystem.allow`
- `profile.policy.add_deny_access` → `profile.filesystem.deny`
- `profile.policy.add_deny_commands` → `profile.commands.deny`
- `profile.policy.override_deny` → `profile.filesystem.bypass_protection`
- `profile.policy.exclude_groups` → `profile.groups.exclude`

**Step 2: Write a test that would regress** — pick one consumer, write a test asserting it works against canonical data:

```rust
// In crates/nono-cli/src/policy.rs tests module, or a new integration test
#[test]
fn test_resolver_reads_filesystem_deny_not_policy_add_deny_access() {
    let profile = Profile {
        filesystem: FilesystemConfig { deny: vec!["/x".into()], ..Default::default() },
        ..Default::default()
    };
    let capset = resolve_to_capabilities(&profile);
    assert!(capset.denies("/x"));
}
```

**Step 3:** Mechanical rewrite. Delete the `policy` field from `Profile`. Fix compile errors one by one — the compiler is the driver here. Use IDE rename-refactor for `.policy.add_allow_readwrite` → `.filesystem.allow` site-by-site.

Also update `ProfileDeserialize`:
- Keep `policy: Option<LegacyPolicyPatch>` (still needed for deserialization).
- Remove from the `From` impl's construction block (it's consumed purely for draining).

**Step 4:** `cargo test -p nono-cli 2>&1 | tail -30`. Expect all pass.

**Step 5: Commit** — `refactor(profile): remove PolicyPatchConfig from canonical Profile`.

---

### Task C2: Narrow `SecurityConfig`, remove `groups` and `allowed_commands`

**Files:**
- Modify: `crates/nono-cli/src/profile/mod.rs` (`SecurityConfig` at line 1050)
- Modify: consumers of `profile.security.groups` / `profile.security.allowed_commands`

**Step 1:** Identify consumers:

```bash
rg -n 'security\.groups|security\.allowed_commands' crates/ tests/ 2>&1 | tee /tmp/p2-c2-sites.txt
```

Including tests in `crates/nono-cli/src/profile/builtin.rs:36,41,49,51` that do `profile.security.groups.contains(...)` — rewrite to `profile.groups.include.contains(...)`.

**Step 2: Regression test:**

```rust
#[test]
fn test_profile_groups_include_used_for_resolution() {
    let json = r#"{
        "meta": {"name": "t"},
        "groups": {"include": ["node_runtime"]}
    }"#;
    let profile: Profile = serde_json::from_str(json).unwrap();
    assert_eq!(profile.groups.include, vec!["node_runtime"]);
}
```

**Step 3:** Delete `groups` and `allowed_commands` from `SecurityConfig`. Now `RawSecurityConfig` in `deprecated_schema.rs` switches to the clean `#[serde(flatten)]` layout over the canonical `SecurityConfig` (the TODO from Task B4 resolves here).

Rewrite consumer sites.

**Step 4:** `cargo test -p nono-cli` — all pass.

**Step 5: Commit** — `refactor(security): narrow SecurityConfig to process-level knobs only`.

---

### Task C3: Un-ignore the validate-warnings integration test

**Step 1:** Remove `#[ignore]` from `legacy_all_keys_validate_succeeds_and_emits_nine_warnings`.

**Step 2:** Run. It may still fail if `validate` doesn't surface drain warnings. Proceed to Part D if so.

**Step 3–5:** If it passes, commit as `test: enable validate warning integration test`.

---

## Part D — Deprecation warnings surfaced on `validate` and CLI

### Task D1: Rename `override_deny` → `bypass_protection` (Rust field only, no schema change yet)

**Files:**
- `crates/nono-cli/src/cli.rs` — two struct fields at ~866 and ~1115, array membership lists at 1050 and 1211, assignment at 1238, four tests at 2919–2956
- All consumer sites: `policy.rs`, `sandbox_prepare.rs`, `learn.rs`, `profile_cmd.rs`, etc.

**Step 1:** `rg -n 'override_deny' crates/` to enumerate.

**Step 2: Mechanical rename.** Search-replace `override_deny` → `bypass_protection` ONLY on internal Rust identifiers. Do NOT touch profile JSON keys (that's done via `filesystem.bypass_protection` already) or CLI flag strings yet (Task D2).

**Step 3:** Build, tests pass.

**Step 4: Commit** — `refactor(cli): rename override_deny Rust field to bypass_protection`.

---

### Task D2: CLI flag `--bypass-protection` with `--override-deny` alias

**Files:**
- `crates/nono-cli/src/cli.rs` (the two flag declarations and four tests)

**Step 1: Failing test** (add to cli.rs tests):

```rust
#[test]
fn test_bypass_protection_flag_canonical() {
    let args = CliArgs::try_parse_from(&[
        "nono", "run", "--bypass-protection", "/x", "--", "echo"
    ]).expect("parse");
    // assert args.sandbox.bypass_protection == [PathBuf::from("/x")]
}

#[test]
fn test_override_deny_alias_populates_bypass_protection() {
    let args = CliArgs::try_parse_from(&[
        "nono", "run", "--override-deny", "/x", "--", "echo"
    ]).expect("parse");
    // same assertion
}
```

**Step 2:** Run, fail (neither flag exists yet under the new name).

**Step 3:** Update both flag declarations:

```rust
/// ALIAS(canonical="--bypass-protection", introduced="v0.41.0", remove_by="v1.0.0", issue="#594")
#[arg(long = "bypass-protection", alias = "override-deny", value_name = "PATH")]
pub bypass_protection: Vec<PathBuf>,
```

Update the two membership lists (line 1050, 1211) and the assignment (line 1238). Rename the four existing tests from `test_override_deny_*` to `test_bypass_protection_*` and assert canonical. Keep one explicit `test_override_deny_alias_*` test.

**Step 4:** `cargo test -p nono-cli --lib cli::tests::` — expect pass.

**Step 5: Commit** — `feat(cli): rename --override-deny to --bypass-protection with alias`.

---

### Task D3: `warn_for_deprecated_flags` + `main()` wiring

**Files:**
- Modify: `crates/nono-cli/src/deprecated_schema.rs`
- Modify: `crates/nono-cli/src/main.rs`

**Step 1: Failing test** in `deprecated_schema.rs`:

```rust
#[test]
fn test_warn_for_deprecated_flags_detects_override_deny() {
    use std::ffi::OsString;
    let args: Vec<OsString> = vec!["nono", "run", "--override-deny", "/x"]
        .into_iter().map(OsString::from).collect();
    let detected = detect_deprecated_flags(&args);
    assert_eq!(detected, vec!["--override-deny"]);
}

#[test]
fn test_warn_for_deprecated_flags_detects_override_deny_equals_form() {
    use std::ffi::OsString;
    let args: Vec<OsString> = vec!["nono", "run", "--override-deny=/x"]
        .into_iter().map(OsString::from).collect();
    let detected = detect_deprecated_flags(&args);
    assert_eq!(detected, vec!["--override-deny"]);
}
```

**Step 2:** Run, fail.

**Step 3:** Implement:

```rust
pub(crate) fn detect_deprecated_flags(args: &[std::ffi::OsString]) -> Vec<&'static str> {
    let mut hits = Vec::new();
    for a in args {
        let s = a.to_string_lossy();
        if s == "--override-deny" || s.starts_with("--override-deny=") {
            if !hits.contains(&"--override-deny") { hits.push("--override-deny"); }
        }
    }
    hits
}

pub fn warn_for_deprecated_flags(args: &[std::ffi::OsString]) {
    for flag in detect_deprecated_flags(args) {
        let canonical = match flag {
            "--override-deny" => "--bypass-protection",
            _ => continue,
        };
        emit_deprecation_warning(flag, canonical, "v1.0.0", "#594");
    }
}
```

In `main.rs`, before clap parsing:

```rust
let os_args: Vec<_> = std::env::args_os().collect();
deprecated_schema::warn_for_deprecated_flags(&os_args);
```

**Step 4:** Add an integration test: invoke binary with `--override-deny /tmp --dry-run` and assert stderr contains the warning once.

**Step 5: Commit** — `feat(cli): warn on deprecated --override-deny flag use`.

---

### Task D4: `nono profile validate` — deprecation summary + `--strict` flag

**Files:**
- Modify: `crates/nono-cli/src/profile_cmd.rs` (the `cmd_validate` handler)
- Modify: `crates/nono-cli/src/cli.rs` (`ProfileValidateArgs` — add `strict: bool`)

**Step 1: Failing test** (integration, in `tests/deprecated_schema.rs`):

```rust
#[test]
fn test_validate_strict_upgrades_warnings_to_errors() {
    let out = Command::new(bin())
        .args(["profile", "validate", "--strict",
               "tests/fixtures/legacy_profiles/legacy_all_keys.json"])
        .output().expect("run");
    assert_eq!(out.status.code(), Some(2), "expected exit 2 for strict fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("found 9 deprecated keys"), "stderr: {stderr}");
}

#[test]
fn test_validate_prints_summary_of_deprecated_keys() {
    let out = Command::new(bin())
        .args(["profile", "validate",
               "tests/fixtures/legacy_profiles/legacy_all_keys.json"])
        .output().expect("run");
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("found 9 deprecated keys"));
}
```

**Step 2:** Run, fail.

**Step 3:**
- Add `#[arg(long)] strict: bool` to `ProfileValidateArgs`.
- In `cmd_validate`, wrap the parse in a warning-counting context. Easiest path: add a thread-local counter incremented inside `emit_deprecation_warning` (gated to validate-only via an enable flag set by `cmd_validate`). On completion, print the summary line; if `strict && count > 0`, exit with code 2.

Pseudocode:

```rust
pub fn cmd_validate(args: ProfileValidateArgs) -> Result<()> {
    deprecated_schema::begin_counting_warnings();
    let _profile = load_and_validate(&args.path)?;
    let count = deprecated_schema::end_counting_warnings();
    if count > 0 {
        eprintln!("found {count} deprecated keys; run 'nono profile guide' for migration mapping");
    }
    if args.strict && count > 0 {
        std::process::exit(2);
    }
    Ok(())
}
```

**Step 4:** Tests pass.

**Step 5: Commit** — `feat(profile): validate surfaces deprecation summary and --strict flag`.

---

## Part E — Migrate built-ins and qa-profiles

### Task E1: Migrate built-in profiles in `crates/nono-cli/data/policy.json`

**Files:**
- Modify: `crates/nono-cli/data/policy.json` — the `profiles` object keys

**Step 1: Check existing profile definitions**

```bash
jq '.profiles | keys' crates/nono-cli/data/policy.json
```

For each profile, grep for legacy keys:

```bash
jq '.profiles | to_entries | map(select(.value.policy or .value.security.groups or .value.security.allowed_commands)) | .[].key' crates/nono-cli/data/policy.json
```

**Step 2: Regression test** — add a test in `profile/builtin.rs` tests that enumerates every built-in and asserts `profile.policy` is an empty default (or once the field is gone, just that resolution works via new sections):

```rust
#[test]
fn test_all_builtins_use_canonical_schema_only() {
    for name in list_builtin() {
        let profile = get_builtin(&name).expect(&name);
        // Canonical invariant: post-migration, built-ins emit zero
        // deprecation warnings. Easiest check — parse strictness is
        // already enforced by the migration; this test validates that
        // resolved state is non-empty where expected.
        assert!(
            !profile.groups.include.is_empty() || !profile.filesystem.allow.is_empty(),
            "{name} has empty canonical sections"
        );
    }
}
```

**Step 3:** Edit `policy.json`. For each profile:
- Rename top-level `policy.*` keys per the migration table.
- Rename `security.groups` → `groups.include`, `security.allowed_commands` → `commands.allow`.

Example diff, for the `claude-code` profile:

```diff
 "claude-code": {
   "security": {
-    "groups": ["deny_credentials", "claude_code_macos"],
     "ipc_mode": "full"
   },
+  "groups": {
+    "include": ["deny_credentials", "claude_code_macos"]
+  },
   "filesystem": {
     "allow": ["$HOME/.cache/claude"],
     "allow_file": ["$HOME/.claude.lock"]
   },
-  "policy": {
-    "add_deny_access": ["..."]
-  }
+  "filesystem": {
+    "deny": ["..."]
+  }
 }
```

**Step 4:** `cargo test -p nono-cli` — no test should emit a deprecation warning when loading built-ins. Add a grep check:

```bash
cargo test -p nono-cli 2>&1 | grep -c "warning: deprecated key"
```

Expected: `0`.

**Step 5: Commit** — `refactor(policy-json): migrate built-in profiles to canonical #594 schema`.

---

### Task E2: Update `profile/builtin.rs` tests to reference canonical fields

**Files:** `crates/nono-cli/src/profile/builtin.rs` (test module, line ~28 onward)

**Step 1:** `rg -n 'profile\.security\.groups|profile\.policy\.' crates/nono-cli/src/profile/builtin.rs`

**Step 2:** Rewrite each assertion to canonical equivalent. Run tests — expect pass.

**Step 3:** Commit — `test(builtin): assert canonical schema fields after #594 migration`.

---

### Task E3: Migrate `qa-profiles/*.json` (if any legacy keys present)

**Step 1:** Check each file:

```bash
for f in qa-profiles/*.json; do
  if jq -r 'keys | .[]' "$f" | grep -qE '^policy$'; then echo "LEGACY: $f"; fi
done
```

Current qa-profiles (credentials-focused) likely have no legacy keys. If none found, skip this task.

**Step 2–5:** If legacy found, migrate analogously to E1 with a test fixture expectation.

---

## Part F — Enforcement tooling

### Task F1: `scripts/test-list-aliases.sh`

**Files:**
- Create: `scripts/test-list-aliases.sh` (POSIX shell, `grep -RE` only)

**Step 1: Specify behavior.**

Input: the repo `crates/` tree. Output:
- Exit 0 if every `#[serde(alias = ...)]`, `#[serde(rename = "X", alias = ...)]` where rename differs, `#[arg(..., alias = ...)]`, and every legacy capture field in `deprecated_schema.rs`/`deprecated_policy.rs` has a preceding `/// ALIAS(canonical="...", introduced="...", remove_by="...", issue="...")` comment.
- Exit 1 if any alias is missing its marker, or if any `/// ALIAS(...)` marker has a missing field.
- Print inventory grouped by `remove_by`, nearest first.
- Also check: `grep -RE 'use crate::deprecated_schema|use crate::deprecated_policy' crates/` — only `main.rs`, `app_runtime.rs`, `profile/mod.rs`, and `cli.rs` may contain these imports.

**Step 2: Write a Rust-level test** that shells out:

```rust
// crates/nono-cli/tests/alias_inventory.rs
#[test]
fn test_alias_inventory_script_passes() {
    let out = std::process::Command::new("bash")
        .arg("scripts/test-list-aliases.sh")
        .output().expect("run");
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
}
```

**Step 3: Write the script.** Target ~80 lines. Skeleton:

```bash
#!/usr/bin/env bash
set -euo pipefail

# Scan all aliases in crates/ and verify each has a /// ALIAS marker
# with all four fields: canonical, introduced, remove_by, issue.
# Also verifies only approved callers import deprecated_* modules.

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

# 1. Find all alias attributes (serde + clap)
aliases=$(grep -RnE '#\[serde\(.*alias = |#\[arg\(.*alias = ' crates/ || true)

# 2. For each, check preceding line for /// ALIAS(
fail=0
while IFS= read -r line; do
  file=$(echo "$line" | cut -d: -f1)
  lineno=$(echo "$line" | cut -d: -f2)
  prev=$((lineno - 1))
  # Also scan up to 3 lines above in case of multi-line attribute
  if ! sed -n "${prev}p" "$file" | grep -q '/// ALIAS(' ; then
    # Try one more line up
    ppp=$((prev - 1))
    if ! sed -n "${ppp}p" "$file" | grep -q '/// ALIAS(' ; then
      echo "MISSING /// ALIAS above $file:$lineno"
      fail=1
    fi
  fi
done <<< "$aliases"

# 3. Validate every /// ALIAS(...) marker has all four fields
markers=$(grep -RnE '/// ALIAS\(' crates/)
while IFS= read -r line; do
  for field in canonical introduced remove_by issue; do
    if ! echo "$line" | grep -q "${field}="; then
      echo "MISSING field '${field}' in $line"
      fail=1
    fi
  done
done <<< "$markers"

# 4. Approved deprecated_* importers only
approved='main\.rs|app_runtime\.rs|profile/mod\.rs|cli\.rs'
unapproved=$(grep -RnE 'use crate::deprecated_(schema|policy)' crates/ \
             | grep -vE "(${approved})(:| )")
if [ -n "$unapproved" ]; then
  echo "UNAPPROVED import:"
  echo "$unapproved"
  fail=1
fi

# 5. Inventory
echo "---"
echo "Alias inventory (sorted by remove_by):"
grep -RnE '/// ALIAS\(' crates/ \
  | sed -E 's/.*canonical="([^"]+)".*remove_by="([^"]+)".*/\2\t\1/' \
  | sort | uniq -c

exit $fail
```

Make executable: `chmod +x scripts/test-list-aliases.sh`.

**Step 4:** Run locally; iterate until it passes with the aliases introduced so far (tasks B2, B4, D2). Expect it to flag missing markers on any pre-existing serde aliases in `NetworkConfig`, `SecretsConfig`, `command_args` — deferred to Task F3.

**Step 5: Commit** — `feat(scripts): add test-list-aliases.sh deprecation inventory check`.

---

### Task F2: Wire `test-list-aliases.sh` into `make ci`

**Files:** Modify `Makefile`.

**Step 1:** Add target:

```makefile
.PHONY: lint-aliases
lint-aliases:
	bash scripts/test-list-aliases.sh

ci: check test audit lint-aliases lint-docs
	@echo "CI checks passed"
```

**Step 2–4:** Run `make ci`. Iterate.

**Step 5: Commit** — `build: wire lint-aliases into make ci`.

---

### Task F3: Retrofit existing aliases with `/// ALIAS` markers

**Files:**
- `crates/nono-cli/src/profile/mod.rs`: `NetworkConfig::allow_domain`, `credentials`, `open_port`, `upstream_proxy`, `upstream_bypass`; `ProfileDeserialize.env_credentials` (alias "secrets"); `ProfileDeserialize.command_args` (alias "brokered_commands"); `ProfileDeserialize.rollback` (alias "undo")
- `crates/nono/src/trust/types.rs:24` — `instruction_patterns` alias
- Phase 1's deprecated_policy aliases, if any

**Step 1:** Run `scripts/test-list-aliases.sh` — get the list of aliases missing markers.

**Step 2: For each alias, pick `remove_by`.** For `#594`-unrelated legacy aliases that are already in the wild, use `remove_by="indefinite"`. The script flags these separately in its inventory output (see F1, step 5) so we have an explicit list to revisit.

**Step 3:** Add markers. Example:

```rust
/// Canonical profile key: `allow_domain` (legacy `proxy_allow` and `allow_proxy` are also accepted).
/// ALIAS(canonical="allow_domain", introduced="v0.0.0", remove_by="indefinite", issue="#594")
#[serde(default, rename = "allow_domain", alias = "proxy_allow", alias = "allow_proxy")]
pub allow_domain: Vec<String>,
```

Two aliases on one field = one `/// ALIAS` marker per alias, but in practice one marker covering both is allowed if clearly listing both.

**Step 4:** `bash scripts/test-list-aliases.sh` passes.

**Step 5: Commit** — `chore(aliases): retrofit /// ALIAS markers on pre-existing legacy aliases`.

---

### Task F4: `make lint-docs` target and allowlist

**Files:**
- Modify: `Makefile`
- Create: `scripts/lint-docs.sh` (optional — can inline if small)

**Step 1:** Specify forbidden tokens:

```
policy\.add_
policy\.override_deny
policy\.exclude_groups
security\.groups
security\.allowed_commands
--override-deny
```

Allowlisted paths:
- `crates/nono-cli/src/deprecated_schema.rs`
- `crates/nono-cli/src/deprecated_policy.rs`
- `crates/nono-cli/tests/fixtures/legacy_profiles/`
- `crates/nono-cli/tests/deprecated_schema.rs`
- `crates/nono-cli/tests/deprecated_policy.rs`
- `docs/plans/`
- `CHANGELOG.md`

**Step 2:** Makefile:

```makefile
.PHONY: lint-docs
lint-docs:
	@bash -c '\
	  forbidden="policy\\.add_|policy\\.override_deny|policy\\.exclude_groups|security\\.groups|security\\.allowed_commands|--override-deny"; \
	  allow="deprecated_schema\\.rs|deprecated_policy\\.rs|fixtures/legacy_profiles|docs/plans|CHANGELOG\\.md"; \
	  hits=$$(grep -RnE "$$forbidden" crates/ docs/ README.md 2>/dev/null | grep -vE "$$allow" || true); \
	  if [ -n "$$hits" ]; then echo "Forbidden tokens in docs:"; echo "$$hits"; exit 1; fi; \
	  echo "lint-docs: ok"'
```

**Step 3:** `make lint-docs` — iterate until clean (will find deprecated refs in the existing embedded guide, rustdoc comments, and mdx files — those are fixed in Part G).

Initially, mark failing files as "expected to fail — fixed in G1..Gn". Easiest: temporarily allowlist `crates/nono-cli/data/profile-authoring-guide.md` and the mdx pages, remove from allowlist in G1/G2 once rewritten.

**Step 4:** Commit — `build: add make lint-docs target`.

---

## Part G — Documentation

### Task G1: Update embedded `profile-authoring-guide.md` with a migration section

**Files:**
- Modify: `crates/nono-cli/data/profile-authoring-guide.md`

**Step 1: Draft migration section content.** Before/after diff for every legacy → canonical mapping; link to issue #594.

**Step 2:** Rewrite every example in the guide to canonical schema.

**Step 3:** `cargo test -p nono-cli` — existing test (from phase 1 precedent) greps embedded guide for forbidden tokens; expect pass.

**Step 4:** Run `nono profile guide` via `cargo run -p nono-cli -- profile guide | head -60` to eyeball rendering.

**Step 5:** Commit — `docs(guide): migrate profile-authoring-guide to canonical schema with #594 migration section`.

---

### Task G2: Update `docs/cli/**/*.mdx` site docs

**Files:**
- `docs/cli/features/profiles-groups.mdx`
- `docs/cli/features/profile-authoring.mdx`
- `docs/cli/features/profile-introspection.mdx`
- `docs/cli/usage/flags.mdx`
- Anywhere else `rg 'policy\.(add_|override_deny|exclude_groups)|security\.(groups|allowed_commands)|--override-deny' docs/` hits

**Step 1:** Enumerate with `rg -l '...' docs/`.

**Step 2:** Edit each file. Preserve "previously called X" callouts where the user will recognize the old term.

**Step 3:** `make lint-docs` passes.

**Step 4:** Commit — `docs(cli): update mdx docs to canonical #594 schema`.

---

### Task G3: Update rustdoc comments, error messages, suggestion strings

**Files:**
- `crates/nono-cli/src/policy.rs`, `profile_cmd.rs`, `learn.rs`, `sandbox_prepare.rs` — any user-facing string or rustdoc referencing old keys
- `crates/nono-cli/src/profile/mod.rs` — rustdoc on `FilesystemConfig`, `SecurityConfig`, etc.

**Step 1:** `rg -n 'policy\.(add_|override_deny|exclude_groups)|--override-deny' crates/` excluding `deprecated_*.rs` and fixture dirs. This will be the last batch of internal references to rewrite.

**Step 2–4:** Rewrite. Ensure `learn` mode suggestions use canonical keys. Run `make ci`.

**Step 5:** Commit — `docs(code): update rustdoc and suggestion strings to canonical schema`.

---

### Task G4: Schema JSON regeneration

**Files:**
- `crates/nono-cli/data/nono-profile.schema.json` (regenerated output)
- wherever the schema-emit test lives

**Step 1:** Regenerate:

```bash
cargo run -p nono-cli -- profile schema > crates/nono-cli/data/nono-profile.schema.json
```

**Step 2:** Snapshot test asserts:
- `$.properties.groups` exists.
- `$.properties.commands` exists.
- `$.properties.filesystem.properties.deny` exists.
- `$.properties.filesystem.properties.bypass_protection` exists.
- `$.properties.policy` does NOT exist (old keys no longer advertised).
- `$.properties.security` has no `groups` / `allowed_commands`.

Use `jq` in a shell test or parse with `serde_json` in a Rust integration test.

**Step 3:** Commit — `docs(schema): regenerate profile JSON schema for #594`.

---

## Part H — Final verification

### Task H1: Full `make ci` pass + manual smoke tests

**Step 1:** `make ci` — must pass cleanly. Watch for:
- Any `deprecated key` warnings when loading built-ins (MUST be zero — grep stderr).
- clippy warnings.
- `scripts/test-list-aliases.sh` output matches expected inventory.

**Step 2:** Manual smoke:

```bash
# 1. legacy fixture parses + warns
cargo run -p nono-cli -- profile validate \
  crates/nono-cli/tests/fixtures/legacy_profiles/legacy_all_keys.json

# 2. legacy ≡ canonical semantically
diff <(cargo run -p nono-cli -- profile show --json \
         crates/nono-cli/tests/fixtures/legacy_profiles/legacy_all_keys.json) \
     <(cargo run -p nono-cli -- profile show --json \
         crates/nono-cli/tests/fixtures/legacy_profiles/canonical_equivalent_of_all_keys.json)

# 3. --override-deny alias still works, emits warning
cargo run -p nono-cli -- run --dry-run --override-deny /tmp -- echo test 2>&1 \
  | grep -q "'--override-deny' is deprecated"

# 4. guide renders, no forbidden tokens
cargo run -p nono-cli -- profile guide | grep -E 'policy\.add_|--override-deny' && echo FAIL
```

**Step 3:** Open the PR. Title: `feat(profile)!: restructure profile JSON schema (#594)`. Body: phase 2 summary + agent-compliance checklist per CLAUDE.md.

**Step 4:** Post on issue #594 linking the PR and stating removal targets `v1.0.0`.

---

## Task dependency summary

```
A1 → A2 → A3          (non-breaking additions; can interleave)
     ↓
B1 → B2 → B3 → B4 → B5 → B6
                         ↓
C1 → C2 → C3             (invasive; order matters)
     ↓
D1 → D2 → D3 → D4        (CLI + validate)
     ↓
E1 → E2 → E3             (migrate built-ins/fixtures)
     ↓
F1 → F2 → F3 → F4        (enforcement; F3 unblocks lint-aliases CI)
     ↓
G1 → G2 → G3 → G4        (docs + schema)
     ↓
H1                       (final)
```

Total: 25 tasks. Expected timeline: ~1 week of focused work.

## Skill references

- @superpowers:test-driven-development — every task follows Red/Green/Commit.
- @superpowers:verification-before-completion — no task is complete until its test passes and `cargo test -p nono-cli` is green.
- @superpowers:systematic-debugging — for any test that fails unexpectedly, stop and diagnose before changing approach.
- @superpowers:receiving-code-review — phase-2 changes will receive review; apply the skill when integrating feedback.
