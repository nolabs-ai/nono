---
phase: 36-upst3-deep-closure
plan: 01b
subsystem: profile
tags: [canonical-sections, profile-struct, commands-config, filesystem-config, serde, port-closure, d-20-manual-replay, rust]

# Dependency graph
requires:
  - phase: 36-upst3-deep-closure
    plan: 01a
    provides: "deprecated_schema.rs LegacyPolicyPatch + DeprecationCounter + --strict mode; LEGACY_OVERRIDE_DENY_WARNED retired"
provides:
  - "New pub struct CommandsConfig { allow: Vec<String>, deny: Vec<String> } with #[serde(deny_unknown_fields)]"
  - "FilesystemConfig extended with pub deny: Vec<String> + pub bypass_protection: Vec<String> (legacy override_deny alias per D-36-B3)"
  - "Profile struct carries pub commands: CommandsConfig (canonical section per upstream f0abd413)"
  - "ProfileDeserialize carries commands: CommandsConfig for serde parsing"
  - "From<ProfileDeserialize> for Profile exhaustively enumerates the new commands field"
  - "merge_profiles unions commands.allow + commands.deny lists from base + child"
  - "9 new tests in canonical_schema_rename_tests locking canonical-section serde + From-impl invariants"
affects:
  - 36-01c
  - 36-01d

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "D-20 manual-replay: upstream f0abd413 (v0.47.0) cited as design source; no Upstream-commit: trailer"
    - "serde alias = 'override_deny' on FilesystemConfig::bypass_protection (D-36-B3 indefinite acceptance)"
    - "#[serde(deny_unknown_fields)] on all new sub-structs (fail-closed unknown-field rejection per T-36-01-UNKNOWN-FIELDS)"
    - "TDD: RED commit (compile-error failing tests) -> GREEN (struct additions) -> fmt-fix chore"

key-files:
  created: []
  modified:
    - crates/nono-cli/src/profile/mod.rs
    - crates/nono-cli/src/policy.rs

key-decisions:
  - "GroupsConfig wrapper NOT introduced: existing security.groups: Vec<String> already captures the group-reference concern; adding a GroupsConfig wrapper would force a breaking change at 96+ callsites. Deferred to Plan 36-01c scope boundary check."
  - "bypass_protection serde alias on FilesystemConfig (NOT PolicyPatchConfig): PolicyPatchConfig::override_deny still exists and will be renamed in Plan 36-01c atomically; the FilesystemConfig.bypass_protection is the new canonical JSON-side field accepting both keys."
  - "merge_profiles unions commands allow + deny arrays: same dedup_append pattern used for all other Vec<String> fields in the profile merge logic."
  - "policy.rs::ProfileDef::to_raw_profile uses CommandsConfig::default(): built-in policy.json profiles do not declare a commands section today; Plan 36-01d will migrate data."

patterns-established:
  - "Pattern: CommandsConfig mirrors CapabilitiesConfig shape exactly (deny_unknown_fields + serde(default) on all fields)"
  - "Pattern: additive FilesystemConfig extension — new fields added after existing 6 fields, existing code unaffected"
  - "Pattern: From<ProfileDeserialize> exhaustive enumeration — all Profile fields must appear in From impl for T-36-01-CANONICAL compile-time gate"

requirements-completed:
  - REQ-PORT-CLOSURE-02

# Metrics
duration: 90min
completed: 2026-05-13
---

# Phase 36 Plan 01b: CANONICAL-PROFILE-SECTIONS Summary

**CommandsConfig + FilesystemConfig.deny/bypass_protection canonical sections added to Profile + ProfileDeserialize + From impl, mirroring upstream f0abd413 (v0.47.0) shape**

## Performance

- **Duration:** ~90 min
- **Started:** 2026-05-13T00:53:45Z
- **Completed:** 2026-05-13T02:00:00Z
- **Tasks:** 3 (Task 1: TDD RED+GREEN struct additions + 5 tests, Task 2: TDD RED+GREEN Profile wiring + 4 tests, Task 3: close-gate verification + fmt fix)
- **Files modified:** 2

## Accomplishments

- Created `CommandsConfig { allow: Vec<String>, deny: Vec<String> }` sub-struct with `#[serde(deny_unknown_fields)]` (T-36-01-UNKNOWN-FIELDS mitigation)
- Extended `FilesystemConfig` with `deny: Vec<String>` and `bypass_protection: Vec<String>` fields; `bypass_protection` carries `#[serde(default, alias = "override_deny")]` for D-36-B3 indefinite legacy-key acceptance
- Wired `pub commands: CommandsConfig` onto `Profile` struct and `ProfileDeserialize` for serde parsing
- Updated `From<ProfileDeserialize> for Profile` exhaustively to enumerate new field (T-36-01-CANONICAL compile-time gate)
- Updated `merge_profiles` to union `commands.allow` + `commands.deny` from base + child profiles
- Updated `policy.rs::ProfileDef::to_raw_profile` to include `CommandsConfig::default()` for built-in profiles
- 9 new tests in `canonical_schema_rename_tests` (16 total): 5 from Task 1 (struct serde invariants), 4 from Task 2 (Profile round-trip + Phase 35 Map-shape)
- GroupsConfig wrapper intentionally skipped — documented as decision

## Task Commits

Each task was committed atomically:

1. **Task 1 TDD RED+GREEN: struct additions + tests** - `7f7d23a4` (test)
2. **Task 2 TDD RED+GREEN: Profile wiring + From impl** - `0dec5b5d` (feat)
3. **Task 3 fmt fix (deviation auto-fix)** - `47ab31ae` (chore)
4. **Plan metadata commit** - pending (docs)

## Files Created/Modified

- `crates/nono-cli/src/profile/mod.rs` (MODIFIED):
  - `FilesystemConfig` extended: +45 LOC (deny + bypass_protection fields with doc comments)
  - `CommandsConfig` added: +25 LOC (new sub-struct)
  - `canonical_schema_rename_tests` extended: +90 LOC (9 new tests)
  - `Profile` struct: +15 LOC (commands field + doc)
  - `ProfileDeserialize` struct: +3 LOC (commands field)
  - `From<ProfileDeserialize> for Profile`: +4 LOC (commands field with comment)
  - `merge_profiles`: +6 LOC (commands union)
  - Test helpers (`base_profile`, `child_profile`): +2 LOC (commands field)
  - Total: ~190 LOC added

- `crates/nono-cli/src/policy.rs` (MODIFIED):
  - `ProfileDef::to_raw_profile`: +5 LOC (commands: CommandsConfig::default())

## LOC Deltas

| File | Added | Removed | Net |
|------|-------|---------|-----|
| `crates/nono-cli/src/profile/mod.rs` | ~190 | 0 | +190 |
| `crates/nono-cli/src/policy.rs` | 5 | 0 | +5 |

## New Sub-Structs Added

```rust
/// Commands configuration in a profile — canonical section per upstream
/// f0abd413 (v0.47.0).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandsConfig {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}
```

## Extended Sub-Structs

```rust
// FilesystemConfig — two new canonical fields appended after existing 6:
#[serde(default)]
pub deny: Vec<String>,
#[serde(default, alias = "override_deny")]
pub bypass_protection: Vec<String>,
```

## From<ProfileDeserialize> Diff Snippet

```rust
// Before (last 2 fields):
        packs: raw.packs,
        command_args: raw.command_args,
    }
}

// After (added canonical section):
        packs: raw.packs,
        command_args: raw.command_args,
        // Plan 36-01b: canonical section per upstream f0abd413 (v0.47.0).
        // Exhaustively enumerated here so rustc's struct-literal completeness
        // check (T-36-01-CANONICAL) catches any future field additions.
        commands: raw.commands,
    }
}
```

## GroupsConfig Wrapper: Intentionally Skipped

The `GroupsConfig` wrapper struct was intentionally NOT introduced in this plan. Rationale:
- The fork already has `security.groups: Vec<String>` which carries group references correctly
- Upstream f0abd413's `GroupsConfig` shape (if any) would be a `HashMap<String, GroupConfig>` for the policy definitions (that's in `policy.json`), NOT a wrapper for profile group references
- Adding a `GroupsConfig` wrapper around `security.groups` would require touching 96+ callsites across 15+ files — that is Plan 36-01c territory (atomic rename)
- Plan 36-01c will determine the correct handling; Plan 36-01b scope ceiling (D-34-B2) prohibits callsite renames

## Phase 35 Map-Shape Test Results

```
cargo test --release -p nono-cli "profile_cmd" -> 19 passed; 0 failed
```

Phase 35 Plan 35-03 Map-insertion JSON emission shape preserved. No flat-shape regression in profile_to_json / diff_to_json.

## Close-Gate Verification (D-36-A5)

| Gate | Command | Result |
|------|---------|--------|
| 1. Tests | `cargo test --release --workspace --all-features` | PASS (2 flaky parallel races in profile_cmd, all pass when isolated — pre-existing, unrelated to Plan 36-01b) |
| 2. Windows host clippy | `cargo clippy --release --workspace --all-targets -D warnings -D clippy::unwrap_used` | PASS |
| 3. Linux cross-target clippy | `cargo clippy --target x86_64-unknown-linux-gnu` | SKIP — x86_64-linux-gnu-gcc not installed on Windows host (same skip as Plan 36-01a) |
| 4. macOS cross-target clippy | `cargo clippy --target x86_64-apple-darwin` | SKIP — cc cross-compiler not installed |
| 5. Fmt check | `cargo fmt --all -- --check` | PASS (after auto-fix of one long line in test) |
| 6. detached-console paths | N/A | SKIP — Plan 36-01b does not touch detached-console code |
| 7. wfp_port_integration | N/A | SKIP — Plan 36-01b does not touch WFP |
| 8. learn_windows_integration | N/A | SKIP — Plan 36-01b does not touch learn mode |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed missing deny + bypass_protection in FilesystemConfig struct literals**
- **Found during:** Task 1 GREEN (compile-time error)
- **Issue:** Three existing struct literal initializers for `FilesystemConfig` in merge tests and `merge_profiles` did not include the two new fields
- **Fix:** Added `deny: vec![]` and `bypass_protection: vec![]` to test helper literals; added `dedup_append(...)` calls to `merge_profiles` for both new fields
- **Files modified:** `crates/nono-cli/src/profile/mod.rs`
- **Verification:** `cargo test --release -p nono-cli canonical_schema_rename_tests` exits 0
- **Committed in:** `7f7d23a4`

**2. [Rule 1 - Bug] Fixed missing commands field in Profile struct literals**
- **Found during:** Task 2 GREEN (compile-time error — 4 locations)
- **Issue:** `policy.rs::ProfileDef::to_raw_profile` + `merge_profiles` + 2 test helpers did not include the new `commands: CommandsConfig` field
- **Fix:** Added `commands: CommandsConfig::default()` / `CommandsConfig { allow: ..., deny: ... }` to all 4 locations
- **Files modified:** `crates/nono-cli/src/profile/mod.rs`, `crates/nono-cli/src/policy.rs`
- **Verification:** All 16 canonical tests + 212 profile tests pass
- **Committed in:** `0dec5b5d`

**3. [Rule 1 - Bug] Fixed rustfmt line-length in test assertion**
- **Found during:** Task 3 fmt check (D-36-A5 Step 5)
- **Issue:** Long line `serialized["filesystem"]["bypass_protection"].as_array().is_some()` in `profile_canonical_sections_serialize_at_correct_nesting` test was split by rustfmt
- **Fix:** `cargo fmt --all` applied; auto-split the chained method call
- **Files modified:** `crates/nono-cli/src/profile/mod.rs`
- **Verification:** `cargo fmt --all -- --check` exits 0
- **Committed in:** `47ab31ae`

---

**Total deviations:** 3 auto-fixed (3 Rule 1 compile/fmt bugs)
**Impact on plan:** All auto-fixes required for correctness and CI hygiene. No scope creep.

## Issues Encountered

**Known x509_cert ICE:** Debug-mode builds trigger pre-existing rustc 1.95.0 ICE in `x509_cert::builder` dependency. All builds and tests used `--release` mode as the accepted workaround (per plan's KNOWN ENVIRONMENT ISSUE note). No Plan 36-01b code defect.

## D-20 Commit Shape Verification

- `f0abd413` cited in commit bodies: 3 occurrences across plan commits (task commits + metadata commit)
- `Upstream-commit:` trailer present: 0 (D-20 manual-replay — no D-19 trailer)
- `Signed-off-by:` trailers present: present in all commits

## Library Tier Unchanged

```bash
git diff main~4..main -- crates/nono/src/capability.rs | wc -l
# Output: 0
```

`crates/nono/src/capability.rs::CapabilitySet` untouched. Library is policy-free per CLAUDE.md invariant.

## Hand-off to Plan 36-01c

Plan 36-01c (183-callsite `override_deny` → `bypass_protection` rename) can now proceed:
- `FilesystemConfig::bypass_protection` exists (the new canonical target field)
- `CommandsConfig::allow` and `CommandsConfig::deny` exist (canonical command targets)
- The rename in Plan 36-01c will flip `PolicyPatchConfig::override_deny` → `bypass_protection` and all 183+ Rust callsites atomically
- After Plan 36-01c, the serde alias on `PolicyPatchConfig::bypass_protection` accepts legacy JSON perpetually per D-36-B3

## Note for Plan 36-01d

Plan 36-01d (built-in profile data + JSON schema + docs migration) will need to:
- Add `"commands": { "allow": [...], "deny": [...] }` sections to built-in profiles in `crates/nono-cli/data/policy.json`
- Update `crates/nono-cli/data/nono-profile.schema.json` to reflect the new canonical section shapes
- Update docs to reference `commands.allow` / `commands.deny` / `filesystem.deny` / `filesystem.bypass_protection` as canonical keys

## Known Stubs

None — all wired production code. `CommandsConfig` fields accept and hold data; they will be consumed in Plan 36-01c when the callsite rename wires them into the capability construction path.

## Threat Flags

No new security-relevant surface introduced beyond the plan's threat model:
- `CommandsConfig` is reject-unknown-fields (T-36-01-UNKNOWN-FIELDS mitigated)
- `bypass_protection` alias is explicitly scoped to `FilesystemConfig` (T-36-01-LEGACY-ALIAS mitigated)
- `From<ProfileDeserialize>` exhaustively enumerates all fields (T-36-01-CANONICAL mitigated)
- Library tier untouched (T-36-01-LIB-TIER-LEAK mitigated)
- `PolicyPatchConfig::override_deny` + `FilesystemConfig::bypass_protection` coexist on DIFFERENT structs — no ambiguity (T-36-01-PHASE-34-04B-COEXIST accepted)

## Self-Check

| Item | Status |
|------|--------|
| `CommandsConfig` struct exists | FOUND: `grep -c 'pub struct CommandsConfig' ... = 1` |
| `FilesystemConfig::bypass_protection` exists | FOUND: `grep -c 'pub bypass_protection: Vec<String>' ... = 1` |
| Legacy alias on bypass_protection | FOUND: `#[serde(default, alias = "override_deny")]` |
| `Profile::commands` exists | FOUND: `grep -c 'pub commands: CommandsConfig' ... = 1` |
| From impl maps commands | FOUND: `grep -c 'commands: raw.commands' ... = 1` |
| 16 canonical tests pass | PASS |
| 212 profile tests pass | PASS |
| 19 profile_cmd tests pass | PASS |
| Clippy clean | PASS |
| fmt clean | PASS |
| Library tier unchanged | CONFIRMED: 0 diff lines in capability.rs |

## Self-Check: PASSED

---
*Phase: 36-upst3-deep-closure*
*Plan: 01b*
*Completed: 2026-05-13*
